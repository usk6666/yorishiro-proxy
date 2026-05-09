//go:build e2e

// USK-791: capture_scope must apply to the upstream-TLS-handshake-error
// path introduced by USK-784. Pre-fix, BuildLiveStack wired the recorder
// without consulting Deps.RecordScope so any TLS handshake failure was
// persisted as a state="error" Stream — even when the operator scoped
// recording to a specific host. This caused HSTS-pinned services the
// browser dialled on its own (accounts.google.com / android.clients.google.com /
// www.google.com etc.) to flood the flow store during validation
// sessions limited to a single target hostname.
//
// This e2e test stands up a real BuildLiveStack with a populated
// RecordScope, drives a CONNECT + TLS handshake against an upstream
// presenting a self-signed cert (so the proxy's verification path
// actually fails), and asserts:
//
//   - Out-of-scope target → no Stream recorded.
//   - In-scope target → state="error" Stream recorded (USK-784 parity).
//
// The smoke build tag puts this in the merge gate so a regression in
// the proxybuild wiring surfaces in per-PR CI.
package proxybuild_test

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestProxybuild_CONNECT_UpstreamTLSError_RespectsCaptureScope drives the
// USK-791 acceptance criteria end to end through BuildLiveStack with a
// non-empty RecordScope.
//
// Each subtest stands up an isolated BuildLiveStack so streams from one
// case do not leak into the next.
func TestProxybuild_CONNECT_UpstreamTLSError_RespectsCaptureScope(t *testing.T) {
	cases := []struct {
		name      string
		scopeHost string // RecordScope.includes hostname (port-stripped)
		// wantRecordedForLoopback asserts whether the loopback target the
		// test always uses (127.0.0.1:<random>) is in scope under the
		// configured RecordScope.includes rule.
		wantRecordedForLoopback bool
	}{
		{
			// 127.0.0.1 is in scope: USK-784's behaviour preserved.
			name:                    "in_scope_records_error_stream",
			scopeHost:               "127.0.0.1",
			wantRecordedForLoopback: true,
		},
		{
			// only some-other-host is in scope: 127.0.0.1 must be dropped
			// silently (USK-791 fix).
			name:                    "out_of_scope_drops_silently",
			scopeHost:               "in-scope-only.example.test",
			wantRecordedForLoopback: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tlsCfg := selfSignedTLSConfig(t)

			// Stand up a TLS listener whose cert the proxy will reject
			// (self-signed → x509 unknown authority).
			upstreamLn, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
			if err != nil {
				t.Fatalf("upstream tls listen: %v", err)
			}

			var serverWG sync.WaitGroup
			serverWG.Add(1)
			go func() {
				defer serverWG.Done()
				for {
					c, aerr := upstreamLn.Accept()
					if aerr != nil {
						return
					}
					if tc, ok := c.(*tls.Conn); ok {
						_ = tc.Handshake()
					}
					_ = c.Close()
				}
			}()
			defer serverWG.Wait()
			defer upstreamLn.Close()

			target := upstreamLn.Addr().String()

			store := &upstreamTLSErrorStore{}
			ca := &cert.CA{}
			if err := ca.Generate(); err != nil {
				t.Fatalf("CA.Generate: %v", err)
			}

			scope := flow.NewRecordScope()
			scope.SetRules([]flow.ScopeRule{{Hostname: tc.scopeHost}}, nil)

			deps := proxybuild.Deps{
				Logger:       testutil.DiscardLogger(),
				ListenerName: "usk-791-test",
				ListenAddr:   "127.0.0.1:0",
				FlowStore:    store,
				RecordScope:  scope,
				BuildConfig: &connector.BuildConfig{
					ProxyConfig:        &config.ProxyConfig{},
					Issuer:             cert.NewIssuer(ca),
					InsecureSkipVerify: false, // force the verification path
				},
			}

			stack, err := proxybuild.BuildLiveStack(ctx, deps)
			if err != nil {
				t.Fatalf("BuildLiveStack: %v", err)
			}
			go func() { _ = stack.Listener.Start(ctx) }()
			select {
			case <-stack.Listener.Ready():
			case <-time.After(5 * time.Second):
				t.Fatal("listener not ready")
			}

			proxyAddr := stack.Listener.Addr()
			if proxyAddr == "" {
				t.Fatal("listener has no addr")
			}

			// Drive CONNECT + TLS handshake through the proxy. The
			// upstream cert is self-signed, so the proxy's verification
			// fails and the CONNECT tunnel is torn down — ideal trigger
			// for the OnUpstreamTLSError callback.
			gotErr := connectAndAttemptHandshake(t, proxyAddr, target)
			if gotErr == nil {
				// We expect the inner TLS handshake to fail because the
				// proxy aborts on upstream cert reject. A nil error here
				// would mean the proxy never noticed the upstream
				// failure — which would silently invalidate the test.
				t.Errorf("client TLS handshake unexpectedly succeeded; expected proxy abort")
			}

			// The OnUpstreamTLSError callback fires synchronously inside
			// runTLSMITM, so a short poll loop is enough to drain it.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if !tc.wantRecordedForLoopback {
					// Negative case: nothing more to wait for. Brief
					// pause so any spurious callback has time to fire.
					time.Sleep(200 * time.Millisecond)
					break
				}
				if findErrorStreamForTarget(store.Streams(), target) != nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}

			errStream := findErrorStreamForTarget(store.Streams(), target)
			if tc.wantRecordedForLoopback {
				if errStream == nil {
					t.Fatalf("in-scope host: expected state=\"error\" Stream for %q; streams=%+v",
						target, store.Streams())
				}
				if errStream.State != "error" {
					t.Errorf("State = %q, want %q", errStream.State, "error")
				}
				if errStream.FailureReason != "upstream_tls_error" {
					t.Errorf("FailureReason = %q, want %q",
						errStream.FailureReason, "upstream_tls_error")
				}
				return
			}

			// Out-of-scope: no Stream must be recorded for the loopback
			// target. Defence in depth: also ensure no Stream was
			// recorded for any other authority — an out-of-scope CONNECT
			// must not produce ANY error Stream.
			if errStream != nil {
				t.Errorf("out-of-scope host: unexpected state=\"error\" Stream recorded: %+v",
					errStream)
			}
			for _, st := range store.Streams() {
				if st == nil {
					continue
				}
				if st.State == "error" {
					t.Errorf("out-of-scope host: unexpected error Stream: %+v", st)
				}
			}
		})
	}
}

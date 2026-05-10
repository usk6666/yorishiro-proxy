//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// TestALPNFilter_RespectsEnabledProtocols is the regression guard for
// USK-808: when proxy_start specifies protocols=["HTTP/1.x","HTTPS"]
// (HTTP/2 deliberately omitted), the MITM TLS handshake must not
// advertise "h2" in NextProtos so the browser/client cannot negotiate
// HTTP/2.
//
// Pre-fix: enabled_protocols at the listener level prevented inbound
// h2c (cleartext HTTP/2) but had no effect on the MITM TLS ALPN
// extension, so a CONNECT-then-TLS browser still ended up on HTTP/2.
//
// Setup: synthetic h2-capable upstream advertising both ["h2","http/1.1"];
// proxy with EnabledProtocols filter installed on BuildConfig.
//
// Negative case (filter excludes h2): client offers ["h2","http/1.1"],
// must negotiate "http/1.1" because the proxy never advertises h2.
//
// Positive control (no filter / filter includes h2): same client
// offers, must negotiate "h2" so we know the test isn't trivially
// blocking h2 by other means.
//
// Operator-flip case: warm an h2 pool entry while h2 is enabled, then
// flip the filter to exclude h2; the next request must downgrade to
// http/1.1 (covers the pool fast-path path in stack_builder.go).
func TestALPNFilter_RespectsEnabledProtocols(t *testing.T) {
	cases := []struct {
		name             string
		enabledProtocols []string
		clientALPNOffers []string
		wantALPN         string
	}{
		{
			name:             "filter_excludes_h2_client_downgrades_to_http1",
			enabledProtocols: []string{"HTTP/1.x", "HTTPS"},
			clientALPNOffers: []string{"h2", "http/1.1"},
			wantALPN:         "http/1.1",
		},
		{
			name:             "filter_allows_h2_client_negotiates_h2",
			enabledProtocols: []string{"HTTP/1.x", "HTTPS", "HTTP/2"},
			clientALPNOffers: []string{"h2", "http/1.1"},
			wantALPN:         "h2",
		},
		{
			name:             "no_filter_legacy_behavior_keeps_h2",
			enabledProtocols: nil,
			clientALPNOffers: []string{"h2", "http/1.1"},
			wantALPN:         "h2",
		},
		{
			name:             "filter_only_https_falls_back_to_http1",
			enabledProtocols: []string{"HTTPS"},
			clientALPNOffers: []string{"h2", "http/1.1"},
			wantALPN:         "http/1.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			upstreamLn, _ := startUpstreamHTTPSWithALPN(t,
				[]string{"h2", "http/1.1"},
				func(_ []byte) []byte {
					return []byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nh1-served")
				},
			)
			defer upstreamLn.Close()
			target := upstreamLn.Addr().String()

			proxyAddr, _, wg, _ := startFullListenerProxyWithALPNFilter(t, ctx, tc.enabledProtocols)

			wg.Add(1)
			tlsConn := connectThroughProxyWithALPN(t, proxyAddr, target, tc.clientALPNOffers)
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()
			if state.NegotiatedProtocol != tc.wantALPN {
				t.Errorf("NegotiatedProtocol = %q, want %q (enabled=%v offers=%v)",
					state.NegotiatedProtocol, tc.wantALPN,
					tc.enabledProtocols, tc.clientALPNOffers)
			}
		})
	}
}

// TestALPNFilter_RuntimeFlipDowngrades verifies the operator-flip
// scenario: the proxy starts with HTTP/2 enabled, then the operator
// flips the filter to exclude HTTP/2. The next MITM handshake must
// advertise only http/1.1, even though a previous h2 connection may
// have warmed a pool entry. Covers buildPoolHitFastPath's interaction
// with the runtime ALPN filter.
//
// USK-813: also asserts that the per-CONNECT client MITM handshake
// count is exactly 1 after the flip — the short-circuit in
// buildPoolHitFastPath must release the pool reservation BEFORE doing
// the handshake. The pre-USK-813 shape of the code completed the
// handshake just to fall back via the post-handshake clientALPN check,
// yielding a count of 2 per CONNECT.
func TestALPNFilter_RuntimeFlipDowngrades(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startUpstreamHTTPSWithALPN(t,
		[]string{"h2", "http/1.1"},
		func(_ []byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nh1-served")
		},
	)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, wg, buildCfg := startFullListenerProxyWithALPNFilter(t, ctx, []string{"HTTP/1.x", "HTTPS", "HTTP/2"})

	// Phase 1: filter allows h2 — confirm the client negotiates h2 to
	// warm any caching paths.
	wg.Add(1)
	t1 := connectThroughProxyWithALPN(t, proxyAddr, target, []string{"h2", "http/1.1"})
	if got := t1.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("phase 1 NegotiatedProtocol = %q, want %q", got, "h2")
	}
	t1.Close()

	// Phase 2: flip the filter to exclude h2 and snapshot the handshake
	// counter so we can assert exactly one MITM handshake happens for the
	// next CONNECT.
	buildCfg.SetEnabledProtocols([]string{"HTTP/1.x", "HTTPS"})
	buildCfg.ResetClientMITMHandshakeCount()

	// New connection must downgrade.
	wg.Add(1)
	t2 := connectThroughProxyWithALPN(t, proxyAddr, target, []string{"h2", "http/1.1"})
	defer t2.Close()
	if got := t2.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Errorf("phase 2 NegotiatedProtocol = %q, want %q (runtime filter flip did not propagate)",
			got, "http/1.1")
	}

	// USK-813: the post-flip CONNECT must perform exactly one client MITM
	// handshake. The pool fast path (if it was warmed in phase 1) must
	// short-circuit BEFORE performClientMITM rather than after. A count
	// of 2 here indicates the regression has returned. A count of 1
	// covers both the "no pool entry" case (cache-miss path runs the
	// handshake once) and the "pool entry declined" case (short-circuit
	// fires, then cache-miss path runs the handshake once).
	if got := buildCfg.ClientMITMHandshakeCount(); got != 1 {
		t.Errorf("phase 2 ClientMITMHandshakeCount = %d, want 1 (USK-813: fast path should short-circuit before the wasted handshake)", got)
	}
}

// TestALPNFilter_FlowRecording verifies that when the filter forces an
// HTTP/1.1 downgrade, the recorded flow's protocol/scheme reflect the
// downgrade reality (not stale h2 from upstream).
func TestALPNFilter_FlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startUpstreamHTTPSWithALPN(t,
		[]string{"h2", "http/1.1"},
		func(_ []byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nh1-served")
		},
	)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, wg, _ := startFullListenerProxyWithALPNFilter(t, ctx, []string{"HTTP/1.x", "HTTPS"})

	wg.Add(1)
	rawReq := fmt.Sprintf(
		"GET /alpn-filter HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		target,
	)
	resp := connectAndSendHTTPWithClientALPN(t, proxyAddr, target, []string{"h2", "http/1.1"}, rawReq)
	waitSessionDone(t, wg)

	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}

	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	// Stream must be HTTP (not h2-misdispatched), state healthy, scheme https.
	if streams[0].Protocol != "http" {
		t.Errorf("stream protocol = %q, want %q", streams[0].Protocol, "http")
	}
	if streams[0].Scheme != "https" {
		t.Errorf("stream scheme = %q, want %q", streams[0].Scheme, "https")
	}
	if streams[0].State == "error" {
		t.Errorf("stream state = %q (regression: filter downgrade misdispatched)", streams[0].State)
	}
}

// startFullListenerProxyWithALPNFilter mirrors startFullListenerProxy
// from full_listener_integration_test.go but threads an EnabledProtocols
// allow-list through the BuildConfig (USK-808 wiring) and returns the
// BuildConfig pointer so tests can flip the allow-list at runtime.
//
// Kept local to this test file to avoid coupling the shared helper to
// the new BuildConfig knob; the shared helper continues to serve the
// pre-USK-808 majority of integration tests unchanged.
func startFullListenerProxyWithALPNFilter(
	t *testing.T,
	ctx context.Context,
	enabledProtocols []string,
) (proxyAddr string, store *testStore, wg *sync.WaitGroup, buildCfg *connector.BuildConfig) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	store = &testStore{}
	wg = &sync.WaitGroup{}

	buildCfg = &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}
	if len(enabledProtocols) > 0 {
		buildCfg.SetEnabledProtocols(enabledProtocols)
	}

	connectNeg := connector.NewCONNECTNegotiator(slog.Default())
	socks5Neg := connector.NewSOCKS5Negotiator(slog.Default())

	onStack := func(ctx context.Context, stack *connector.ConnectionStack, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
		defer wg.Done()
		defer stack.Close()

		clientCh := <-stack.ClientTopmost().Channels()

		steps := []pipeline.Step{
			pipeline.NewHostScopeStep(nil),
			pipeline.NewRecordStep(store, slog.Default()),
		}
		p := pipeline.New(steps...)

		session.RunSession(ctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return <-stack.UpstreamTopmost().Channels(), nil
		}, p)
	}

	flCfg := connector.FullListenerConfig{
		Name: "test-alpn-filter",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connectNeg,
			BuildCfg:   buildCfg,
			OnStack:    onStack,
		}),
		OnSOCKS5: connector.NewSOCKS5Handler(connector.SOCKS5HandlerConfig{
			Negotiator: socks5Neg,
			BuildCfg:   buildCfg,
			OnStack:    onStack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx)

	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for FullListener to be ready")
	}

	return fl.Addr(), store, wg, buildCfg
}

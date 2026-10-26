//go:build e2e && !e2e_smoke

// USK-1380 exhaustive tier: the Policy / Agent rate limit applies to
// tcp_forwards connections, once per accepted connection, after the scope
// gate and before client TLS termination and the upstream dial. Fixtures
// come from tcp_forward_scope_integration_test.go (startScopeForward,
// acceptCountingUpstream, settleAccepts, readClosedNoBytes) and
// transparent_ratelimit_integration_test.go (burstOneLimiter,
// withRateLimiter).
package proxybuild_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// forwardRateLimitStreams returns the recorded rate_limit Streams.
func forwardRateLimitStreams(f *scopeForwardFixture) []*flow.Stream {
	var out []*flow.Stream
	for _, st := range f.store.Streams() {
		if st.BlockedBy == "rate_limit" {
			out = append(out, st)
		}
	}
	return out
}

// waitForwardRateLimitStreams polls until want rate_limit Streams exist.
func waitForwardRateLimitStreams(t *testing.T, f *scopeForwardFixture, want int) []*flow.Stream {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := forwardRateLimitStreams(f)
		if len(got) >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// flowsOf counts the Flow rows recorded on streamID.
func flowsOf(f *scopeForwardFixture, streamID string) int {
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	n := 0
	for _, fl := range f.store.flows {
		if fl.StreamID == streamID {
			n++
		}
	}
	return n
}

// TestProxybuild_TCPForwardRateLimit_RawOverLimitClosed is test-plan 1/7:
// under a burst-1 limit the first raw forward connection reaches the
// upstream, the second is closed with no byte written and never dialled,
// an Info log names the limit, and exactly one rate_limit Stream (no Flow
// rows) records the refusal.
func TestProxybuild_TCPForwardRateLimit_RawOverLimitClosed(t *testing.T) {
	target, accepts := acceptCountingUpstream(t)
	f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "raw"}, withRateLimiter(burstOneLimiter(false)))

	c1 := dialScopeForward(t, f.fwdAddr)
	_, _ = c1.Write([]byte("usk1380-first"))
	if got := settleAccepts(accepts, 1, 5*time.Second); got != 1 {
		t.Fatalf("first connection: upstream accepted %d, want 1", got)
	}

	c2 := dialScopeForward(t, f.fwdAddr)
	_, _ = c2.Write([]byte("usk1380-second"))
	readClosedNoBytes(t, c2, 5*time.Second)
	if got := settleAccepts(accepts, 0, 300*time.Millisecond); got != 1 {
		t.Errorf("upstream accepted %d connections, want 1 (the over-limit connection must not be dialled)", got)
	}

	streams := waitForwardRateLimitStreams(t, f, 1)
	if len(streams) != 1 {
		t.Fatalf("%d rate_limit Streams, want 1; streams=%v", len(streams), f.store.Streams())
	}
	st := streams[0]
	if st.State != "error" || st.FailureReason != "rate_limit" {
		t.Errorf("Stream State=%q FailureReason=%q, want error / rate_limit", st.State, st.FailureReason)
	}
	if st.Protocol != "raw" || st.Scheme != "http" {
		t.Errorf("Stream Protocol=%q Scheme=%q, want raw / http", st.Protocol, st.Scheme)
	}
	if st.ListenerName != proxybuild.DefaultListenerName {
		t.Errorf("Stream ListenerName = %q, want %q", st.ListenerName, proxybuild.DefaultListenerName)
	}
	if st.ConnID == "" {
		t.Error("Stream ConnID is empty")
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr != c2.LocalAddr().String() || st.ConnInfo.ServerAddr != "" {
		t.Errorf("Stream ConnInfo = %+v, want ClientAddr %s and no ServerAddr", st.ConnInfo, c2.LocalAddr())
	}
	wantTags := map[string]string{
		"via":             "tcp-forward",
		"target":          target,
		"forward_port":    "0",
		"rate_limit_type": "global",
	}
	for k, v := range wantTags {
		if st.Tags[k] != v {
			t.Errorf("Tags[%s] = %q, want %q (tags %v)", k, st.Tags[k], v, st.Tags)
		}
	}
	if st.Tags["rate_limit_effective_rps"] == "" {
		t.Errorf("Tags = %v, want rate_limit_effective_rps", st.Tags)
	}
	if n := flowsOf(f, st.ID); n != 0 {
		t.Errorf("rate_limit Stream has %d Flow rows, want 0", n)
	}
	out := f.logs.Output()
	if !strings.Contains(out, "tcp forward target blocked by rate limit") || !strings.Contains(out, "limit_type=global") {
		t.Errorf("missing Info 'tcp forward target blocked by rate limit' with limit_type; logs:\n%s", out)
	}
	// The refusal Stream and its Info log share the connection's conn_id
	// (minted at admission, before the gate runs).
	if st.ConnID != "" && !strings.Contains(out, "conn_id="+st.ConnID) {
		t.Errorf("rate-limit log does not carry the refusal Stream's conn_id %q; logs:\n%s", st.ConnID, out)
	}
}

// TestProxybuild_TCPForwardRateLimit_HTTPGets429 is test-plan 2: a
// plaintext http / websocket / sse forward over the limit answers the
// CONNECT gate's exact 429 bytes, then EOF; the upstream is not contacted.
func TestProxybuild_TCPForwardRateLimit_HTTPGets429(t *testing.T) {
	for _, proto := range []string{"http", "websocket", "sse"} {
		t.Run(proto, func(t *testing.T) {
			target, accepts := acceptCountingUpstream(t)
			rl := burstOneLimiter(false)
			f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: proto}, withRateLimiter(rl))
			if d := rl.Check("spend.example"); d != nil {
				t.Fatalf("pre-spend denied: %+v", d)
			}

			c := dialScopeForward(t, f.fwdAddr)
			_, _ = io.WriteString(c, "GET /usk1380 HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read refusal: %v (got %q)", err, got)
			}
			want := connector.RateLimitRefusalResponse()
			if len(want) == 0 || !bytes.Equal(got, want) {
				t.Errorf("over-limit %s forward answered %q, want the CONNECT gate's 429 %q", proto, got, want)
			}
			if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != 0 {
				t.Errorf("upstream accepted %d connections, want 0", n)
			}
			if streams := waitForwardRateLimitStreams(t, f, 1); len(streams) != 1 || streams[0].Protocol != "http" {
				t.Errorf("rate_limit Streams = %v, want one with Protocol http", streams)
			}
		})
	}
}

// TestProxybuild_TCPForwardRateLimit_SilentArms is test-plan 3: every arm
// that cannot carry a plaintext HTTP/1.1 answer — raw, auto, http2, grpc
// and every tls=true entry (refused before client TLS termination) — is
// closed with no byte written and never dialled.
func TestProxybuild_TCPForwardRateLimit_SilentArms(t *testing.T) {
	cases := []struct {
		proto string
		tls   bool
	}{
		{"raw", false}, {"auto", false}, {"http2", false}, {"grpc", false},
		{"raw", true}, {"http", true}, {"http2", true}, {"sse", true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/tls=%v", tc.proto, tc.tls), func(t *testing.T) {
			target, accepts := acceptCountingUpstream(t)
			rl := burstOneLimiter(false)
			f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: tc.proto, TLS: tc.tls}, withRateLimiter(rl))
			if d := rl.Check("spend.example"); d != nil {
				t.Fatalf("pre-spend denied: %+v", d)
			}

			if tc.tls {
				nextProtos := []string{"http/1.1"}
				if tc.proto == "http2" {
					nextProtos = []string{"h2"}
				}
				tconn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", f.fwdAddr, &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // proxy's ephemeral MITM CA
					ServerName:         "127.0.0.1",
					NextProtos:         nextProtos,
				})
				if err == nil {
					_ = tconn.Close()
					t.Errorf("client TLS handshake succeeded on an over-limit forward; want the gate to close before termination")
				}
			} else {
				c := dialScopeForward(t, f.fwdAddr)
				probe := []byte{0x00, 0x01, 'u', 's', 'k', '1', '3', '8', '0'}
				if tc.proto == "http2" || tc.proto == "grpc" {
					probe = h2Preface
				}
				_, _ = c.Write(probe)
				readClosedNoBytes(t, c, 5*time.Second)
			}
			if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != 0 {
				t.Errorf("upstream accepted %d connections, want 0", n)
			}
			streams := waitForwardRateLimitStreams(t, f, 1)
			if len(streams) != 1 {
				t.Fatalf("%d rate_limit Streams, want 1", len(streams))
			}
			wantScheme := "http"
			if tc.tls {
				wantScheme = "https"
			}
			if streams[0].Scheme != wantScheme {
				t.Errorf("Stream Scheme = %q, want %q (client leg)", streams[0].Scheme, wantScheme)
			}
		})
	}
}

// TestProxybuild_TCPForwardRateLimit_NoLimitUnchanged is test-plan 4: with
// no rate limiter, and with a limiter that has no limits, rapid forward
// connections are all relayed and nothing is recorded as rate_limit.
func TestProxybuild_TCPForwardRateLimit_NoLimitUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		rl   *connector.RateLimiter
	}{
		{"nil limiter", nil},
		{"zero limits", connector.NewRateLimiter()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, accepts := acceptCountingUpstream(t)
			var opts []func(*proxybuild.Deps)
			if tc.rl != nil {
				opts = append(opts, withRateLimiter(tc.rl))
			}
			f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "raw"}, opts...)
			const n = 5
			for i := 0; i < n; i++ {
				c := dialScopeForward(t, f.fwdAddr)
				_, _ = c.Write([]byte{byte(i)})
			}
			if got := settleAccepts(accepts, n, 5*time.Second); got != n {
				t.Errorf("upstream accepted %d connections, want %d", got, n)
			}
			if s := forwardRateLimitStreams(f); len(s) != 0 {
				t.Errorf("%d rate_limit Streams with no limit, want 0", len(s))
			}
		})
	}
}

// TestProxybuild_TCPForwardRateLimit_ScopeRefusalConsumesNoToken is
// test-plan 5: a scope-denied connection is refused before the rate-limit
// gate, so it spends no token — after the deny is lifted the next
// connection is admitted under a burst-1 limit.
func TestProxybuild_TCPForwardRateLimit_ScopeRefusalConsumesNoToken(t *testing.T) {
	target, accepts := acceptCountingUpstream(t)
	f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "raw"}, withRateLimiter(burstOneLimiter(false)))
	f.deny(t, target)

	c1 := dialScopeForward(t, f.fwdAddr)
	_, _ = c1.Write([]byte("denied"))
	readClosedNoBytes(t, c1, 5*time.Second)

	f.scope.SetPolicyRules(nil, nil)
	c2 := dialScopeForward(t, f.fwdAddr)
	_, _ = c2.Write([]byte("admitted"))
	if got := settleAccepts(accepts, 1, 5*time.Second); got != 1 {
		t.Errorf("upstream accepted %d connections, want 1 (the scope refusal must not spend the token)", got)
	}
	if s := forwardRateLimitStreams(f); len(s) != 0 {
		t.Errorf("%d rate_limit Streams, want 0", len(s))
	}
}

// TestProxybuild_TCPForwardRateLimit_SharedBucketWithCONNECT is test-plan
// 6: the forward gate keys the per-host bucket on the target host, the
// same bucket the CONNECT gate spends — one CONNECT to the target spends
// the burst and the forward to it is refused.
func TestProxybuild_TCPForwardRateLimit_SharedBucketWithCONNECT(t *testing.T) {
	target, accepts := acceptCountingUpstream(t)
	f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "raw"}, withRateLimiter(burstOneLimiter(true)))
	_, proxyAddr := f.mgr.Status()

	// The CONNECT gate spends the per-host token when it answers 200,
	// whether or not the tunnel goes on to dial.
	_, _, line := connectStatus(t, proxyAddr, target)
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("CONNECT status = %q, want 200", line)
	}
	before := settleAccepts(accepts, 0, 300*time.Millisecond)

	c := dialScopeForward(t, f.fwdAddr)
	_, _ = c.Write([]byte("forward"))
	readClosedNoBytes(t, c, 5*time.Second)
	if got := settleAccepts(accepts, 0, 300*time.Millisecond); got != before {
		t.Errorf("upstream accepted %d connections after the forward, want %d (the forward shares the CONNECT gate's per-host bucket)", got, before)
	}
	streams := waitForwardRateLimitStreams(t, f, 1)
	if len(streams) != 1 || streams[0].Tags["rate_limit_type"] != "per_host" {
		t.Errorf("rate_limit Streams = %v, want one with rate_limit_type per_host", streams)
	}
}

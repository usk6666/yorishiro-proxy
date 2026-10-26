//go:build e2e && !e2e_smoke

// USK-1381 exhaustive tier: a CONNECT, plain-HTTP forward or SOCKS5
// connection the main listener's rate-limit gate refuses leaves one
// State="error", BlockedBy="rate_limit" Stream (no Flow rows), while the
// client still sees exactly the refusal bytes it saw before. Driven through
// a real Manager + BuildLiveStack. Fixtures come from
// tcp_forward_scope_integration_test.go (acceptCountingUpstream,
// settleAccepts), transparent_ratelimit_integration_test.go
// (burstOneLimiter), scope_host_alias_integration_test.go (connectStatus,
// socks5Connect, portOf) and onhttp1_integration_test.go (flowStoreCapture).
package proxybuild_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// gateRateLimitProxy is a main listener (CONNECT / SOCKS5 / plain forward)
// with a capture store.
type gateRateLimitProxy struct {
	scope     *connector.TargetScope
	store     *flowStoreCapture
	proxyAddr string
}

// startGateRateLimitProxy starts the fixture. rl and recordScope may be nil.
func startGateRateLimitProxy(t *testing.T, rl *connector.RateLimiter, recordScope *flow.RecordScope) *gateRateLimitProxy {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, logger := testutil.NewCaptureLogger()
	scope := connector.NewTargetScope()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	store := &flowStoreCapture{}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:      logger,
		BuildConfig: buildCfg,
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:       logger,
				ListenerName: name,
				ListenAddr:   addr,
				FlowStore:    store,
				BuildConfig:  buildCfg,
				Scope:        scope,
				LiveConns:    connector.NewLiveConns(logger),
				RateLimiter:  rl,
				RecordScope:  recordScope,
			})
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	_, addr := mgr.Status()
	if addr == "" {
		t.Fatal("main listener not bound")
	}
	return &gateRateLimitProxy{scope: scope, store: store, proxyAddr: addr}
}

// rateLimitStreams returns the rate_limit Streams.
func (p *gateRateLimitProxy) rateLimitStreams() []*flow.Stream {
	var out []*flow.Stream
	for _, st := range p.store.Streams() {
		if st.BlockedBy == "rate_limit" {
			out = append(out, st)
		}
	}
	return out
}

// waitRateLimitStreams polls until want rate_limit Streams exist or 5s pass.
func (p *gateRateLimitProxy) waitRateLimitStreams(want int) []*flow.Stream {
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := p.rateLimitStreams()
		if len(got) >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// flowCount counts the Flow rows recorded on streamID.
func (p *gateRateLimitProxy) flowCount(streamID string) int {
	n := 0
	for _, fl := range p.store.Flows() {
		if fl.StreamID == streamID {
			n++
		}
	}
	return n
}

// sendAndReadAll dials the proxy, writes req and reads until the proxy
// closes the connection.
func sendAndReadAll(t *testing.T, proxyAddr, req string) (net.Conn, []byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read refusal: %v (got %q)", err, got)
	}
	return c, got
}

// checkGateRefusalStream asserts the common shape of a gate rate-limit
// refusal Stream.
func checkGateRefusalStream(t *testing.T, p *gateRateLimitProxy, st *flow.Stream, protocol, scheme, via, target, limitType string, client net.Conn) {
	t.Helper()
	if st.State != "error" || st.FailureReason != "rate_limit" || st.BlockedBy != "rate_limit" {
		t.Errorf("Stream State=%q FailureReason=%q BlockedBy=%q, want error / rate_limit / rate_limit", st.State, st.FailureReason, st.BlockedBy)
	}
	if st.Protocol != protocol || st.Scheme != scheme {
		t.Errorf("Stream Protocol=%q Scheme=%q, want %q / %q", st.Protocol, st.Scheme, protocol, scheme)
	}
	if st.ListenerName != proxybuild.DefaultListenerName {
		t.Errorf("Stream ListenerName = %q, want %q", st.ListenerName, proxybuild.DefaultListenerName)
	}
	if st.ConnID == "" {
		t.Error("Stream ConnID is empty")
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr != client.LocalAddr().String() || st.ConnInfo.ServerAddr != "" {
		t.Errorf("Stream ConnInfo = %+v, want ClientAddr %s and no ServerAddr", st.ConnInfo, client.LocalAddr())
	}
	wantTags := map[string]string{
		"via":                      via,
		"target":                   target,
		"rate_limit_type":          limitType,
		"rate_limit_effective_rps": "0.001",
		"reason":                   limitType + " limit 0.001 rps",
	}
	for k, v := range wantTags {
		if st.Tags[k] != v {
			t.Errorf("Tags[%s] = %q, want %q (tags %v)", k, st.Tags[k], v, st.Tags)
		}
	}
	if n := p.flowCount(st.ID); n != 0 {
		t.Errorf("rate_limit Stream has %d Flow rows, want 0", n)
	}
}

// TestProxybuild_GateRateLimitRecord_CONNECT is test-plan 1: under a
// burst-1 per-host limit the first CONNECT is admitted, the second gets
// exactly the 429 bytes, the upstream is not dialled for it, and one
// via=connect rate_limit Stream records the refusal.
func TestProxybuild_GateRateLimitRecord_CONNECT(t *testing.T) {
	target, accepts := acceptCountingUpstream(t)
	p := startGateRateLimitProxy(t, burstOneLimiter(true), nil)

	c1, _, line := connectStatus(t, p.proxyAddr, target)
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("first CONNECT status = %q, want 200", line)
	}
	_ = c1.Close()
	before := settleAccepts(accepts, 0, 300*time.Millisecond)

	c2, got := sendAndReadAll(t, p.proxyAddr, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	if want := connector.RateLimitRefusalResponse(); !bytes.Equal(got, want) {
		t.Errorf("over-limit CONNECT answered %q, want %q", got, want)
	}
	if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != before {
		t.Errorf("upstream accepted %d connections, want %d (the refused CONNECT must not be dialled)", n, before)
	}

	streams := p.waitRateLimitStreams(1)
	if len(streams) != 1 {
		t.Fatalf("%d rate_limit Streams, want 1; streams=%v", len(streams), p.store.Streams())
	}
	checkGateRefusalStream(t, p, streams[0], "http", "", "connect", target, "per_host", c2)
}

// TestProxybuild_GateRateLimitRecord_Forward is test-plan 2: an over-limit
// plain-HTTP forward request gets exactly the 429 bytes and one
// via=http1-forward rate_limit Stream with scheme http.
func TestProxybuild_GateRateLimitRecord_Forward(t *testing.T) {
	target, accepts := acceptCountingUpstream(t)
	rl := burstOneLimiter(false)
	p := startGateRateLimitProxy(t, rl, nil)
	if d := rl.Check("spend.example"); d != nil {
		t.Fatalf("pre-spend denied: %+v", d)
	}

	c, got := sendAndReadAll(t, p.proxyAddr, "GET http://"+target+"/usk1381 HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	if want := connector.RateLimitRefusalResponse(); !bytes.Equal(got, want) {
		t.Errorf("over-limit forward answered %q, want %q", got, want)
	}
	if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != 0 {
		t.Errorf("upstream accepted %d connections, want 0", n)
	}

	streams := p.waitRateLimitStreams(1)
	if len(streams) != 1 {
		t.Fatalf("%d rate_limit Streams, want 1; streams=%v", len(streams), p.store.Streams())
	}
	checkGateRefusalStream(t, p, streams[0], "http", "http", "http1-forward", target, "global", c)
}

// TestProxybuild_GateRateLimitRecord_SOCKS5 is test-plan 3: an over-limit
// SOCKS5 CONNECT gets REP=0x02 and one via=socks5 rate_limit Stream with
// protocol raw.
func TestProxybuild_GateRateLimitRecord_SOCKS5(t *testing.T) {
	target, accepts := acceptCountingUpstream(t)
	rl := burstOneLimiter(false)
	p := startGateRateLimitProxy(t, rl, nil)
	if d := rl.Check("spend.example"); d != nil {
		t.Fatalf("pre-spend denied: %+v", d)
	}

	c, rep := socks5Connect(t, p.proxyAddr, "127.0.0.1", portOf(t, target))
	if rep != 0x02 {
		t.Errorf("over-limit SOCKS5 REP = 0x%02x, want 0x02", rep)
	}
	if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != 0 {
		t.Errorf("upstream accepted %d connections, want 0", n)
	}

	streams := p.waitRateLimitStreams(1)
	if len(streams) != 1 {
		t.Fatalf("%d rate_limit Streams, want 1; streams=%v", len(streams), p.store.Streams())
	}
	checkGateRefusalStream(t, p, streams[0], "raw", "", "socks5", target, "global", c)
}

// TestProxybuild_GateRateLimitRecord_NoLimitUnchanged is test-plan 5: with
// no limiter, and with a limiter that has no limits, repeated CONNECT,
// forward and SOCKS5 connections are admitted and nothing is recorded as
// rate_limit.
func TestProxybuild_GateRateLimitRecord_NoLimitUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		rl   *connector.RateLimiter
	}{
		{"nil limiter", nil},
		{"zero limits", connector.NewRateLimiter()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, accepts := acceptCountingUpstream(t)
			p := startGateRateLimitProxy(t, tc.rl, nil)
			const n = 3
			for i := 0; i < n; i++ {
				c, _, line := connectStatus(t, p.proxyAddr, target)
				if !strings.HasPrefix(line, "HTTP/1.1 200") {
					t.Errorf("CONNECT #%d status = %q, want 200", i, line)
				}
				_ = c.Close()
				c, rep := socks5Connect(t, p.proxyAddr, "127.0.0.1", portOf(t, target))
				if rep != 0x00 {
					t.Errorf("SOCKS5 #%d REP = 0x%02x, want 0x00", i, rep)
				}
				_ = c.Close()
			}
			before := accepts.Load()
			for i := 0; i < n; i++ {
				line := forwardStatus(t, p.proxyAddr, "http://"+target+"/", target)
				if strings.Contains(line, " 429") {
					t.Errorf("forward #%d status = %q, want no 429", i, line)
				}
			}
			if got := settleAccepts(accepts, before+n, 5*time.Second); got < before+n {
				t.Errorf("upstream accepted %d connections, want at least %d (every forward dialled)", got, before+n)
			}
			if s := p.rateLimitStreams(); len(s) != 0 {
				t.Errorf("%d rate_limit Streams with no limit, want 0", len(s))
			}
		})
	}
}

// TestProxybuild_GateRateLimitRecord_ScopeRefusalNotRecorded is test-plan
// 6: a scope-refused CONNECT (403) spends no token and records no
// rate_limit Stream; once the deny is lifted the next CONNECT is admitted
// under a burst-1 per-host limit.
func TestProxybuild_GateRateLimitRecord_ScopeRefusalNotRecorded(t *testing.T) {
	target, _ := acceptCountingUpstream(t)
	p := startGateRateLimitProxy(t, burstOneLimiter(true), nil)
	p.scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{portOf(t, target)}}})

	_, _, line := connectStatus(t, p.proxyAddr, target)
	if !strings.HasPrefix(line, "HTTP/1.1 403") {
		t.Fatalf("denied CONNECT status = %q, want 403", line)
	}
	p.scope.SetPolicyRules(nil, nil)
	_, _, line = connectStatus(t, p.proxyAddr, target)
	if !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Errorf("CONNECT after lifting the deny = %q, want 200 (the scope refusal must not spend the token)", line)
	}
	time.Sleep(200 * time.Millisecond)
	if s := p.rateLimitStreams(); len(s) != 0 {
		t.Errorf("%d rate_limit Streams, want 0", len(s))
	}
}

// TestProxybuild_GateRateLimitRecord_CaptureScopeExcluded is test-plan 7:
// a refusal whose target capture_scope excludes is still answered 429 but
// writes no Stream.
func TestProxybuild_GateRateLimitRecord_CaptureScopeExcluded(t *testing.T) {
	target, _ := acceptCountingUpstream(t)
	rs := flow.NewRecordScope()
	rs.SetRules(nil, []flow.ScopeRule{{Hostname: "127.0.0.1"}})
	rl := burstOneLimiter(false)
	p := startGateRateLimitProxy(t, rl, rs)
	if d := rl.Check("spend.example"); d != nil {
		t.Fatalf("pre-spend denied: %+v", d)
	}

	_, got := sendAndReadAll(t, p.proxyAddr, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	if want := connector.RateLimitRefusalResponse(); !bytes.Equal(got, want) {
		t.Errorf("over-limit CONNECT answered %q, want %q", got, want)
	}
	time.Sleep(200 * time.Millisecond)
	if s := p.store.Streams(); len(s) != 0 {
		t.Errorf("%d Streams recorded for a capture_scope-excluded target, want 0: %v", len(s), s)
	}
}

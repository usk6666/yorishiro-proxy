//go:build e2e

// USK-1165 / USK-1178 smoke-tier coverage: after an upstream HTTP/2
// connection sends GOAWAY, the proxy opens a new upstream connection the way
// a browser does, instead of refusing every later stream on the stale one.
//
//   - USK-1165: tcp_forward (protocol=http2, h2c upstream) had no redial
//     machinery at all — one upstream Layer per forward connection, so every
//     stream after the first GOAWAY was RST_STREAM(REFUSED_STREAM), and the
//     client's retry landed on the same stale Layer again.
//   - USK-1178: on the CONNECT path the pre-warm worker woken by chain[0]'s
//     GOAWAY (USK-994) called the real redial with stale=nil, which fails
//     ("stale is nil"), so the proactive second connection was never opened.
//
// The origin is the frame-level refusingH2Origin (USK-1157 fixture) in
// originGoAwayAfterFirst mode with batch=1: answer the first request with
// 200, send GOAWAY(NO_ERROR, last_stream_id=1), keep the connection open for
// refusalHold, then close it. Every later connection answers 200.
package proxybuild_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startH2ForwardForRedialTest starts a Manager with one tcp_forward entry
// (fc) recording into a flowStoreForH2Pool. The proxy trusts any upstream
// certificate (InsecureSkipVerify) and can terminate client TLS (Issuer).
func startH2ForwardForRedialTest(t *testing.T, ctx context.Context, fc config.ForwardConfig) (
	*proxybuild.Manager, string, *flowStoreForH2Pool,
) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	store := &flowStoreForH2Pool{}
	logger := testutil.DiscardLogger()
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
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
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": &fc},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	addr := mgr.TCPForwardAddrs()["0"]
	if addr == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}
	return mgr, addr, store
}

// dialRawH2Direct opens a frame-level h2 client straight to addr (a
// tcp_forward listener — no CONNECT). tlsCfg nil speaks h2c with prior
// knowledge; otherwise the client does TLS with ALPN h2 first.
func dialRawH2Direct(t *testing.T, addr string, tlsCfg *tls.Config) *rawH2Client {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward listener: %v", err)
	}
	conn := raw
	scheme := "http"
	if tlsCfg != nil {
		tc := tls.Client(raw, tlsCfg)
		if err := tc.Handshake(); err != nil {
			raw.Close()
			t.Fatalf("TLS handshake with forward listener: %v", err)
		}
		if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
			tc.Close()
			t.Fatalf("negotiated ALPN = %q, want h2", got)
		}
		conn = tc
		scheme = "https"
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		conn.Close()
		t.Fatalf("write preface: %v", err)
	}
	c := &rawH2Client{conn: conn, fr: http2.NewFramer(conn, conn), scheme: scheme}
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.fr.MaxHeaderListSize = 1 << 20
	if err := c.fr.WriteSettings(); err != nil {
		conn.Close()
		t.Fatalf("write SETTINGS: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return c
}

// requireOK fails unless r is a single 200 response that ended normally.
func requireOK(t *testing.T, id uint32, r *rawStreamResult) {
	t.Helper()
	if !r.ended || r.rst || len(r.statuses) == 0 || r.statuses[0] != "200" {
		t.Fatalf("stream %d: statuses=%v ended=%v rst=%v code=%v; want :status 200",
			id, r.statuses, r.ended, r.rst, r.rstCode)
	}
}

// waitAccepts polls origin.accepts until it reaches want or timeout.
func waitAccepts(origin *refusingH2Origin, want int64, timeout time.Duration) int64 {
	deadline := time.Now().Add(timeout)
	for {
		n := origin.accepts.Load()
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitH2Metrics polls snap until done reports true or timeout, returning
// the last snapshot.
func waitH2Metrics(
	snap func() proxybuild.H2UpstreamMetricsSnapshot,
	done func(proxybuild.H2UpstreamMetricsSnapshot) bool,
	timeout time.Duration,
) proxybuild.H2UpstreamMetricsSnapshot {
	deadline := time.Now().Add(timeout)
	for {
		m := snap()
		if done(m) || time.Now().After(deadline) {
			return m
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// updatesFor returns every StreamUpdate recorded for id.
func (s *flowStoreForH2Pool) updatesFor(id string) []flow.StreamUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]flow.StreamUpdate(nil), s.updates[id]...)
}

// runForwardGoAwayRedial drives the USK-1165 scenario over an established
// forward-listener client: stream 1 is answered and followed by upstream
// GOAWAY; stream 3, opened afterwards on the SAME client connection, must be
// answered by a second upstream connection. send writes the request for one
// stream id.
func runForwardGoAwayRedial(
	t *testing.T,
	cli *rawH2Client,
	origin *refusingH2Origin,
	mgr *proxybuild.Manager,
	store *flowStoreForH2Pool,
	send func(id uint32),
) {
	t.Helper()
	send(1)
	requireOK(t, 1, cli.collect(t, 10*time.Second, 1)[1])

	// The origin wrote GOAWAY right behind stream 1's response; give the
	// proxy's upstream reader a moment to consume it so stream 3 is opened
	// strictly after the GOAWAY was observed.
	time.Sleep(100 * time.Millisecond)

	send(3)
	requireOK(t, 3, cli.collect(t, 10*time.Second, 3)[3])

	if n := origin.accepts.Load(); n != 2 {
		t.Errorf("origin accepted %d connections, want 2 (stream 3 served by a new upstream connection)", n)
	}
	waitStreamOutcomes(t, store, map[string]int{"complete/": 2}, 5*time.Second)

	// The pre-warm success counter is bumped just after the fresh Layer is
	// published as the chain head, so stream 3 may complete first.
	totalRedials := func(m proxybuild.H2UpstreamMetricsSnapshot) int64 {
		return m.RedialReactive + m.RedialPrewarm + m.RedialRefusedStream
	}
	m := waitH2Metrics(mgr.H2UpstreamMetrics, func(m proxybuild.H2UpstreamMetricsSnapshot) bool {
		return totalRedials(m) >= 1
	}, 2*time.Second)
	if redials := totalRedials(m); redials < 1 {
		t.Errorf("h2 upstream redials = %d (%+v), want >= 1", redials, m)
	}
}

// TestTCPForwardH2C_UpstreamGoAway_NextStreamRedials is AC1 / AC2 for the
// h2c cell (tls=false, upstream_tls=false, protocol=http2).
func TestTCPForwardH2C_UpstreamGoAway_NextStreamRedials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2OriginOpts(t, refusingOriginOpts{
		mode: originGoAwayAfterFirst, batch: 1, plaintext: true,
	})
	mgr, fwdAddr, store := startH2ForwardForRedialTest(t, ctx, config.ForwardConfig{
		Target: origin.addr, Protocol: "http2",
	})
	cli := dialRawH2Direct(t, fwdAddr, nil)
	runForwardGoAwayRedial(t, cli, origin, mgr, store, func(id uint32) {
		cli.sendGETs(t, origin.addr, id)
	})

	for _, st := range store.Streams() {
		if st.Protocol != "http" {
			t.Errorf("stream %s protocol = %q, want http", st.ID, st.Protocol)
		}
	}
}

// TestH2Prewarm_Chain0GoAway_OpensSecondConnectionWithoutRequest is
// USK-1178 on the CONNECT path with the production redial function: right
// after the pooled chain[0] receives GOAWAY the pre-warm worker opens the
// second upstream connection on its own — no further request is sent.
func TestH2Prewarm_Chain0GoAway_OpensSecondConnectionWithoutRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originGoAwayAfterFirst, 1)
	store := &flowStoreForH2Pool{}
	metrics := proxybuild.NewH2UpstreamMetrics()
	proxyAddr := startProxyForH2PoolInterceptTestWithMetrics(t, ctx, store,
		httprules.NewInterceptEngine(), common.NewHoldQueue(), h2pool.New(h2pool.PoolOptions{}), metrics)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	cli.sendGETs(t, origin.addr, 1)
	requireOK(t, 1, cli.collect(t, 10*time.Second, 1)[1])

	if n := waitAccepts(origin, 2, 2*time.Second); n != 2 {
		m := metrics.Snapshot()
		t.Fatalf("origin accepted %d connections after chain[0] GOAWAY, want 2 via pre-warm (prewarm redials=%d, prewarm failures=%d)",
			n, m.RedialPrewarm, m.RedialFailedPrewarm)
	}
	// The origin counts the accept at TCP accept time; the pre-warm success
	// counter is bumped only after the TLS handshake and http2.New return,
	// so wait for it rather than sampling it at the instant of the accept.
	m := waitH2Metrics(metrics.Snapshot, func(m proxybuild.H2UpstreamMetricsSnapshot) bool {
		return m.RedialPrewarm >= 1
	}, 2*time.Second)
	if m.RedialPrewarm < 1 {
		t.Errorf("RedialPrewarm = %d, want >= 1", m.RedialPrewarm)
	}
	if m.RedialFailedPrewarm != 0 {
		t.Errorf("RedialFailedPrewarm = %d, want 0", m.RedialFailedPrewarm)
	}
	if m.RedialReactive != 0 {
		t.Errorf("RedialReactive = %d, want 0 (no request was sent after GOAWAY)", m.RedialReactive)
	}
}

//go:build e2e && !e2e_smoke

// USK-1179 exhaustive tier: the HTTP/2 upstream pre-warm worker must not
// redial in a loop against an upstream that answers every new connection
// with GOAWAY. Before the cap, each speculative connection was replaced the
// moment its GOAWAY arrived, so an idle CONNECT tunnel or tcp_forward
// connection opened a new upstream connection roughly every RTT, holding
// every replaced one open until the client connection closed (CWE-770).
//
// The rule: the worker does not replace a head it produced itself that
// never carried a locally initiated stream. chain[0] and heads minted by the
// reactive request path are still pre-warmed; a speculative head that did
// carry a request is still pre-warmed (normal GOAWAY, USK-992 / USK-994).
//
// Fixtures: refusingH2Origin in originGoAwayEveryConn / originGoAwayAfterEachFirst
// mode (h2_upstream_refused_integration_test.go); CONNECT harness
// startProxyForH2PoolInterceptTestWithMetrics; forward harness
// startH2ForwardForRedialTest (h2_upstream_goaway_redial_integration_test.go).
package proxybuild_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// prewarmCapIdleConns is the upstream connection budget of an idle client
// connection against an always-GOAWAY upstream: chain[0] plus one
// speculative pre-warm.
const prewarmCapIdleConns = 2

// requirePrewarmCapped waits for the pre-warm worker to report a suppressed
// wake, then fails unless the origin's accept count stays at or below the
// idle budget and does not grow over a following 500ms window. Returns the
// stable accept count.
func requirePrewarmCapped(
	t *testing.T,
	origin *refusingH2Origin,
	snap func() proxybuild.H2UpstreamMetricsSnapshot,
) int64 {
	t.Helper()
	m := waitH2Metrics(snap, func(m proxybuild.H2UpstreamMetricsSnapshot) bool {
		return m.PrewarmSuppressed >= 1
	}, 3*time.Second)
	before := origin.accepts.Load()
	time.Sleep(500 * time.Millisecond)
	after := origin.accepts.Load()
	if after > prewarmCapIdleConns || after != before {
		t.Fatalf("origin accepted %d connections (%d at the start of a 500ms window), want <= %d and stable (metrics %+v)",
			after, before, prewarmCapIdleConns, snap())
	}
	if m.PrewarmSuppressed < 1 {
		t.Errorf("PrewarmSuppressed = %d, want >= 1 (metrics %+v)", m.PrewarmSuppressed, m)
	}
	return after
}

// TestH2Prewarm_GoAwayEveryConn_ConnectIdleIsCapped is AC1 on the CONNECT
// path: an idle client tunnel, no request at all.
func TestH2Prewarm_GoAwayEveryConn_ConnectIdleIsCapped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originGoAwayEveryConn, 0)
	metrics := proxybuild.NewH2UpstreamMetrics()
	proxyAddr := startProxyForH2PoolInterceptTestWithMetrics(t, ctx, &flowStoreForH2Pool{},
		httprules.NewInterceptEngine(), common.NewHoldQueue(), h2pool.New(h2pool.PoolOptions{}), metrics)

	_ = dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	requirePrewarmCapped(t, origin, metrics.Snapshot)
}

// TestTCPForwardH2_GoAwayEveryConn_IdleIsCapped is AC1 on the tcp_forward
// path (protocol=http2, h2c upstream): an idle forward connection.
func TestTCPForwardH2_GoAwayEveryConn_IdleIsCapped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2OriginOpts(t, refusingOriginOpts{mode: originGoAwayEveryConn, plaintext: true})
	mgr, fwdAddr, _ := startH2ForwardForRedialTest(t, ctx, config.ForwardConfig{
		Target: origin.addr, Protocol: "http2",
	})

	_ = dialRawH2Direct(t, fwdAddr, nil)
	requirePrewarmCapped(t, origin, mgr.H2UpstreamMetrics)
}

// TestTCPForwardH2_GoAwayEveryConn_RequestsStayBounded: once the pre-warm
// is capped, client traffic still reaches the upstream — each request
// redials reactively — but costs a bounded number of upstream connections,
// every stream is refused with REFUSED_STREAM (so a browser may retry), and
// stopping the forward listener releases every redialed Layer.
func TestTCPForwardH2_GoAwayEveryConn_RequestsStayBounded(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2OriginOpts(t, refusingOriginOpts{mode: originGoAwayEveryConn, plaintext: true})
	mgr, fwdAddr, _ := startH2ForwardForRedialTest(t, ctx, config.ForwardConfig{
		Target: origin.addr, Protocol: "http2",
	})
	cli := dialRawH2Direct(t, fwdAddr, nil)
	idle := requirePrewarmCapped(t, origin, mgr.H2UpstreamMetrics)

	const requests = 3
	// Per request: one reactive dial, at most one refused-stream retry
	// dial, and one pre-warm off the used reactive head.
	const perRequest = 3
	ids := []uint32{1, 3, 5}
	for _, id := range ids {
		cli.sendGETs(t, origin.addr, id)
		r := cli.collect(t, 10*time.Second, id)[id]
		if !r.rst || r.rstCode != http2.ErrCodeRefusedStream {
			t.Errorf("stream %d: statuses=%v ended=%v rst=%v code=%v; want RST_STREAM(REFUSED_STREAM)",
				id, r.statuses, r.ended, r.rst, r.rstCode)
		}
	}

	limit := idle + requests*perRequest
	before := origin.accepts.Load()
	time.Sleep(500 * time.Millisecond)
	after := origin.accepts.Load()
	if after > limit || after != before {
		t.Errorf("origin accepted %d connections after %d requests (%d at the start of a 500ms window), want <= %d and stable (metrics %+v)",
			after, requests, before, limit, mgr.H2UpstreamMetrics())
	}

	if err := mgr.StopAll(context.Background()); err != nil {
		t.Fatalf("StopAll: %v", err)
	}
	cancel()
	_ = cli.conn.Close()
	goleak.VerifyNone(t, ignore,
		goleak.IgnoreAnyFunction("github.com/usk6666/yorishiro-proxy/internal/proxybuild_test.(*refusingH2Origin).acceptLoop"),
		goleak.IgnoreAnyFunction("github.com/usk6666/yorishiro-proxy/internal/proxybuild_test.(*refusingH2Origin).acceptLoop.func1"),
	)
}

// TestH2Prewarm_NormalGoAway_PrewarmsPastUsedSpeculativeHead is AC2: a
// pre-warmed connection that served a request and then sent a normal
// GOAWAY is pre-warmed past, without waiting for another request.
//
//	conn1 (chain[0]) serves stream 1, GOAWAY → pre-warm opens conn2
//	conn2 (speculative) serves stream 3, GOAWAY → pre-warm opens conn3
func TestH2Prewarm_NormalGoAway_PrewarmsPastUsedSpeculativeHead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originGoAwayAfterEachFirst, 0)
	metrics := proxybuild.NewH2UpstreamMetrics()
	proxyAddr := startProxyForH2PoolInterceptTestWithMetrics(t, ctx, &flowStoreForH2Pool{},
		httprules.NewInterceptEngine(), common.NewHoldQueue(), h2pool.New(h2pool.PoolOptions{}), metrics)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	cli.sendGETs(t, origin.addr, 1)
	requireOK(t, 1, cli.collect(t, 10*time.Second, 1)[1])

	if n := waitAccepts(origin, 2, 3*time.Second); n != 2 {
		t.Fatalf("origin accepted %d connections after conn1 GOAWAY, want 2 via pre-warm (metrics %+v)", n, metrics.Snapshot())
	}
	// conn2 must be the published head before stream 3 is sent, so the
	// request lands on the speculative connection.
	waitH2Metrics(metrics.Snapshot, func(m proxybuild.H2UpstreamMetricsSnapshot) bool {
		return m.RedialPrewarm >= 1
	}, 3*time.Second)

	cli.sendGETs(t, origin.addr, 3)
	requireOK(t, 3, cli.collect(t, 10*time.Second, 3)[3])

	if n := waitAccepts(origin, 3, 3*time.Second); n != 3 {
		t.Fatalf("origin accepted %d connections after conn2 served a request and sent GOAWAY, want 3 via pre-warm (metrics %+v)",
			n, metrics.Snapshot())
	}
	m := waitH2Metrics(metrics.Snapshot, func(m proxybuild.H2UpstreamMetricsSnapshot) bool {
		return m.RedialPrewarm >= 2
	}, 3*time.Second)
	if m.RedialPrewarm != 2 || m.RedialReactive != 0 || m.PrewarmSuppressed != 0 {
		t.Errorf("RedialPrewarm=%d RedialReactive=%d PrewarmSuppressed=%d; want 2, 0, 0", m.RedialPrewarm, m.RedialReactive, m.PrewarmSuppressed)
	}
}

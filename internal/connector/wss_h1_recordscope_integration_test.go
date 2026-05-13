//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// ---------------------------------------------------------------------------
// USK-841 Phase C: capture_scope-gated WS frame recording regression test.
//
// The live-wire trace on 2026-05-12 (`grep recordstep-entry` against
// usk841-repro.log) revealed that every WS frame envelope emitted by the
// post-swap ws.Layer carried `connID=""` and an empty Context. The
// downstream consequence: with a non-trivial capture_scope rule
// (`includes=[{hostname:"httpbingo.org"}]`) the RecordStep evaluator
// dropped every WS frame as out-of-scope because the scope-evaluation path
// for non-HTTP envelopes keys off `Context.TargetHost` / `Context.TLS.SNI`
// (see flow.scopeHostnameFromContext) — neither of which were populated
// on the post-swap WS envelope.
//
// USK-839's existing e2e harness
// (TestFullListener_CONNECT_WS_H1Listener_H2AdvertisingUpstream_FlowPersistence)
// uses the default empty RecordScope so the bug is invisible: an empty
// scope short-circuits to capture-all and the missing context never
// manifests as a recording miss.
//
// This test installs a hostname-keyed RecordScope rule that ONLY matches
// the CONNECT target (port-stripped, per scopeHostnameFromAuthority). It
// reproduces the live-wire repro shape end-to-end:
//
//	(1) Production wiring via proxybuild.BuildLiveStack + connector.FullListener
//	    (the same path the live trace exercised).
//	(2) RecordScope.includes=[{hostname:<upstream-host>}] set on Deps.RecordScope.
//	(3) Drive a CONNECT + TLS + RFC 6455 Upgrade + text-frame round-trip
//	    against an in-process WS echo upstream.
//	(4) Assert that:
//	    - At least one Stream with Protocol="ws" is recorded.
//	    - Send + Receive flows under that Stream both carry non-empty
//	      RawBytes (L4-capable principle).
//	    - The recorded Stream has a non-empty ConnID — the connection-
//	      scoped identifier propagated through the swap.
//
// On the parent commit (`15c53b6`) every assertion in (4) FAILS because
// the post-swap WS envelopes emerge with empty Context.TargetHost: the
// scope evaluator rejects them and no WS Stream lands. On HEAD (with the
// USK-841 fix that propagates the wire-observed EnvelopeContext into the
// post-swap ws.Layer pair) the assertions pass.
//
// e2e tier: exhaustive (//go:build e2e && !e2e_smoke). The new
// `wss_h1_h1upstream` smoke test already exercises the production wiring
// without RecordScope; this exhaustive sibling pins the capture_scope
// interaction so the smoke tier stays fast.
// ---------------------------------------------------------------------------

// TestWSS_H1Listener_RecordScope_HostFilter_FramesRecorded reproduces
// USK-841 by installing a hostname-keyed RecordScope rule and asserting
// post-Upgrade WS frames clear the scope evaluator.
//
// The Fly.io-edge harness from wss_h1_flyedge_integration_test.go is
// intentionally NOT reused — it adds optional handshake fragmentation +
// pre-frame push padding shape variants that are orthogonal to the
// scope-evaluator gap. Sticking with the simpler USK-839-shaped upstream
// keeps the failure surface focused on the capture_scope precondition.
func TestWSS_H1Listener_RecordScope_HostFilter_FramesRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Upstream: USK-839-shaped TLS server (advertising NextProtos=["h2","http/1.1"];
	//    serves http/1.1 with a WS echo handler).
	hits := newWSEchoHits()
	upstreamAddr, upstreamShutdown := startWSEchoUpstreamH1AdvertisingH2(t, hits)
	defer upstreamShutdown()

	// 2. Proxy: production wiring (proxybuild.BuildLiveStack) PLUS a
	//    hostname-keyed RecordScope rule. The hostname is derived from
	//    the upstream listener — net.SplitHostPort splits 127.0.0.1:PORT
	//    so the scope hostname is "127.0.0.1" (matches
	//    scopeHostnameFromAuthority's port-strip behaviour against the
	//    CONNECT TargetHost).
	proxyAddr, store, shutdown := startWSH1RecordScopeProxy(t, ctx, upstreamAddr)
	defer shutdown()

	// 3. Drive the WS echo round-trip through the proxy. driveWSEchoThroughProxyH1
	//    issues CONNECT + TLS handshake (NextProtos=["http/1.1"]) + RFC 6455
	//    handshake + masked text frame + echo read.
	const payload = "usk-841-recordscope-hello"
	if err := driveWSEchoThroughProxyH1(ctx, proxyAddr, upstreamAddr, payload); err != nil {
		t.Fatalf("WS echo through proxy (RecordScope hostname filter): %v", err)
	}

	// Upstream durably observed the frame.
	if got := hits.totalText(); got < 1 {
		t.Fatalf("upstream WS echo handler text-frame hits = %d, want >= 1 (proxy never delivered the frame)", got)
	}

	// Allow asynchronous Stream/Flow recording to settle.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasWSStreamWithFlows(store) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// (a) Stream recording: a Stream with Protocol="ws" must be present
	//     AFTER the RecordScope hostname filter — proves the post-swap
	//     WS envelope carried a hostname the evaluator could match.
	//     Pre-fix this assertion fails: scope drops every WS envelope
	//     and the Stream row never lands.
	streams := store.getStreams()
	var wsStream *flow.Stream
	for _, st := range streams {
		if st != nil && st.Protocol == "ws" {
			wsStream = st
			break
		}
	}
	if wsStream == nil {
		t.Fatalf("no Stream with Protocol=ws under hostname-filtered RecordScope; got %+v "+
			"(USK-841: WS envelopes carry empty Context.TargetHost so scope rejects them)",
			summarizeStreams(streams))
	}

	// The recorded Stream must carry a non-empty ConnID — the connection-
	// scoped identifier propagated through the swap is the keystone for
	// log correlation. Pre-fix the WS envelope's Context.ConnID is empty
	// so the recorder either drops the row or persists it with ConnID="".
	if wsStream.ConnID == "" {
		t.Errorf("WS Stream ConnID is empty after capture_scope-gated WS round-trip "+
			"(USK-841: Context.ConnID not propagated from upgrade request to post-swap WS Layer); stream=%+v",
			wsStream)
	}

	// (b) Flow recording: at least one Send and one Receive flow under
	//     the WS protocol tag with non-empty RawBytes (L4-capable principle).
	sendFlows := store.flowsByDirection("send")
	recvFlows := store.flowsByDirection("receive")
	if !wsFlowHasNonEmptyRaw(sendFlows) {
		t.Errorf("no ws-protocol send flow with non-empty RawBytes "+
			"(USK-841 reproduction: scope dropped post-swap WS frames); sendCount=%d", len(sendFlows))
	}
	if !wsFlowHasNonEmptyRaw(recvFlows) {
		t.Errorf("no ws-protocol receive flow with non-empty RawBytes "+
			"(USK-841 reproduction: scope dropped post-swap WS frames); recvCount=%d", len(recvFlows))
	}
}

// startWSH1RecordScopeProxy is a sibling of startWSH1H2AdvertProxy that
// additionally installs a hostname-keyed RecordScope filter on Deps.RecordScope.
// The hostname is the port-stripped portion of upstreamAddr (which the
// proxy's CONNECT path sets as Context.TargetHost on every envelope
// generated by the inner stack — including the post-swap WS envelopes
// once USK-841 is fixed).
//
// Mirrors USK-839's startWSH1H2AdvertProxy verbatim except for the extra
// RecordScope wiring so a behavioural divergence between this test and
// USK-839's baseline test is unambiguously attributable to the scope
// filter, not to a setup drift.
func startWSH1RecordScopeProxy(t *testing.T, ctx context.Context, upstreamAddr string) (string, *testStore, func()) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}

	store := &testStore{}

	// Hostname for the RecordScope rule: scopeHostnameFromAuthority strips
	// the optional ":port" suffix, so we feed the bare host portion of
	// upstreamAddr to keep the rule independent of the OS-allocated port.
	scopeHost := hostFromHostPort(upstreamAddr)
	scope := flow.NewRecordScope()
	scope.SetRules([]flow.ScopeRule{{Hostname: scopeHost}}, nil)

	deps := proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-841-recordscope",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig:  buildCfg,
		RecordScope:  scope,
	}

	stack, err := proxybuild.BuildLiveStack(ctx, deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}

	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}

	proxyAddr := stack.Listener.Addr()
	if proxyAddr == "" {
		t.Fatal("listener has no addr")
	}

	shutdown := func() {}
	return proxyAddr, store, shutdown
}

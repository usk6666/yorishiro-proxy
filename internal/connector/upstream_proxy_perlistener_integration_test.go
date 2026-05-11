//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"log/slog"
	"net/url"
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

// TestPerListener_UpstreamProxy_ChainedMITM_NoSelfRecursion is the
// canonical USK-826 repro: two listeners sharing a single BuildConfig.
// Listener "outer" has no upstream_proxy. Listener "chained" is
// configured (via SetUpstreamProxyForListener) to route through listener
// "outer". A CONNECT through "chained" therefore CONNECTs to "outer",
// which CONNECTs directly to the real upstream. Without the per-listener
// fix, both listeners would observe the same upstream_proxy and "outer"
// would itself recurse through "chained"'s URL.
//
// The test exercises the production data path end-to-end:
//   - real BuildConfig with per-listener upstream-proxy entries
//   - real CONNECT handler dispatching via the per-listener
//     EffectiveUpstreamProxyForCtx accessor
//   - real upstream that records the number of times it accepts a
//     CONNECT (must be exactly 1; recursion would multiply it).
func TestPerListener_UpstreamProxy_ChainedMITM_NoSelfRecursion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Real upstream HTTPS server. Returns a small response and counts
	// CONNECT-style requests via the accept counter the test rig owns.
	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// ProxyConfig + Issuer shared by both listeners.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	// Listener "outer" — no upstream_proxy override; dials upstream
	// directly. Counts sessions so we can assert exactly one MITM
	// completed end-to-end (no recursion).
	outerStore := &testStore{}
	outerWg := &sync.WaitGroup{}
	outerAddr := startNamedListenerForChain(t, ctx, "outer", buildCfg, outerStore, outerWg)

	// Listener "chained" — upstream_proxy points at "outer".
	chainedStore := &testStore{}
	chainedWg := &sync.WaitGroup{}
	chainedAddr := startNamedListenerForChain(t, ctx, "chained", buildCfg, chainedStore, chainedWg)

	// CRITICAL: per-listener override. Only "chained" gets the override;
	// "outer" must remain on direct dial. Pre-USK-826 setting this
	// globally would cause "outer" to also recurse through this URL.
	outerListenerURL := &url.URL{Scheme: "http", Host: outerAddr}
	buildCfg.SetUpstreamProxyForListener("chained", outerListenerURL)

	// Drive traffic through the "chained" listener. The CONNECT request
	// should:
	//   1. Hit "chained" → it dials through buildCfg.EffectiveUpstreamProxyForCtx,
	//      which resolves to outerListenerURL (per-listener override).
	//   2. Hit "outer" → it dials through buildCfg.EffectiveUpstreamProxyForCtx,
	//      which resolves to NO override (outer's slot is empty) → direct dial.
	//   3. Hit upstream → exactly once.
	outerWg.Add(1)   // outer accepts the inner CONNECT from chained.
	chainedWg.Add(1) // chained accepts the request from the test client.

	rawReq := "GET /chain HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
	resp := connectAndSendHTTP(t, chainedAddr, target, rawReq)

	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("response missing 200 OK: %q", resp)
	}

	// Wait for both sessions to finish; bound by ctx timeout.
	waitSessionDone(t, chainedWg)
	waitSessionDone(t, outerWg)

	// USK-826: exactly ONE upstream request. Recursion through "outer"
	// (the pre-fix bug) would multiply this count or hit rate-limit /
	// connection-refused before reaching upstream.
	upstreamReqs := getUpstreamReqs()
	if got := len(upstreamReqs); got != 1 {
		t.Errorf("upstream saw %d requests, want 1 (self-recursion regression?)", got)
	}

	// Both listeners recorded streams: outer (CONNECT from chained),
	// chained (CONNECT from test client).
	outerStreams := outerStore.getStreams()
	chainedStreams := chainedStore.getStreams()
	if len(outerStreams) < 1 {
		t.Errorf("outer listener recorded %d streams, want >= 1", len(outerStreams))
	}
	if len(chainedStreams) < 1 {
		t.Errorf("chained listener recorded %d streams, want >= 1", len(chainedStreams))
	}
}

// startNamedListenerForChain spins up a FullListener bound to the given
// shared BuildConfig under the given listener name, mirroring the
// minimal pipeline of startFullListenerProxy. Returns the listener
// address. The store/WaitGroup arguments are used by the OnStack
// closure so the caller can assert recording and synchronise teardown.
func startNamedListenerForChain(
	t *testing.T,
	ctx context.Context,
	name string,
	buildCfg *connector.BuildConfig,
	store *testStore,
	wg *sync.WaitGroup,
) string {
	t.Helper()

	connectNeg := connector.NewCONNECTNegotiator(slog.Default())

	onStack := func(ctx context.Context, stack *connector.ConnectionStack, _ *envelope.TLSSnapshot, _ *envelope.TLSSnapshot, _ string) {
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
		Name: name,
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connectNeg,
			BuildCfg:   buildCfg,
			OnStack:    onStack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx)

	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for FullListener %q to be ready", name)
	}

	return fl.Addr()
}

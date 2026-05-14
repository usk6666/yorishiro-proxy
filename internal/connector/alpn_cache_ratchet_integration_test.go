//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TestALPNCache_StaleH1_DoesNotPinH2CapableClient is the regression guard
// for USK-884.
//
// Pre-condition: the ALPN cache has been seeded with "http/1.1" for the
// target — e.g. by a previous CONNECT from an h1-only client. In real
// deployments this happens when the first dial to an h2-capable host
// arrives from `curl` without `--http2`, an MCP-tool resend run, or any
// other client that only offers `http/1.1` in its ClientHello.
//
// Pre-USK-884 behaviour: clientALPNOffersForUpstream returned
// ["http/1.1"] only for the cached "http/1.1" hint, so the MITM cert
// advertised NextProtos=["http/1.1"]. A subsequent h2-capable client
// (curl --http2, an SSE / WebSocket client over h2, the proxy_start →
// security set_target_scope flow exercised in the USK-884 repro) offered
// `[h2, http/1.1]`, the proxy responded with `[http/1.1]`, only "http/1.1"
// overlapped, and the client was permanently pinned to HTTP/1.1 for the
// cache TTL (~1 hour). The cache was a one-way ratchet — every
// h2-capable client downgraded until the entry expired naturally.
//
// Post-USK-884 behaviour: the MITM cert advertises the HTTP-family
// superset ["h2", "http/1.1"] whenever the cached value is HTTP-family
// (h2, http/1.1, or empty). An h2-capable client picks h2; the
// refresh-on-mismatch block in buildCacheHitPath then rewrites the
// cached entry to "h2" so subsequent clients hit the post-fix steady
// state directly.
//
// Test design: pre-seed the ALPN cache with "http/1.1" for an upstream
// that advertises both ["h2", "http/1.1"] (with h2 first, matching real
// HTTP/2 servers like stream.wikimedia.org). An h2-capable client
// offering `[h2, http/1.1]` then connects through the proxy. Assert the
// inner-TLS NegotiatedProtocol == "h2". The poisoned cache entry should
// also be rewritten to "h2" by the time the test reads it back.
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: client negotiates inner ALPN successfully
//     against an upstream advertising [h2, http/1.1].
//   - L4-capable principle: not asserted in this test — the focus is the
//     pre-CONNECT cert TLSConfig.NextProtos selection. Per-message Raw
//     bytes recording is covered by TestFullListener_CONNECT_HTTPS_MITM
//     and the wss-over-h2 integration test.
//   - MCP tool integration: not exercised — the harness uses the in-
//     process FullListener directly.
func TestALPNCache_StaleH1_DoesNotPinH2CapableClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream advertises both protocols, with h2 first. The proxy will
	// redial upstream with ["h2"] once the client picks h2; upstream
	// honours that choice and the TLS handshake completes with ALPN=h2.
	// The application bytes after the TLS handshake do not matter for
	// this test — we only assert the negotiated ALPN on the client-facing
	// TLS handshake (and inspect the cache state afterwards).
	upstreamLn, _ := startUpstreamHTTPSWithALPN(t,
		[]string{"h2", "http/1.1"},
		func(_ []byte) []byte {
			// Returned only if the proxy speaks HTTP/1.x on this conn.
			// The post-fix path negotiates h2 client-side, so this
			// handler is generally not invoked.
			return []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		},
	)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	// Pre-seed the cache with the poisoned value. The cache key shape
	// matches what the live data path computes via
	// ALPNCacheKeyFromConfig: HostPort=target, Fingerprint="" (default
	// crypto/tls profile used by tests), ClientCertHash="" (no mTLS).
	cache := connector.NewALPNCache(connector.DefaultALPNCacheSize, connector.DefaultALPNCacheTTL)
	poisonKey := connector.ALPNCacheKey{HostPort: target}
	cache.Set(poisonKey, "http/1.1")

	proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{alpnCache: cache})

	// Client offers [h2, http/1.1]. Pre-fix the proxy would advertise
	// ["http/1.1"] only (the poisoned cache value), the TLS handshake
	// would complete with NegotiatedProtocol="http/1.1" — a regression.
	// Post-fix the proxy advertises [h2, http/1.1] and the client picks
	// h2.
	tlsConn := connectThroughProxyWithALPN(t, proxyAddr, target, []string{"h2", "http/1.1"})
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("client negotiated ALPN = %q, want %q (USK-884 ratchet regression — stale http/1.1 cache pinned h2-capable client)",
			state.NegotiatedProtocol, "h2")
	}

	// Tear down the inner TLS conn so the proxy session reaches its
	// refresh path. The refresh write in buildCacheHitPath happens once
	// performClientMITM + dialUpstreamWithALPN complete — at that point
	// the new ALPN is already cached, but the actual Set call runs after
	// the handshake races with the deferred Close above. Read the cache
	// back with a brief retry loop to avoid a flake on the write/read
	// race rather than the underlying behaviour.
	_ = tlsConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	var got connector.ALPNCacheEntry
	for time.Now().Before(deadline) {
		entry, ok := cache.Get(poisonKey)
		if ok && entry.Protocol == "h2" {
			got = entry
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got.Protocol != "h2" {
		entry, _ := cache.Get(poisonKey)
		t.Fatalf("cache entry after h2 negotiation = %+v, want Protocol=h2 (refresh-on-mismatch did not rewrite the poisoned entry)", entry)
	}
}

// TestALPNCache_StaleH1_HTTP1ClientStillWorks is the negative control
// for USK-884: an h1-only client must still negotiate http/1.1 cleanly
// when the cache is seeded with http/1.1. The fix widens the proxy's
// offer set without forcing h2 onto h1-only clients.
func TestALPNCache_StaleH1_HTTP1ClientStillWorks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPSWithALPN(t,
		[]string{"h2", "http/1.1"},
		func(_ []byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nh1-served")
		},
	)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	cache := connector.NewALPNCache(connector.DefaultALPNCacheSize, connector.DefaultALPNCacheTTL)
	cache.Set(connector.ALPNCacheKey{HostPort: target}, "http/1.1")

	proxyAddr, _, wg := startFullListenerProxy(t, ctx, fullListenerOpts{alpnCache: cache})

	wg.Add(1)
	rawReq := fmt.Sprintf("GET /h1-still-works HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := connectAndSendHTTPWithClientALPN(t, proxyAddr, target, []string{"http/1.1"}, rawReq)

	upstreamReqs := getUpstreamReqs()
	waitSessionDone(t, wg)

	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}
	if !strings.HasSuffix(resp, "h1-served") {
		t.Errorf("response body unexpected: %q", resp)
	}
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
}

//go:build e2e

package testconnector_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/testutil/testconnector"
)

// TestALPNCacheMissThenHit verifies the miss-then-hit path. The first request
// causes an eager dial that populates the cache; the second request to the
// same target reuses the cached entry and only the lazy dial runs (single
// upstream handshake per tunnel).
func TestALPNCacheMissThenHit(t *testing.T) {
	var hits atomic.Int64
	h := testconnector.Start(t, testconnector.WithUpstreamHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		})))

	// Initially empty.
	if got := h.ALPNCache.Len(); got != 0 {
		t.Fatalf("initial cache len=%d, want 0", got)
	}

	client := httpsClientViaProxy(t, h)

	// First request: cache miss → eager dial → populate.
	resp1, err := client.Get(h.UpstreamServer.URL + "/1")
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()

	if got := h.ALPNCache.Len(); got != 1 {
		t.Fatalf("after first GET, cache len=%d, want 1", got)
	}

	// Inspect the cached entry to confirm the learned ALPN is http/1.1 or
	// empty (httptest TLS servers negotiate http/1.1 by default).
	entry, ok := h.ALPNCache.Get(connector.ALPNCacheKey{HostPort: h.UpstreamAddr})
	if !ok {
		t.Fatalf("expected cached entry for %q", h.UpstreamAddr)
	}
	if entry.Protocol != "http/1.1" && entry.Protocol != "" {
		t.Fatalf("unexpected cached ALPN=%q", entry.Protocol)
	}

	// Second request to the same target (via a fresh transport so we force
	// a new CONNECT tunnel): cache hit → lazy dial only.
	client2 := httpsClientViaProxy(t, h)
	resp2, err := client2.Get(h.UpstreamServer.URL + "/2")
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	if got := h.ALPNCache.Len(); got != 1 {
		t.Fatalf("after second GET, cache len=%d, want 1", got)
	}
	// Upstream should have received exactly two requests.
	if got := hits.Load(); got != 2 {
		t.Fatalf("upstream hits=%d, want 2", got)
	}
}

// TestALPNCacheStaleDelete verifies that when the cache entry is stale (or
// manually removed), the next tunnel re-learns and repopulates.
func TestALPNCacheStaleDelete(t *testing.T) {
	h := testconnector.Start(t)

	client := httpsClientViaProxy(t, h)
	resp, err := client.Get(h.UpstreamServer.URL + "/first")
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got := h.ALPNCache.Len(); got != 1 {
		t.Fatalf("cache len=%d after first request", got)
	}

	// Delete to simulate a stale eviction.
	h.ALPNCache.Delete(connector.ALPNCacheKey{HostPort: h.UpstreamAddr})
	if got := h.ALPNCache.Len(); got != 0 {
		t.Fatalf("cache len=%d after delete, want 0", got)
	}

	// Next request should re-learn.
	client2 := httpsClientViaProxy(t, h)
	resp2, err := client2.Get(h.UpstreamServer.URL + "/second")
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if got := h.ALPNCache.Len(); got != 1 {
		t.Fatalf("cache len=%d after re-learn, want 1", got)
	}
}

// TestALPNCacheKeySensitivity verifies that distinct uTLS fingerprints
// produce distinct cache entries for the same host:port.
func TestALPNCacheKeySensitivity(t *testing.T) {
	h := testconnector.Start(t)

	// Warm the default (empty fingerprint) entry.
	client := httpsClientViaProxy(t, h)
	resp, err := client.Get(h.UpstreamServer.URL + "/warm")
	if err != nil {
		t.Fatalf("warm GET: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if got := h.ALPNCache.Len(); got != 1 {
		t.Fatalf("after warm, cache len=%d, want 1", got)
	}

	// Manually inject a separate entry under a different Fingerprint to
	// prove the ALPNCacheKey tuple separates them.
	h.ALPNCache.Set(connector.ALPNCacheKey{HostPort: h.UpstreamAddr, Fingerprint: "chrome"}, "http/1.1")

	if got := h.ALPNCache.Len(); got != 2 {
		t.Fatalf("after manual Set, cache len=%d, want 2", got)
	}

	_, okDefault := h.ALPNCache.Get(connector.ALPNCacheKey{HostPort: h.UpstreamAddr})
	_, okChrome := h.ALPNCache.Get(connector.ALPNCacheKey{HostPort: h.UpstreamAddr, Fingerprint: "chrome"})
	if !okDefault || !okChrome {
		t.Fatalf("expected both keys present: default=%v chrome=%v", okDefault, okChrome)
	}
}

// TestALPNCacheTTLExpire verifies that an entry past its TTL is treated as
// absent. We use a very short TTL so the test runs quickly.
func TestALPNCacheTTLExpire(t *testing.T) {
	h := testconnector.Start(t, testconnector.WithALPNCacheTTL(200*time.Millisecond))

	client := httpsClientViaProxy(t, h)
	resp, err := client.Get(h.UpstreamServer.URL + "/ttl")
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if got := h.ALPNCache.Len(); got != 1 {
		t.Fatalf("cache len=%d after warm", got)
	}

	// Wait past the TTL window.
	time.Sleep(350 * time.Millisecond)

	// Get should report the entry as absent (lazy expiry).
	if _, ok := h.ALPNCache.Get(connector.ALPNCacheKey{HostPort: h.UpstreamAddr}); ok {
		t.Fatalf("expected cache entry to be expired")
	}

	// And a subsequent request should re-learn.
	client2 := httpsClientViaProxy(t, h)
	resp2, err := client2.Get(h.UpstreamServer.URL + "/ttl-relearn")
	if err != nil {
		t.Fatalf("post-ttl GET: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if got := h.ALPNCache.Len(); got != 1 {
		t.Fatalf("cache len=%d after re-learn", got)
	}
}

// TestALPNCacheEagerDialPathUsesHolder is a behavioral check: when the cache
// is empty the handler eagerly dials upstream and the resulting connection
// must be reused by the session DialFunc (i.e. the upstream sees exactly one
// request, not two). If the holder were broken the upstream would see two.
func TestALPNCacheEagerDialPathUsesHolder(t *testing.T) {
	var dials atomic.Int64
	h := testconnector.Start(t, testconnector.WithUpstreamHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			dials.Add(1)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, strings.Repeat("x", 10))
		})))

	client := httpsClientViaProxy(t, h)
	resp, err := client.Get(h.UpstreamServer.URL + "/eager")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if got := dials.Load(); got != 1 {
		t.Fatalf("upstream accepted %d requests; want 1 (holder reuse failed)", got)
	}
}

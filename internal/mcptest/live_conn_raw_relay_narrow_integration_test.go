//go:build e2e && !e2e_smoke

// USK-1283 exhaustive tier: a raw relay admitted under a host-only allow
// is cut when the scope is narrowed to a path-scoped allow only.
//
// USK-1130 made the connection gates admit a path-scoped allow
// provisionally on routes that may still carry HTTP, and refuseRawRelay
// re-checks strictly when such a route resolves to raw bytes. A relay that
// started under a host-only allow passed that check; when the scope was
// later narrowed to {hostname, path_prefix} the live-connection registry
// kept re-running the provisional check, so the relay survived even
// though an identical new one is refused — and HostScopeStep only sees
// Send, so a server-first upstream kept reaching a silent client.
//
// Connections whose route is HTTP (MITM, plain forward) must stay open
// under the same narrowing; HTTPScopeStep judges each later request path.
package mcptest_test

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

const (
	hostOnlyPolicyFile = `{"allows":[{"hostname":"127.0.0.1"}]}`
	pathOnlyPolicyFile = `{"allows":[{"hostname":"127.0.0.1","path_prefix":"/api/"}]}`
	// rawNarrowChunk is what the server-first upstream keeps writing, once
	// every rawNarrowInterval.
	rawNarrowChunk    = "220 server-first stream chunk\r\n"
	rawNarrowInterval = 100 * time.Millisecond
)

// narrowPolicyToPathOnly rewrites the policy file to the path-only allow
// and reloads it (the SIGHUP path, which runs LiveConns reconciliation).
func narrowPolicyToPathOnly(t *testing.T, h *mcptest.Harness, policyPath string) {
	t.Helper()
	writePolicyFile(t, policyPath, pathOnlyPolicyFile)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
}

// readRelayedChunk waits until the raw relay delivers upstream bytes.
func readRelayedChunk(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("raw relay delivered %d upstream bytes before narrowing (%v), want the server-first stream", n, err)
	}
	_ = c.SetReadDeadline(time.Time{})
}

// drainRelayed discards upstream bytes already relayed to the client, so
// that chunks delivered before the narrowing are not counted after it.
// It returns once the relay has been quiet for half a chunk interval.
func drainRelayed(t *testing.T, c net.Conn) {
	t.Helper()
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(rawNarrowInterval / 2))
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			break
		}
		t.Fatalf("raw relay closed before narrowing: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
}

// narrowTimed drains the bytes relayed so far, runs narrow, and returns
// how long narrow took.
func narrowTimed(t *testing.T, c net.Conn, narrow func()) time.Duration {
	t.Helper()
	drainRelayed(t, c)
	start := time.Now()
	narrow()
	return time.Since(start)
}

// assertRawRelayCutAfterNarrowing asserts that, after the narrowing
// returned, the proxy closes the client connection within 5s. The upstream
// keeps writing a chunk every rawNarrowInterval, so a surviving relay
// stays open and keeps delivering; the close-within-deadline check is the
// essential one. The byte bound allows the chunks the upstream could
// legitimately have relayed while the narrowing call ran (narrowDur, which
// can be long under load) plus one chunk in flight on each side of it.
func assertRawRelayCutAfterNarrowing(t *testing.T, c net.Conn, narrowDur time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	after := 0
	for {
		n, err := c.Read(buf)
		after += n
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("raw relay still open 5s after narrowing to a path-only allow (%d upstream bytes relayed meanwhile); want it cut", after)
		}
		break
	}
	allowedChunks := int(narrowDur/rawNarrowInterval) + 2
	if limit := allowedChunks * len(rawNarrowChunk); after > limit {
		t.Errorf("client received %d upstream bytes after draining (narrowing took %v), want at most %d (%d chunks of %d bytes)", after, narrowDur, limit, allowedChunks, len(rawNarrowChunk))
	}
}

// writeNonHTTPBytes makes the tunnel's inner peek classify the stream as
// neither TLS nor HTTP, so it runs as a raw (bytechunk) relay.
func writeNonHTTPBytes(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte{0x00, 0x01, 'r', 'a', 'w'}); err != nil {
		t.Fatalf("write raw bytes: %v", err)
	}
}

func TestE2E_LiveConnRawRelayNarrow_CONNECTCutOnReload(t *testing.T) {
	target := serverFirstStreamUpstream(t, rawNarrowChunk, 200, rawNarrowInterval)
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithPassthrough(t, h)

	c, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	writeNonHTTPBytes(t, c)
	readRelayedChunk(t, c, 10*time.Second)

	d := narrowTimed(t, c, func() { narrowPolicyToPathOnly(t, h, policyPath) })
	assertRawRelayCutAfterNarrowing(t, c, d)
}

// SOCKS5, narrowed through the agent layer (security tool) instead of a
// policy reload.
func TestE2E_LiveConnRawRelayNarrow_SOCKS5CutOnAgentNarrowing(t *testing.T) {
	target := serverFirstStreamUpstream(t, rawNarrowChunk, 200, rawNarrowInterval)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	h.MustOK(t, "security", map[string]any{
		"action": "set_target_scope",
		"params": map[string]any{"allows": []map[string]any{{"hostname": "127.0.0.1"}}},
	})
	proxyAddr := startProxyWithPassthrough(t, h)

	host, port := splitHostPortInt(t, target)
	c := socks5DialNoAuth(t, proxyAddr, host, port)
	t.Cleanup(func() { _ = c.Close() })
	writeNonHTTPBytes(t, c)
	readRelayedChunk(t, c, 10*time.Second)

	d := narrowTimed(t, c, func() {
		h.MustOK(t, "security", map[string]any{
			"action": "set_target_scope",
			"params": map[string]any{"allows": []map[string]any{{"hostname": "127.0.0.1", "path_prefix": "/api/"}}},
		})
	})
	assertRawRelayCutAfterNarrowing(t, c, d)
}

// tcp_forwards auto with a silent client: the auto peek times out and the
// connection falls back to a raw relay of the server-first stream.
func TestE2E_LiveConnRawRelayNarrow_TCPForwardAutoCutOnReload(t *testing.T) {
	target := serverFirstStreamUpstream(t, rawNarrowChunk, 200, rawNarrowInterval)
	h, policyPath := bootReloadHarness(t)
	fwd := startForwards(t, h, nil, map[string]any{"target": target, "protocol": "auto"})[0]

	c, err := net.DialTimeout("tcp", fwd, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// Stay silent past the 5 s auto peek.
	readRelayedChunk(t, c, 10*time.Second)

	d := narrowTimed(t, c, func() { narrowPolicyToPathOnly(t, h, policyPath) })
	assertRawRelayCutAfterNarrowing(t, c, d)
}

// Guard: a CONNECT TLS MITM connection (HTTP/1.1 inside) is not cut by the
// same narrowing; HTTPScopeStep judges its next requests by path.
func TestE2E_LiveConnRawRelayNarrow_CONNECTMITMStaysOpen(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	target := upstream.Listener.Addr().String()
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithPassthrough(t, h)

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)
	if got := keepAliveGet(t, c, target, "/other-before"); got != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("before narrowing: status=%d hits=%d, want 200 and 1", got, hits.Load())
	}

	narrowPolicyToPathOnly(t, h, policyPath)
	if got := keepAliveGet(t, c, target, "/api/x"); got != http.StatusOK {
		t.Errorf("GET /api/x on the MITM connection after narrowing = %d, want 200", got)
	}
	if got := keepAliveGet(t, c, target, "/other"); got != http.StatusForbidden {
		t.Errorf("GET /other on the MITM connection after narrowing = %d, want 403", got)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("upstream hits = %d, want 2 (/other must not reach the upstream)", got)
	}
}

// Guard: a plain-HTTP forward connection is not cut by the narrowing
// either.
func TestE2E_LiveConnRawRelayNarrow_PlainForwardStaysOpen(t *testing.T) {
	target, hits := countingHTTPUpstream(t)
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithPassthrough(t, h)

	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	br := bufio.NewReader(c)
	get := func(path string) int {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		defer func() { _ = c.SetDeadline(time.Time{}) }()
		if _, err := io.WriteString(c, "GET http://"+target+path+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := get("/other-before"); got != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("before narrowing: status=%d hits=%d, want 200 and 1", got, hits.Load())
	}

	narrowPolicyToPathOnly(t, h, policyPath)
	if got := get("/api/x"); got != http.StatusOK {
		t.Errorf("GET /api/x on the forward connection after narrowing = %d, want 200", got)
	}
	if got := get("/other"); got != http.StatusForbidden {
		t.Errorf("GET /other on the forward connection after narrowing = %d, want 403", got)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("upstream hits = %d, want 2 (/other must not reach the upstream)", got)
	}
}

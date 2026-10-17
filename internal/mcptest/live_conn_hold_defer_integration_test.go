//go:build e2e && !e2e_smoke

// USK-1192: a policy change that denies the host of a connection carrying
// an intercept hold revokes the connection at once but closes it only after
// the hold resolved and its Result was delivered. Helpers live in
// live_conn_reconcile_*_integration_test.go and
// intercept_scope_recheck_smoke_integration_test.go.
package mcptest_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// holdResponsesRule holds the response to every request whose path
// starts with /resp.
var holdResponsesRule = []map[string]any{{
	"id":        "hold-responses",
	"enabled":   true,
	"protocol":  "http",
	"direction": "response",
	"http":      map[string]any{"path_pattern": "^/resp"},
}}

func assertTargetScope403Body(t *testing.T, status int, body []byte, what string) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("%s: status = %d (body %q), want 403", what, status, body)
	}
	var b struct {
		BlockedBy string `json:"blocked_by"`
	}
	if err := json.Unmarshal(body, &b); err != nil || b.BlockedBy != "target_scope" {
		t.Errorf("%s: 403 body %q (err %v), want blocked_by target_scope", what, body, err)
	}
}

func releaseHeld(t *testing.T, h *mcptest.Harness, entry map[string]any) {
	t.Helper()
	h.MustOK(t, "intercept", map[string]any{"action": "release", "params": map[string]any{"intercept_id": entry["id"]}})
}

// TestE2E_LiveConnHoldDefer_MITMHTTP2 is test-plan 10: on a CONNECT tunnel
// MITM'd on the h2 route, stream A is held; a reload denies the host; a new
// stream B on the same connection is answered 403 target_scope; releasing
// A answers it 403 target_scope; then the connection is closed. Nothing
// reaches the upstream.
func TestE2E_LiveConnHoldDefer_MITMHTTP2(t *testing.T) {
	upstream, hits := h2CountingUpstream(t)
	target := upstream.Listener.Addr().String()
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithRules(t, h, holdHeldPathRule, nil)

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{ //nolint:gosec // the client does not trust the proxy's MITM CA
		InsecureSkipVerify: true,
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"h2"},
	})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		t.Fatalf("client TLS handshake over tunnel: %v", err)
	}
	_ = tc.SetDeadline(time.Time{})
	t.Cleanup(func() { _ = tc.Close() })
	if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated ALPN = %q, want h2", got)
	}
	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		t.Fatalf("http2 NewClientConn: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	type result struct {
		status int
		body   []byte
		err    error
	}
	get := func(path string) chan result {
		out := make(chan result, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+target+path, nil)
			if err != nil {
				out <- result{err: err}
				return
			}
			resp, err := cc.RoundTrip(req)
			if err != nil {
				out <- result{err: err}
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			out <- result{status: resp.StatusCode, body: body, err: err}
		}()
		return out
	}
	await := func(ch chan result, what string) result {
		t.Helper()
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("%s: %v", what, r.err)
			}
			return r
		case <-time.After(20 * time.Second):
			t.Fatalf("%s: timed out", what)
			return result{}
		}
	}

	aCh := get("/held-a")
	entry := waitForHeldEntry(t, h, 5*time.Second)
	reloadDenyLoopback(t, h, policyPath)

	b := await(get("/other-b"), "stream B")
	assertTargetScope403Body(t, b.status, b.body, "stream B on the revoked connection")
	if cc.State().Closed {
		t.Fatal("h2 connection closed while stream A is still held")
	}

	releaseHeld(t, h, entry)
	a := await(aCh, "stream A")
	assertTargetScope403Body(t, a.status, a.body, "released stream A")

	deadline := time.Now().Add(5 * time.Second)
	for !cc.State().Closed {
		if time.Now().After(deadline) {
			t.Fatalf("h2 connection still open 5s after its last hold resolved (state %+v)", cc.State())
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := hits.Load(); got != 0 {
		t.Errorf("upstream hits = %d, want 0", got)
	}
	assertBlockedFlowRecorded(t, h)
}

// TestE2E_LiveConnHoldDefer_HoldFreeConnCutImmediately is test-plan 11
// (guard): while connection 1 defers its cut for a hold, a separate
// hold-free plain-forward connection to the same host is cut at once.
func TestE2E_LiveConnHoldDefer_HoldFreeConnCutImmediately(t *testing.T) {
	sseTarget, _ := sseUpstream(t)
	upstreamAddr, upstream := startObservedUpstream(t)
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithRules(t, h, holdHeldPathRule, nil)
	client := proxyHTTPClient(t, proxyAddr)

	respCh := requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/held-1", upstreamAddr), nil, nil)
	entry := waitForHeldEntry(t, h, 5*time.Second)

	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "GET http://"+sseTarget+"/stream HTTP/1.1\r\nHost: "+sseTarget+"\r\nAccept: text/event-stream\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("stream response = %v, %v; want 200", resp, err)
	}
	_ = c.SetDeadline(time.Time{})

	reloadDenyLoopback(t, h, policyPath)
	assertConnClosedWithin(t, br, c.SetReadDeadline, 5*time.Second)
	if items := queryHeldItems(t, h); len(items) != 1 {
		t.Fatalf("held entries after reload = %d, want 1 (the deferred connection's hold)", len(items))
	}

	releaseHeld(t, h, entry)
	assertScopeBlockedResponse(t, awaitResponse(t, respCh))
	if got := upstream.hitCount(); got != 0 {
		t.Errorf("upstream hits = %d, want 0", got)
	}
}

// TestE2E_LiveConnHoldDefer_ReceiveHoldDelivered is test-plan 12: a held
// response on a connection whose host is then denied is delivered on
// release (it sends nothing upstream — D3), and the connection is closed
// afterwards.
func TestE2E_LiveConnHoldDefer_ReceiveHoldDelivered(t *testing.T) {
	upstreamAddr, upstream := startObservedUpstream(t)
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithRules(t, h, holdResponsesRule, nil)

	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := io.WriteString(c, "GET http://"+upstreamAddr+"/resp HTTP/1.1\r\nHost: "+upstreamAddr+"\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	entry := waitForHeldEntry(t, h, 5*time.Second)
	reloadDenyLoopback(t, h, policyPath)
	if items := queryHeldItems(t, h); len(items) != 1 {
		t.Fatalf("held entries after reload = %d, want 1", len(items))
	}
	releaseHeld(t, h, entry)

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read released response: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, resp.ContentLength))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("released response status = %d (body %q), want the original 200", resp.StatusCode, body)
	}
	_ = c.SetReadDeadline(time.Time{})
	assertConnClosedWithin(t, br, c.SetReadDeadline, 5*time.Second)
	if got := upstream.hitCount(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 (only the original request)", got)
	}
}

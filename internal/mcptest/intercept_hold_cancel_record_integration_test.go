//go:build e2e && !e2e_smoke

// USK-1193: an intercept hold whose ctx ends without an agent action
// (proxy_stop, session teardown, peer-direction failure) is recorded as an
// audit Stream with state=error and blocked_by=intercept_cancelled, through
// the production assembly (mcpserver.Run → proxybuild → session
// OnPipelineDrop) instead of vanishing from both the queue and the store.
package mcptest_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	wslayer "github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// waitForCancelledFlow polls query(flows, blocked_by=intercept_cancelled)
// until one Stream is recorded and returns it.
func waitForCancelledFlow(t *testing.T, h *mcptest.Harness) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter":   map[string]any{"blocked_by": "intercept_cancelled"},
		})
		if flows, _ := res.Decoded["flows"].([]any); len(flows) > 0 {
			if len(flows) != 1 {
				t.Errorf("query(blocked_by=intercept_cancelled) returned %d flows, want 1", len(flows))
			}
			m, _ := flows[0].(map[string]any)
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
	all := h.MustOK(t, "query", map[string]any{"resource": "flows"})
	t.Fatalf("no blocked_by=intercept_cancelled Stream recorded; all flows: %s", all.Text)
	return nil
}

func assertCancelledAuditStream(t *testing.T, got map[string]any, entry map[string]any) {
	t.Helper()
	wantID, _ := entry["stream_id"].(string)
	if wantID == "" {
		t.Fatalf("held entry has no stream_id: %+v", entry)
	}
	if got["id"] != wantID {
		t.Errorf("audit Stream id = %v, want the held entry's stream_id %q", got["id"], wantID)
	}
	if got["state"] != "error" {
		t.Errorf("audit Stream state = %v, want error", got["state"])
	}
	if got["blocked_by"] != "intercept_cancelled" {
		t.Errorf("audit Stream blocked_by = %v, want intercept_cancelled", got["blocked_by"])
	}
}

// T1: an HTTP/1 request held on Send, then proxy_stop.
func TestE2E_InterceptHoldCancel_ProxyStopRecordsHeldRequest(t *testing.T) {
	upstreamAddr, upstream := startObservedUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	client := proxyHTTPClient(t, startProxyWithRules(t, h, holdHeldPathRule, nil))

	respCh := requestThroughProxy(t, client, "GET", fmt.Sprintf("http://%s/held-stop", upstreamAddr), nil, nil)
	entry := waitForHeldEntry(t, h, 5*time.Second)

	h.MustOK(t, "proxy_stop", map[string]any{})

	select {
	case <-respCh:
	case <-time.After(20 * time.Second):
		t.Fatal("client request still pending 20s after proxy_stop")
	}
	assertCancelledAuditStream(t, waitForCancelledFlow(t, h), entry)
	if got := upstream.hitCount(); got != 0 {
		t.Errorf("upstream hits = %d, want 0 (the held request was never released)", got)
	}
}

// T2: a WS echo frame held on Receive, then the client's TCP connection is
// cut without a Close frame.
func TestE2E_InterceptHoldCancel_WSClientAbortRecordsHeldFrame(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: "ws"})
	proxyAddr := startProxyWithRules(t, h, []map[string]any{{
		"id":        "hold-ws-receive",
		"enabled":   true,
		"protocol":  "ws",
		"direction": "receive",
		"ws":        map[string]any{"payload_pattern": "^echo-me$"},
	}}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialWSThroughProxy(ctx, t, proxyAddr, wsUpstreamHostPort(t, h.UpstreamTLS.URL))
	if err != nil {
		t.Fatalf("dial WS through proxy: %v", err)
	}
	defer conn.Close()

	if err := writeMaskedClientFrame(conn, wslayer.OpcodeText, []byte("echo-me")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	entry := waitForHeldEntry(t, h, 5*time.Second)
	if got := h.WSObservedHits.Total(); got != 1 {
		t.Errorf("upstream WS hits = %d, want 1", got)
	}

	// Abrupt client abort: drop the TCP connection under TLS, no WS Close.
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("conn is %T, want *tls.Conn", conn)
	}
	_ = tlsConn.NetConn().Close()

	assertCancelledAuditStream(t, waitForCancelledFlow(t, h), entry)
}

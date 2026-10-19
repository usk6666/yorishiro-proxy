//go:build e2e

// USK-1181 smoke coverage: a request head the proxy itself closes before an
// Envelope exists (header deadline, 414) must be visible to the agent
// through MCP `query` — the failure reason, the proxy-closed marker, the
// bytes the client sent, and (for 414) the response the proxy returned.
package mcptest_test

import (
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// startHoldingUpstream accepts TCP connections and holds them open, so the
// plain-forward handler's upstream dial succeeds while no request is ever
// forwarded.
func startHoldingUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	return ln.Addr().String()
}

// pollErrorFlow polls query(flows, state=error) until an entry with
// failure_reason == reason appears and returns it.
func pollErrorFlow(t *testing.T, h *mcptest.Harness, reason string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": map[string]any{"state": "error"}})
		raw, _ := res.Decoded["flows"].([]any)
		for _, r := range raw {
			if m, ok := r.(map[string]any); ok && m["failure_reason"] == reason {
				return m
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("query(flows, state=error) has no failure_reason=%q entry: %s", reason, res.Text)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// pollFlowDetail polls query(flow, id) until every key in fields is a
// non-empty string. The Stream row lands before its Flows (the store
// writes asynchronously, in order), so a detail read right after the
// stream appears can miss them.
func pollFlowDetail(t *testing.T, h *mcptest.Harness, id string, fields ...string) mcptest.ToolResult {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
		ready := true
		for _, f := range fields {
			if s, _ := res.Decoded[f].(string); s == "" {
				ready = false
			}
		}
		if ready || time.Now().After(deadline) {
			return res
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func decodeB64Field(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, _ := m[key].(string)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %s: %v", key, err)
	}
	return string(b)
}

func TestE2E_RequestHeadTimeout_RecordedAndQueryable(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	upstream := startHoldingUpstream(t)

	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":        "127.0.0.1:0",
		"request_timeout_ms": 300,
	})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	// > 4100 bytes so the request passes the forward handler's target peek.
	head := "GET http://" + upstream + "/stall HTTP/1.1\r\nHost: " + upstream + "\r\nX-Pad: " + strings.Repeat("a", 4100)
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, _ := io.ReadAll(conn); len(got) != 0 {
		t.Errorf("proxy replied to a stalled request head: %.120q", got)
	}

	entry := pollErrorFlow(t, h, "request_head_timeout")
	tags, _ := entry["tags"].(map[string]any)
	if tags["closed_by"] != "proxy" {
		t.Errorf("tags.closed_by = %v, want proxy (entry=%v)", tags["closed_by"], entry)
	}
	if tags["request_timeout_ms"] != "300" {
		t.Errorf("tags.request_timeout_ms = %v, want 300", tags["request_timeout_ms"])
	}
	if entry["protocol"] != "http" {
		t.Errorf("protocol = %v, want http", entry["protocol"])
	}

	id, _ := entry["id"].(string)
	detail := pollFlowDetail(t, h, id, "raw_request")
	if detail.Decoded["state"] != "error" {
		t.Errorf("flow state = %v, want error", detail.Decoded["state"])
	}
	if got := decodeB64Field(t, detail.Decoded, "raw_request"); got != head {
		t.Errorf("raw_request = %d bytes (prefix ok=%v), want the %d bytes sent",
			len(got), strings.HasPrefix(head, got), len(head))
	}
}

func TestE2E_RequestLineTooLong_RecordedWithResponse(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	upstream := startHoldingUpstream(t)

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	payload := "GET http://" + upstream + "/" + strings.Repeat("x", 4<<20) + " HTTP/1.1\r\nHost: " + upstream + "\r\n\r\n"
	// Half-close once the upload is done so the proxy's post-414 drain
	// ends at EOF instead of waiting out its linger deadline.
	go func() {
		_, _ = conn.Write([]byte(payload))
		_ = conn.(*net.TCPConn).CloseWrite()
	}()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, _ := io.ReadAll(conn)
	if !strings.HasPrefix(string(got), "HTTP/1.1 414 ") {
		t.Fatalf("client read %.120q, want HTTP/1.1 414", got)
	}

	entry := pollErrorFlow(t, h, "request_line_too_long")
	id, _ := entry["id"].(string)
	detail := pollFlowDetail(t, h, id, "raw_request", "raw_response")
	if code, _ := detail.Decoded["response_status_code"].(float64); int(code) != 414 {
		t.Errorf("response_status_code = %v, want 414", detail.Decoded["response_status_code"])
	}
	if resp := decodeB64Field(t, detail.Decoded, "raw_response"); resp != string(got) {
		t.Errorf("raw_response = %q, want the bytes the client read %q", resp, got)
	}
	if req := decodeB64Field(t, detail.Decoded, "raw_request"); req == "" || !strings.HasPrefix(payload, req) {
		t.Errorf("raw_request is not a non-empty prefix of the rejected request (%d bytes)", len(req))
	}
}

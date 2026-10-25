//go:build e2e && !e2e_smoke

// USK-1343: `query resource=flow` on a streaming flow (WebSocket, gRPC,
// SSE) projects the head message of each direction — the Upgrade GET /
// 101, the gRPC Start, the SSE request / response head — at the top
// level, and reports original_request / original_response only for a
// variant pair at the head. Before the fix an unmodified flow with two or
// more messages per direction reported its first message as "original"
// and its last frame as the effective request / response.
//
// Driven through the production wiring: JSON-RPC harness → proxy_start →
// proxybuild live stack → RecordStep → SQLite → query tool.
package mcptest_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	wslayer "github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// waitCompleteStreamID polls `query resource=flows` with filter until
// exactly one Stream in state "complete" matches and returns its ID.
func waitCompleteStreamID(t *testing.T, h *mcptest.Harness, filter map[string]any) string {
	t.Helper()
	f := map[string]any{"state": "complete"}
	for k, v := range filter {
		f[k] = v
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": f})
		flows, _ := res.Decoded["flows"].([]any)
		if len(flows) == 1 {
			e, _ := flows[0].(map[string]any)
			id, _ := e["id"].(string)
			if id != "" {
				return id
			}
		}
		if len(flows) > 1 {
			t.Fatalf("%d complete Streams match %v, want 1: %s", len(flows), f, res.Text)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no complete Stream matched %v within 10s: %s", f, res.Text)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// queryFlowDecoded returns the decoded `query resource=flow` result.
func queryFlowDecoded(t *testing.T, h *mcptest.Harness, id string) map[string]any {
	t.Helper()
	return h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id}).Decoded
}

// headerValues returns the values of the header named name (exact case
// first, then case-insensitive) from a decoded headers object.
func headerValues(headers any, name string) []string {
	m, _ := headers.(map[string]any)
	pick := func(v any) []string {
		raw, _ := v.([]any)
		out := make([]string, 0, len(raw))
		for _, s := range raw {
			if str, ok := s.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	if v, ok := m[name]; ok {
		return pick(v)
	}
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return pick(v)
		}
	}
	return nil
}

// assertNoOriginal fails when the flow detail carries original_*.
func assertNoOriginal(t *testing.T, fl map[string]any) {
	t.Helper()
	if v, ok := fl["original_request"]; ok {
		t.Errorf("original_request = %v, want absent (the flow was not modified)", v)
	}
	if v, ok := fl["original_response"]; ok {
		t.Errorf("original_response = %v, want absent (the flow was not modified)", v)
	}
}

func assertPreviewNonEmpty(t *testing.T, fl map[string]any) {
	t.Helper()
	if p, _ := fl["message_preview"].([]any); len(p) == 0 {
		t.Errorf("message_preview is empty, want the streamed messages")
	}
}

// TestE2E_QueryFlow_UnmodifiedWS_TopLevelIsUpgrade reproduces the reported
// failure: an unmodified WS flow (Upgrade → text frames both ways → Close)
// must report no original_* and the Upgrade GET / 101 at the top level.
func TestE2E_QueryFlow_UnmodifiedWS_TopLevelIsUpgrade(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: "ws"})
	proxyAddr := startProxyWithPassthrough(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := wsUpstreamHostPort(t, h.UpstreamTLS.URL)
	conn, err := dialWSThroughProxy(ctx, t, proxyAddr, upstream)
	if err != nil {
		t.Fatalf("dial WS through proxy: %v", err)
	}
	defer conn.Close()

	for _, p := range []string{"first", "second"} {
		if err := writeMaskedClientFrame(conn, wslayer.OpcodeText, []byte(p)); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
		echo, err := readServerFrameWithDeadline(conn, 5*time.Second)
		if err != nil {
			t.Fatalf("read echo of %q: %v", p, err)
		}
		if !bytes.Equal(echo.Payload, []byte(p)) {
			t.Fatalf("echo = %q, want %q", echo.Payload, p)
		}
	}
	if err := writeMaskedClientFrame(conn, wslayer.OpcodeClose, []byte{0x03, 0xe8}); err != nil {
		t.Fatalf("write close: %v", err)
	}
	_, _ = readServerFrameWithDeadline(conn, 5*time.Second)
	_ = conn.Close()

	id := waitCompleteStreamID(t, h, map[string]any{"url_pattern": "/ws"})
	fl := queryFlowDecoded(t, h, id)

	assertNoOriginal(t, fl)
	if m, _ := fl["method"].(string); m != "GET" {
		t.Errorf("method = %q, want GET (Upgrade request)", m)
	}
	wantURL := "https://" + upstream + "/ws"
	if u, _ := fl["url"].(string); u != wantURL {
		t.Errorf("url = %q, want %q", u, wantURL)
	}
	if got := headerValues(fl["request_headers"], "Upgrade"); len(got) != 1 || got[0] != "websocket" {
		t.Errorf("request_headers[Upgrade] = %v, want [websocket]", got)
	}
	if sc, _ := fl["response_status_code"].(float64); sc != 101 {
		t.Errorf("response_status_code = %v, want 101", sc)
	}
	assertPreviewNonEmpty(t, fl)
}

// TestE2E_QueryFlow_GRPCUnary_TopLevelIsStart: a gRPC unary RPC records
// Start + Data (+ End) per direction; the top level is the Start
// (url = RPC path, request metadata, :status 200) and no original_*.
func TestE2E_QueryFlow_GRPCUnary_TopLevelIsStart(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: "grpc"})
	proxyAddr := startProxyWithPassthrough(t, h)

	cc := dialGRPCThroughProxy(t, proxyAddr, grpcUpstreamHostPort(t, h.UpstreamTLS.URL))
	defer cc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req := []byte("usk1343 head projection")
	var resp []byte
	if err := cc.Invoke(ctx, mcptest.GRPCSafetyEchoMethod, &req, &resp,
		grpc.ForceCodec(grpcRegressionRawCodec{})); err != nil {
		t.Fatalf("gRPC Invoke: %v", err)
	}

	id := waitCompleteStreamID(t, h, map[string]any{"protocol": "grpc"})
	fl := queryFlowDecoded(t, h, id)

	assertNoOriginal(t, fl)
	// The :authority is whatever grpc-go put on the wire, so only the
	// scheme and the RPC path are pinned.
	if u, _ := fl["url"].(string); !strings.HasPrefix(u, "https://") || !strings.HasSuffix(u, mcptest.GRPCSafetyEchoMethod) {
		t.Errorf("url = %q, want https://<authority>%s (Send Start)", u, mcptest.GRPCSafetyEchoMethod)
	}
	// Send Start metadata (content-type lives on GRPCStartMessage.ContentType,
	// not in the metadata list; te: trailers is request metadata grpc-go sends).
	if got := headerValues(fl["request_headers"], "te"); len(got) != 1 || got[0] != "trailers" {
		t.Errorf("request_headers[te] = %v, want [trailers] (Send Start metadata)", got)
	}
	if sc, _ := fl["response_status_code"].(float64); sc != 200 {
		t.Errorf("response_status_code = %v, want 200 (Receive Start)", sc)
	}
	assertPreviewNonEmpty(t, fl)
}

// sseFiniteUpstream serves three SSE events on /events and ends the
// response.
func sseFiniteUpstream(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		fl.Flush()
		for i := 0; i < 3; i++ {
			if _, err := fmt.Fprintf(w, "data: event-%d\n\n", i); err != nil {
				return
			}
			fl.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// TestE2E_QueryFlow_SSE_TopLevelIsResponseHead: an SSE flow records the
// response head and one row per event on Receive; the top level is the
// response head (200, text/event-stream) and no original_response.
func TestE2E_QueryFlow_SSE_TopLevelIsResponseHead(t *testing.T) {
	target := sseFiniteUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxyAddr := startProxyWithPassthrough(t, h)

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}
	resp, err := client.Get("http://" + target + "/events")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read SSE body: %v", err)
	}
	if !strings.Contains(string(body), "event-2") {
		t.Fatalf("SSE body = %q, want three events", body)
	}

	id := waitCompleteStreamID(t, h, map[string]any{"url_pattern": "/events"})
	fl := queryFlowDecoded(t, h, id)

	assertNoOriginal(t, fl)
	if m, _ := fl["method"].(string); m != "GET" {
		t.Errorf("method = %q, want GET", m)
	}
	if sc, _ := fl["response_status_code"].(float64); sc != 200 {
		t.Errorf("response_status_code = %v, want 200 (response head)", sc)
	}
	if got := headerValues(fl["response_headers"], "Content-Type"); len(got) != 1 || got[0] != "text/event-stream" {
		t.Errorf("response_headers[Content-Type] = %v, want [text/event-stream]", got)
	}
	assertPreviewNonEmpty(t, fl)
}

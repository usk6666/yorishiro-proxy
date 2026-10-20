//go:build e2e && !e2e_smoke

// USK-1109: safety_filter.input.action "log_only" is the observe-only
// mode of the Input SafetyFilter. Before the fix the live-wire engines
// never carried the action, so log_only blocked exactly like block. These
// tests boot the production server with a log_only config and prove, per
// protocol, that a matching Send payload REACHES the upstream and that the
// match is recorded as a Stream tag an agent can see through `query`.
//
// The block-mode siblings (security_safetyfilter*_smoke_integration_test.go)
// are the reverse guard and stay unchanged.
package mcptest_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	wslayer "github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

const safetyFilterDestructiveSQLLogOnlyConfig = `{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "log_only",
      "rules": [
        {"preset": "destructive-sql"}
      ]
    }
  }
}`

const safetyFilterWSPayloadLogOnlyConfig = `{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "log_only",
      "rules": [
        {"id": "ws-leak", "pattern": "password=", "targets": ["payload"]}
      ]
    }
  }
}`

// waitForLogOnlyTag polls query(flows, protocol) until a flow carries the
// tag key, and returns that flow. RecordStep writes go through the store's
// write queue, so the tag may land just after the client sees the reply.
func waitForLogOnlyTag(t *testing.T, h *mcptest.Harness, protocol, tagKey string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last []any
	for time.Now().Before(deadline) {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter":   map[string]any{"protocol": protocol},
		})
		last, _ = res.Decoded["flows"].([]any)
		for _, raw := range last {
			fl, _ := raw.(map[string]any)
			tags, _ := fl["tags"].(map[string]any)
			if v, ok := tags[tagKey].(string); ok && v != "" {
				return fl
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("query(flows, protocol=%s): no flow carries tag %q; flows=%v", protocol, tagKey, last)
	return nil
}

func assertNotBlocked(t *testing.T, fl map[string]any) {
	t.Helper()
	if got, _ := fl["blocked_by"].(string); got != "" {
		t.Errorf("log_only flow blocked_by = %q, want empty", got)
	}
}

func TestE2E_SafetyFilter_LogOnly_HTTPForwardsDestructiveSQL(t *testing.T) {
	upstreamAddr, upstreamObs := startObservedUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: safetyFilterDestructiveSQLLogOnlyConfig})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	client := proxyHTTPClient(t, proxyAddr)

	resp, err := client.Post("http://"+upstreamAddr+"/api/query", "text/plain", bytes.NewBufferString("DROP TABLE users"))
	if err != nil {
		t.Fatalf("destructive POST under log_only: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("destructive POST status = %d, want 200 from upstream (log_only must not block)", resp.StatusCode)
	}
	if got := upstreamObs.hitCount(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1 (log_only must forward)", got)
	}

	fl := waitForLogOnlyTag(t, h, "http", "safety_log_only:destructive-sql:drop")
	assertNotBlocked(t, fl)
}

func TestE2E_SafetyFilter_LogOnly_WSForwardsPayload(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    safetyFilterWSPayloadLogOnlyConfig,
		UpstreamProto: "ws",
	})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialWSThroughProxy(ctx, t, proxyAddr, wsUpstreamHostPort(t, h.UpstreamTLS.URL))
	if err != nil {
		t.Fatalf("dial WS through proxy: %v", err)
	}
	defer conn.Close()

	payload := []byte("password=hunter2")
	if err := writeMaskedClientFrame(conn, wslayer.OpcodeText, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	echo, err := readServerFrameWithDeadline(conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read echo under log_only (frame was dropped?): %v", err)
	}
	if !bytes.Equal(echo.Payload, payload) {
		t.Errorf("echo = %q, want %q", echo.Payload, payload)
	}
	if got := h.WSObservedHits.Total(); got != 1 {
		t.Fatalf("upstream WS hits = %d, want 1 (log_only must forward)", got)
	}

	fl := waitForLogOnlyTag(t, h, "ws", "safety_log_only:ws-leak")
	assertNotBlocked(t, fl)
}

func TestE2E_SafetyFilter_LogOnly_GRPCForwardsDestructiveSQL(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    safetyFilterDestructiveSQLLogOnlyConfig,
		UpstreamProto: "grpc",
	})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	cc := dialGRPCThroughProxy(t, proxyAddr, grpcUpstreamHostPort(t, h.UpstreamTLS.URL))
	defer cc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req := []byte("DROP TABLE users")
	var resp []byte
	if err := cc.Invoke(ctx, mcptest.GRPCSafetyEchoMethod, &req, &resp,
		grpc.ForceCodec(grpcRegressionRawCodec{})); err != nil {
		t.Fatalf("destructive gRPC call under log_only failed (want grpc-status 0): %v", err)
	}
	if !bytes.Equal(resp, req) {
		t.Errorf("gRPC echo = %q, want %q", resp, req)
	}
	if got := h.GRPCObservedHits.PerMethod(mcptest.GRPCSafetyEchoMethod); got != 1 {
		t.Fatalf("upstream per-method hits = %d, want 1 (log_only must forward)", got)
	}

	fl := waitForLogOnlyTag(t, h, "grpc", "safety_log_only:destructive-sql:drop")
	assertNotBlocked(t, fl)
	if got, _ := fl["state"].(string); strings.EqualFold(got, "error") {
		t.Errorf("log_only gRPC stream state = %q, want not error", got)
	}
}

// TestE2E_SafetyFilter_LogOnly_WSForwardsDestructiveSQLPreset pins
// USK-1275 under log_only: with ONLY the destructive-sql preset, a
// `DROP TABLE users` WS frame is forwarded and the ws flow is tagged with
// the preset rule ID.
func TestE2E_SafetyFilter_LogOnly_WSForwardsDestructiveSQLPreset(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    safetyFilterDestructiveSQLLogOnlyConfig,
		UpstreamProto: "ws",
	})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialWSThroughProxy(ctx, t, proxyAddr, wsUpstreamHostPort(t, h.UpstreamTLS.URL))
	if err != nil {
		t.Fatalf("dial WS through proxy: %v", err)
	}
	defer conn.Close()

	payload := []byte("DROP TABLE users")
	if err := writeMaskedClientFrame(conn, wslayer.OpcodeText, payload); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	echo, err := readServerFrameWithDeadline(conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read echo under log_only (frame was dropped?): %v", err)
	}
	if !bytes.Equal(echo.Payload, payload) {
		t.Errorf("echo = %q, want %q", echo.Payload, payload)
	}
	if got := h.WSObservedHits.Total(); got != 1 {
		t.Fatalf("upstream WS hits = %d, want 1 (log_only must forward)", got)
	}

	fl := waitForLogOnlyTag(t, h, "ws", "safety_log_only:destructive-sql:drop")
	assertNotBlocked(t, fl)
}

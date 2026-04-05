//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// ============================================================================
// 1. Query filter tests (conn_id, host)
// ============================================================================

// TestM19_QueryFilter_ConnID verifies that the conn_id filter returns only flows
// from the same connection.
func TestM19_QueryFilter_ConnID(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnv(t)

	// Start proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Send two requests through the proxy (may share or differ in conn_id).
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL1 := fmt.Sprintf("http://%s/api/test1", upstreamAddr)
	resp1, err := client.Get(targetURL1)
	if err != nil {
		t.Fatalf("GET 1: %v", err)
	}
	resp1.Body.Close()

	// Force a new connection for the second request.
	client.CloseIdleConnections()
	targetURL2 := fmt.Sprintf("http://%s/api/test2", upstreamAddr)
	resp2, err := client.Get(targetURL2)
	if err != nil {
		t.Fatalf("GET 2: %v", err)
	}
	resp2.Body.Close()

	time.Sleep(300 * time.Millisecond)

	// List all flows.
	allResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if allResult.Count < 2 {
		t.Fatalf("expected at least 2 flows, got %d", allResult.Count)
	}

	// Get the conn_id from the first flow's detail.
	flowDetail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       allResult.Flows[0].ID,
	})
	connID := flowDetail.ConnID
	if connID == "" {
		t.Fatal("flow conn_id is empty")
	}

	// Filter by conn_id.
	filtered := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"conn_id": connID,
		},
	})

	// All returned flows should have the same conn_id.
	if filtered.Count < 1 {
		t.Fatal("conn_id filter returned no flows")
	}
	for _, f := range filtered.Flows {
		detail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
			"resource": "flow",
			"id":       f.ID,
		})
		if detail.ConnID != connID {
			t.Errorf("flow %s conn_id = %q, want %q", f.ID, detail.ConnID, connID)
		}
	}

	client.CloseIdleConnections()
}

// TestM19_QueryFilter_Host verifies that the host filter returns only flows
// for the specified host.
func TestM19_QueryFilter_Host(t *testing.T) {
	// Create two upstream servers to get different hosts.
	upstream1 := startUpstreamServer(t)
	upstream2 := startUpstreamServer(t)
	env := setupIntegrationEnv(t)

	// Start proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)

	// Send requests to two different hosts.
	resp1, err := client.Get(fmt.Sprintf("http://%s/api/host1", upstream1))
	if err != nil {
		t.Fatalf("GET host1: %v", err)
	}
	resp1.Body.Close()

	resp2, err := client.Get(fmt.Sprintf("http://%s/api/host2", upstream2))
	if err != nil {
		t.Fatalf("GET host2: %v", err)
	}
	resp2.Body.Close()

	time.Sleep(300 * time.Millisecond)

	// Filter by the first upstream host.
	filtered := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"host": upstream1,
		},
	})

	if filtered.Count != 1 {
		t.Fatalf("host filter count = %d, want 1", filtered.Count)
	}
	if !strings.Contains(filtered.Flows[0].URL, upstream1) {
		t.Errorf("filtered flow URL = %q, want to contain %q", filtered.Flows[0].URL, upstream1)
	}

	client.CloseIdleConnections()
}

// ============================================================================
// 2. Comparer tests
// ============================================================================

// TestM19_Compare_JSONResponse verifies that the compare action detects
// differences between two flows with JSON responses.
func TestM19_Compare_JSONResponse(t *testing.T) {
	store := newFuzzTestStore(t)
	ctx := context.Background()

	// Create two flows with different JSON responses.
	flowA := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, flowA); err != nil {
		t.Fatalf("SaveFlow A: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  flowA.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       mustParseURL("http://example.com/api"),
	}); err != nil {
		t.Fatalf("AppendMessage A send: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:   flowA.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"name":"alice","age":30}`),
	}); err != nil {
		t.Fatalf("AppendMessage A recv: %v", err)
	}

	flowB := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  80 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, flowB); err != nil {
		t.Fatalf("SaveFlow B: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  flowB.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       mustParseURL("http://example.com/api"),
	}); err != nil {
		t.Fatalf("AppendMessage B send: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:   flowB.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"name":"bob","age":30,"role":"admin"}`),
	}); err != nil {
		t.Fatalf("AppendMessage B recv: %v", err)
	}

	// Set up MCP session with store.
	cs := setupResendCompareSession(t, store)

	// Compare the two flows.
	result := callTool[compareResult](t, cs, "resend", map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": flowA.ID,
			"flow_id_b": flowB.ID,
		},
	})

	// Status code should not have changed.
	if result.StatusCode == nil {
		t.Fatal("compare result status_code is nil")
	}
	if result.StatusCode.Changed {
		t.Error("status_code changed, expected unchanged (both 200)")
	}

	// Body should not be identical (different JSON content).
	if result.Body == nil {
		t.Fatal("compare result body is nil")
	}
	if result.Body.Identical {
		t.Error("body identical = true, want false")
	}

	// JSON diff should detect key changes.
	if result.Body.JSONDiff == nil {
		t.Fatal("compare result json_diff is nil")
	}
	// "role" was added in B.
	if len(result.Body.JSONDiff.KeysAdded) == 0 {
		t.Error("json_diff keys_added is empty, want 'role'")
	}
	// "name" value changed.
	if len(result.Body.JSONDiff.KeysChanged) == 0 {
		t.Error("json_diff keys_changed is empty, want 'name'")
	}
}

// TestM19_Compare_DifferentStatusCodes verifies comparison of flows with
// different status codes.
func TestM19_Compare_DifferentStatusCodes(t *testing.T) {
	store := newFuzzTestStore(t)
	ctx := context.Background()

	flowA := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  30 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, flowA); err != nil {
		t.Fatalf("SaveFlow A: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: flowA.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET",
		URL: mustParseURL("http://example.com/api"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: flowA.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("OK"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	flowB := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  30 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, flowB); err != nil {
		t.Fatalf("SaveFlow B: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: flowB.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET",
		URL: mustParseURL("http://example.com/api"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: flowB.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 404,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("Not Found"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupResendCompareSession(t, store)

	result := callTool[compareResult](t, cs, "resend", map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": flowA.ID,
			"flow_id_b": flowB.ID,
		},
	})

	if result.StatusCode == nil {
		t.Fatal("status_code is nil")
	}
	if !result.StatusCode.Changed {
		t.Error("status_code changed = false, want true")
	}
	if result.StatusCode.A != 200 {
		t.Errorf("status_code.a = %d, want 200", result.StatusCode.A)
	}
	if result.StatusCode.B != 404 {
		t.Errorf("status_code.b = %d, want 404", result.StatusCode.B)
	}

	// Body length should differ.
	if result.BodyLength == nil {
		t.Fatal("body_length is nil")
	}
	if result.BodyLength.Delta == 0 {
		t.Error("body_length delta = 0, want non-zero")
	}
}

// ============================================================================
// 3. Fuzz aggregate statistics tests
// ============================================================================

// TestM19_FuzzStats_Aggregation verifies that fuzz_results include aggregate
// statistics (status_code_distribution, body_length, timing_ms).
func TestM19_FuzzStats_Aggregation(t *testing.T) {
	store := newFuzzTestStore(t)

	// Target server returns different body sizes based on input.
	var reqCount atomic.Int32
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		// Vary body size slightly.
		body := fmt.Sprintf(`{"result":"ok","seq":%d}`, n)
		w.Write([]byte(body))
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	// Start a fuzz job.
	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     sessID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-user",
					"location":    "body_json",
					"json_path":   "$.username",
					"payload_set": "pos-user",
				},
			},
			"payload_sets": map[string]any{
				"pos-user": map[string]any{
					"type":   "wordlist",
					"values": []any{"admin", "root", "test", "user", "guest"},
				},
			},
			"tag": "m19-stats",
		},
	})
	if result.IsError {
		t.Fatalf("fuzz error: %v", result.Content)
	}

	var ar fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &ar)

	// Wait for completion.
	waitForFuzzCompletion(t, cs, ar.FuzzID, 15*time.Second)

	// Query fuzz results with summary.
	rr := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  ar.FuzzID,
	})
	if rr.IsError {
		t.Fatalf("query fuzz_results error: %v", rr.Content)
	}

	var fuzzResults queryFuzzResultsResult
	unmarshalQueryResultRaw(t, rr, &fuzzResults)

	if fuzzResults.Total != 5 {
		t.Errorf("total = %d, want 5", fuzzResults.Total)
	}

	// Verify summary statistics.
	if fuzzResults.Summary == nil {
		t.Fatal("summary is nil")
	}
	if fuzzResults.Summary.Statistics == nil {
		t.Fatal("statistics is nil")
	}

	stats := fuzzResults.Summary.Statistics
	if stats.StatusCodeDistribution == nil {
		t.Fatal("status_code_distribution is nil")
	}
	if stats.StatusCodeDistribution["200"] != 5 {
		t.Errorf("status_code_distribution[200] = %d, want 5", stats.StatusCodeDistribution["200"])
	}

	if stats.BodyLength == nil {
		t.Fatal("body_length stats is nil")
	}
	if stats.BodyLength.Min <= 0 {
		t.Errorf("body_length.min = %v, want > 0", stats.BodyLength.Min)
	}

	if stats.TimingMs == nil {
		t.Fatal("timing_ms stats is nil")
	}
	if stats.TimingMs.Min < 0 {
		t.Errorf("timing_ms.min = %v, want >= 0", stats.TimingMs.Min)
	}
}

// TestM19_FuzzStats_Outliers verifies outlier detection works correctly.
func TestM19_FuzzStats_Outliers(t *testing.T) {
	store := newFuzzTestStore(t)

	// Target server returns 403 for "forbidden" and 200 for everything else.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		json.Unmarshal(body, &parsed)

		if pw, ok := parsed["username"].(string); ok && pw == "outlier" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     sessID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-user",
					"location":    "body_json",
					"json_path":   "$.username",
					"payload_set": "pos-user",
				},
			},
			"payload_sets": map[string]any{
				"pos-user": map[string]any{
					"type":   "wordlist",
					"values": []any{"admin", "root", "test", "user", "outlier"},
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("fuzz error: %v", result.Content)
	}

	var ar fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &ar)
	waitForFuzzCompletion(t, cs, ar.FuzzID, 15*time.Second)

	// Query with outliers_only.
	rr := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  ar.FuzzID,
		"filter": map[string]any{
			"outliers_only": true,
		},
	})
	if rr.IsError {
		t.Fatalf("query fuzz_results outliers error: %v", rr.Content)
	}

	var fuzzResults queryFuzzResultsResult
	unmarshalQueryResultRaw(t, rr, &fuzzResults)

	// The outlier (403 status code) should be detected.
	if fuzzResults.Summary == nil {
		t.Fatal("summary is nil")
	}
	if fuzzResults.Summary.Outliers == nil {
		t.Fatal("outliers is nil")
	}
	if len(fuzzResults.Summary.Outliers.ByStatusCode) == 0 {
		t.Error("by_status_code outliers is empty, expected at least 1 outlier (403)")
	}
}

// ============================================================================
// 4. Rate limit tests
// ============================================================================

// TestM19_RateLimit_GlobalRPS verifies that global RPS rate limiting blocks
// requests exceeding the limit with 429 responses.
func TestM19_RateLimit_GlobalRPS(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnvWithRateLimiter(t, nil) // default rate limiter

	// Start proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Set a very low rate limit (1 RPS).
	rps := float64(1)
	callTool[rateLimitResult](t, env.cs, "security", map[string]any{
		"action": "set_rate_limits",
		"params": map[string]any{
			"max_requests_per_second": rps,
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/ratelimit", upstreamAddr)

	// Send several rapid requests; at least one should be rate limited.
	got429 := false
	for i := 0; i < 10; i++ {
		resp, err := client.Get(targetURL)
		if err != nil {
			// Connection reset is acceptable for rate-limited connections.
			continue
		}
		if resp.StatusCode == 429 {
			got429 = true
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}

	if !got429 {
		t.Error("expected at least one 429 response from rate limiting")
	}

	client.CloseIdleConnections()
}

// TestM19_RateLimit_PerHostRPS verifies per-host rate limiting.
func TestM19_RateLimit_PerHostRPS(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnvWithRateLimiter(t, nil)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Set per-host rate limit.
	hostRPS := float64(1)
	callTool[rateLimitResult](t, env.cs, "security", map[string]any{
		"action": "set_rate_limits",
		"params": map[string]any{
			"max_requests_per_host_per_second": hostRPS,
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/hostlimit", upstreamAddr)

	got429 := false
	for i := 0; i < 10; i++ {
		resp, err := client.Get(targetURL)
		if err != nil {
			continue
		}
		if resp.StatusCode == 429 {
			got429 = true
			resp.Body.Close()
			break
		}
		resp.Body.Close()
	}

	if !got429 {
		t.Error("expected at least one 429 response from per-host rate limiting")
	}

	client.CloseIdleConnections()
}

// TestM19_RateLimit_429Response verifies that 429 responses include the
// X-Blocked-By and X-Block-Reason headers.
func TestM19_RateLimit_429Response(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnvWithRateLimiter(t, nil)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	rps := float64(1)
	callTool[rateLimitResult](t, env.cs, "security", map[string]any{
		"action": "set_rate_limits",
		"params": map[string]any{
			"max_requests_per_second": rps,
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/headers", upstreamAddr)

	// Send rapid requests until we get a 429.
	var rateLimitResp *http.Response
	for i := 0; i < 20; i++ {
		resp, err := client.Get(targetURL)
		if err != nil {
			continue
		}
		if resp.StatusCode == 429 {
			rateLimitResp = resp
			break
		}
		resp.Body.Close()
	}

	if rateLimitResp == nil {
		t.Fatal("never received 429 response")
	}
	defer rateLimitResp.Body.Close()

	// Verify headers.
	blockedBy := rateLimitResp.Header.Get("X-Blocked-By")
	if blockedBy == "" {
		t.Error("X-Blocked-By header is missing on 429 response")
	}
	blockReason := rateLimitResp.Header.Get("X-Block-Reason")
	if blockReason != "rate_limit" {
		t.Errorf("X-Block-Reason = %q, want %q", blockReason, "rate_limit")
	}

	// Verify body contains rate limit info.
	body, _ := io.ReadAll(rateLimitResp.Body)
	if !strings.Contains(string(body), "rate limit") {
		t.Errorf("429 response body = %q, want to contain 'rate limit'", body)
	}

	client.CloseIdleConnections()
}

// TestM19_RateLimit_PolicyAgentLayer verifies that Agent cannot exceed
// Policy rate limits.
func TestM19_RateLimit_PolicyAgentLayer(t *testing.T) {
	rl := proxy.NewRateLimiter()
	rl.SetPolicyLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond: 10,
	})
	env := setupIntegrationEnvWithRateLimiter(t, rl)

	// Agent tries to set a higher limit than policy allows.
	rps := float64(20)
	result, err := env.cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: map[string]any{
			"action": "set_rate_limits",
			"params": map[string]any{
				"max_requests_per_second": rps,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error when agent exceeds policy rate limit")
	}

	// Agent sets within policy limit — should succeed.
	rps = float64(5)
	setResult := callTool[rateLimitResult](t, env.cs, "security", map[string]any{
		"action": "set_rate_limits",
		"params": map[string]any{
			"max_requests_per_second": rps,
		},
	})
	if setResult.Status != "updated" {
		t.Errorf("status = %q, want updated", setResult.Status)
	}
	if setResult.Effective.MaxRequestsPerSecond != 5 {
		t.Errorf("effective.max_rps = %v, want 5", setResult.Effective.MaxRequestsPerSecond)
	}
}

// ============================================================================
// 5. Budget tests
// ============================================================================

// TestM19_Budget_MaxTotalRequests verifies that the proxy triggers shutdown
// when max_total_requests is exceeded.
func TestM19_Budget_MaxTotalRequests(t *testing.T) {
	bm := proxy.NewBudgetManager()

	shutdownCh := make(chan string, 1)
	bm.Start(func(reason string) {
		shutdownCh <- reason
	})
	t.Cleanup(func() { bm.Stop() })

	// Set a very low budget.
	if err := bm.SetAgentBudget(proxy.BudgetConfig{
		MaxTotalRequests: 3,
	}); err != nil {
		t.Fatalf("SetAgentBudget: %v", err)
	}

	// Record requests.
	for i := 0; i < 4; i++ {
		bm.RecordRequest()
	}

	// Shutdown should have been triggered.
	select {
	case reason := <-shutdownCh:
		if !strings.Contains(reason, "request budget exhausted") {
			t.Errorf("shutdown reason = %q, want to contain 'request budget exhausted'", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for budget shutdown")
	}

	// Verify shutdown reason is recorded.
	if r := bm.ShutdownReason(); r == "" {
		t.Error("ShutdownReason is empty after budget exhaustion")
	}
}

// TestM19_Budget_MaxDuration verifies that the proxy triggers shutdown
// when max_duration is exceeded.
func TestM19_Budget_MaxDuration(t *testing.T) {
	bm := proxy.NewBudgetManager()

	shutdownCh := make(chan string, 1)
	bm.Start(func(reason string) {
		shutdownCh <- reason
	})
	t.Cleanup(func() { bm.Stop() })

	// Set a very short duration (100ms).
	if err := bm.SetAgentBudget(proxy.BudgetConfig{
		MaxDuration: 100 * time.Millisecond,
	}); err != nil {
		t.Fatalf("SetAgentBudget: %v", err)
	}

	// Wait for the duration to expire.
	select {
	case reason := <-shutdownCh:
		if !strings.Contains(reason, "duration budget exhausted") {
			t.Errorf("shutdown reason = %q, want to contain 'duration budget exhausted'", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for duration budget shutdown")
	}
}

// TestM19_Budget_PolicyAgentLayer verifies that Agent cannot exceed
// Policy budget limits.
func TestM19_Budget_PolicyAgentLayer(t *testing.T) {
	bm := proxy.NewBudgetManager()
	bm.SetPolicyBudget(proxy.BudgetConfig{
		MaxTotalRequests: 100,
		MaxDuration:      time.Hour,
	})

	env := setupIntegrationEnvWithBudgetManager(t, bm)

	// Agent tries to exceed policy.
	maxReqs := int64(200)
	result, err := env.cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: map[string]any{
			"action": "set_budget",
			"params": map[string]any{
				"max_total_requests": maxReqs,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error when agent exceeds policy budget")
	}

	// Agent sets within policy — should succeed.
	maxReqs = int64(50)
	setResult := callTool[budgetResult](t, env.cs, "security", map[string]any{
		"action": "set_budget",
		"params": map[string]any{
			"max_total_requests": maxReqs,
		},
	})
	if setResult.Status != "updated" {
		t.Errorf("status = %q, want updated", setResult.Status)
	}
	if setResult.Effective.MaxTotalRequests != 50 {
		t.Errorf("effective.max_total_requests = %d, want 50", setResult.Effective.MaxTotalRequests)
	}
}

// TestM19_Budget_StatusResource verifies that the stop reason is recorded
// in the status resource after budget exhaustion.
func TestM19_Budget_StatusResource(t *testing.T) {
	bm := proxy.NewBudgetManager()

	shutdownCh := make(chan string, 1)
	bm.Start(func(reason string) {
		shutdownCh <- reason
	})
	t.Cleanup(func() { bm.Stop() })

	env := setupIntegrationEnvWithBudgetManager(t, bm)

	// Set budget via MCP tool.
	maxReqs := int64(2)
	callTool[budgetResult](t, env.cs, "security", map[string]any{
		"action": "set_budget",
		"params": map[string]any{
			"max_total_requests": maxReqs,
		},
	})

	// Exhaust the budget.
	for i := 0; i < 3; i++ {
		bm.RecordRequest()
	}

	// Wait for shutdown.
	select {
	case <-shutdownCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for budget shutdown")
	}

	// Verify via get_budget that stop_reason is recorded.
	budgetStatus := callTool[getBudgetResult](t, env.cs, "security", map[string]any{
		"action": "get_budget",
		"params": map[string]any{},
	})
	if budgetStatus.StopReason == "" {
		t.Error("stop_reason is empty after budget exhaustion")
	}
	if !strings.Contains(budgetStatus.StopReason, "request budget exhausted") {
		t.Errorf("stop_reason = %q, want to contain 'request budget exhausted'", budgetStatus.StopReason)
	}
}

// ============================================================================
// 6. Plugin shutdown API test
// ============================================================================

// TestM19_PluginShutdown verifies that proxy.shutdown() from a Starlark plugin
// triggers shutdown and records the reason.
func TestM19_PluginShutdown(t *testing.T) {
	bm := proxy.NewBudgetManager()

	shutdownCh := make(chan string, 1)
	bm.Start(func(reason string) {
		shutdownCh <- reason
	})
	t.Cleanup(func() { bm.Stop() })

	// Create a plugin engine with the shutdown function wired to budget manager.
	logger := testutil.DiscardLogger()
	engine := plugin.NewEngine(logger)
	engine.SetShutdownFunc(bm.TriggerShutdown)

	// Create a minimal Starlark script that calls proxy.shutdown().
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "shutdown_test.star")
	scriptContent := `
def on_receive_from_client(data):
    proxy.shutdown("test shutdown from plugin")
    return {"action": action.CONTINUE, "data": data}
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
		t.Fatalf("write script: %v", err)
	}

	// Load the plugin.
	if err := engine.LoadPlugins(context.Background(), []plugin.PluginConfig{
		{
			Path:     scriptPath,
			Protocol: "http",
			Hooks:    []string{"on_receive_from_client"},
		},
	}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	// Dispatch a hook to trigger proxy.shutdown().
	result, err := engine.Dispatch(context.Background(), plugin.HookOnReceiveFromClient, map[string]any{
		"method": "GET",
		"url":    "http://example.com/test",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	// Result should be non-nil (the hook result).
	if result == nil {
		t.Error("dispatch result is nil")
	}

	// Verify shutdown was triggered.
	select {
	case reason := <-shutdownCh:
		if reason != "test shutdown from plugin" {
			t.Errorf("shutdown reason = %q, want %q", reason, "test shutdown from plugin")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for plugin shutdown")
	}

	// Verify reason is recorded in budget manager.
	if r := bm.ShutdownReason(); r != "test shutdown from plugin" {
		t.Errorf("ShutdownReason = %q, want %q", r, "test shutdown from plugin")
	}
}

// ============================================================================
// Helpers
// ============================================================================

// mustParseURL parses a URL string or panics.
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(fmt.Sprintf("mustParseURL(%q): %v", rawURL, err))
	}
	return u
}

// setupResendCompareSession creates an MCP client session with a store for
// testing the resend compare action.
func setupResendCompareSession(t *testing.T, store flow.Store) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(ctx, nil, store, nil)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

// setupIntegrationEnvWithRateLimiter creates an integration test environment
// with a rate limiter injected into both the MCP server and HTTP handler.
func setupIntegrationEnvWithRateLimiter(t *testing.T, rl *proxy.RateLimiter) *testEnv {
	t.Helper()
	if rl == nil {
		rl = proxy.NewRateLimiter()
	}

	ctx := context.Background()

	// Create a temporary SQLite store.
	dbPath := filepath.Join(t.TempDir(), "integration.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Generate an ephemeral CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	// Build protocol handlers with rate limiter.
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	httpHandler.SetRateLimiter(rl)
	detector := protocol.NewDetector(httpHandler)

	// Create proxy manager.
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() {
		manager.Stop(context.Background())
	})

	// Create MCP server with rate limiter wired.
	mcpServer := NewServer(ctx, ca, store, manager,
		WithRateLimiter(rl),
		WithRateLimiterSetter(httpHandler),
	)

	// Connect server and client via in-memory transport.
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "integration-test",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return &testEnv{
		cs:      cs,
		store:   store,
		manager: manager,
	}
}

// setupIntegrationEnvWithBudgetManager creates an integration test environment
// with a budget manager injected into the MCP server.
func setupIntegrationEnvWithBudgetManager(t *testing.T, bm *proxy.BudgetManager) *testEnv {
	t.Helper()
	if bm == nil {
		bm = proxy.NewBudgetManager()
	}
	return setupIntegrationEnvWithOpts(t,
		WithBudgetManager(bm),
	)
}

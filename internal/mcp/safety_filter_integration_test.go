//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	gohttp "net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// setupSafetyFilterEnv creates a fully-wired MCP test environment with the
// SafetyFilter engine configured. The engine is wired into both the MCP server
// and the HTTP protocol handler so that proxy-layer and MCP-layer blocking are
// both active.
func setupSafetyFilterEnv(t *testing.T, engine *safety.Engine, opts ...ServerOption) *testEnv {
	t.Helper()
	store := newSafetyTestStore(t)
	return setupSafetyFilterEnvWithStore(t, store, engine, opts...)
}

// newDefaultSafetyEngine creates a safety engine with both destructive-sql and
// destructive-os-command presets loaded in block mode.
func newDefaultSafetyEngine(t *testing.T) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{Preset: "destructive-sql", Action: "block"},
			{Preset: "destructive-os-command", Action: "block"},
		},
	})
	if err != nil {
		t.Fatalf("create safety engine: %v", err)
	}
	return engine
}

// newLogOnlySafetyEngine creates a safety engine with presets in log_only mode.
func newLogOnlySafetyEngine(t *testing.T) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{Preset: "destructive-sql", Action: "log_only"},
			{Preset: "destructive-os-command", Action: "log_only"},
		},
	})
	if err != nil {
		t.Fatalf("create log_only safety engine: %v", err)
	}
	return engine
}

// --- Proxy Layer Tests ---

// TestSafetyFilter_Proxy_BlocksDestructiveSQL verifies that a request with a
// DROP TABLE payload is blocked at the proxy layer with 403 and correct headers.
func TestSafetyFilter_Proxy_BlocksDestructiveSQL(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newDefaultSafetyEngine(t)
	env := setupSafetyFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/test", upstreamAddr)

	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("DROP TABLE users;"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	client.CloseIdleConnections()
}

// TestSafetyFilter_Proxy_BlocksDestructiveOSCommand verifies that a request with
// rm -rf is blocked at the proxy layer.
func TestSafetyFilter_Proxy_BlocksDestructiveOSCommand(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newDefaultSafetyEngine(t)
	env := setupSafetyFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/cmd", upstreamAddr)

	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("rm -rf /"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	client.CloseIdleConnections()
}

// TestSafetyFilter_Proxy_AllowsDiagnosticPayloads verifies that non-destructive
// SQL injection test payloads (UNION SELECT, OR 1=1) are forwarded to upstream.
func TestSafetyFilter_Proxy_AllowsDiagnosticPayloads(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newDefaultSafetyEngine(t)
	env := setupSafetyFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)

	tests := []struct {
		name    string
		payload string
	}{
		{"UNION SELECT", "' UNION SELECT username, password FROM users--"},
		{"OR 1=1", "' OR 1=1--"},
		{"SELECT with WHERE", "SELECT * FROM users WHERE id = 1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetURL := fmt.Sprintf("http://%s/api/query", upstreamAddr)
			resp, err := client.Post(targetURL, "text/plain", strings.NewReader(tt.payload))
			if err != nil {
				t.Fatalf("POST through proxy: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != gohttp.StatusOK {
				t.Fatalf("status = %d, want %d for diagnostic payload %q", resp.StatusCode, gohttp.StatusOK, tt.name)
			}
		})
	}

	client.CloseIdleConnections()
}

// TestSafetyFilter_Proxy_ResponseFormat verifies the 403 blocked response
// contains X-Block-Reason: safety_filter and a JSON body.
func TestSafetyFilter_Proxy_ResponseFormat(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newDefaultSafetyEngine(t)
	env := setupSafetyFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/test", upstreamAddr)

	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("DROP TABLE users;"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	defer resp.Body.Close()

	// Check status code.
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	// Check X-Block-Reason header.
	blockReason := resp.Header.Get("X-Block-Reason")
	if blockReason != "safety_filter" {
		t.Errorf("X-Block-Reason = %q, want %q", blockReason, "safety_filter")
	}

	// Check JSON body.
	body, _ := io.ReadAll(resp.Body)
	var jsonBody map[string]any
	if err := json.Unmarshal(body, &jsonBody); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if jsonBody["blocked_by"] != "safety_filter" {
		t.Errorf("body.blocked_by = %q, want %q", jsonBody["blocked_by"], "safety_filter")
	}

	client.CloseIdleConnections()
}

// TestSafetyFilter_Proxy_FlowRecording verifies that blocked requests are recorded
// with BlockedBy = "safety_filter".
func TestSafetyFilter_Proxy_FlowRecording(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newDefaultSafetyEngine(t)
	env := setupSafetyFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/blocked", upstreamAddr)

	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("DROP TABLE users;"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	resp.Body.Close()

	// Wait for asynchronous flow persistence to complete. The proxy handler
	// saves flows in a background goroutine, so a short delay is needed before
	// querying. This matches the established pattern in other integration tests.
	time.Sleep(200 * time.Millisecond)

	// Query flows filtered by blocked_by.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"blocked_by": "safety_filter",
		},
	})
	if listResult.Count < 1 {
		t.Fatalf("expected at least 1 blocked flow, got %d", listResult.Count)
	}

	found := false
	for _, f := range listResult.Flows {
		if f.BlockedBy == "safety_filter" {
			found = true
			break
		}
	}
	if !found {
		t.Error("no flow found with blocked_by = safety_filter")
	}

	client.CloseIdleConnections()
}

// TestSafetyFilter_Proxy_LogOnlyMode verifies that log_only mode allows requests
// to pass through without blocking.
func TestSafetyFilter_Proxy_LogOnlyMode(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newLogOnlySafetyEngine(t)
	env := setupSafetyFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/test", upstreamAddr)

	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("DROP TABLE users;"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// In log_only mode, the request should pass through.
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d (log_only should not block)", resp.StatusCode, gohttp.StatusOK)
	}
	if !strings.Contains(string(respBody), "echo:") {
		t.Errorf("expected upstream echo response, got %q", string(respBody))
	}

	client.CloseIdleConnections()
}

// TestSafetyFilter_Proxy_NoEngine verifies that when no SafetyFilter engine is
// configured, requests pass through normally including destructive payloads.
func TestSafetyFilter_Proxy_NoEngine(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	// Pass nil engine to verify no filtering.
	env := setupSafetyFilterEnv(t, nil)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/test", upstreamAddr)

	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("DROP TABLE users;"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d (no safety filter configured)", resp.StatusCode, gohttp.StatusOK)
	}
	if !strings.Contains(string(respBody), "echo:") {
		t.Errorf("expected upstream echo response, got %q", string(respBody))
	}

	client.CloseIdleConnections()
}

// --- MCP Tool Layer Tests ---

// TestSafetyFilter_MCP_ResendBlock verifies that the resend tool blocks destructive
// payloads before sending.
func TestSafetyFilter_MCP_ResendBlock(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newDefaultSafetyEngine(t)
	env := setupSafetyFilterEnv(t, engine)

	// Start proxy and send a safe request to create a flow for resend.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/safe", upstreamAddr)
	resp, err := client.Post(targetURL, "text/plain", strings.NewReader("safe data"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	resp.Body.Close()
	client.CloseIdleConnections()

	// Wait for asynchronous flow persistence (see comment in FlowRecording test).
	time.Sleep(200 * time.Millisecond)

	// Get the flow ID.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatal("no flows recorded")
	}
	flowID := listResult.Flows[0].ID

	// Resend with destructive body override should fail.
	callToolExpectError(t, env.cs, "resend", map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":       flowID,
			"override_body": "DROP TABLE users;",
		},
	})
}

// TestSafetyFilter_MCP_FuzzTemplateBlock verifies that the fuzz tool blocks
// destructive patterns in the template flow.
func TestSafetyFilter_MCP_FuzzTemplateBlock(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newDefaultSafetyEngine(t)

	// Create stores and fuzz runner.
	mainStore := newSafetyTestStore(t)
	fuzzStore := newFuzzStore(t)
	fuzzEngine := fuzzer.NewEngine(mainStore, mainStore, fuzzStore, NewDefaultHTTPClient(), "")
	fuzzRegistry := fuzzer.NewJobRegistry()
	fuzzRunner := fuzzer.NewRunner(fuzzEngine, fuzzRegistry)

	env := setupSafetyFilterEnvWithStore(t, mainStore, engine,
		WithFuzzRunner(fuzzRunner),
		WithFuzzStore(fuzzStore),
	)

	// Start proxy.
	_ = callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Directly save a flow with destructive body (bypassing proxy filter).
	ctx := context.Background()
	u, _ := url.Parse(fmt.Sprintf("http://%s/api/fuzz", upstreamAddr))
	fl := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	if err := mainStore.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := mainStore.SaveFlow(ctx, &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"text/plain"}},
		Body:      []byte("DROP TABLE users;"),
	}); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}
	if err := mainStore.SaveFlow(ctx, &flow.Flow{
		StreamID:   fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now(),
		StatusCode: 200,
		Body:       []byte("ok"),
	}); err != nil {
		t.Fatalf("AppendMessage(recv): %v", err)
	}

	// Fuzz with destructive template body should be blocked.
	callToolExpectError(t, env.cs, "fuzz", map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     fl.ID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-1",
					"location":    "body",
					"mode":        "replace",
					"payload_set": "test",
				},
			},
			"payload_sets": map[string]any{
				"test": map[string]any{
					"type":   "wordlist",
					"values": []any{"a", "b"},
				},
			},
		},
	})
}

// TestSafetyFilter_MCP_FuzzExpandedPayloadBlock verifies that the fuzz tool's
// per-payload safety checker blocks destructive payloads after expansion.
// The template body is safe, but the payload set contains a destructive value.
// The fuzz job should start (template passes), but the destructive payload
// should be skipped during execution.
func TestSafetyFilter_MCP_FuzzExpandedPayloadBlock(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	engine := newDefaultSafetyEngine(t)

	mainStore := newSafetyTestStore(t)
	fuzzStore := newFuzzStore(t)
	fuzzEngine := fuzzer.NewEngine(mainStore, mainStore, fuzzStore, NewDefaultHTTPClient(), "")
	fuzzRegistry := fuzzer.NewJobRegistry()
	fuzzRunner := fuzzer.NewRunner(fuzzEngine, fuzzRegistry)

	env := setupSafetyFilterEnvWithStore(t, mainStore, engine,
		WithFuzzRunner(fuzzRunner),
		WithFuzzStore(fuzzStore),
	)

	// Proxy must be running for fuzz runner's HTTP client.
	_ = callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Create a safe template flow.
	ctx := context.Background()
	u, _ := url.Parse(fmt.Sprintf("http://%s/api/fuzz", upstreamAddr))
	fl := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	if err := mainStore.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := mainStore.SaveFlow(ctx, &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(`{"query":"safe_placeholder"}`),
	}); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}
	if err := mainStore.SaveFlow(ctx, &flow.Flow{
		StreamID:   fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now(),
		StatusCode: 200,
		Body:       []byte("ok"),
	}); err != nil {
		t.Fatalf("AppendMessage(recv): %v", err)
	}

	// Start fuzz with payloads that include destructive and safe values.
	// The fuzz job should start successfully because the template is safe.
	result, err := env.cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "fuzz",
		Arguments: map[string]any{
			"action": "fuzz",
			"params": map[string]any{
				"flow_id":     fl.ID,
				"attack_type": "sequential",
				"positions": []any{
					map[string]any{
						"id":          "pos-1",
						"location":    "body_json",
						"json_path":   "$.query",
						"payload_set": "mixed",
					},
				},
				"payload_sets": map[string]any{
					"mixed": map[string]any{
						"type":   "wordlist",
						"values": []any{"safe_value", "DROP TABLE users;", "another_safe"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool(fuzz): %v", err)
	}
	// The fuzz job should start (template is safe), not be rejected.
	if result.IsError {
		tc := result.Content[0].(*gomcp.TextContent)
		t.Fatalf("expected fuzz job to start, got error: %s", tc.Text)
	}

	// Parse the async result to get fuzz_id and verify the job started.
	var asyncResult fuzzer.AsyncResult
	tc := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(tc.Text), &asyncResult); err != nil {
		t.Fatalf("unmarshal fuzz result: %v", err)
	}
	if asyncResult.FuzzID == "" {
		t.Fatal("fuzz_id is empty — fuzz job did not start")
	}
	if asyncResult.Status != "running" {
		t.Errorf("fuzz status = %q, want %q", asyncResult.Status, "running")
	}
	// The job started with 3 payloads (safe_value, DROP TABLE users;, another_safe).
	// The destructive payload should be skipped at execution time by the
	// SafetyInputChecker, but the job itself should not be rejected.
	if asyncResult.TotalRequests != 3 {
		t.Errorf("total_requests = %d, want 3", asyncResult.TotalRequests)
	}

	// Poll the fuzz job until it completes and verify the skipped (error) count.
	// The destructive payload "DROP TABLE users;" should be skipped, resulting
	// in error_count >= 1.
	var jobResult queryFuzzJobsResult
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobResult = callTool[queryFuzzJobsResult](t, env.cs, "query", map[string]any{
			"resource": "fuzz_jobs",
			"filter": map[string]any{
				"status": "completed",
			},
		})
		if jobResult.Count > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if jobResult.Count == 0 {
		t.Fatal("fuzz job not found with status=completed after polling")
	}
	// Find the job matching our fuzz ID.
	var foundJob *queryFuzzJobEntry
	for i := range jobResult.Jobs {
		if jobResult.Jobs[i].ID == asyncResult.FuzzID {
			foundJob = &jobResult.Jobs[i]
			break
		}
	}
	if foundJob == nil {
		t.Fatalf("fuzz job %s not found in completed jobs", asyncResult.FuzzID)
	}
	if foundJob.ErrorCount < 1 {
		t.Errorf("error_count = %d, want >= 1 (destructive payload should be skipped)", foundJob.ErrorCount)
	}
}

// TestSafetyFilter_MCP_InterceptModifyAndForwardBlock verifies that the intercept
// tool's modify_and_forward action blocks destructive request mutations.
func TestSafetyFilter_MCP_InterceptModifyAndForwardBlock(t *testing.T) {
	engine := newDefaultSafetyEngine(t)
	queue := intercept.NewQueue()
	env := setupSafetyFilterEnv(t, engine,
		WithInterceptQueue(queue),
	)

	// modify_and_forward with destructive body should be blocked by safety filter.
	callToolExpectError(t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id":  "test-intercept-id",
			"override_body": "DROP TABLE orders;",
		},
	})
}

// --- Config Tests ---

// TestSafetyFilter_Config_PresetAndCustomRules verifies that presets and custom rules
// are loaded correctly via the safety engine configuration.
func TestSafetyFilter_Config_PresetAndCustomRules(t *testing.T) {
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{Preset: "destructive-sql", Action: "block"},
			{
				ID:      "custom-xss",
				Name:    "XSS script tag",
				Pattern: `(?i)<script[^>]*>`,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	rules := engine.InputRules()
	if len(rules) == 0 {
		t.Fatal("expected input rules, got none")
	}

	// Verify preset rules are present.
	hasDropRule := false
	hasCustomXSS := false
	for _, r := range rules {
		if r.ID == "destructive-sql:drop" {
			hasDropRule = true
		}
		if r.ID == "custom-xss" {
			hasCustomXSS = true
			if r.Category != "custom" {
				t.Errorf("custom rule category = %q, want %q", r.Category, "custom")
			}
		}
	}
	if !hasDropRule {
		t.Error("preset destructive-sql:drop rule not found")
	}
	if !hasCustomXSS {
		t.Error("custom-xss rule not found")
	}

	// Verify custom XSS rule blocks.
	v := engine.CheckInput([]byte("<script>alert(1)</script>"), "", nil)
	if v == nil {
		t.Error("expected XSS violation, got nil")
	}
	if v != nil && v.RuleID != "custom-xss" {
		t.Errorf("violation rule_id = %q, want %q", v.RuleID, "custom-xss")
	}
}

// TestSafetyFilter_MCP_GetSafetyFilter verifies the get_safety_filter action
// returns the current rules.
func TestSafetyFilter_MCP_GetSafetyFilter(t *testing.T) {
	engine := newDefaultSafetyEngine(t)
	env := setupSafetyFilterEnv(t, engine)

	result := callTool[getSafetyFilterResult](t, env.cs, "security", map[string]any{
		"action": "get_safety_filter",
		"params": map[string]any{},
	})

	if !result.Enabled {
		t.Error("get_safety_filter enabled = false, want true")
	}
	if !result.Immutable {
		t.Error("get_safety_filter immutable = false, want true")
	}
	if len(result.InputRules) == 0 {
		t.Fatal("get_safety_filter input_rules is empty")
	}

	// Verify both presets' rules are present.
	categories := make(map[string]bool)
	for _, r := range result.InputRules {
		categories[r.Category] = true
	}
	if !categories["destructive-sql"] {
		t.Error("missing destructive-sql category rules")
	}
	if !categories["destructive-os-command"] {
		t.Error("missing destructive-os-command category rules")
	}
}

// TestSafetyFilter_MCP_GetSafetyFilter_Disabled verifies the get_safety_filter
// action returns enabled=false when no engine is configured.
func TestSafetyFilter_MCP_GetSafetyFilter_Disabled(t *testing.T) {
	env := setupSafetyFilterEnv(t, nil)

	result := callTool[getSafetyFilterResult](t, env.cs, "security", map[string]any{
		"action": "get_safety_filter",
		"params": map[string]any{},
	})

	if result.Enabled {
		t.Error("get_safety_filter enabled = true, want false (no engine)")
	}
	if len(result.InputRules) != 0 {
		t.Errorf("get_safety_filter input_rules count = %d, want 0", len(result.InputRules))
	}
}

// TestSafetyFilter_Config_CustomRegexPattern verifies that user-defined regex
// patterns are correctly applied by the safety engine.
func TestSafetyFilter_Config_CustomRegexPattern(t *testing.T) {
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "custom-secret-token",
				Name:    "Blocks secret token pattern",
				Pattern: `SECRET_TOKEN_[A-Z0-9]+`,
				Targets: []string{"body", "url"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name    string
		body    string
		url     string
		blocked bool
	}{
		{"matches in body", "data with SECRET_TOKEN_ABC123 inside", "", true},
		{"matches in URL", "", "http://example.com/api?token=SECRET_TOKEN_XYZ789", true},
		{"no match", "normal data", "http://example.com/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := engine.CheckInput([]byte(tt.body), tt.url, nil)
			if tt.blocked && v == nil {
				t.Errorf("expected violation, got nil")
			}
			if !tt.blocked && v != nil {
				t.Errorf("expected no violation, got rule_id=%q", v.RuleID)
			}
		})
	}
}

// --- Helpers ---

// newSafetyTestStore creates a new SQLite store for testing.
func newSafetyTestStore(t *testing.T) flow.Store {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "safety_test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// newFuzzStore creates a temporary fuzz store for testing.
func newFuzzStore(t *testing.T) flow.FuzzStore {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "fuzz_integration.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore(fuzz): %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// setupSafetyFilterEnvWithStore creates a fully-wired MCP test environment with
// a pre-existing store. This is used when the store must be shared with other
// components (e.g., fuzz engine).
func setupSafetyFilterEnvWithStore(t *testing.T, store flow.Store, engine *safety.Engine, opts ...ServerOption) *testEnv {
	t.Helper()
	ctx := context.Background()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	httpHandler := protohttp.NewHandler(store, issuer, testutil.DiscardLogger())
	if engine != nil {
		httpHandler.SetSafetyEngine(engine)
	}
	detector := protocol.NewDetector(httpHandler)
	manager := proxy.NewManager(detector, testutil.DiscardLogger())
	t.Cleanup(func() { manager.Stop(context.Background()) })

	allOpts := []ServerOption{
		WithSafetyEngine(engine),
		WithSafetyEngineSetter(httpHandler),
	}
	allOpts = append(allOpts, opts...)

	mcpServer := NewServer(ctx, ca, store, manager, allOpts...)

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "safety-integration-test",
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

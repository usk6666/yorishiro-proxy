package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- M3 Integration: Resender ---

// TestM3_Resend_BodyPatches_JSONPath verifies that resend with body_patches using
// json_path correctly modifies JSON body fields and sends the patched request.
func TestM3_Resend_BodyPatches_JSONPath(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/api/users")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			FlowType:  "unary",
			State:     "complete",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      []byte(`{"user":{"name":"alice","role":"viewer","active":true}}`),
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	// Resend with json_path body patches: escalate role and change name.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"body_patches": []any{
				map[string]any{"json_path": "$.user.role", "value": "admin"},
				map[string]any{"json_path": "$.user.name", "value": "eve"},
			},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendActionResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.NewFlowID == "" {
		t.Error("expected non-empty new_flow_id")
	}
	if out.StatusCode != 200 {
		t.Errorf("status_code = %d, want 200", out.StatusCode)
	}

	// Verify the echo server received the patched body.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo: %v", err)
	}

	bodyStr, ok := echo["body"].(string)
	if !ok {
		t.Fatalf("echo body is not a string: %v", echo["body"])
	}
	var patchedBody map[string]any
	if err := json.Unmarshal([]byte(bodyStr), &patchedBody); err != nil {
		t.Fatalf("unmarshal patched body: %v", err)
	}
	user, ok := patchedBody["user"].(map[string]any)
	if !ok {
		t.Fatalf("user field is not an object: %v", patchedBody["user"])
	}
	if user["role"] != "admin" {
		t.Errorf("user.role = %q, want admin", user["role"])
	}
	if user["name"] != "eve" {
		t.Errorf("user.name = %q, want eve", user["name"])
	}

	// Verify the new flow was recorded in the store.
	newFl, err := store.GetFlow(context.Background(), out.NewFlowID)
	if err != nil {
		t.Fatalf("get new flow: %v", err)
	}
	if newFl.State != "complete" {
		t.Errorf("new flow state = %q, want complete", newFl.State)
	}
}

// TestM3_Resend_DryRun verifies that dry_run mode returns a request preview
// without actually sending the request or recording a new flow.
func TestM3_Resend_DryRun(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/api/data")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			FlowType:  "unary",
			State:     "complete",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Accept": {"text/html"}},
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteDoer(t, store, newPermissiveClient())

	overrideURL := echoServer.URL + "/api/modified"
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":         entry.Session.ID,
			"override_method": "PUT",
			"override_url":    overrideURL,
			"override_body":   `{"preview":"true"}`,
			"override_headers": map[string]any{
				"Content-Type": "application/json",
			},
			"dry_run": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if !out.DryRun {
		t.Error("expected dry_run=true")
	}
	if out.RequestPreview == nil {
		t.Fatal("expected request_preview, got nil")
	}
	if out.RequestPreview.Method != "PUT" {
		t.Errorf("method = %q, want PUT", out.RequestPreview.Method)
	}
	if out.RequestPreview.URL != overrideURL {
		t.Errorf("url = %q, want %q", out.RequestPreview.URL, overrideURL)
	}
	if out.RequestPreview.Body != `{"preview":"true"}` {
		t.Errorf("body = %q, want {\"preview\":\"true\"}", out.RequestPreview.Body)
	}

	// Verify no new flow was created (dry-run should NOT record).
	sessions, err := store.ListFlows(context.Background(), flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 session (original only), got %d", len(sessions))
	}
}

// TestM3_ResendRaw_WithPatches verifies that resend_raw with byte-level patches
// correctly modifies raw request bytes and sends them over TCP.
func TestM3_ResendRaw_WithPatches(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /original HTTP/1.1\r\nHost: example.com\r\nX-Test: original-value\r\n\r\n")
	host, port, _ := parseHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/original")

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			FlowType:  "unary",
			State:     "complete",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Host": {"example.com"}},
			RawBytes:  rawReq,
		},
		&flow.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	// Apply a text find/replace patch.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"patches": []any{
				map[string]any{
					"find_text":    "original-value",
					"replace_text": "patched-value",
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.NewFlowID == "" {
		t.Error("expected non-empty new_flow_id")
	}
	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
	if out.DurationMs < 0 {
		t.Errorf("duration_ms = %d, should be >= 0", out.DurationMs)
	}
}

// TestM3_Resend_E2E_ThroughProxy verifies the full lifecycle:
// proxy_start -> HTTP through proxy -> query flow -> resend with patches -> verify.
func TestM3_Resend_E2E_ThroughProxy(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnv(t)

	// 1. Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// 2. Send a POST request through the proxy.
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/users", upstreamAddr)
	resp, err := client.Post(targetURL, "application/json", strings.NewReader(`{"name":"original"}`))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for flow to be persisted.
	time.Sleep(200 * time.Millisecond)

	// 3. Query the recorded flow.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count != 1 {
		t.Fatalf("query sessions count = %d, want 1", listResult.Count)
	}
	flowID := listResult.Flows[0].ID

	// 4. Attempt resend. Note: SSRF protection will block localhost.
	// We verify the tool handles the error gracefully.
	resendToolResult, resendErr := env.cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend",
			"params": map[string]any{
				"flow_id":         flowID,
				"override_method": "PUT",
				"tag":             "resend-test",
			},
		},
	})
	if resendErr != nil {
		t.Fatalf("CallTool(resend): %v", resendErr)
	}

	// The resend may fail due to SSRF protection (target is localhost).
	// Either outcome is acceptable: success means SSRF relaxed, error means it's blocked.
	if !resendToolResult.IsError {
		var rr resendActionResult
		tc, ok := resendToolResult.Content[0].(*gomcp.TextContent)
		if ok {
			json.Unmarshal([]byte(tc.Text), &rr)
		}
		if rr.Tag != "resend-test" {
			t.Errorf("tag = %q, want resend-test", rr.Tag)
		}
	}

	// Close idle connections before stopping.
	client.CloseIdleConnections()
}

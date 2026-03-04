package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- Resend action (new name) tests ---

func TestExecute_Resend_Success(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/api/test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
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
			Body:      []byte(`{"key":"value"}`),
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

	// Use "resend" action name (not "replay").
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendResult
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
}

func TestExecute_Resend_ResendRaw_DeprecatedAlias(t *testing.T) {
	// Verify that "resend_raw" also works (alongside "replay_raw" backward compat).
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := parseHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
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

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":  entry.Session.ID,
			"target_addr": addr,
		},
	})
	if result.IsError {
		t.Fatalf("expected success with resend_raw, got error: %v", result.Content)
	}
}

// --- Header mutation tests ---

func TestExecute_Resend_HeaderMutationOrder(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/header-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers: map[string][]string{
				"X-Remove":   {"should-be-removed"},
				"X-Override": {"original-value"},
				"X-Keep":     {"kept-value"},
			},
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

	// Test the mutation order: remove -> override -> add.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"remove_headers": []any{"X-Remove"},
			"override_headers": map[string]any{
				"X-Override": "overridden-value",
			},
			"add_headers": map[string]any{
				"X-Added": "added-value",
				"X-Keep":  "appended-value",
			},
			"dry_run": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if !out.DryRun {
		t.Error("expected dry_run=true")
	}

	headers := out.RequestPreview.Headers

	// X-Remove should be gone.
	if _, exists := headers["X-Remove"]; exists {
		t.Error("X-Remove header should have been removed")
	}

	// X-Override should have the overridden value.
	if vals, exists := headers["X-Override"]; !exists || len(vals) == 0 || vals[0] != "overridden-value" {
		t.Errorf("X-Override = %v, want [overridden-value]", vals)
	}

	// X-Keep should have both original and appended values.
	if vals, exists := headers["X-Keep"]; !exists || len(vals) != 2 {
		t.Errorf("X-Keep = %v, want [kept-value, appended-value]", vals)
	} else {
		if vals[0] != "kept-value" {
			t.Errorf("X-Keep[0] = %q, want kept-value", vals[0])
		}
		if vals[1] != "appended-value" {
			t.Errorf("X-Keep[1] = %q, want appended-value", vals[1])
		}
	}

	// X-Added should be present.
	if vals, exists := headers["X-Added"]; !exists || len(vals) == 0 || vals[0] != "added-value" {
		t.Errorf("X-Added = %v, want [added-value]", vals)
	}
}

// --- Body mutation tests ---

func TestExecute_Resend_OverrideBody(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/body-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
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
			Body:      []byte(`{"original":"body"}`),
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

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":    entry.Session.ID,
			"override_body": `{"replaced":"body"}`,
			"dry_run":       true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.RequestPreview.Body != `{"replaced":"body"}` {
		t.Errorf("body = %q, want {\"replaced\":\"body\"}", out.RequestPreview.Body)
	}
}

func TestExecute_Resend_OverrideBodyBase64(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/body-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{},
			Body:      []byte("original"),
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

	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
	b64 := base64.StdEncoding.EncodeToString(binaryData)

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":           entry.Session.ID,
			"override_body_base64": b64,
			"dry_run":              true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Binary body should be base64-encoded in the preview.
	if out.RequestPreview.BodyEncoding != "base64" {
		t.Errorf("body_encoding = %q, want base64", out.RequestPreview.BodyEncoding)
	}
}

func TestExecute_Resend_OverrideBodyBase64_Invalid(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/body-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{},
			Body:      []byte("original"),
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

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":           entry.Session.ID,
			"override_body_base64": "not-valid-base64!!!",
			"dry_run":              true,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid base64")
	}
}

func TestExecute_Resend_BodyPatches_OverrideBodyTakesPriority(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/priority-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{},
			Body:      []byte(`{"name":"original"}`),
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

	// When both override_body and body_patches are set, override_body wins.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":    entry.Session.ID,
			"override_body": `{"full":"replace"}`,
			"body_patches": []any{
				map[string]any{"json_path": "$.name", "value": "patched"},
			},
			"dry_run": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// override_body should win.
	if out.RequestPreview.Body != `{"full":"replace"}` {
		t.Errorf("body = %q, want {\"full\":\"replace\"}", out.RequestPreview.Body)
	}
}

func TestExecute_Resend_BodyPatches_JSONPath(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/patch-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
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
			Body:      []byte(`{"user":{"name":"original","role":"viewer"}}`),
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

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"body_patches": []any{
				map[string]any{"json_path": "$.user.name", "value": "injected"},
				map[string]any{"json_path": "$.user.role", "value": "admin"},
			},
			"dry_run": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(out.RequestPreview.Body), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}

	user := body["user"].(map[string]any)
	if user["name"] != "injected" {
		t.Errorf("user.name = %q, want injected", user["name"])
	}
	if user["role"] != "admin" {
		t.Errorf("user.role = %q, want admin", user["role"])
	}
}

func TestExecute_Resend_BodyPatches_Regex(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/regex-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
			Body:      []byte("csrf_token=abc123&name=test&role=user"),
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

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"body_patches": []any{
				map[string]any{"regex": "csrf_token=[^&]+", "replace": "csrf_token=newvalue"},
				map[string]any{"regex": "role=user", "replace": "role=admin"},
			},
			"dry_run": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	want := "csrf_token=newvalue&name=test&role=admin"
	if out.RequestPreview.Body != want {
		t.Errorf("body = %q, want %q", out.RequestPreview.Body, want)
	}
}

// --- Dry-run tests ---

func TestExecute_Resend_DryRun(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/dry-run")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
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

	overrideURL := echoServer.URL + "/new-path"
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":      entry.Session.ID,
			"override_method": "POST",
			"override_url":    overrideURL,
			"override_body":   "dry-run-body",
			"dry_run":         true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDryRunResult
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
	if out.RequestPreview.Method != "POST" {
		t.Errorf("method = %q, want POST", out.RequestPreview.Method)
	}
	if out.RequestPreview.URL != overrideURL {
		t.Errorf("url = %q, want %q", out.RequestPreview.URL, overrideURL)
	}
	if out.RequestPreview.Body != "dry-run-body" {
		t.Errorf("body = %q, want dry-run-body", out.RequestPreview.Body)
	}
	if out.RequestPreview.BodyEncoding != "text" {
		t.Errorf("body_encoding = %q, want text", out.RequestPreview.BodyEncoding)
	}

	// Verify no new flow was created (dry-run should NOT record).
	sessions, err := store.ListFlows(context.Background(), flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	// Should only have the original flow.
	if len(sessions) != 1 {
		t.Errorf("expected 1 session (original only), got %d", len(sessions))
	}
}

// --- Tag tests ---

func TestExecute_Resend_Tag(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/tag-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
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

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"tag":        "auth-bypass-test-01",
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.Tag != "auth-bypass-test-01" {
		t.Errorf("tag = %q, want auth-bypass-test-01", out.Tag)
	}

	// Verify the tag was stored on the flow.
	newFl, err := store.GetFlow(context.Background(), out.NewFlowID)
	if err != nil {
		t.Fatalf("get new flow: %v", err)
	}
	if newFl.Tags == nil || newFl.Tags["tag"] != "auth-bypass-test-01" {
		t.Errorf("flow tags = %v, want tag=auth-bypass-test-01", newFl.Tags)
	}
}

// --- override_host validation tests ---

func TestExecute_Resend_OverrideHost_Invalid(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/host-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
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

	tests := []struct {
		name string
		host string
	}{
		{name: "no port", host: "example.com"},
		{name: "empty host", host: ":8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := executeCallTool(t, cs, map[string]any{
				"action": "resend",
				"params": map[string]any{
					"flow_id":    entry.Session.ID,
					"override_host": tt.host,
				},
			})
			if !result.IsError {
				t.Fatalf("expected error for override_host %q", tt.host)
			}
		})
	}
}

// --- buildResendHeaders unit tests ---

func TestBuildResendHeaders(t *testing.T) {
	original := map[string][]string{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer old-token"},
		"X-Remove-Me":   {"value"},
		"X-Multi":       {"val1"},
	}

	params := executeParams{
		RemoveHeaders:   []string{"X-Remove-Me"},
		OverrideHeaders: map[string]string{"Authorization": "Bearer new-token"},
		AddHeaders:      map[string]string{"X-Multi": "val2", "X-New": "new-value"},
	}

	got := buildResendHeaders(original, params)

	// X-Remove-Me should be present with an empty slice to suppress Go's defaults.
	if vals, exists := got["X-Remove-Me"]; !exists {
		t.Error("X-Remove-Me should be present with empty slice")
	} else if len(vals) != 0 {
		t.Errorf("X-Remove-Me = %v, want empty slice", vals)
	}

	// Authorization should be overridden.
	if v := got["Authorization"]; len(v) != 1 || v[0] != "Bearer new-token" {
		t.Errorf("Authorization = %v, want [Bearer new-token]", v)
	}

	// Content-Type should be unchanged.
	if v := got["Content-Type"]; len(v) != 1 || v[0] != "application/json" {
		t.Errorf("Content-Type = %v, want [application/json]", v)
	}

	// X-Multi should have both values.
	if v := got["X-Multi"]; len(v) != 2 || v[0] != "val1" || v[1] != "val2" {
		t.Errorf("X-Multi = %v, want [val1, val2]", v)
	}

	// X-New should be added.
	if v := got["X-New"]; len(v) != 1 || v[0] != "new-value" {
		t.Errorf("X-New = %v, want [new-value]", v)
	}
}

func TestBuildResendHeaders_CaseInsensitiveRemove(t *testing.T) {
	original := map[string][]string{
		"Content-Type": {"application/json"},
	}

	params := executeParams{
		RemoveHeaders: []string{"content-type"},
	}

	got := buildResendHeaders(original, params)

	// Content-Type should be present with empty slice even though the case doesn't match.
	if vals, exists := got["Content-Type"]; !exists {
		t.Error("Content-Type should be present with empty slice (case-insensitive)")
	} else if len(vals) != 0 {
		t.Errorf("Content-Type = %v, want empty slice", vals)
	}
}

// --- buildResendBody unit tests ---

func TestBuildResendBody(t *testing.T) {
	originalBody := []byte(`{"original":"body"}`)

	t.Run("no mutations returns original", func(t *testing.T) {
		got, err := buildResendBody(originalBody, executeParams{})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if string(got) != string(originalBody) {
			t.Errorf("got %q, want %q", string(got), string(originalBody))
		}
	})

	t.Run("override_body replaces entirely", func(t *testing.T) {
		body := "replaced"
		got, err := buildResendBody(originalBody, executeParams{OverrideBody: &body})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if string(got) != "replaced" {
			t.Errorf("got %q, want replaced", string(got))
		}
	})

	t.Run("override_body_base64 replaces entirely", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("binary-data"))
		got, err := buildResendBody(originalBody, executeParams{OverrideBodyBase64: &encoded})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if string(got) != "binary-data" {
			t.Errorf("got %q, want binary-data", string(got))
		}
	})

	t.Run("override_body takes priority over patches", func(t *testing.T) {
		body := "override wins"
		got, err := buildResendBody(originalBody, executeParams{
			OverrideBody: &body,
			BodyPatches:  []BodyPatch{{JSONPath: "$.original", Value: "patched"}},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if string(got) != "override wins" {
			t.Errorf("got %q, want override wins", string(got))
		}
	})

	t.Run("body_patches applied to original", func(t *testing.T) {
		got, err := buildResendBody(originalBody, executeParams{
			BodyPatches: []BodyPatch{{JSONPath: "$.original", Value: "patched"}},
		})
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		var result map[string]any
		if err := json.Unmarshal(got, &result); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if result["original"] != "patched" {
			t.Errorf("original = %q, want patched", result["original"])
		}
	})
}

// --- validateOverrideHost unit tests ---

func TestValidateOverrideHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{name: "valid host:port", host: "example.com:8443", wantErr: false},
		{name: "valid IP:port", host: "10.0.0.1:443", wantErr: false},
		{name: "no port", host: "example.com", wantErr: true},
		{name: "empty host", host: ":8080", wantErr: true},
		{name: "empty string", host: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOverrideHost(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateOverrideHost(%q) error = %v, wantErr %v", tt.host, err, tt.wantErr)
			}
		})
	}
}

// --- Actual HTTP send tests (not dry-run) ---

func TestExecute_Resend_WithBodyPatches_ActuallySent(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/actual-send")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
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
			Body:      []byte(`{"user":"original"}`),
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

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"body_patches": []any{
				map[string]any{"json_path": "$.user", "value": "modified"},
			},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify the echo server received the patched body.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo: %v", err)
	}

	// The echo body should be the patched JSON.
	bodyStr, ok := echo["body"].(string)
	if !ok {
		t.Fatalf("echo body is not a string: %v", echo["body"])
	}
	var patchedBody map[string]any
	if err := json.Unmarshal([]byte(bodyStr), &patchedBody); err != nil {
		t.Fatalf("unmarshal patched body: %v", err)
	}
	if patchedBody["user"] != "modified" {
		t.Errorf("user = %q, want modified", patchedBody["user"])
	}
}

// TestExecute_Resend_RemoveHeaders_SuppressesGoDefaults verifies that remove_headers
// completely suppresses headers including Go's auto-added defaults (e.g., User-Agent).
// This is the regression test for USK-95.
func TestExecute_Resend_RemoveHeaders_SuppressesGoDefaults(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/remove-headers-test")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers: map[string][]string{
				"User-Agent": {"curl/7.88.1"},
				"Accept":     {"*/*"},
			},
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

	// Remove User-Agent header and actually send the request.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"remove_headers": []any{"User-Agent"},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Parse the echo server response to check actual headers received.
	var echo map[string]any
	if err := json.Unmarshal([]byte(out.ResponseBody), &echo); err != nil {
		t.Fatalf("unmarshal echo: %v", err)
	}

	// The echo server returns headers as map[string][]string.
	echoHeaders, ok := echo["headers"].(map[string]any)
	if !ok {
		t.Fatalf("echo headers is not a map: %v", echo["headers"])
	}

	// User-Agent should NOT be present at all (not even Go's default "Go-http-client/1.1").
	if ua, exists := echoHeaders["User-Agent"]; exists {
		t.Errorf("User-Agent header should be absent, but got: %v", ua)
	}

	// Accept header should still be present since it was not removed.
	if _, exists := echoHeaders["Accept"]; !exists {
		t.Error("Accept header should still be present")
	}
}

// TestExecute_Resend_RemoveHeaders_DryRun verifies that removed headers do not
// appear in the dry-run preview.
func TestExecute_Resend_RemoveHeaders_DryRun(t *testing.T) {
	store := newTestStore(t)
	echoServer := newEchoServer(t)

	u, _ := url.Parse(echoServer.URL + "/remove-headers-dryrun")
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers: map[string][]string{
				"User-Agent": {"curl/7.88.1"},
				"Accept":     {"*/*"},
			},
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

	result := executeCallTool(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"remove_headers": []any{"User-Agent"},
			"dry_run":        true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// User-Agent should not appear in the dry-run preview.
	if _, exists := out.RequestPreview.Headers["User-Agent"]; exists {
		t.Error("User-Agent should not appear in dry-run preview when removed")
	}

	// Accept should still be present.
	if _, exists := out.RequestPreview.Headers["Accept"]; !exists {
		t.Error("Accept header should still be present in dry-run preview")
	}
}

// TestBuildResendHeaders_RemoveHeaders_EmptySlice verifies that removed headers
// are set to empty slices (not deleted) to suppress Go's net/http defaults.
func TestBuildResendHeaders_RemoveHeaders_EmptySlice(t *testing.T) {
	original := map[string][]string{
		"User-Agent":   {"curl/7.88.1"},
		"Content-Type": {"application/json"},
	}

	params := executeParams{
		RemoveHeaders: []string{"User-Agent"},
	}

	got := buildResendHeaders(original, params)

	// User-Agent should be present with an empty slice, not deleted.
	if vals, exists := got["User-Agent"]; !exists {
		t.Error("User-Agent should be present with empty slice")
	} else if len(vals) != 0 {
		t.Errorf("User-Agent = %v, want empty slice", vals)
	}

	// Content-Type should be unchanged.
	if v := got["Content-Type"]; len(v) != 1 || v[0] != "application/json" {
		t.Errorf("Content-Type = %v, want [application/json]", v)
	}
}

// parseHostPort is a helper to split host:port.
func parseHostPort(addr string) (string, string, error) {
	host, port, err := splitHostPort(addr)
	return host, port, err
}

func splitHostPort(addr string) (string, string, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", nil
}

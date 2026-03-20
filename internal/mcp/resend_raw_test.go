package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// --- resend_raw with patches tests ---

func TestExecute_ResendRaw_OffsetPatch(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	// Raw request: "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
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

	// Patch: overwrite "GET " with "PUT " at offset 0
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"patches": []any{
				map[string]any{
					"offset":      0,
					"data_base64": base64.StdEncoding.EncodeToString([]byte("PUT ")),
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

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
	if out.NewFlowID == "" {
		t.Error("expected non-empty new_flow_id")
	}
}

func TestExecute_ResendRaw_TextFindReplace(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
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
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"patches": []any{
				map[string]any{
					"find_text":    "example.com",
					"replace_text": "target.com",
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

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
}

func TestExecute_ResendRaw_BinaryFindReplace(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
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
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"patches": []any{
				map[string]any{
					"find_base64":    base64.StdEncoding.EncodeToString([]byte("/test")),
					"replace_base64": base64.StdEncoding.EncodeToString([]byte("/new")),
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

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
}

// --- dry_run tests ---

func TestExecute_ResendRaw_DryRun_NoPatches(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

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
			"flow_id": entry.Session.ID,
			"dry_run": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if !out.DryRun {
		t.Error("expected dry_run=true")
	}
	if out.RawPreview == nil {
		t.Fatal("expected raw_preview, got nil")
	}
	if out.RawPreview.DataSize != len(rawReq) {
		t.Errorf("data_size = %d, want %d", out.RawPreview.DataSize, len(rawReq))
	}
	if out.RawPreview.PatchesApplied != 0 {
		t.Errorf("patches_applied = %d, want 0", out.RawPreview.PatchesApplied)
	}

	// Decode and verify the raw data.
	decoded, err := base64.StdEncoding.DecodeString(out.RawPreview.DataBase64)
	if err != nil {
		t.Fatalf("decode data_base64: %v", err)
	}
	if string(decoded) != string(rawReq) {
		t.Errorf("data = %q, want %q", string(decoded), string(rawReq))
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

func TestExecute_ResendRaw_DryRun_WithPatches(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

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
			"flow_id": entry.Session.ID,
			"dry_run": true,
			"patches": []any{
				map[string]any{
					"find_text":    "example.com",
					"replace_text": "target.com",
				},
				map[string]any{
					"find_text":    "/test",
					"replace_text": "/new-path",
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if !out.DryRun {
		t.Error("expected dry_run=true")
	}
	if out.RawPreview.PatchesApplied != 2 {
		t.Errorf("patches_applied = %d, want 2", out.RawPreview.PatchesApplied)
	}

	// Decode and verify the patched data.
	decoded, err := base64.StdEncoding.DecodeString(out.RawPreview.DataBase64)
	if err != nil {
		t.Fatalf("decode data_base64: %v", err)
	}
	want := "GET /new-path HTTP/1.1\r\nHost: target.com\r\n\r\n"
	if string(decoded) != want {
		t.Errorf("patched data = %q, want %q", string(decoded), want)
	}

	// Verify no new flow was created.
	sessions, err := store.ListFlows(context.Background(), flow.ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 session (original only), got %d", len(sessions))
	}
}

func TestExecute_ResendRaw_DryRun_WithOverrideRawBase64(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

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

	replacement := []byte("POST /replaced HTTP/1.1\r\n\r\n")
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":             entry.Session.ID,
			"override_raw_base64": base64.StdEncoding.EncodeToString(replacement),
			"dry_run":             true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if !out.DryRun {
		t.Error("expected dry_run=true")
	}
	if out.RawPreview.PatchesApplied != 0 {
		t.Errorf("patches_applied = %d, want 0 (override replaces entirely)", out.RawPreview.PatchesApplied)
	}
	if out.RawPreview.DataSize != len(replacement) {
		t.Errorf("data_size = %d, want %d", out.RawPreview.DataSize, len(replacement))
	}

	decoded, err := base64.StdEncoding.DecodeString(out.RawPreview.DataBase64)
	if err != nil {
		t.Fatalf("decode data_base64: %v", err)
	}
	if string(decoded) != string(replacement) {
		t.Errorf("data = %q, want %q", string(decoded), string(replacement))
	}
}

// --- override_raw_base64 tests ---

func TestExecute_ResendRaw_OverrideRawBase64_NoOriginalRawBytes(t *testing.T) {
	t.Parallel()
	// Start an HTTP/2 echo server (no TLS).
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	store := newTestStore(t)
	ctx := context.Background()

	u, _ := url.Parse("https://" + echoAddr + "/test")

	// Create a flow with NO RawBytes — the test verifies that
	// override_raw_base64 can supply raw bytes when the original flow has none.
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       u,
		Headers:   map[string][]string{},
		RawBytes:  nil, // No raw bytes stored
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	recvMsg := &flow.Message{
		FlowID:     fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    map[string][]string{},
		Body:       []byte("ok"),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Build override H2 HEADERS frame bytes.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/test"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	overrideB64 := base64.StdEncoding.EncodeToString(rawBuf.Bytes())

	// Set up MCP server with a testDialer (no TLS).
	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	// Should succeed because override_raw_base64 provides the raw H2 frame bytes.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id":             fl.ID,
				"target_addr":         echoAddr,
				"use_tls":             false,
				"override_raw_base64": overrideB64,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		var errText string
		for _, c := range result.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				errText = tc.Text
			}
		}
		t.Fatalf("expected success with override_raw_base64, got error: %s", errText)
	}

	var out resendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
	if out.NewFlowID == "" {
		t.Error("expected non-empty new_flow_id")
	}
}

func TestExecute_ResendRaw_OverrideRawBase64_NoOriginalRawBytes_DryRun(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	u, _ := url.Parse("http://example.com/test")

	// Create a flow with NO RawBytes.
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/2",
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
			RawBytes:  nil,
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

	replacement := []byte("POST /replaced HTTP/1.1\r\n\r\n")
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":             entry.Session.ID,
			"override_raw_base64": base64.StdEncoding.EncodeToString(replacement),
			"dry_run":             true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success with override_raw_base64 dry_run, got error: %v", result.Content)
	}

	var out resendRawDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if !out.DryRun {
		t.Error("expected dry_run=true")
	}
	if out.RawPreview.DataSize != len(replacement) {
		t.Errorf("data_size = %d, want %d", out.RawPreview.DataSize, len(replacement))
	}

	decoded, err := base64.StdEncoding.DecodeString(out.RawPreview.DataBase64)
	if err != nil {
		t.Fatalf("decode data_base64: %v", err)
	}
	if string(decoded) != string(replacement) {
		t.Errorf("data = %q, want %q", string(decoded), string(replacement))
	}
}

func TestExecute_ResendRaw_NoRawBytesNoOverride_Error(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	u, _ := url.Parse("http://example.com/test")

	// Create a flow with NO RawBytes and no override.
	entry := saveTestEntry(t, store,
		&flow.Flow{
			Protocol:  "HTTP/2",
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
			RawBytes:  nil,
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

	// Without override_raw_base64, should still fail with no raw bytes error.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"dry_run": true,
		},
	})
	if !result.IsError {
		t.Fatal("expected error when no raw bytes and no override_raw_base64")
	}
}

func TestExecute_ResendRaw_OverrideRawBase64(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /original HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/original")

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

	replacement := []byte("GET /replaced HTTP/1.1\r\nHost: target.com\r\n\r\n")
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":             entry.Session.ID,
			"target_addr":         addr,
			"override_raw_base64": base64.StdEncoding.EncodeToString(replacement),
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

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
	if out.NewFlowID == "" {
		t.Error("expected non-empty new_flow_id")
	}
}

func TestExecute_ResendRaw_OverrideRawBase64_IgnoresPatches(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

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

	replacement := []byte("REPLACED")
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":             entry.Session.ID,
			"override_raw_base64": base64.StdEncoding.EncodeToString(replacement),
			"patches": []any{
				map[string]any{
					"find_text":    "example.com",
					"replace_text": "patched.com",
				},
			},
			"dry_run": true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out resendRawDryRunResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// override_raw_base64 should win over patches.
	decoded, err := base64.StdEncoding.DecodeString(out.RawPreview.DataBase64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != "REPLACED" {
		t.Errorf("got %q, want REPLACED (override should take priority)", string(decoded))
	}
}

// --- Tag tests ---

func TestExecute_ResendRaw_Tag(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
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
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"tag":         "raw-test-01",
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

	if out.Tag != "raw-test-01" {
		t.Errorf("tag = %q, want raw-test-01", out.Tag)
	}

	// Verify the tag was stored on the flow.
	newFl, err := store.GetFlow(context.Background(), out.NewFlowID)
	if err != nil {
		t.Fatalf("get new flow: %v", err)
	}
	if newFl.Tags == nil || newFl.Tags["tag"] != "raw-test-01" {
		t.Errorf("flow tags = %v, want tag=raw-test-01", newFl.Tags)
	}
}

// --- Session recording tests ---

func TestExecute_ResendRaw_RecordsSession(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
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
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"patches": []any{
				map[string]any{
					"find_text":    "example.com",
					"replace_text": "target.com",
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

	// Verify a new flow was created with correct metadata.
	newFl, err := store.GetFlow(context.Background(), out.NewFlowID)
	if err != nil {
		t.Fatalf("get new flow: %v", err)
	}
	if newFl.FlowType != "unary" {
		t.Errorf("flow_type = %q, want unary", newFl.FlowType)
	}
	if newFl.State != "complete" {
		t.Errorf("state = %q, want complete", newFl.State)
	}

	// Verify send message has patched raw bytes.
	sendMsgs, err := store.GetMessages(context.Background(), out.NewFlowID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("GetMessages(send): %v", err)
	}
	if len(sendMsgs) == 0 {
		t.Fatal("expected send message")
	}
	patchedReq := "GET /test HTTP/1.1\r\nHost: target.com\r\n\r\n"
	if string(sendMsgs[0].RawBytes) != patchedReq {
		t.Errorf("recorded send raw_bytes = %q, want %q", string(sendMsgs[0].RawBytes), patchedReq)
	}

	// Verify receive message exists.
	recvMsgs, err := store.GetMessages(context.Background(), out.NewFlowID, flow.MessageListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages(receive): %v", err)
	}
	if len(recvMsgs) == 0 {
		t.Fatal("expected receive message")
	}
	if len(recvMsgs[0].RawBytes) == 0 {
		t.Error("receive message raw_bytes should not be empty")
	}
}

// --- Error case tests ---

func TestExecute_ResendRaw_InvalidOverrideRawBase64(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

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
			"flow_id":             entry.Session.ID,
			"override_raw_base64": "not-valid-base64!!!",
			"dry_run":             true,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid override_raw_base64")
	}
}

func TestExecute_ResendRaw_InvalidPatch(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

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

	// Patch with invalid base64 data.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id": entry.Session.ID,
			"patches": []any{
				map[string]any{
					"offset":      0,
					"data_base64": "not-valid!!!",
				},
			},
			"dry_run": true,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid patch data_base64")
	}
}

func TestExecute_ResendRaw_PatchOffsetBeyondData(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	rawReq := []byte("Hello")
	u, _ := url.Parse("http://example.com/test")

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
			"flow_id": entry.Session.ID,
			"patches": []any{
				map[string]any{
					"offset":      100,
					"data_base64": base64.StdEncoding.EncodeToString([]byte("X")),
				},
			},
			"dry_run": true,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for offset beyond data length")
	}
}

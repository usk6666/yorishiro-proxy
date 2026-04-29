package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
	sessions, err := store.ListStreams(context.Background(), flow.StreamListOptions{})
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
	sessions, err := store.ListStreams(context.Background(), flow.StreamListOptions{})
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
	fl := &flow.Stream{
		Protocol:  "HTTP/2",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       u,
		Headers:   map[string][]string{},
		RawBytes:  nil, // No raw bytes stored
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	recvMsg := &flow.Flow{
		StreamID:   fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Headers:    map[string][]string{},
		Body:       []byte("ok"),
	}
	if err := store.SaveFlow(ctx, recvMsg); err != nil {
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
	s := newServer(ctx, nil, store, nil)
	s.jobRunner.rawReplayDialer = &testDialer{}

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
		&flow.Stream{
			Protocol:  "HTTP/2",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  nil,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/2",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  nil,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
	newFl, err := store.GetStream(context.Background(), out.NewFlowID)
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
	newFl, err := store.GetStream(context.Background(), out.NewFlowID)
	if err != nil {
		t.Fatalf("get new flow: %v", err)
	}
	if newFl.State != "complete" {
		t.Errorf("state = %q, want complete", newFl.State)
	}

	// Verify send message has patched raw bytes.
	sendMsgs, err := store.GetFlows(context.Background(), out.NewFlowID, flow.FlowListOptions{Direction: "send"})
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
	recvMsgs, err := store.GetFlows(context.Background(), out.NewFlowID, flow.FlowListOptions{Direction: "receive"})
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
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

// --- resend_raw hooks tests ---

// setupTestSessionWithRawDialerAndMacro creates an MCP client session with
// both rawReplayDialer (for raw resend) and replayDoer (for macro HTTP calls).
func setupTestSessionWithRawDialerAndMacro(t *testing.T, store flow.Store, dialer rawDialer) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := newServer(context.Background(), nil, store, nil)
	s.jobRunner.rawReplayDialer = dialer
	s.jobRunner.replayDoer = newPermissiveClient()
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

func TestExecute_ResendRaw_HooksNil_BackwardCompat(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	// Use standard raw dialer setup (no macro support needed).
	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	// Explicitly pass hooks=nil to verify backward compatibility.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
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
}

func TestExecute_ResendRaw_InvalidHooksRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://127.0.0.1/test")

	fl := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: fl.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now(), Method: "GET", URL: u,
		Headers: map[string][]string{}, RawBytes: rawReq,
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupTestSessionWithExecuteRawDialer(t, store, &testDialer{})

	// Invalid hooks: pre_send with empty macro name.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     fl.ID,
			"target_addr": "127.0.0.1:9999",
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro":        "",
					"run_interval": "always",
				},
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid hooks (empty macro name)")
	}

	// Invalid hooks: pre_send with invalid run_interval.
	result = executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     fl.ID,
			"target_addr": "127.0.0.1:9999",
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro":        "some-macro",
					"run_interval": "invalid_interval",
				},
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid run_interval")
	}

	// Invalid hooks: post_receive with on_status but no status_codes.
	result = executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     fl.ID,
			"target_addr": "127.0.0.1:9999",
			"hooks": map[string]any{
				"post_receive": map[string]any{
					"macro":        "some-macro",
					"run_interval": "on_status",
				},
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for on_status without status_codes")
	}
}

func TestExecute_ResendRaw_WithPreSendHook(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	// Save the raw resend target flow.
	entry := saveTestEntry(t, store,
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	// Create a token server for the macro step.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Token", "raw-pre-send-token")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer tokenServer.Close()

	ctx := context.Background()

	// Save the macro step flow.
	tokenURL, _ := url.Parse(tokenServer.URL + "/token")
	tokenSess := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, tokenSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: tokenSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: tokenURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Set up session with both raw dialer and macro HTTP support.
	cs := setupTestSessionWithRawDialerAndMacro(t, store, &testDialer{})

	// Define the pre-send macro.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "raw-auth-flow",
			"steps": []any{
				map[string]any{
					"id":      "get-token",
					"flow_id": tokenSess.ID,
					"extract": []any{
						map[string]any{
							"name":        "token",
							"from":        "response",
							"source":      "header",
							"header_name": "X-Token",
						},
					},
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Resend raw with pre_send hook.
	// Note: template expansion is NOT applied to raw bytes (L4 integrity).
	// The hook executes but the KV Store is only available for post_receive.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"hooks": map[string]any{
				"pre_send": map[string]any{
					"macro": "raw-auth-flow",
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("resend_raw with pre_send hook failed: %v", result.Content)
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
}

func TestExecute_ResendRaw_WithPostReceiveHook(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	// Save the raw resend target flow.
	entry := saveTestEntry(t, store,
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&flow.Flow{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&flow.Flow{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       []byte("ok"),
		},
	)

	// Create a macro step server for the post_receive hook.
	var postReceiveInvoked bool
	macroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postReceiveInvoked = true
		w.WriteHeader(200)
		w.Write([]byte("logged"))
	}))
	defer macroServer.Close()

	ctx := context.Background()

	// Save the macro step flow.
	macroURL, _ := url.Parse(macroServer.URL + "/log")
	macroSess := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, macroSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: macroSess.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "POST", URL: macroURL,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("log entry"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Set up session with both raw dialer and macro HTTP support.
	cs := setupTestSessionWithRawDialerAndMacro(t, store, &testDialer{})

	// Define the post-receive macro.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "raw-log-response",
			"steps": []any{
				map[string]any{
					"id":      "log",
					"flow_id": macroSess.ID,
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Resend raw with post_receive hook.
	result := executeCallTool(t, cs, map[string]any{
		"action": "resend_raw",
		"params": map[string]any{
			"flow_id":     entry.Session.ID,
			"target_addr": addr,
			"hooks": map[string]any{
				"post_receive": map[string]any{
					"macro":        "raw-log-response",
					"run_interval": "always",
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("resend_raw with post_receive hook failed: %v", result.Content)
	}

	var out resendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if out.NewFlowID == "" {
		t.Error("expected non-empty new_flow_id")
	}

	if !postReceiveInvoked {
		t.Error("post_receive hook was not invoked")
	}
}

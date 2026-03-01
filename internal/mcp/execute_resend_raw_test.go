package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// --- resend_raw with patches tests ---

func TestExecute_ResendRaw_OffsetPatch(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	// Raw request: "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":  entry.Session.ID,
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

	var out executeResendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
	if out.NewSessionID == "" {
		t.Error("expected non-empty new_session_id")
	}
}

func TestExecute_ResendRaw_TextFindReplace(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":  entry.Session.ID,
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

	var out executeResendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
}

func TestExecute_ResendRaw_BinaryFindReplace(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":  entry.Session.ID,
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

	var out executeResendRawResult
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
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id": entry.Session.ID,
			"dry_run":    true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeRawDryRunResult
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

	// Verify no new session was created (dry-run should NOT record).
	sessions, err := store.ListSessions(context.Background(), session.ListOptions{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 session (original only), got %d", len(sessions))
	}
}

func TestExecute_ResendRaw_DryRun_WithPatches(t *testing.T) {
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id": entry.Session.ID,
			"dry_run":    true,
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

	var out executeRawDryRunResult
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

	// Verify no new session was created.
	sessions, err := store.ListSessions(context.Background(), session.ListOptions{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 session (original only), got %d", len(sessions))
	}
}

func TestExecute_ResendRaw_DryRun_WithOverrideRawBase64(t *testing.T) {
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":         entry.Session.ID,
			"override_raw_base64": base64.StdEncoding.EncodeToString(replacement),
			"dry_run":            true,
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeRawDryRunResult
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

func TestExecute_ResendRaw_OverrideRawBase64(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /original HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/original")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":         entry.Session.ID,
			"target_addr":        addr,
			"override_raw_base64": base64.StdEncoding.EncodeToString(replacement),
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.ResponseSize == 0 {
		t.Error("expected non-zero response_size")
	}
	if out.NewSessionID == "" {
		t.Error("expected non-empty new_session_id")
	}
}

func TestExecute_ResendRaw_OverrideRawBase64_IgnoresPatches(t *testing.T) {
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":         entry.Session.ID,
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

	var out executeRawDryRunResult
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
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":  entry.Session.ID,
			"target_addr": addr,
			"tag":         "raw-test-01",
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out executeResendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if out.Tag != "raw-test-01" {
		t.Errorf("tag = %q, want raw-test-01", out.Tag)
	}

	// Verify the tag was stored on the session.
	newSess, err := store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	if newSess.Tags == nil || newSess.Tags["tag"] != "raw-test-01" {
		t.Errorf("session tags = %v, want tag=raw-test-01", newSess.Tags)
	}
}

// --- Session recording tests ---

func TestExecute_ResendRaw_RecordsSession(t *testing.T) {
	store := newTestStore(t)
	addr, cleanup := newRawEchoServer(t)
	defer cleanup()

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	host, port, _ := net.SplitHostPort(addr)
	u, _ := url.Parse("http://" + host + ":" + port + "/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":  entry.Session.ID,
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

	var out executeResendRawResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// Verify a new session was created with correct metadata.
	newSess, err := store.GetSession(context.Background(), out.NewSessionID)
	if err != nil {
		t.Fatalf("get new session: %v", err)
	}
	if newSess.SessionType != "unary" {
		t.Errorf("session_type = %q, want unary", newSess.SessionType)
	}
	if newSess.State != "complete" {
		t.Errorf("state = %q, want complete", newSess.State)
	}

	// Verify send message has patched raw bytes.
	sendMsgs, err := store.GetMessages(context.Background(), out.NewSessionID, session.MessageListOptions{Direction: "send"})
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
	recvMsgs, err := store.GetMessages(context.Background(), out.NewSessionID, session.MessageListOptions{Direction: "receive"})
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
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id":         entry.Session.ID,
			"override_raw_base64": "not-valid-base64!!!",
			"dry_run":            true,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid override_raw_base64")
	}
}

func TestExecute_ResendRaw_InvalidPatch(t *testing.T) {
	store := newTestStore(t)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	u, _ := url.Parse("http://example.com/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id": entry.Session.ID,
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
	store := newTestStore(t)

	rawReq := []byte("Hello")
	u, _ := url.Parse("http://example.com/test")

	entry := saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{},
			RawBytes:  rawReq,
		},
		&session.Message{
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
			"session_id": entry.Session.ID,
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

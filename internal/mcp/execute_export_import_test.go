package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// --- validateFilePath unit tests ---

func TestValidateFilePath_NormalPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.jsonl")

	result, err := validateFilePath(path)
	if err != nil {
		t.Fatalf("validateFilePath: %v", err)
	}
	if result != path {
		t.Errorf("expected %q, got %q", path, result)
	}
}

func TestValidateFilePath_EmptyPath(t *testing.T) {
	_, err := validateFilePath("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateFilePath_RelativePath(t *testing.T) {
	result, err := validateFilePath("relative/path/file.jsonl")
	if err != nil {
		t.Fatalf("validateFilePath: %v", err)
	}
	if !filepath.IsAbs(result) {
		t.Errorf("expected absolute path, got %q", result)
	}
}

func TestValidateFilePath_DotDotTraversal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "..", "..", "etc", "passwd")

	result, err := validateFilePath(path)
	if err != nil {
		t.Fatalf("validateFilePath: %v", err)
	}
	if strings.Contains(result, "..") {
		t.Errorf("expected cleaned path without .., got %q", result)
	}
}

func TestValidateFilePath_SymlinkRejected(t *testing.T) {
	dir := t.TempDir()

	realFile := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(realFile, []byte("data"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	symlinkPath := filepath.Join(dir, "link.txt")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := validateFilePath(symlinkPath)
	if err == nil {
		t.Fatal("expected error for symlink path")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateFilePath_NonExistentIsOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.jsonl")

	result, err := validateFilePath(path)
	if err != nil {
		t.Fatalf("validateFilePath: %v", err)
	}
	if result != path {
		t.Errorf("expected %q, got %q", path, result)
	}
}

func TestValidateFilePath_RegularFileIsOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.jsonl")
	if err := os.WriteFile(path, []byte("data"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	result, err := validateFilePath(path)
	if err != nil {
		t.Fatalf("validateFilePath: %v", err)
	}
	if result != path {
		t.Errorf("expected %q, got %q", path, result)
	}
}

// --- MCP handler integration tests ---

// makeExportTestSession creates a test session with a single message for MCP handler tests.
func makeExportTestSession(t *testing.T, store session.Store, id string) {
	t.Helper()
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	sess := &session.Session{
		ID:          id,
		ConnID:      "conn-" + id,
		Protocol:    "HTTPS",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   ts,
		Duration:    100 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	msg := &session.Message{
		ID:        "msg-" + id,
		SessionID: id,
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    "GET",
	}
	if err := store.AppendMessage(ctx, msg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
}

func TestExportSessionsAction_FilePermissions(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeExportTestSession(t, store, "sess-perm-1")

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "export.jsonl")

	result := executeCallTool(t, cs, map[string]any{
		"action": "export_sessions",
		"params": map[string]any{
			"output_path": outputPath,
		},
	})
	if result.IsError {
		t.Fatalf("export returned error: %v", result.Content)
	}

	// S-8: check file permissions are 0600
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}

func TestExportSessionsAction_SymlinkRejected(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeExportTestSession(t, store, "sess-symlink-1")

	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.jsonl")
	if err := os.WriteFile(realFile, []byte(""), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	symlinkPath := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	result := executeCallTool(t, cs, map[string]any{
		"action": "export_sessions",
		"params": map[string]any{
			"output_path": symlinkPath,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for symlink output_path, but got success")
	}
}

func TestExportSessionsAction_InlineLimit(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	// Create more sessions than the inline limit
	for i := 0; i < maxInlineExportSessions+10; i++ {
		id := fmt.Sprintf("sess-inline-%04d", i)
		makeExportTestSession(t, store, id)
	}

	result := executeCallTool(t, cs, map[string]any{
		"action": "export_sessions",
		"params": map[string]any{},
	})
	if result.IsError {
		t.Fatalf("export returned error: %v", result.Content)
	}

	// Parse the response to check exported count
	var textContent gomcp.TextContent
	raw, _ := json.Marshal(result.Content[0])
	if err := json.Unmarshal(raw, &textContent); err != nil {
		t.Fatalf("unmarshal text content: %v", err)
	}

	var exportResult executeExportSessionsResult
	if err := json.Unmarshal([]byte(textContent.Text), &exportResult); err != nil {
		t.Fatalf("unmarshal export result: %v", err)
	}

	if exportResult.ExportedCount > maxInlineExportSessions {
		t.Errorf("inline export should be capped at %d, got %d", maxInlineExportSessions, exportResult.ExportedCount)
	}
}

func TestImportSessionsAction_SymlinkRejected(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	dir := t.TempDir()
	realFile := filepath.Join(dir, "data.jsonl")
	if err := os.WriteFile(realFile, []byte(`{"session":{"id":"s","conn_id":"c","protocol":"HTTPS","session_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	symlinkPath := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	result := executeCallTool(t, cs, map[string]any{
		"action": "import_sessions",
		"params": map[string]any{
			"input_path": symlinkPath,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for symlink input_path, but got success")
	}
}

func TestExportSessionsAction_AtomicWrite(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeExportTestSession(t, store, "sess-atomic-1")

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "atomic-export.jsonl")

	result := executeCallTool(t, cs, map[string]any{
		"action": "export_sessions",
		"params": map[string]any{
			"output_path": outputPath,
		},
	})
	if result.IsError {
		t.Fatalf("export returned error: %v", result.Content)
	}

	// Verify file exists and contains valid JSONL
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("exported file is empty")
	}

	// No temp files should remain
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".yorishiro-export-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestImportSessionsAction_ValidUUIDRequired(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	dir := t.TempDir()
	dataFile := filepath.Join(dir, "invalid-ids.jsonl")
	// Non-UUID session IDs should be rejected when MCP handler enables validation
	if err := os.WriteFile(dataFile, []byte(`{"session":{"id":"not-uuid","conn_id":"c","protocol":"HTTPS","session_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	result := executeCallTool(t, cs, map[string]any{
		"action": "import_sessions",
		"params": map[string]any{
			"input_path": dataFile,
		},
	})
	if result.IsError {
		t.Fatalf("import returned error: %v", result.Content)
	}

	// Parse result to check errors count
	var textContent gomcp.TextContent
	raw, _ := json.Marshal(result.Content[0])
	if err := json.Unmarshal(raw, &textContent); err != nil {
		t.Fatalf("unmarshal text content: %v", err)
	}

	var importResult executeImportSessionsResult
	if err := json.Unmarshal([]byte(textContent.Text), &importResult); err != nil {
		t.Fatalf("unmarshal import result: %v", err)
	}

	if importResult.Imported != 0 {
		t.Errorf("expected 0 imported with invalid UUID, got %d", importResult.Imported)
	}
	if importResult.Errors != 1 {
		t.Errorf("expected 1 error for invalid UUID, got %d", importResult.Errors)
	}
}

func TestExportSessionsAction_PathTraversalCleaned(t *testing.T) {
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeExportTestSession(t, store, "sess-traverse-1")

	dir := t.TempDir()
	// Path with .. components - should be cleaned/normalised
	outputPath := filepath.Join(dir, "sub", "..", "export.jsonl")

	result := executeCallTool(t, cs, map[string]any{
		"action": "export_sessions",
		"params": map[string]any{
			"output_path": outputPath,
		},
	})
	if result.IsError {
		t.Fatalf("export returned error: %v", result.Content)
	}

	// File should exist at the cleaned path
	cleanedPath := filepath.Join(dir, "export.jsonl")
	if _, err := os.Stat(cleanedPath); err != nil {
		t.Fatalf("expected file at cleaned path %s: %v", cleanedPath, err)
	}
}

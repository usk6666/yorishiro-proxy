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
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- validateFilePath unit tests ---

func TestValidateFilePath_NormalPath(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	_, err := validateFilePath("")
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateFilePath_RelativePath(t *testing.T) {
	t.Parallel()
	result, err := validateFilePath("relative/path/file.jsonl")
	if err != nil {
		t.Fatalf("validateFilePath: %v", err)
	}
	if !filepath.IsAbs(result) {
		t.Errorf("expected absolute path, got %q", result)
	}
}

func TestValidateFilePath_DotDotTraversal(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// makeExportTestSession creates a test flow with a single message for MCP handler tests.
func makeExportTestSession(t *testing.T, store flow.Store, id string) {
	t.Helper()
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	fl := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: ts,
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	msg := &flow.Message{
		ID:        "msg-" + id,
		FlowID:    id,
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    "GET",
	}
	if err := store.AppendMessage(ctx, msg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
}

func TestExportFlowsAction_FilePermissions(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeExportTestSession(t, store, "sess-perm-1")

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "export.jsonl")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
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

func TestExportFlowsAction_SymlinkRejected(t *testing.T) {
	t.Parallel()
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

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"output_path": symlinkPath,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for symlink output_path, but got success")
	}
}

func TestExportFlowsAction_InlineLimit(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	// Create more sessions than the inline limit
	for i := 0; i < maxInlineExportFlows+10; i++ {
		id := fmt.Sprintf("sess-inline-%04d", i)
		makeExportTestSession(t, store, id)
	}

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
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

	var exportResult executeExportFlowsResult
	if err := json.Unmarshal([]byte(textContent.Text), &exportResult); err != nil {
		t.Fatalf("unmarshal export result: %v", err)
	}

	if exportResult.ExportedCount > maxInlineExportFlows {
		t.Errorf("inline export should be capped at %d, got %d", maxInlineExportFlows, exportResult.ExportedCount)
	}
}

func TestImportFlowsAction_SymlinkRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	dir := t.TempDir()
	realFile := filepath.Join(dir, "data.jsonl")
	if err := os.WriteFile(realFile, []byte(`{"flow":{"id":"s","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	symlinkPath := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(realFile, symlinkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	result := manageCallTool(t, cs, map[string]any{
		"action": "import_flows",
		"params": map[string]any{
			"input_path": symlinkPath,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for symlink input_path, but got success")
	}
}

func TestExportFlowsAction_AtomicWrite(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeExportTestSession(t, store, "sess-atomic-1")

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "atomic-export.jsonl")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
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

func TestImportFlowsAction_ValidUUIDRequired(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	dir := t.TempDir()
	dataFile := filepath.Join(dir, "invalid-ids.jsonl")
	// Non-UUID flow IDs should be rejected when MCP handler enables validation
	if err := os.WriteFile(dataFile, []byte(`{"flow":{"id":"not-uuid","conn_id":"c","protocol":"HTTPS","flow_type":"unary","state":"complete","timestamp":"2026-02-15T10:00:00Z","duration_ms":100},"messages":[],"version":"1"}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	result := manageCallTool(t, cs, map[string]any{
		"action": "import_flows",
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

	var importResult executeImportFlowsResult
	if err := json.Unmarshal([]byte(textContent.Text), &importResult); err != nil {
		t.Fatalf("unmarshal import result: %v", err)
	}

	if importResult.Imported != 0 {
		t.Errorf("expected 0 imported with invalid UUID, got %d", importResult.Imported)
	}
	if importResult.Errors != 1 {
		t.Errorf("expected 1 error for invalid UUID, got %d", importResult.Errors)
	}
	// Verify error details are returned via MCP.
	if len(importResult.ErrorDetails) != 1 {
		t.Fatalf("expected 1 error detail, got %d", len(importResult.ErrorDetails))
	}
	if importResult.ErrorDetails[0].Reason == "" {
		t.Errorf("expected non-empty error reason")
	}
}

// makeRealisticTestSession creates a test session that mimics real proxy data
// with all fields populated, including ConnInfo and message bodies.
func makeRealisticTestSession(t *testing.T, store flow.Store, sessID, sendMsgID, recvMsgID, protocol string, withConnInfo bool) {
	t.Helper()
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	fl := &flow.Flow{
		ID:        sessID,
		Protocol:  protocol,
		FlowType:  "unary",
		State:     "complete",
		Timestamp: ts,
		Duration:  250 * time.Millisecond,
		Tags:      map[string]string{"env": "test"},
	}
	// Resend-generated sessions have empty ConnID
	if withConnInfo {
		fl.ConnID = "conn-" + sessID
		fl.ConnInfo = &flow.ConnectionInfo{
			ClientAddr:           "127.0.0.1:54321",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=example.com",
		}
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &flow.Message{
		ID:        sendMsgID,
		FlowID:    sessID,
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    "POST",
		Headers:   map[string][]string{"Content-Type": {"application/json"}, "Accept": {"*/*"}},
		Body:      []byte(`{"user":"admin","action":"login"}`),
		RawBytes:  []byte("POST /api/login HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Metadata:  map[string]string{"source": "resend"},
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	recvMsg := &flow.Message{
		ID:         recvMsgID,
		FlowID:     sessID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  ts.Add(250 * time.Millisecond),
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Type": {"application/json"}, "Set-Cookie": {"sid=abc; Path=/"}},
		Body:       []byte(`{"ok":true,"token":"secret123"}`),
		RawBytes:   []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(recv): %v", err)
	}
}

// parseMCPImportResult extracts the import result from an MCP CallToolResult.
func parseMCPImportResult(t *testing.T, result *gomcp.CallToolResult) executeImportFlowsResult {
	t.Helper()
	var textContent gomcp.TextContent
	raw, _ := json.Marshal(result.Content[0])
	if err := json.Unmarshal(raw, &textContent); err != nil {
		t.Fatalf("unmarshal text content: %v", err)
	}
	var importRes executeImportFlowsResult
	if err := json.Unmarshal([]byte(textContent.Text), &importRes); err != nil {
		t.Fatalf("unmarshal import result: %v", err)
	}
	return importRes
}

func TestExportImportRoundTrip_MCP(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	// Mix of session types:
	// - HTTPS with ConnInfo (normal proxy session)
	// - HTTPS without ConnInfo (resend-generated, empty ConnID)
	// - HTTP/1.x with ConnInfo
	makeRealisticTestSession(t, store,
		"550e8400-e29b-41d4-a716-446655440001",
		"550e8400-e29b-41d4-a716-446655440002",
		"550e8400-e29b-41d4-a716-446655440003",
		"HTTPS", true)
	makeRealisticTestSession(t, store,
		"550e8400-e29b-41d4-a716-446655440004",
		"550e8400-e29b-41d4-a716-446655440005",
		"550e8400-e29b-41d4-a716-446655440006",
		"HTTPS", false) // resend-like: no ConnID, no ConnInfo
	makeRealisticTestSession(t, store,
		"550e8400-e29b-41d4-a716-446655440007",
		"550e8400-e29b-41d4-a716-446655440008",
		"550e8400-e29b-41d4-a716-446655440009",
		"HTTP/1.x", true)

	dir := t.TempDir()
	exportPath := filepath.Join(dir, "export.jsonl")

	// Step 1: Export
	exportResult := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"output_path": exportPath,
		},
	})
	if exportResult.IsError {
		t.Fatalf("export returned error: %v", exportResult.Content)
	}

	// Verify export count
	var exportTextContent gomcp.TextContent
	exportRaw, _ := json.Marshal(exportResult.Content[0])
	if err := json.Unmarshal(exportRaw, &exportTextContent); err != nil {
		t.Fatalf("unmarshal export text content: %v", err)
	}
	var exportRes executeExportFlowsResult
	if err := json.Unmarshal([]byte(exportTextContent.Text), &exportRes); err != nil {
		t.Fatalf("unmarshal export result: %v", err)
	}
	if exportRes.ExportedCount != 3 {
		t.Fatalf("expected 3 exported, got %d", exportRes.ExportedCount)
	}

	// Log JSONL for debugging
	data, _ := os.ReadFile(exportPath)
	t.Logf("Exported JSONL:\n%s", string(data))

	// Step 2: Delete all sessions
	deleteResult := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"confirm": true,
		},
	})
	if deleteResult.IsError {
		t.Fatalf("delete returned error: %v", deleteResult.Content)
	}

	// Step 3: Import
	importCallResult := manageCallTool(t, cs, map[string]any{
		"action": "import_flows",
		"params": map[string]any{
			"input_path": exportPath,
		},
	})
	if importCallResult.IsError {
		t.Fatalf("import returned error: %v", importCallResult.Content)
	}

	importRes := parseMCPImportResult(t, importCallResult)

	if importRes.Errors != 0 {
		t.Errorf("expected 0 errors, got %d", importRes.Errors)
		for _, e := range importRes.ErrorDetails {
			t.Errorf("  line %d (flow %s): %s", e.Line, e.FlowID, e.Reason)
		}
	}
	if importRes.Imported != 3 {
		t.Errorf("expected 3 imported, got %d", importRes.Imported)
	}
}

func TestExportFlowsAction_PathTraversalCleaned(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeExportTestSession(t, store, "sess-traverse-1")

	dir := t.TempDir()
	// Path with .. components - should be cleaned/normalised
	outputPath := filepath.Join(dir, "sub", "..", "export.jsonl")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
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

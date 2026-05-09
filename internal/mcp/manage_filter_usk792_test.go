package mcp

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// seedFilterStream stores a stream with a single send flow that
// carries the supplied protocol/scheme/http_version triple. The
// USK-792 manage filters target streams.protocol, streams.scheme, and
// flows.http_version respectively, so each axis of the saved row is
// observable through the new filter.
func seedFilterStream(t *testing.T, store flow.Store, id, protocol, scheme, httpVersion string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  protocol,
		Scheme:    scheme,
		State:     "complete",
		Timestamp: now,
		Duration:  10 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream(%s): %v", id, err)
	}
	parsedURL, _ := url.Parse(scheme + "://example.com/" + id)
	send := &flow.Flow{
		ID:          id + "-send",
		StreamID:    id,
		Sequence:    0,
		Direction:   "send",
		Timestamp:   now,
		Method:      "GET",
		URL:         parsedURL,
		HTTPVersion: httpVersion,
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(%s send): %v", id, err)
	}
}

// readExportedJSONL parses a JSONL export file written by the MCP
// manage tool into a slice of stream IDs, used to assert the
// USK-792 filter selected only the expected streams.
func readExportedJSONL(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var ids []string
	for _, line := range splitJSONL(data) {
		var rec struct {
			Stream struct {
				ID string `json:"id"`
			} `json:"stream"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if rec.Stream.ID != "" {
			ids = append(ids, rec.Stream.ID)
		}
	}
	return ids
}

// splitJSONL slices the export bytes by newline, dropping empty
// trailing lines so the caller does not have to special-case the
// final EOL the encoder always emits.
func splitJSONL(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// listStreamIDs returns the set of stored stream IDs sorted
// deterministically — used to verify which streams a filtered delete
// left behind.
func listStreamIDs(t *testing.T, store flow.Store) []string {
	t.Helper()
	ctx := context.Background()
	streams, err := store.ListStreams(ctx, flow.StreamListOptions{})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	out := make([]string, len(streams))
	for i, s := range streams {
		out[i] = s.ID
	}
	return out
}

// TestManageExport_FilterScheme pins that filter.scheme=https on
// export_flows includes only streams whose Stream.Scheme is "https",
// not http (cleartext) and not wss (TLS WebSocket). Mirrors the
// query tool semantics referenced in USK-792.
func TestManageExport_FilterScheme(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "https-h2", "http", "https", "h2")
	seedFilterStream(t, store, "https-h11", "http", "https", "http/1.1")
	seedFilterStream(t, store, "plain-http", "http", "http", "http/1.1")
	seedFilterStream(t, store, "wss", "ws", "wss", "")

	dir := t.TempDir()
	out := filepath.Join(dir, "scheme.jsonl")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"output_path": out,
			"filter": map[string]any{
				"scheme": "https",
			},
		},
	})
	if result.IsError {
		t.Fatalf("export error: %v", result.Content)
	}

	ids := readExportedJSONL(t, out)
	want := []string{"https-h2", "https-h11"}
	if !sameStringSetMCP(ids, want) {
		t.Errorf("exported = %v, want %v", ids, want)
	}
}

// TestManageExport_FilterHTTPVersion pins that filter.http_version=h2
// on export_flows includes only streams whose flows recorded "h2",
// rejecting both http/1.1 and the empty / pre-USK-788 bucket.
func TestManageExport_FilterHTTPVersion(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "h2-https", "http", "https", "h2")
	seedFilterStream(t, store, "h2c-plain", "http", "http", "h2c")
	seedFilterStream(t, store, "h11-https", "http", "https", "http/1.1")

	dir := t.TempDir()
	out := filepath.Join(dir, "version.jsonl")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"output_path": out,
			"filter": map[string]any{
				"http_version": "h2",
			},
		},
	})
	if result.IsError {
		t.Fatalf("export error: %v", result.Content)
	}

	ids := readExportedJSONL(t, out)
	if !sameStringSetMCP(ids, []string{"h2-https"}) {
		t.Errorf("exported = %v, want [h2-https]", ids)
	}
}

// TestManageExport_FilterCombination_AND pins that protocol +
// scheme + http_version compose with AND: only streams that match
// every supplied axis are exported.
func TestManageExport_FilterCombination_AND(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "match", "http", "https", "h2")
	seedFilterStream(t, store, "wrong-scheme", "http", "http", "h2")
	seedFilterStream(t, store, "wrong-version", "http", "https", "http/1.1")
	seedFilterStream(t, store, "wrong-protocol", "ws", "https", "h2")

	dir := t.TempDir()
	out := filepath.Join(dir, "combo.jsonl")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"output_path": out,
			"filter": map[string]any{
				"protocol":     "http",
				"scheme":       "https",
				"http_version": "h2",
			},
		},
	})
	if result.IsError {
		t.Fatalf("export error: %v", result.Content)
	}

	ids := readExportedJSONL(t, out)
	if !sameStringSetMCP(ids, []string{"match"}) {
		t.Errorf("exported = %v, want [match]", ids)
	}
}

// TestManageExport_FilterRejectsInvalidScheme pins that an
// unsupported scheme value is rejected with the same error shape the
// query tool surfaces — keeping the two MCP filter surfaces visibly
// in sync for analysts.
func TestManageExport_FilterRejectsInvalidScheme(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "any", "http", "https", "h2")

	dir := t.TempDir()
	out := filepath.Join(dir, "bad-scheme.jsonl")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"output_path": out,
			"filter": map[string]any{
				"scheme": "ftps",
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid scheme")
	}
}

// TestManageDelete_FilterScheme pins that delete_flows with
// filter.scheme=https removes only HTTPS streams and leaves plain
// http and wss streams intact — the central acceptance criterion in
// USK-792.
func TestManageDelete_FilterScheme(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "https-1", "http", "https", "h2")
	seedFilterStream(t, store, "https-2", "http", "https", "http/1.1")
	seedFilterStream(t, store, "plain", "http", "http", "http/1.1")
	seedFilterStream(t, store, "wss", "ws", "wss", "")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"scheme":  "https",
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 2 {
		t.Errorf("deleted_count = %d, want 2", del.DeletedCount)
	}

	remaining := listStreamIDs(t, store)
	if !sameStringSetMCP(remaining, []string{"plain", "wss"}) {
		t.Errorf("remaining = %v, want [plain wss]", remaining)
	}
}

// TestManageDelete_FilterHTTPVersion pins that delete_flows with
// filter.http_version=h2 removes only h2 streams and leaves h2c,
// http/1.x, and pre-USK-788 (empty version) streams alone.
func TestManageDelete_FilterHTTPVersion(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "h2-1", "http", "https", "h2")
	seedFilterStream(t, store, "h2-2", "http", "http", "h2")
	seedFilterStream(t, store, "h2c", "http", "http", "h2c")
	seedFilterStream(t, store, "h11", "http", "https", "http/1.1")
	seedFilterStream(t, store, "legacy", "http", "https", "")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"http_version": "h2",
			"confirm":      true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 2 {
		t.Errorf("deleted_count = %d, want 2", del.DeletedCount)
	}

	remaining := listStreamIDs(t, store)
	if !sameStringSetMCP(remaining, []string{"h2c", "h11", "legacy"}) {
		t.Errorf("remaining = %v, want [h2c h11 legacy]", remaining)
	}
}

// TestManageDelete_FilterCombination_AND pins that protocol +
// scheme + http_version compose with AND on the delete path.
func TestManageDelete_FilterCombination_AND(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "match", "http", "https", "h2")
	seedFilterStream(t, store, "wrong-scheme", "http", "http", "h2")
	seedFilterStream(t, store, "wrong-version", "http", "https", "http/1.1")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"protocol":     "http",
			"scheme":       "https",
			"http_version": "h2",
			"confirm":      true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", del.DeletedCount)
	}

	remaining := listStreamIDs(t, store)
	if !sameStringSetMCP(remaining, []string{"wrong-scheme", "wrong-version"}) {
		t.Errorf("remaining = %v, want [wrong-scheme wrong-version]", remaining)
	}
}

// TestManageDelete_FilterRequiresConfirm pins that bulk filter-based
// deletion still demands an explicit confirm guard, mirroring the
// pre-USK-792 protocol-only behavior.
func TestManageDelete_FilterRequiresConfirm(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "doomed", "http", "https", "h2")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"scheme": "https",
		},
	})
	if !result.IsError {
		t.Fatal("expected error when confirm is missing")
	}

	if got := listStreamIDs(t, store); len(got) != 1 {
		t.Errorf("remaining = %v, want [doomed] — guard must not delete", got)
	}
}

// TestManageDelete_FilterRejectsInvalidEnums pins that delete_flows
// rejects scheme / http_version values outside the canonical set,
// keeping the manage and query MCP surfaces observably symmetric.
func TestManageDelete_FilterRejectsInvalidEnums(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "keep", "http", "https", "h2")

	bad := []map[string]any{
		{"scheme": "gopher", "confirm": true},
		{"http_version": "http/3", "confirm": true},
	}
	for _, params := range bad {
		result := manageCallTool(t, cs, map[string]any{
			"action": "delete_flows",
			"params": params,
		})
		if !result.IsError {
			t.Errorf("expected error for params=%v", params)
		}
	}

	if got := listStreamIDs(t, store); len(got) != 1 {
		t.Errorf("remaining = %v, want [keep]", got)
	}
}

// TestManageDelete_ProtocolOnly_Compatibility pins the legacy
// protocol-only delete path that USK-792 routed through the new
// filter — pre-existing callers must not see a behavior change.
func TestManageDelete_ProtocolOnly_Compatibility(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStream(t, store, "ws-1", "ws", "wss", "")
	seedFilterStream(t, store, "http-1", "http", "https", "h2")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"protocol": "ws",
			"confirm":  true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", del.DeletedCount)
	}

	remaining := listStreamIDs(t, store)
	if !sameStringSetMCP(remaining, []string{"http-1"}) {
		t.Errorf("remaining = %v, want [http-1]", remaining)
	}
}

// unmarshalManageResult decodes the JSON-encoded TextContent payload
// MCP returns from the manage tool into the supplied destination.
// Mirrors the helper used by the existing manage import/export tests.
func unmarshalManageResult(t *testing.T, result *gomcp.CallToolResult, dest any) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content[0] type = %T, want *TextContent", result.Content[0])
	}
	if err := json.Unmarshal([]byte(text.Text), dest); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// sameStringSetMCP is a local set-equality helper because the flow
// package's helper is not exported.
func sameStringSetMCP(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	m := make(map[string]int, len(want))
	for _, w := range want {
		m[w]++
	}
	for _, g := range got {
		m[g]--
		if m[g] < 0 {
			return false
		}
	}
	return true
}

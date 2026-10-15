package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-1127: manage export_flows / import_flows must confine every
// server-side file read and write to the operator-configured export
// directory. These tests drive the real resolver and the real manage
// handler (in-memory MCP session + real SQLite store).

// setupExportSession returns an MCP client session whose server is
// configured with a fresh export directory, plus that directory.
func setupExportSession(t *testing.T, ca *cert.CA, store flow.Store) (*gomcp.ClientSession, string) {
	t.Helper()
	dir := t.TempDir()
	s := newServer(context.Background(), ca, store, nil, WithExportDir(dir))
	return connectTestSession(t, s), dir
}

// connectTestSession connects an in-memory MCP client to s.
func connectTestSession(t *testing.T, s *Server) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// resultText returns the first text content of a tool result.
func resultText(t *testing.T, result *gomcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result has no content")
	}
	tc, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	return tc.Text
}

// exportFixture is the directory layout the resolver table runs against.
type exportFixture struct {
	root    string // export directory
	outside string // a directory outside the export directory
}

func newExportFixture(t *testing.T) exportFixture {
	t.Helper()
	f := exportFixture{root: t.TempDir(), outside: t.TempDir()}
	mustMkdir(t, filepath.Join(f.root, "sub"))
	mustWrite(t, filepath.Join(f.root, "existing.jsonl"), "{}\n")
	mustWrite(t, filepath.Join(f.outside, "secret.json"), `{"allows":[]}`)
	// Directory symlink inside the root that points outside it.
	mustSymlink(t, f.outside, filepath.Join(f.root, "escape"))
	// File symlink inside the root that points outside it.
	mustSymlink(t, filepath.Join(f.outside, "secret.json"), filepath.Join(f.root, "link.jsonl"))
	// File symlink inside the root that points at a file inside it.
	mustSymlink(t, filepath.Join(f.root, "existing.jsonl"), filepath.Join(f.root, "inlink.jsonl"))
	return f
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}

// TestResolveExportPath is T5: the resolver accepts paths inside the
// export directory and rejects everything that would read or write
// outside it.
func TestResolveExportPath(t *testing.T) {
	t.Parallel()
	f := newExportFixture(t)

	type want int
	const (
		wantOK want = iota
		wantOutside
		wantErr
	)
	cases := []struct {
		name      string
		requested string
		want      want
		wantAbs   string // for wantOK
		errSubstr string // for wantErr
	}{
		{name: "relative file", requested: "flows.jsonl", want: wantOK, wantAbs: filepath.Join(f.root, "flows.jsonl")},
		{name: "relative file in existing subdir", requested: "sub/flows.har", want: wantOK, wantAbs: filepath.Join(f.root, "sub", "flows.har")},
		{name: "relative overwrite of existing file", requested: "existing.jsonl", want: wantOK, wantAbs: filepath.Join(f.root, "existing.jsonl")},
		{name: "relative with harmless dot-dot", requested: "sub/../flows.jsonl", want: wantOK, wantAbs: filepath.Join(f.root, "flows.jsonl")},
		{name: "absolute inside root", requested: filepath.Join(f.root, "abs.jsonl"), want: wantOK, wantAbs: filepath.Join(f.root, "abs.jsonl")},
		{name: "absolute inside root subdir", requested: filepath.Join(f.root, "sub", "abs.jsonl"), want: wantOK, wantAbs: filepath.Join(f.root, "sub", "abs.jsonl")},

		{name: "absolute outside root", requested: filepath.Join(f.outside, "secret.json"), want: wantOutside},
		{name: "absolute outside root, nonexistent", requested: filepath.Join(f.outside, "new.json"), want: wantOutside},
		{name: "relative parent escape", requested: "../x.jsonl", want: wantOutside},
		{name: "relative nested parent escape", requested: "a/../../x.jsonl", want: wantOutside},
		{name: "absolute root prefix sibling", requested: f.root + "-sibling/x.jsonl", want: wantOutside},
		{name: "dir symlink escaping root (relative)", requested: "escape/secret.json", want: wantOutside},
		{name: "dir symlink escaping root (absolute)", requested: filepath.Join(f.root, "escape", "secret.json"), want: wantOutside},
		{name: "dir symlink escaping root, new file", requested: "escape/new.json", want: wantOutside},

		{name: "final-component symlink to outside", requested: "link.jsonl", want: wantErr, errSubstr: "symbolic link"},
		{name: "final-component symlink to inside", requested: "inlink.jsonl", want: wantErr, errSubstr: "symbolic link"},
		{name: "missing subdirectory", requested: "missing/flows.jsonl", want: wantErr, errSubstr: "does not exist"},
		{name: "empty path", requested: "", want: wantErr, errSubstr: "must not be empty"},
		{name: "NUL byte", requested: "flo\x00ws.jsonl", want: wantErr, errSubstr: "NUL"},
		{name: "export directory itself (relative)", requested: ".", want: wantErr, errSubstr: "must name a file"},
		{name: "export directory itself (absolute)", requested: f.root, want: wantErr, errSubstr: "must name a file"},
		{name: "oversized path", requested: strings.Repeat("a", 8192), want: wantErr, errSubstr: "too long"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveExportPath(f.root, tc.requested)
			switch tc.want {
			case wantOK:
				if err != nil {
					t.Fatalf("resolveExportPath(%q) error = %v, want success", tc.requested, err)
				}
				if got.abs != tc.wantAbs {
					t.Errorf("resolveExportPath(%q).abs = %q, want %q", tc.requested, got.abs, tc.wantAbs)
				}
			case wantOutside:
				var outside *exportPathOutsideError
				if !errors.As(err, &outside) {
					t.Fatalf("resolveExportPath(%q) error = %v, want *exportPathOutsideError", tc.requested, err)
				}
				if !strings.Contains(err.Error(), f.root) {
					t.Errorf("error %q does not name the export directory %q", err, f.root)
				}
				if !strings.Contains(err.Error(), "-export-dir") || !strings.Contains(err.Error(), "YP_EXPORT_DIR") {
					t.Errorf("error %q does not name the -export-dir flag / YP_EXPORT_DIR env", err)
				}
			case wantErr:
				if err == nil {
					t.Fatalf("resolveExportPath(%q) = %+v, want error containing %q", tc.requested, got, tc.errSubstr)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("resolveExportPath(%q) error = %q, want substring %q", tc.requested, err, tc.errSubstr)
				}
			}
		})
	}
}

// TestResolveExportPath_RootUnavailable covers the two fail-closed root
// states: no export directory configured, and a configured directory
// that does not exist (e.g. default-root creation failed at boot).
func TestResolveExportPath_RootUnavailable(t *testing.T) {
	t.Parallel()

	if _, err := resolveExportPath("", "flows.jsonl"); err == nil {
		t.Error("resolveExportPath with no export directory: want error, got nil")
	} else if !strings.Contains(err.Error(), "-export-dir") {
		t.Errorf("error %q does not point at -export-dir", err)
	}

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := resolveExportPath(missing, "flows.jsonl"); err == nil {
		t.Error("resolveExportPath with missing export directory: want error, got nil")
	} else if !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "-export-dir") {
		t.Errorf("error %q does not name the missing root %q and the -export-dir flag", err, missing)
	}
}

// TestManageExportImport_RoundTripByRelativeName is T6 (legit path): a
// relative output_path lands in the export directory, the response
// reports the absolute path, and import reads it back by the same
// relative name.
func TestManageExportImport_RoundTripByRelativeName(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs, dir := setupExportSession(t, newTestCA(t), store)

	makeRealisticTestSession(t, store,
		"550e8400-e29b-41d4-a716-446655441127",
		"550e8400-e29b-41d4-a716-446655441128",
		"550e8400-e29b-41d4-a716-446655441129",
		"HTTPS", true)

	const name = "usk1127-roundtrip.jsonl"
	exportResult := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{"output_path": name},
	})
	if exportResult.IsError {
		t.Fatalf("export returned error: %s", resultText(t, exportResult))
	}
	var exportRes executeExportFlowsResult
	if err := json.Unmarshal([]byte(resultText(t, exportResult)), &exportRes); err != nil {
		t.Fatalf("unmarshal export result: %v", err)
	}
	wantPath := filepath.Join(dir, name)
	if exportRes.OutputPath != wantPath {
		t.Errorf("export output_path = %q, want %q", exportRes.OutputPath, wantPath)
	}
	if _, err := os.Stat(wantPath); err != nil {
		t.Fatalf("exported file not in export directory: %v", err)
	}

	if res := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{"confirm": true},
	}); res.IsError {
		t.Fatalf("delete returned error: %s", resultText(t, res))
	}

	importResult := manageCallTool(t, cs, map[string]any{
		"action": "import_flows",
		"params": map[string]any{"input_path": name},
	})
	if importResult.IsError {
		t.Fatalf("import returned error: %s", resultText(t, importResult))
	}
	importRes := parseMCPImportResult(t, importResult)
	if importRes.Imported != 1 {
		t.Errorf("imported = %d, want 1", importRes.Imported)
	}
	if importRes.Source != wantPath {
		t.Errorf("import source = %q, want %q", importRes.Source, wantPath)
	}
}

// TestManageExport_OutsideExportDirRejected is T6 (attack path, write
// side): export_flows to an absolute path outside the export directory
// or to a relative escape is refused for both JSONL and HAR, and the
// target file is left untouched.
func TestManageExport_OutsideExportDirRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs, dir := setupExportSession(t, newTestCA(t), store)
	makeExportTestSession(t, store, "sess-usk1127-out")

	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "policy.json")
	const original = `{"allows":[{"hostname":"target.example"}]}`
	mustWrite(t, victim, original)

	cases := []struct {
		name   string
		params map[string]any
	}{
		{"jsonl absolute outside", map[string]any{"output_path": victim}},
		{"har absolute outside", map[string]any{"format": "har", "output_path": victim}},
		{"jsonl relative escape", map[string]any{"output_path": "../" + filepath.Base(victimDir) + "/policy.json"}},
		{"har relative escape", map[string]any{"format": "har", "output_path": "../../../../../../../../" + strings.TrimPrefix(victim, "/")}},
	}
	for _, tc := range cases {
		res := manageCallTool(t, cs, map[string]any{"action": "export_flows", "params": tc.params})
		if !res.IsError {
			t.Errorf("%s: export_flows succeeded, want rejection: %s", tc.name, resultText(t, res))
			continue
		}
		text := resultText(t, res)
		if !strings.Contains(text, "outside export directory") || !strings.Contains(text, dir) {
			t.Errorf("%s: error = %q, want 'outside export directory' naming %q", tc.name, text, dir)
		}
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("read victim: %v", err)
	}
	if string(got) != original {
		t.Errorf("victim file was overwritten: %q", got)
	}
}

// TestManageImport_OutsideExportDirRejected is T6 (attack path, read
// side): import_flows from a path outside the export directory is
// refused and nothing is imported.
func TestManageImport_OutsideExportDirRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs, dir := setupExportSession(t, newTestCA(t), store)

	// Produce a valid JSONL export, then move it outside the root.
	makeRealisticTestSession(t, store,
		"550e8400-e29b-41d4-a716-446655441130",
		"550e8400-e29b-41d4-a716-446655441131",
		"550e8400-e29b-41d4-a716-446655441132",
		"HTTPS", true)
	var buf strings.Builder
	if _, err := flow.ExportStreams(context.Background(), store, &buf, flow.ExportOptions{IncludeBodies: true}); err != nil {
		t.Fatalf("ExportStreams: %v", err)
	}
	if _, err := store.DeleteAllStreams(context.Background()); err != nil {
		t.Fatalf("DeleteAllStreams: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "flows.jsonl")
	mustWrite(t, outside, buf.String())

	res := manageCallTool(t, cs, map[string]any{
		"action": "import_flows",
		"params": map[string]any{"input_path": outside},
	})
	if !res.IsError {
		t.Fatalf("import_flows from outside the export directory succeeded: %s", resultText(t, res))
	}
	if text := resultText(t, res); !strings.Contains(text, "outside export directory") || !strings.Contains(text, dir) {
		t.Errorf("error = %q, want 'outside export directory' naming %q", text, dir)
	}
	n, err := store.CountStreams(context.Background(), flow.StreamListOptions{})
	if err != nil {
		t.Fatalf("CountStreams: %v", err)
	}
	if n != 0 {
		t.Errorf("streams after rejected import = %d, want 0", n)
	}
}

// TestManageExport_NoExportDirFailsClosed: a server built without an
// export directory refuses file export/import rather than falling back
// to the process cwd. Inline JSONL export keeps working.
func TestManageExport_NoExportDirFailsClosed(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)
	makeExportTestSession(t, store, "sess-usk1127-noroot")

	res := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{"output_path": "usk1127-noroot.jsonl"},
	})
	if !res.IsError {
		t.Errorf("file export without an export directory succeeded: %s", resultText(t, res))
	} else if text := resultText(t, res); !strings.Contains(text, "-export-dir") {
		t.Errorf("error = %q, want a pointer to -export-dir", text)
	}

	inline := manageCallTool(t, cs, map[string]any{"action": "export_flows", "params": map[string]any{}})
	if inline.IsError {
		t.Errorf("inline export failed: %s", resultText(t, inline))
	}
}

// TestQuery_ReportsExportDir is T8: remote agents learn the export
// directory from query status and query config.
func TestQuery_ReportsExportDir(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs, dir := setupExportSession(t, newTestCA(t), store)

	for _, resource := range []string{"status", "config"} {
		res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name:      "query",
			Arguments: map[string]any{"resource": resource},
		})
		if err != nil {
			t.Fatalf("query %s: %v", resource, err)
		}
		if res.IsError {
			t.Fatalf("query %s returned error: %s", resource, resultText(t, res))
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(resultText(t, res)), &decoded); err != nil {
			t.Fatalf("query %s: unmarshal: %v", resource, err)
		}
		if got, _ := decoded["export_dir"].(string); got != dir {
			t.Errorf("query %s export_dir = %q, want %q", resource, got, dir)
		}
	}
}

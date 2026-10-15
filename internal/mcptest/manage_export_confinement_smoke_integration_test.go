//go:build e2e

package mcptest_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1127: an MCP caller must not be able to use manage export_flows to
// overwrite a file outside the operator-configured export directory. The
// harness drives the production mcpserver.Run over JSON-RPC, so the flag
// parsing, boot wiring and tool dispatch are the ones the binary uses.

// fileSnapshot captures a file's bytes and mode so a test can prove the
// file was left untouched.
type fileSnapshot struct {
	data []byte
	mode os.FileMode
}

func snapshotFile(t *testing.T, p string) fileSnapshot {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	return fileSnapshot{data: data, mode: info.Mode()}
}

func (s fileSnapshot) assertUnchanged(t *testing.T, p string) {
	t.Helper()
	now := snapshotFile(t, p)
	if !bytes.Equal(now.data, s.data) {
		t.Errorf("%s was overwritten: now %q, want %q", p, truncate(now.data, 120), truncate(s.data, 120))
	}
	if now.mode != s.mode {
		t.Errorf("%s mode changed: now %v, want %v", p, now.mode, s.mode)
	}
}

func truncate(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// expectExportRejected calls export_flows with output_path=target in the
// given format and asserts the call is refused with an error naming the
// export directory.
func expectExportRejected(t *testing.T, h *mcptest.Harness, format, target string) {
	t.Helper()
	params := map[string]any{"output_path": target}
	if format != "" {
		params["format"] = format
	}
	res := h.CallTool(t, "manage", map[string]any{"action": "export_flows", "params": params})
	text := res.Text
	if res.Err != nil {
		text = res.Err.Error()
	}
	if res.Err == nil && !res.IsError {
		t.Fatalf("export_flows format=%q output_path=%s succeeded, want rejection: %s", format, target, res.Text)
	}
	if !strings.Contains(text, "outside export directory") || !strings.Contains(text, h.ExportDir) {
		t.Errorf("export_flows error = %q, want 'outside export directory' naming %q", text, h.ExportDir)
	}
}

// TestE2E_Manage_ExportCannotOverwritePolicyFile is T1: the agent cannot
// replace the -target-policy-file with a HAR document.
func TestE2E_Manage_ExportCannotOverwritePolicyFile(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"allows":[{"hostname":"target.example"}]}`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	before := snapshotFile(t, policyPath)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})

	expectExportRejected(t, h, "har", policyPath)
	expectExportRejected(t, h, "jsonl", policyPath)
	before.assertUnchanged(t, policyPath)
}

// TestE2E_Manage_ExportLandsInExportDir is the absolute-path half of T4:
// an absolute output_path inside the export directory is accepted and
// reported back verbatim. (The relative-path half lives in
// TestE2E_Manage_ExportFlowsHAR.)
func TestE2E_Manage_ExportLandsInExportDir(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	target := filepath.Join(h.ExportDir, "abs-inside.har")
	res := h.MustOK(t, "manage", map[string]any{
		"action": "export_flows",
		"params": map[string]any{"format": "har", "output_path": target},
	})
	if got, _ := res.Decoded["output_path"].(string); got != target {
		t.Errorf("export_flows output_path = %q, want %q", got, target)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read exported HAR: %v", err)
	}
	var har struct {
		Log struct {
			Version string `json:"version"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &har); err != nil {
		t.Fatalf("exported HAR does not parse: %v", err)
	}
	if har.Log.Version != "1.2" {
		t.Errorf("HAR log.version = %q, want 1.2", har.Log.Version)
	}
}

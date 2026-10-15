//go:build e2e && !e2e_smoke

package mcptest_test

import (
	"path/filepath"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1127 exhaustive tier: siblings of the smoke-tier policy-file case
// for the other operator-owned files an MCP caller must not overwrite.

// TestE2E_Manage_ExportCannotOverwriteConfigFile is T2: the -config file
// (here carrying an inline target_scope_policy, which a HAR overwrite
// would silently drop on the next boot) cannot be replaced.
func TestE2E_Manage_ExportCannotOverwriteConfigFile(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: `{"target_scope_policy":{"allows":[{"hostname":"target.example"}]}}`,
	})
	if h.ConfigPath == "" {
		t.Fatal("harness did not expose ConfigPath")
	}
	before := snapshotFile(t, h.ConfigPath)

	expectExportRejected(t, h, "har", h.ConfigPath)
	expectExportRejected(t, h, "jsonl", h.ConfigPath)
	before.assertUnchanged(t, h.ConfigPath)
}

// TestE2E_Manage_ExportCannotOverwriteCA is T3: the operator-provided
// CA certificate and private key cannot be replaced.
func TestE2E_Manage_ExportCannotOverwriteCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	if err := ca.Save(certPath, keyPath); err != nil {
		t.Fatalf("save CA: %v", err)
	}
	certBefore := snapshotFile(t, certPath)
	keyBefore := snapshotFile(t, keyPath)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-ca-cert", certPath, "-ca-key", keyPath},
	})

	for _, target := range []string{certPath, keyPath} {
		expectExportRejected(t, h, "har", target)
		expectExportRejected(t, h, "jsonl", target)
	}
	certBefore.assertUnchanged(t, certPath)
	keyBefore.assertUnchanged(t, keyPath)
}

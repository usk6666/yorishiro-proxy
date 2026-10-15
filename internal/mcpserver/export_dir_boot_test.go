package mcpserver

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
)

// USK-1127 T7: the server refuses to start when the export directory
// (the only place manage export_flows may write) contains a file the
// operator relies on — policy, config, CA, DB, log, WebUI assets, plugin
// scripts — so an MCP caller can never overwrite it. Every case drives
// the production entry point (Run). -no-http-mcp without -stdio-mcp makes
// a fully booted server return "no MCP transport enabled" instead of
// blocking, so "boot proceeded past the check" is observable.

const bootPassedSentinel = "no MCP transport enabled"

// runBoot runs the production entry point with args and returns its error.
func runBoot(t *testing.T, args []string) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := flag.NewFlagSet("usk1127", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})
	return Run(ctx, fs, append(args, "-no-http-mcp"), RunOptions{Version: "test"})
}

func writeFile(t *testing.T, p, content string) string {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func mkdir(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
	return p
}

// saveTestCA writes a freshly generated CA to certPath / keyPath.
func saveTestCA(t *testing.T, certPath, keyPath string) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	if err := ca.Save(certPath, keyPath); err != nil {
		t.Fatalf("save CA: %v", err)
	}
}

func TestRun_RefusesExportDirContainingProtectedPaths(t *testing.T) {
	cases := []struct {
		name string
		// setup returns the Run args (excluding -export-dir) and the
		// protected path the refusal must name. exportDir already exists;
		// outside is a scratch directory outside it.
		setup func(t *testing.T, exportDir, outside string) (args []string, protected string)
		// exportDirArg, when set, overrides the -export-dir value.
		exportDirArg func(exportDir, outside string) string
	}{
		{
			name: "target policy file",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				p := writeFile(t, filepath.Join(exportDir, "policy.json"), `{"allows":[{"hostname":"target.example"}]}`)
				return []string{"-target-policy-file", p, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, p
			},
		},
		{
			name: "config file",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				p := writeFile(t, filepath.Join(exportDir, "config.json"), `{}`)
				return []string{"-config", p, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, p
			},
		},
		{
			name: "explicit CA certificate",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				certPath, keyPath := filepath.Join(exportDir, "ca.crt"), filepath.Join(outside, "ca.key")
				saveTestCA(t, certPath, keyPath)
				return []string{"-ca-cert", certPath, "-ca-key", keyPath, "-db", filepath.Join(outside, "f.db")}, certPath
			},
		},
		{
			name: "explicit CA private key",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				certPath, keyPath := filepath.Join(outside, "ca.crt"), filepath.Join(exportDir, "ca.key")
				saveTestCA(t, certPath, keyPath)
				return []string{"-ca-cert", certPath, "-ca-key", keyPath, "-db", filepath.Join(outside, "f.db")}, keyPath
			},
		},
		{
			name: "database",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				p := filepath.Join(exportDir, "flows.db")
				return []string{"-db", p, "-ca-ephemeral"}, p
			},
		},
		{
			name: "log file",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				p := filepath.Join(exportDir, "proxy.log")
				return []string{"-log-file", p, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, p
			},
		},
		{
			name: "WebUI directory inside export directory",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				p := mkdir(t, filepath.Join(exportDir, "ui"))
				return []string{"-ui-dir", p, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, p
			},
		},
		{
			name: "export directory inside WebUI directory",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				ui := filepath.Dir(exportDir)
				return []string{"-ui-dir", ui, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, ui
			},
		},
		{
			name: "plugin script",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				script := writeFile(t, filepath.Join(exportDir, "p.star"), "")
				cfg := writeFile(t, filepath.Join(outside, "config.json"), `{"plugins":[{"path":"`+script+`"}]}`)
				return []string{"-config", cfg, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, script
			},
		},
		{
			name: "export directory given through a symlink",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				p := writeFile(t, filepath.Join(exportDir, "policy.json"), `{"allows":[{"hostname":"target.example"}]}`)
				return []string{"-target-policy-file", p, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, p
			},
			exportDirArg: func(exportDir, outside string) string {
				link := filepath.Join(outside, "exports-link")
				if err := os.Symlink(exportDir, link); err != nil {
					panic(err)
				}
				return link
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exportDir := mkdir(t, filepath.Join(t.TempDir(), "exports"))
			outside := t.TempDir()
			args, protected := tc.setup(t, exportDir, outside)
			dirArg := exportDir
			if tc.exportDirArg != nil {
				dirArg = tc.exportDirArg(exportDir, outside)
			}
			err := runBoot(t, append([]string{"-export-dir", dirArg}, args...))
			if err == nil || strings.Contains(err.Error(), bootPassedSentinel) {
				t.Fatalf("Run booted with %s inside the export directory (err = %v), want refusal", tc.name, err)
			}
			if !strings.Contains(err.Error(), "export directory") || !strings.Contains(err.Error(), filepath.Base(protected)) {
				t.Errorf("Run error = %q, want refusal naming the export directory and %q", err, protected)
			}
		})
	}
}

// TestRun_RefusesHomeExportDirWithDefaultCA: -export-dir $HOME with the
// auto-persisted default CA (~/.yorishiro-proxy/ca/) must be refused even
// though no CA flag was given.
func TestRun_RefusesHomeExportDirWithDefaultCA(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	err := runBoot(t, []string{"-export-dir", home, "-db", filepath.Join(t.TempDir(), "f.db")})
	if err == nil || strings.Contains(err.Error(), bootPassedSentinel) {
		t.Fatalf("Run booted with -export-dir $HOME and the default persisted CA (err = %v), want refusal", err)
	}
	if !strings.Contains(err.Error(), "export directory") || !strings.Contains(err.Error(), "ca.crt") {
		t.Errorf("Run error = %q, want refusal naming the export directory and ca.crt", err)
	}
}

// TestRun_AcceptsDefaultExportLayout: with every path at its default
// (~/.yorishiro-proxy/{yorishiro.db,ca/,exports/}) the server boots and
// creates the default export directory with mode 0700.
func TestRun_AcceptsDefaultExportLayout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("YP_EXPORT_DIR", "")
	err := runBoot(t, nil)
	if err == nil || !strings.Contains(err.Error(), bootPassedSentinel) {
		t.Fatalf("Run with the default layout: err = %v, want boot to proceed (%q)", err, bootPassedSentinel)
	}
	exports := filepath.Join(home, ".yorishiro-proxy", "exports")
	info, statErr := os.Stat(exports)
	if statErr != nil {
		t.Fatalf("default export directory not created: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", exports)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("default export directory mode = %04o, want 0700", perm)
	}
}

// TestRun_AcceptsSeparateExportDir: an explicit export directory that
// overlaps nothing boots normally.
func TestRun_AcceptsSeparateExportDir(t *testing.T) {
	base := t.TempDir()
	exportDir := mkdir(t, filepath.Join(base, "exports"))
	policy := writeFile(t, filepath.Join(base, "policy.json"), `{"allows":[{"hostname":"target.example"}]}`)
	err := runBoot(t, []string{
		"-export-dir", exportDir,
		"-target-policy-file", policy,
		"-db", filepath.Join(base, "flows.db"),
		"-log-file", filepath.Join(base, "proxy.log"),
		"-ca-ephemeral",
	})
	if err == nil || !strings.Contains(err.Error(), bootPassedSentinel) {
		t.Fatalf("Run with a separate export directory: err = %v, want boot to proceed (%q)", err, bootPassedSentinel)
	}
}

// TestRun_RejectsMissingExplicitExportDir: an operator-supplied
// -export-dir must exist (sibling of body_spill_dir validation); only the
// default directory is created on demand.
func TestRun_RejectsMissingExplicitExportDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	err := runBoot(t, []string{"-export-dir", missing, "-db", filepath.Join(t.TempDir(), "f.db"), "-ca-ephemeral"})
	if err == nil || !strings.Contains(err.Error(), "invalid configuration") || !strings.Contains(err.Error(), missing) {
		t.Fatalf("Run with missing -export-dir: err = %v, want invalid configuration naming %q", err, missing)
	}
}

package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
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
// the production entry point (Run). The OnBootComplete hook makes a fully
// booted server return bootPassedSentinel instead of starting its
// transports, so "boot proceeded past the check" is observable.

const bootPassedSentinel = "usk1127 test: boot completed"

// runBoot runs the production entry point with args and returns its error.
func runBoot(t *testing.T, args []string) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := flag.NewFlagSet("usk1127", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})
	return Run(ctx, fs, append(args, "-mcp-http-addr", "127.0.0.1:0"), RunOptions{
		Version:        "test",
		OnBootComplete: func() error { return errors.New(bootPassedSentinel) },
		// Backstop: reached only if OnBootComplete stopped aborting Run;
		// end it so that is an assertion failure, not a hang.
		OnHTTPListening: func(string) { cancel() },
	})
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

// writeJSON marshals v into p (so paths are escaped correctly on every OS).
func writeJSON(t *testing.T, p string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", p, err)
	}
	return writeFile(t, p, string(data))
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
		exportDirArg func(t *testing.T, exportDir, outside string) string
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
			name: "config client_cert file",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				certPath, keyPath := filepath.Join(exportDir, "client.crt"), filepath.Join(outside, "client.key")
				saveTestCA(t, certPath, keyPath)
				cfg := writeJSON(t, filepath.Join(outside, "config.json"), map[string]any{"client_cert": certPath, "client_key": keyPath})
				return []string{"-config", cfg, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, certPath
			},
		},
		{
			name: "config client_key file",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				certPath, keyPath := filepath.Join(outside, "client.crt"), filepath.Join(exportDir, "client.key")
				saveTestCA(t, certPath, keyPath)
				cfg := writeJSON(t, filepath.Join(outside, "config.json"), map[string]any{"client_cert": certPath, "client_key": keyPath})
				return []string{"-config", cfg, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, keyPath
			},
		},
		{
			name: "host_tls client_cert file",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				certPath, keyPath := filepath.Join(exportDir, "host.crt"), filepath.Join(outside, "host.key")
				saveTestCA(t, certPath, keyPath)
				cfg := writeJSON(t, filepath.Join(outside, "config.json"), map[string]any{
					"host_tls": map[string]any{"api.example.com": map[string]any{"client_cert": certPath, "client_key": keyPath}},
				})
				return []string{"-config", cfg, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, certPath
			},
		},
		{
			name: "host_tls client_key file",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				certPath, keyPath := filepath.Join(outside, "host.crt"), filepath.Join(exportDir, "host.key")
				saveTestCA(t, certPath, keyPath)
				cfg := writeJSON(t, filepath.Join(outside, "config.json"), map[string]any{
					"host_tls": map[string]any{"api.example.com": map[string]any{"client_cert": certPath, "client_key": keyPath}},
				})
				return []string{"-config", cfg, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, keyPath
			},
		},
		{
			name: "host_tls ca_bundle file",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				bundle := filepath.Join(exportDir, "bundle.pem")
				saveTestCA(t, bundle, filepath.Join(outside, "bundle.key"))
				cfg := writeJSON(t, filepath.Join(outside, "config.json"), map[string]any{
					"host_tls": map[string]any{"api.example.com": map[string]any{"ca_bundle": bundle}},
				})
				return []string{"-config", cfg, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, bundle
			},
		},
		{
			name: "export directory given through a symlink",
			setup: func(t *testing.T, exportDir, outside string) ([]string, string) {
				p := writeFile(t, filepath.Join(exportDir, "policy.json"), `{"allows":[{"hostname":"target.example"}]}`)
				return []string{"-target-policy-file", p, "-db", filepath.Join(outside, "f.db"), "-ca-ephemeral"}, p
			},
			exportDirArg: func(t *testing.T, exportDir, outside string) string {
				link := filepath.Join(outside, "exports-link")
				if err := os.Symlink(exportDir, link); err != nil {
					t.Fatalf("symlink %s -> %s: %v", link, exportDir, err)
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
				dirArg = tc.exportDirArg(t, exportDir, outside)
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

// TestRun_RefusesExportDirContainingServerJSON: server.json
// (~/.yorishiro-proxy/server.json, holding the MCP HTTP Bearer token) is
// protected even with -db / CA moved elsewhere, which also makes $HOME
// itself (and any ancestor) an unusable export directory.
func TestRun_RefusesExportDirContainingServerJSON(t *testing.T) {
	cases := []struct {
		name      string
		exportDir func(home string) string
	}{
		{name: "export dir is ~/.yorishiro-proxy", exportDir: func(home string) string {
			return mkdir(t, filepath.Join(home, ".yorishiro-proxy"))
		}},
		{name: "export dir is $HOME", exportDir: func(home string) string { return home }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			outside := t.TempDir()
			err := runBoot(t, []string{
				"-export-dir", tc.exportDir(home),
				"-db", filepath.Join(outside, "f.db"),
				"-ca-ephemeral",
			})
			if err == nil || strings.Contains(err.Error(), bootPassedSentinel) {
				t.Fatalf("Run booted with server.json inside the export directory (err = %v), want refusal", err)
			}
			if !strings.Contains(err.Error(), "export directory") || !strings.Contains(err.Error(), "server.json") {
				t.Errorf("Run error = %q, want refusal naming the export directory and server.json", err)
			}
		})
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

// TestInsideDir covers the identity (os.SameFile) branch of the boot
// isolation check (S-2). The path is passed unresolved, so the lexical
// comparison misses the symlinked alias exactly as it would miss a
// case-variant spelling on a case-insensitive filesystem or a bind mount;
// only the ancestor walk recognises it.
func TestInsideDir(t *testing.T) {
	base := t.TempDir()
	dir := mkdir(t, filepath.Join(base, "exports"))
	mkdir(t, filepath.Join(dir, "sub"))
	other := mkdir(t, filepath.Join(base, "other"))
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatalf("symlink %s -> %s: %v", alias, dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}

	cases := []struct {
		name    string
		dirInfo os.FileInfo
		p       string
		want    bool
	}{
		{name: "lexically inside", dirInfo: info, p: filepath.Join(dir, "policy.json"), want: true},
		{name: "dir itself", dirInfo: info, p: dir, want: true},
		{name: "alias, existing parent", dirInfo: info, p: filepath.Join(alias, "sub", "policy.json"), want: true},
		{name: "alias, missing tail", dirInfo: info, p: filepath.Join(alias, "missing", "flows.db"), want: true},
		{name: "alias, dir itself", dirInfo: info, p: alias, want: true},
		{name: "alias without identity info (lexical only)", dirInfo: nil, p: filepath.Join(alias, "policy.json"), want: false},
		{name: "unrelated directory", dirInfo: info, p: filepath.Join(other, "policy.json"), want: false},
		{name: "parent of dir", dirInfo: info, p: base, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := insideDir(dir, tc.dirInfo, tc.p); got != tc.want {
				t.Errorf("insideDir(%q, %q) = %v, want %v", dir, tc.p, got, tc.want)
			}
		})
	}
}

// TestCheckExportDirIsolation_CaseVariant: on a case-insensitive
// filesystem (macOS / Windows defaults) a protected path spelled with a
// different case than the export directory must still be refused, in
// both directions. Skipped on case-sensitive filesystems.
func TestCheckExportDirIsolation_CaseVariant(t *testing.T) {
	base := t.TempDir()
	exportDir := mkdir(t, filepath.Join(base, "ui", "exports"))
	upperExports := filepath.Join(base, "ui", "EXPORTS")
	exportInfo, err := os.Stat(exportDir)
	if err != nil {
		t.Fatalf("stat %s: %v", exportDir, err)
	}
	if fi, err := os.Stat(upperExports); err != nil || !os.SameFile(exportInfo, fi) {
		t.Skip("case-sensitive filesystem: a case-variant spelling is a different path")
	}

	err = checkExportDirIsolation(exportDir, []protectedPath{
		{what: "-target-policy-file", path: filepath.Join(upperExports, "policy.json")},
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("checkExportDirIsolation with a case-variant policy path: err = %v, want refusal", err)
	}

	err = checkExportDirIsolation(exportDir, []protectedPath{
		{what: "-ui-dir", path: filepath.Join(base, "UI"), isDir: true},
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Errorf("checkExportDirIsolation with a case-variant -ui-dir ancestor: err = %v, want refusal", err)
	}
}

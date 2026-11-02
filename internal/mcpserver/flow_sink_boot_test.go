package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// USK-1119: the flow sink directory is written by the proxy and read by an
// external consumer. The MCP manage tool must not be able to plant or
// overwrite files there (export_flows) or read them back (import_flows),
// so boot refuses a sink directory inside the export directory and an
// export directory inside the sink directory.

func TestRun_RefusesFlowSinkDirOverlappingExportDir(t *testing.T) {
	cases := []struct {
		name string
		// dirs returns (export dir, sink dir).
		dirs func(base string) (string, string)
	}{
		{"sink dir inside export dir", func(base string) (string, string) {
			e := filepath.Join(base, "exports")
			return e, filepath.Join(e, "sink")
		}},
		{"export dir inside sink dir", func(base string) (string, string) {
			s := filepath.Join(base, "sink")
			return filepath.Join(s, "exports"), s
		}},
		{"same directory", func(base string) (string, string) {
			d := filepath.Join(base, "shared")
			return d, d
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			exportDir, sinkDir := tc.dirs(base)
			mkdir(t, exportDir)
			mkdir(t, sinkDir)
			cfg := writeJSON(t, filepath.Join(base, "config.json"), map[string]any{
				"flow_sink": map[string]any{"dir": sinkDir},
			})
			err := runBoot(t, []string{"-export-dir", exportDir, "-config", cfg, "-db", filepath.Join(base, "f.db"), "-ca-ephemeral"})
			if err == nil || strings.Contains(err.Error(), bootPassedSentinel) {
				t.Fatalf("Run booted with %s (err = %v), want refusal", tc.name, err)
			}
			if !strings.Contains(err.Error(), "export directory") || !strings.Contains(err.Error(), "flow_sink") {
				t.Errorf("Run error = %q, want a refusal naming the export directory and flow_sink", err)
			}
		})
	}
}

// TestRun_FlowSinkConfigStartsSink: a separate flow_sink.dir boots, and
// the sink's active file exists once boot completes (config → runtime).
func TestRun_FlowSinkConfigStartsSink(t *testing.T) {
	base := t.TempDir()
	exportDir := mkdir(t, filepath.Join(base, "exports"))
	sinkDir := filepath.Join(base, "sink") // created by the sink
	cfg := writeJSON(t, filepath.Join(base, "config.json"), map[string]any{
		"flow_sink": map[string]any{"dir": sinkDir, "max_file_bytes": 4096},
	})
	err := runBoot(t, []string{"-export-dir", exportDir, "-config", cfg, "-db", filepath.Join(base, "f.db"), "-ca-ephemeral"})
	if err == nil || !strings.Contains(err.Error(), bootPassedSentinel) {
		t.Fatalf("Run with a flow sink: err = %v, want boot to proceed (%q)", err, bootPassedSentinel)
	}
	if _, statErr := os.Stat(filepath.Join(sinkDir, "flows.jsonl")); statErr != nil {
		t.Fatalf("flow sink file not created at boot: %v", statErr)
	}
}

// TestRun_RefusesUnusableFlowSinkDir: a sink that cannot open its file
// refuses boot instead of running without the replica.
func TestRun_RefusesUnusableFlowSinkDir(t *testing.T) {
	base := t.TempDir()
	exportDir := mkdir(t, filepath.Join(base, "exports"))
	// flows.jsonl is a directory, so the sink cannot open its file. (A
	// dir below a regular file would be refused earlier, by the export
	// directory isolation check, and never reach the sink.)
	sinkDir := mkdir(t, filepath.Join(base, "sink"))
	mkdir(t, filepath.Join(sinkDir, "flows.jsonl"))
	cfg := writeJSON(t, filepath.Join(base, "config.json"), map[string]any{
		"flow_sink": map[string]any{"dir": sinkDir},
	})
	err := runBoot(t, []string{"-export-dir", exportDir, "-config", cfg, "-db", filepath.Join(base, "f.db"), "-ca-ephemeral"})
	if err == nil || strings.Contains(err.Error(), bootPassedSentinel) {
		t.Fatalf("Run booted with an unusable flow sink dir (err = %v), want refusal", err)
	}
	if !strings.Contains(err.Error(), "flow sink") {
		t.Errorf("Run error = %q, want it to name the flow sink", err)
	}
}

package mcpserver

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sandboxBootEnv points HOME at a fresh temp dir and clears the YP_* env
// vars that would otherwise redirect boot side effects (DB, CA, log,
// export dir) somewhere the test does not look.
func sandboxBootEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	for _, k := range []string{"YP_DB", "YP_CA_CERT", "YP_CA_KEY", "YP_CA_EPHEMERAL", "YP_LOG_FILE", "YP_EXPORT_DIR", "YP_STDIO_MCP", "YP_NO_HTTP_MCP", "YP_MCP_HTTP_ADDR", "YP_CONFIG", "YP_TARGET_POLICY_FILE"} {
		t.Setenv(k, "")
	}
	return home
}

// TestRun_RejectsAllTransportsDisabled_LeavesNothingOnDisk is USK-1208 T0:
// a boot refused because no MCP transport is enabled is a configuration
// error, so — like every other check in checkResolvedConfig — it must be
// raised before any infrastructure exists. Persisted CA, default export
// directory, explicit DB and log paths are all in play so each side
// effect has a place to show up.
func TestRun_RejectsAllTransportsDisabled_LeavesNothingOnDisk(t *testing.T) {
	home := sandboxBootEnv(t)
	work := t.TempDir()
	dbPath := filepath.Join(work, "flows.db")
	logPath := filepath.Join(work, "proxy.log")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fs := flag.NewFlagSet("usk1208-no-transport", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})
	err := Run(ctx, fs, []string{
		"-db", dbPath,
		"-log-file", logPath,
		"-no-http-mcp",
	}, RunOptions{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "no MCP transport enabled: use -stdio-mcp or remove -no-http-mcp") {
		t.Fatalf("Run error = %v, want the \"no MCP transport enabled\" refusal", err)
	}

	for _, p := range []string{
		dbPath,
		logPath,
		filepath.Join(home, ".yorishiro-proxy"), // CA dir, default export dir, server.json
	} {
		if _, statErr := os.Lstat(p); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("refused boot left %s on disk (stat err = %v)", p, statErr)
		}
	}
	entries, _ := os.ReadDir(work)
	for _, e := range entries {
		t.Errorf("refused boot left %s in the work dir", e.Name())
	}
}

// TestRun_OnBootCompleteAbortsBeforeServers is USK-1208 T0b: the
// OnBootComplete hook fires once boot side effects exist and before any MCP
// transport starts; its error is what Run returns.
func TestRun_OnBootCompleteAbortsBeforeServers(t *testing.T) {
	home := sandboxBootEnv(t)
	work := t.TempDir()
	dbPath := filepath.Join(work, "flows.db")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fs := flag.NewFlagSet("usk1208-hook", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})

	errStop := errors.New("boot complete: stop here")
	var hookCalls, listening atomic.Int32
	var dbAtHook atomic.Bool
	err := Run(ctx, fs, []string{
		"-db", dbPath,
		"-ca-ephemeral",
		"-mcp-http-addr", "127.0.0.1:0",
		"-log-level", "error",
	}, RunOptions{
		Version: "test",
		OnBootComplete: func() error {
			hookCalls.Add(1)
			_, statErr := os.Stat(dbPath)
			dbAtHook.Store(statErr == nil)
			return errStop
		},
		OnHTTPListening: func(string) {
			// Reached only when the hook did not abort; end Run so a
			// missing hook is an assertion failure, not a hang.
			listening.Add(1)
			cancel()
		},
	})
	if !errors.Is(err, errStop) {
		t.Errorf("Run error = %v, want the OnBootComplete error", err)
	}
	if got := hookCalls.Load(); got != 1 {
		t.Errorf("OnBootComplete called %d times, want 1", got)
	}
	if !dbAtHook.Load() {
		t.Error("OnBootComplete fired before the flow DB was created")
	}
	if got := listening.Load(); got != 0 {
		t.Errorf("HTTP MCP listener started %d times despite OnBootComplete aborting", got)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".yorishiro-proxy", "server.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("server.json written despite OnBootComplete aborting (stat err = %v)", statErr)
	}
}

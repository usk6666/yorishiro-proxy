package mcpserver

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// errPositionalSentinel is returned from OnBootComplete so a boot that was
// NOT refused stops before any MCP transport starts.
var errPositionalSentinel = errors.New("boot complete: positional-args sentinel")

// runPositionalBoot runs Run with args in a sandboxed HOME and returns its
// error. A boot that gets past flag handling stops at OnBootComplete with
// errPositionalSentinel; a listener that starts anyway cancels Run so a
// missing check fails an assertion instead of hanging.
func runPositionalBoot(t *testing.T, args []string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fs := flag.NewFlagSet("usk1047-positional", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})
	return Run(ctx, fs, args, RunOptions{
		Version:         "test",
		OnBootComplete:  func() error { return errPositionalSentinel },
		OnHTTPListening: func(string) { cancel() },
	})
}

// TestRun_RejectsPositionalArguments_LeavesNothingOnDisk is USK-1047 T4:
// the server takes flags only. Go's flag package stops at the first
// non-flag token and silently drops the rest, so `-insecure true -db x`
// used to boot with -db ignored. Any leftover positional must be refused
// before a single side effect (DB, log, CA, export dir, server.json).
func TestRun_RejectsPositionalArguments_LeavesNothingOnDisk(t *testing.T) {
	tests := []struct {
		name string
		// args gets the per-test db/log paths appended after a "-db"/"-log-file"
		// prefix so the dropped-flag case is observable on disk.
		build func(db, log string) []string
		word  string
	}{
		{
			name:  "space-separated boolean value",
			build: func(db, log string) []string { return []string{"-log-file", log, "-insecure", "true", "-db", db} },
			word:  "true",
		},
		{
			name:  "trailing extra word",
			build: func(db, log string) []string { return []string{"-db", db, "-log-file", log, "extra"} },
			word:  "extra",
		},
		{
			name: "subcommand after server flags",
			build: func(db, log string) []string {
				return []string{"-db", db, "-log-file", log, "client", "query", "resource=flows"}
			},
			word: "client",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := sandboxBootEnv(t)
			work := t.TempDir()
			dbPath := filepath.Join(work, "flows.db")
			logPath := filepath.Join(work, "proxy.log")

			err := runPositionalBoot(t, tt.build(dbPath, logPath))
			if err == nil || !strings.Contains(err.Error(), `unexpected argument "`+tt.word+`"`) {
				t.Fatalf("Run error = %v, want an `unexpected argument %q` refusal", err, tt.word)
			}
			if !strings.Contains(err.Error(), "-flag=value") {
				t.Errorf("Run error %q does not show the -flag=value form", err)
			}

			for _, p := range []string{dbPath, logPath, filepath.Join(home, ".yorishiro-proxy")} {
				if _, statErr := os.Lstat(p); !errors.Is(statErr, os.ErrNotExist) {
					t.Errorf("refused boot left %s on disk (stat err = %v)", p, statErr)
				}
			}
		})
	}
}

// TestRun_FlagOnlyArgumentsStillBoot is USK-1047 T4b (negative control):
// flags with values — separate (`-db x`), joined (`-insecure=true`) and
// -config <file> — are not positionals and must reach the boot sentinel.
func TestRun_FlagOnlyArgumentsStillBoot(t *testing.T) {
	tests := []struct {
		name  string
		build func(work string) []string
	}{
		{"separate flag value", func(work string) []string {
			return []string{"-db", filepath.Join(work, "flows.db")}
		}},
		{"joined boolean value", func(work string) []string {
			return []string{"-insecure=true", "-db", filepath.Join(work, "flows.db")}
		}},
		{"config file", func(work string) []string {
			cfg := filepath.Join(work, "config.json")
			if err := os.WriteFile(cfg, []byte("{}"), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			return []string{"-config", cfg, "-db", filepath.Join(work, "flows.db")}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sandboxBootEnv(t)
			work := t.TempDir()
			args := append(tt.build(work), "-ca-ephemeral", "-mcp-http-addr", "127.0.0.1:0", "-log-level", "error")
			if err := runPositionalBoot(t, args); !errors.Is(err, errPositionalSentinel) {
				t.Fatalf("Run(%q) error = %v, want the OnBootComplete sentinel", args, err)
			}
		})
	}
}

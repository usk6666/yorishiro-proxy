package mcpserver

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// TestRun_RejectsUnknownMCPTool_LeavesNothingOnDisk: an allowlist naming a
// tool the server does not have is a boot error raised before any
// infrastructure exists. The error names the bad entry and lists the valid
// names.
func TestRun_RejectsUnknownMCPTool_LeavesNothingOnDisk(t *testing.T) {
	home := sandboxBootEnv(t)
	work := t.TempDir()
	dbPath := filepath.Join(work, "flows.db")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fs := flag.NewFlagSet("mcp-tools-unknown", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})

	errBooted := errors.New("boot completed")
	var hookCalls atomic.Int32
	err := Run(ctx, fs, []string{
		"-db", dbPath,
		"-ca-ephemeral",
		"-mcp-http-addr", "127.0.0.1:0",
		"-log-level", "error",
		"-mcp-tools", "resend_http,nope",
	}, RunOptions{
		Version: "test",
		OnBootComplete: func() error {
			hookCalls.Add(1)
			return errBooted
		},
		OnHTTPListening: func(string) { cancel() },
	})
	if err == nil || errors.Is(err, errBooted) {
		t.Fatalf("Run error = %v, want a refusal naming the unknown tool", err)
	}
	if !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("Run error %q does not name the unknown tool \"nope\"", err)
	}
	if !strings.Contains(err.Error(), "configure") || !strings.Contains(err.Error(), "query") {
		t.Errorf("Run error %q does not list the valid tool names", err)
	}
	if got := hookCalls.Load(); got != 0 {
		t.Errorf("OnBootComplete reached %d times despite the invalid allowlist", got)
	}
	for _, p := range []string{dbPath, filepath.Join(home, ".yorishiro-proxy")} {
		if _, statErr := os.Lstat(p); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("refused boot left %s on disk (stat err = %v)", p, statErr)
		}
	}
}

// TestRun_RejectsEmptyMCPToolElement: the shape check (Config.Validate)
// refuses an allowlist with an empty element.
func TestRun_RejectsEmptyMCPToolElement(t *testing.T) {
	sandboxBootEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fs := flag.NewFlagSet("mcp-tools-empty", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})
	err := Run(ctx, fs, []string{
		"-db", filepath.Join(t.TempDir(), "flows.db"),
		"-ca-ephemeral",
		"-log-level", "error",
		"-mcp-tools", "query,,docs",
	}, RunOptions{
		Version:         "test",
		OnBootComplete:  func() error { return errors.New("boot completed") },
		OnHTTPListening: func(string) { cancel() },
	})
	if err == nil || !strings.Contains(err.Error(), "mcp_tools") {
		t.Errorf("Run error = %v, want an mcp_tools shape error", err)
	}
}

// TestMCPToolsFlag_ParseAndEnvFallback covers the flag -> Config path: the
// flag value is split and trimmed, YP_MCP_TOOLS applies when the flag is
// absent, the flag wins over the env var, and leaving both unset keeps the
// allowlist nil (all tools).
func TestMCPToolsFlag_ParseAndEnvFallback(t *testing.T) {
	tests := []struct {
		name string
		env  string
		args []string
		want []string
	}{
		{name: "unset", want: nil},
		{name: "flag trimmed", args: []string{"-mcp-tools", " query , docs "}, want: []string{"query", "docs"}},
		{name: "env fallback", env: "resend_http,fuzz_http,query", want: []string{"resend_http", "fuzz_http", "query"}},
		{name: "flag wins over env", env: "configure", args: []string{"-mcp-tools", "query"}, want: []string{"query"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("YP_MCP_TOOLS", tt.env)
			fs := flag.NewFlagSet("mcp-tools", flag.ContinueOnError)
			fs.SetOutput(discardWriter{})
			cfg := config.Default()
			registerFlags(fs, cfg)
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("parse: %v", err)
			}
			ApplyEnvFallback(fs)
			if !slices.Equal(cfg.MCPTools, tt.want) || (cfg.MCPTools == nil) != (tt.want == nil) {
				t.Errorf("cfg.MCPTools = %#v, want %#v", cfg.MCPTools, tt.want)
			}
		})
	}
	if got := EnvVarMap["mcp-tools"]; got != "YP_MCP_TOOLS" {
		t.Errorf(`EnvVarMap["mcp-tools"] = %q, want YP_MCP_TOOLS`, got)
	}
}

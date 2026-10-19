package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/setup"
)

// sandboxInstallEnv points HOME (and XDG_CONFIG_HOME) at a fresh temp dir
// and changes into another, so an install writes nothing under the
// developer's real home or the package directory (USK-1208). Returns
// (home, cwd).
func sandboxInstallEnv(t *testing.T) (string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	cwd := t.TempDir()
	t.Chdir(cwd)
	return home, cwd
}

// stubVerifyBinary writes a shell script that records it ran and exits 0.
// It stands in for the yorishiro-proxy binary that the install's
// verification step executes; without it the step executes os.Executable()
// — this test binary — which runs the whole test suite until the 3 s
// verification timeout kills it.
func stubVerifyBinary(t *testing.T) (bin, marker string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the verification stub is a POSIX shell script")
	}
	dir := t.TempDir()
	marker = filepath.Join(dir, "verified")
	bin = filepath.Join(dir, "yorishiro-proxy-stub")
	script := "#!/bin/sh\n: > " + shellQuote(marker) + "\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write verify stub: %v", err)
	}
	return bin, marker
}

func TestRunInstall_AllTargets(t *testing.T) {
	home, cwd := sandboxInstallEnv(t)
	bin, marker := stubVerifyBinary(t)

	// No target (all), non-interactive by default, no --ca-dir.
	opts, err := parseInstallOptions(nil)
	if err != nil {
		t.Fatalf("parseInstallOptions() error: %v", err)
	}
	if opts.Target != setup.TargetAll {
		t.Fatalf("parsed target = %q, want %q", opts.Target, setup.TargetAll)
	}
	opts.BinaryPath = bin

	runner := setup.NewRunner(opts, setup.NewStdinPrompter(strings.NewReader(""), io.Discard), io.Discard)
	if err := runner.Install(context.Background()); err != nil {
		t.Fatalf("Install() error: %v", err)
	}

	// The project-scope MCP config lands in cwd and points at the binary.
	data, err := os.ReadFile(filepath.Join(cwd, ".mcp.json"))
	if err != nil {
		t.Fatalf(".mcp.json not created: %v", err)
	}
	if !strings.Contains(string(data), bin) {
		t.Errorf(".mcp.json does not reference the binary %s:\n%s", bin, data)
	}

	// The default CA directory resolves under the sandboxed HOME.
	for _, name := range []string{"ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(home, ".yorishiro-proxy", "ca", name)); err != nil {
			t.Errorf("%s not created under the sandboxed HOME: %v", name, err)
		}
	}

	// The verification step ran the configured binary, not this test binary.
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("verification did not execute the configured binary: %v", err)
	}
}

func TestRunInstall_MCPTarget(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Logf("chdir back: %v", err)
		}
	}()

	err = runInstall(context.Background(), []string{"mcp"})
	if err != nil {
		t.Fatalf("runInstall(mcp) error: %v", err)
	}

	configPath := filepath.Join(dir, ".mcp.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf(".mcp.json not created: %v", err)
	}
}

func TestRunInstall_CATarget(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Logf("chdir back: %v", err)
		}
	}()

	// Use --ca-dir to avoid polluting the default CA directory.
	caDir := filepath.Join(dir, "test-ca")
	err = runInstall(context.Background(), []string{"ca", "--ca-dir", caDir})
	if err != nil {
		t.Fatalf("runInstall(ca) error: %v", err)
	}

	// Check that CA files were created.
	certPath := filepath.Join(caDir, "ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("ca.crt not created: %v", err)
	}
	keyPath := filepath.Join(caDir, "ca.key")
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("ca.key not created: %v", err)
	}
}

func TestRunInstall_SkillsTarget_NowUnknown(t *testing.T) {
	// USK-951: the `skills` install target was removed. Calling it must
	// now produce an "unknown install target" error and must not perform
	// any filesystem side effect.
	err := runInstall(context.Background(), []string{"skills"})
	if err == nil {
		t.Fatal("expected error for removed 'skills' target")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown install target") {
		t.Errorf("error should report unknown install target, got: %v", err)
	}
	if !strings.Contains(msg, "skills") {
		t.Errorf("error should mention the rejected target name, got: %v", err)
	}
}

func TestRunInstall_InvalidTarget(t *testing.T) {
	err := runInstall(context.Background(), []string{"invalid"})
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if !strings.Contains(err.Error(), "unknown install target") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunInstall_HelpFlag(t *testing.T) {
	err := runInstall(context.Background(), []string{"-h"})
	if err == nil {
		t.Fatal("expected error from -h flag (flag.ErrHelp)")
	}
}

func TestRunInstall_TrustFlagOnWrongTarget(t *testing.T) {
	err := runInstall(context.Background(), []string{"mcp", "--trust"})
	if err == nil {
		t.Fatal("expected error for --trust on mcp target")
	}
	if !strings.Contains(err.Error(), "--trust is only valid") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunInstall_UserScopeFlag(t *testing.T) {
	home, cwd := sandboxInstallEnv(t)

	// --user-scope writes ~/.claude/settings.json — under the sandboxed HOME.
	if err := runInstall(context.Background(), []string{"mcp", "--user-scope"}); err != nil {
		t.Fatalf("runInstall(mcp --user-scope) error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("user-scope settings.json not created under the sandboxed HOME: %v", err)
	}
	var settings struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("decode settings.json: %v\n%s", err, data)
	}
	if _, ok := settings.MCPServers["yorishiro-proxy"]; !ok {
		t.Errorf("settings.json has no mcpServers.yorishiro-proxy entry:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(cwd, ".mcp.json")); !os.IsNotExist(err) {
		t.Errorf("--user-scope also wrote a project .mcp.json (stat err = %v)", err)
	}
}

func TestParseInstallTarget(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     setup.Target
		wantArgs []string
		wantErr  bool
	}{
		{
			name:     "no args",
			args:     nil,
			want:     setup.TargetAll,
			wantArgs: nil,
		},
		{
			name:     "empty args",
			args:     []string{},
			want:     setup.TargetAll,
			wantArgs: []string{},
		},
		{
			name:     "mcp target",
			args:     []string{"mcp"},
			want:     setup.TargetMCP,
			wantArgs: []string{},
		},
		{
			name:     "ca target with flags",
			args:     []string{"ca", "--trust"},
			want:     setup.TargetCA,
			wantArgs: []string{"--trust"},
		},
		{
			name:     "flag first (no target)",
			args:     []string{"--interactive"},
			want:     setup.TargetAll,
			wantArgs: []string{"--interactive"},
		},
		{
			name:    "invalid target",
			args:    []string{"unknown"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotArgs, err := parseInstallTarget(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInstallTarget() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got != tt.want {
					t.Errorf("parseInstallTarget() target = %v, want %v", got, tt.want)
				}
				if len(gotArgs) != len(tt.wantArgs) {
					t.Errorf("parseInstallTarget() args = %v, want %v", gotArgs, tt.wantArgs)
				}
			}
		})
	}
}

// shellQuote returns s as a single-quoted POSIX shell word, escaping any
// embedded single quote (close the quote, emit an escaped quote, reopen)
// so a quote in TMPDIR cannot break out of the script's quoting.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

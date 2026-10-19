package setup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// mockPrompter provides pre-configured responses for interactive prompts.
type mockPrompter struct {
	responses []string
	index     int
}

func (m *mockPrompter) Prompt(message string) (string, error) {
	if m.index >= len(m.responses) {
		return "", nil
	}
	resp := m.responses[m.index]
	m.index++
	return resp, nil
}

// --- Install method tests ---

func TestRunner_Install_AllTargets(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)
	home := sandboxHome(t)
	bin, marker := stubVerifyBinary(t)

	var out bytes.Buffer
	opts := Options{
		Target:     TargetAll,
		Scope:      "project",
		ListenAddr: "127.0.0.1:8080",
		BinaryPath: bin,
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Install(ctx)
	if err != nil {
		t.Fatalf("Install() error: %v", err)
	}

	output := out.String()
	expectedSubstrings := []string{
		"yorishiro-proxy install",
		"MCP configuration",
		"CA certificate",
		"Verification",
		"Install complete!",
	}
	for _, s := range expectedSubstrings {
		if !strings.Contains(output, s) {
			t.Errorf("output missing %q\nfull output:\n%s", s, output)
		}
	}

	// .mcp.json should be created.
	if _, err := os.Stat(dir + "/.mcp.json"); err != nil {
		t.Errorf(".mcp.json not created: %v", err)
	}
	if !strings.Contains(output, "Testing MCP server startup... OK") {
		t.Errorf("verification did not report OK\nfull output:\n%s", output)
	}
	assertInstallAllSandboxed(t, home, marker)
}

func TestRunner_Install_MCPOnly(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	opts := Options{
		Target:     TargetMCP,
		Scope:      "project",
		ListenAddr: "127.0.0.1:8080",
		BinaryPath: "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Install(ctx)
	if err != nil {
		t.Fatalf("Install(mcp) error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "MCP configuration") {
		t.Errorf("output missing MCP step\nfull output:\n%s", output)
	}

	// Should NOT contain CA steps.
	if strings.Contains(output, "CA certificate") {
		t.Error("MCP-only should not run CA step")
	}

	if _, err := os.Stat(dir + "/.mcp.json"); err != nil {
		t.Errorf(".mcp.json not created: %v", err)
	}
}

func TestRunner_Install_CAOnly(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	caDir := dir + "/testca"

	var out bytes.Buffer
	opts := Options{
		Target:     TargetCA,
		CADir:      caDir,
		BinaryPath: "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Install(ctx)
	if err != nil {
		t.Fatalf("Install(ca) error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "CA certificate") {
		t.Errorf("output missing CA step\nfull output:\n%s", output)
	}
	if !strings.Contains(output, "Generated new CA certificate") {
		t.Errorf("output missing generation message\nfull output:\n%s", output)
	}

	// Check CA files exist.
	if _, err := os.Stat(caDir + "/ca.crt"); err != nil {
		t.Errorf("ca.crt not created: %v", err)
	}
	if _, err := os.Stat(caDir + "/ca.key"); err != nil {
		t.Errorf("ca.key not created: %v", err)
	}
}

func TestRunner_Install_CAOnly_Idempotent(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	caDir := dir + "/testca"

	opts := Options{
		Target:     TargetCA,
		CADir:      caDir,
		BinaryPath: "/usr/bin/yorishiro-proxy",
	}

	// First run: generate.
	var out1 bytes.Buffer
	runner1 := NewRunner(opts, &mockPrompter{}, &out1)
	if err := runner1.Install(context.Background()); err != nil {
		t.Fatalf("first Install(ca) error: %v", err)
	}
	if !strings.Contains(out1.String(), "Generated new CA certificate") {
		t.Error("first run should generate CA")
	}

	// Second run: should load existing.
	var out2 bytes.Buffer
	runner2 := NewRunner(opts, &mockPrompter{}, &out2)
	if err := runner2.Install(context.Background()); err != nil {
		t.Fatalf("second Install(ca) error: %v", err)
	}
	if !strings.Contains(out2.String(), "CA certificate already exists") {
		t.Errorf("second run should detect existing CA\nfull output:\n%s", out2.String())
	}
}

func TestRunner_Install_Interactive(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)
	home := sandboxHome(t)
	bin, marker := stubVerifyBinary(t)

	var out bytes.Buffer
	prompter := &mockPrompter{
		responses: []string{
			"1", // scope: project
		},
	}

	opts := Options{
		Target:      TargetAll,
		ListenAddr:  "127.0.0.1:8080",
		Interactive: true,
		BinaryPath:  bin,
	}

	runner := NewRunner(opts, prompter, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Install(ctx)
	if err != nil {
		t.Fatalf("Install(interactive) error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "MCP configuration") {
		t.Error("output missing MCP step")
	}
	assertInstallAllSandboxed(t, home, marker)
}

func TestRunner_Install_PlaywrightNonInteractive(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	opts := Options{
		Target:     TargetPlaywright,
		ListenAddr: "127.0.0.1:8080",
		BinaryPath: "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)

	ctx := context.Background()
	err := runner.Install(ctx)
	if err != nil {
		t.Fatalf("Install(playwright) error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Playwright integration") {
		t.Errorf("output missing Playwright step\nfull output:\n%s", output)
	}
	// The test runs in a clean temp dir. If playwright-cli is not in PATH
	// and no .playwright dir exists, it should skip. If it is detected,
	// it should configure without error (non-interactive default).
}

func TestRunner_Install_PlaywrightNotDetected(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	// Override PATH to ensure playwright-cli is not found.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir) // empty dir as PATH

	var out bytes.Buffer
	opts := Options{
		Target:     TargetPlaywright,
		ListenAddr: "127.0.0.1:8080",
		BinaryPath: "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)

	ctx := context.Background()
	err := runner.Install(ctx)
	if err != nil {
		t.Fatalf("Install(playwright) error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "not detected") {
		t.Errorf("should report playwright not detected\nfull output:\n%s", output)
	}

	_ = origPath // used by t.Setenv cleanup
}

// --- Test TrustCA OS detection ---

func TestTrustCAForOS_UnsupportedOS(t *testing.T) {
	err := trustCAForOS("/tmp/ca.crt", "freebsd")
	if err == nil {
		t.Fatal("expected error for unsupported OS")
	}
	if !strings.Contains(err.Error(), "unsupported OS") {
		t.Errorf("unexpected error: %v", err)
	}
}

// chdir changes directory and returns the original directory.
func chdir(t *testing.T, dir string) string {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	return orig
}

// sandboxHome points HOME (and XDG_CONFIG_HOME) at a fresh temp dir so the
// default CA directory and the user-scope MCP config resolve there instead
// of the developer's real home (USK-1208). Returns the temp HOME.
func sandboxHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return home
}

// stubVerifyBinary writes a shell script that records it ran and exits 0,
// for the install's VerifyMCPServer step. A hard-coded path such as
// /usr/bin/yorishiro-proxy would start a real proxy for 3 s wherever one
// is installed. Returns (binary, marker).
func stubVerifyBinary(t *testing.T) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the verification stub is a POSIX shell script")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "verified")
	bin := filepath.Join(dir, "yorishiro-proxy-stub")
	script := "#!/bin/sh\n: > " + shellQuote(marker) + "\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write verify stub: %v", err)
	}
	return bin, marker
}

// assertInstallAllSandboxed checks that an all-targets install put its CA
// under the sandboxed HOME and verified the stub binary.
func assertInstallAllSandboxed(t *testing.T, home, marker string) {
	t.Helper()
	for _, name := range []string{"ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(home, ".yorishiro-proxy", "ca", name)); err != nil {
			t.Errorf("%s not created under the sandboxed HOME: %v", name, err)
		}
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("verification did not execute the configured binary: %v", err)
	}
}

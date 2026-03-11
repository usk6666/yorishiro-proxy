package setup

import (
	"bytes"
	"context"
	"os"
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

	var out bytes.Buffer
	opts := Options{
		Target:     TargetAll,
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
		t.Fatalf("Install() error: %v", err)
	}

	output := out.String()
	expectedSubstrings := []string{
		"yorishiro-proxy install",
		"MCP configuration",
		"CA certificate",
		"Skills installation",
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

	// Should NOT contain CA or Skills steps.
	if strings.Contains(output, "CA certificate") {
		t.Error("MCP-only should not run CA step")
	}
	if strings.Contains(output, "Skills installation") {
		t.Error("MCP-only should not run Skills step")
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

func TestRunner_Install_SkillsOnly(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	opts := Options{
		Target:     TargetSkills,
		BinaryPath: "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Install(ctx)
	if err != nil {
		t.Fatalf("Install(skills) error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Skills installation") {
		t.Errorf("output missing Skills step\nfull output:\n%s", output)
	}

	// Skills directory should exist.
	skillsDir := dir + "/.claude/skills/yorishiro"
	if _, err := os.Stat(skillsDir); err != nil {
		t.Errorf("skills directory not created: %v", err)
	}
}

func TestRunner_Install_SkillsWithCustomDir(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	customDir := dir + "/custom-project"
	if err := os.MkdirAll(customDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var out bytes.Buffer
	opts := Options{
		Target:     TargetSkills,
		SkillsDir:  customDir,
		BinaryPath: "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Install(ctx)
	if err != nil {
		t.Fatalf("Install(skills --dir) error: %v", err)
	}

	// Skills should be installed in the custom directory.
	skillsDir := customDir + "/.claude/skills/yorishiro"
	if _, err := os.Stat(skillsDir); err != nil {
		t.Errorf("skills directory not created in custom dir: %v", err)
	}
}

func TestRunner_Install_Interactive(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	prompter := &mockPrompter{
		responses: []string{
			"1", // scope: project
			"Y", // install skills
		},
	}

	opts := Options{
		Target:      TargetAll,
		ListenAddr:  "127.0.0.1:8080",
		Interactive: true,
		BinaryPath:  "/usr/bin/yorishiro-proxy",
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

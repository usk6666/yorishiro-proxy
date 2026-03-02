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

func TestRunner_NonInteractive(t *testing.T) {
	dir := t.TempDir()

	// Change to temp dir so project-scoped config writes there.
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	opts := Options{
		Scope:          "project",
		ListenAddr:     "127.0.0.1:9090",
		NonInteractive: true,
		SkipPlaywright: true,
		SkipSkills:     true,
		BinaryPath:     "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	// We can't actually verify MCP server without a real binary,
	// but the runner handles verification errors gracefully.
	ctx := context.Background()
	err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	output := out.String()

	// Check output contains expected steps.
	expectedSubstrings := []string{
		"yorishiro-proxy setup",
		"Step 1: MCP configuration",
		"Step 2: CA certificate",
		"Step 3: playwright-cli integration (skipped)",
		"Step 4: Skill installation (skipped)",
		"Step 5: Verification",
		"Setup complete!",
	}

	for _, s := range expectedSubstrings {
		if !strings.Contains(output, s) {
			t.Errorf("output missing %q\nfull output:\n%s", s, output)
		}
	}
}

func TestRunner_InteractiveScope(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	prompter := &mockPrompter{
		responses: []string{
			"1",  // scope: project
			"Y",  // install skills
		},
	}

	opts := Options{
		ListenAddr:     "127.0.0.1:8080",
		SkipPlaywright: true,
		BinaryPath:     "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, prompter, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Step 1: MCP configuration") {
		t.Error("output missing Step 1")
	}
}

func TestRunner_UserScope(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	prompter := &mockPrompter{
		responses: []string{
			"2",  // scope: user
			"n",  // skip skills
		},
	}

	opts := Options{
		ListenAddr:     "127.0.0.1:8080",
		SkipPlaywright: true,
		BinaryPath:     "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, prompter, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Step 1: MCP configuration") {
		t.Error("output missing Step 1")
	}
}

func TestRunner_SkipMCPConfig_Flag(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	opts := Options{
		ListenAddr:     "127.0.0.1:8080",
		NonInteractive: true,
		SkipMCPConfig:  true,
		SkipPlaywright: true,
		SkipSkills:     true,
		BinaryPath:     "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, &mockPrompter{}, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	output := out.String()

	// Should show skipped message.
	if !strings.Contains(output, "Step 1: MCP configuration (skipped)") {
		t.Errorf("output missing skip message\nfull output:\n%s", output)
	}

	// .mcp.json should NOT be created.
	configPath := dir + "/.mcp.json"
	if _, err := os.Stat(configPath); err == nil {
		t.Error(".mcp.json should not be created when SkipMCPConfig is true")
	}
}

func TestRunner_SkipMCPConfig_InteractiveChoice3(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	prompter := &mockPrompter{
		responses: []string{
			"3", // scope: skip
			"n", // skip skills
		},
	}

	opts := Options{
		ListenAddr:     "127.0.0.1:8080",
		SkipPlaywright: true,
		BinaryPath:     "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, prompter, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	output := out.String()

	// Should show the skip message within step 1.
	if !strings.Contains(output, "Skipping MCP configuration") {
		t.Errorf("output missing skip message\nfull output:\n%s", output)
	}

	// .mcp.json should NOT be created.
	configPath := dir + "/.mcp.json"
	if _, err := os.Stat(configPath); err == nil {
		t.Error(".mcp.json should not be created when user chooses skip")
	}
}

func TestRunner_SkipMCPConfig_InteractiveChoiceSkipText(t *testing.T) {
	dir := t.TempDir()
	origDir := chdir(t, dir)
	defer chdir(t, origDir)

	var out bytes.Buffer
	prompter := &mockPrompter{
		responses: []string{
			"skip", // scope: skip (text variant)
			"n",    // skip skills
		},
	}

	opts := Options{
		ListenAddr:     "127.0.0.1:8080",
		SkipPlaywright: true,
		BinaryPath:     "/usr/bin/yorishiro-proxy",
	}

	runner := NewRunner(opts, prompter, &out)
	runner.SetNowFunc(func() time.Time {
		return time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)
	})

	ctx := context.Background()
	err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	output := out.String()

	// Should show the skip message within step 1.
	if !strings.Contains(output, "Skipping MCP configuration") {
		t.Errorf("output missing skip message\nfull output:\n%s", output)
	}

	// .mcp.json should NOT be created.
	configPath := dir + "/.mcp.json"
	if _, err := os.Stat(configPath); err == nil {
		t.Error(".mcp.json should not be created when user types 'skip'")
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

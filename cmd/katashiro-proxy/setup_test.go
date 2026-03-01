package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSetup_InvalidScope(t *testing.T) {
	err := runSetup(context.Background(), []string{"--scope", "invalid"})
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}
	if !strings.Contains(err.Error(), "invalid --scope value") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunSetup_HelpFlag(t *testing.T) {
	err := runSetup(context.Background(), []string{"-h"})
	if err == nil {
		t.Fatal("expected error from -h flag (flag.ErrHelp)")
	}
}

func TestRunSetup_NonInteractive(t *testing.T) {
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

	// Use a fake binary path that won't actually exist.
	args := []string{
		"--scope", "project",
		"--non-interactive",
		"--skip-playwright",
		"--skip-skills",
	}

	// This will fail at verification step because the binary doesn't exist,
	// but should not return an error (verification failures are warnings).
	err = runSetup(context.Background(), args)
	if err != nil {
		t.Fatalf("runSetup() error: %v", err)
	}

	// Check that .mcp.json was created.
	configPath := filepath.Join(dir, ".mcp.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf(".mcp.json not created: %v", err)
	}
}

func TestRun_SubcommandRouting(t *testing.T) {
	// Verify that runSetup works with valid args by running in a temp dir.
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

	err = runSetup(context.Background(), []string{
		"--scope", "project",
		"--non-interactive",
		"--skip-playwright",
		"--skip-skills",
	})
	if err != nil {
		t.Fatalf("runSetup() error: %v", err)
	}

	// Verify .mcp.json was created.
	configPath := filepath.Join(dir, ".mcp.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf(".mcp.json not created: %v", err)
	}
}

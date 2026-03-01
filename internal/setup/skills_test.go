package setup

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestInstallSkills_NewInstallation(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	installed, backupPath, err := InstallSkills(dir, now)
	if err != nil {
		t.Fatalf("InstallSkills() error: %v", err)
	}

	if backupPath != "" {
		t.Errorf("expected empty backup path for new install, got %q", backupPath)
	}

	if len(installed) == 0 {
		t.Fatal("expected at least one installed file")
	}

	// Check that SKILL.md was installed.
	if !slices.Contains(installed, "SKILL.md") {
		t.Error("SKILL.md not found in installed files")
	}

	// Verify file exists on disk.
	skillPath := filepath.Join(dir, ".claude", "skills", "katashiro", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Errorf("skill file not found: %v", err)
	}

	// Verify file has content.
	data, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatalf("read skill file: %v", err)
	}
	if len(data) == 0 {
		t.Error("skill file is empty")
	}
}

func TestInstallSkills_ReferencesSubdirectory(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	installed, _, err := InstallSkills(dir, now)
	if err != nil {
		t.Fatalf("InstallSkills() error: %v", err)
	}

	// Verify that reference files are included in the installed list.
	wantFiles := []string{
		"SKILL.md",
		filepath.Join("references", "self-contained-iteration.md"),
		filepath.Join("references", "playwright-capture.md"),
		filepath.Join("references", "verify-vulnerability.md"),
		filepath.Join("references", "payload-patterns.md"),
	}
	for _, want := range wantFiles {
		if !slices.Contains(installed, want) {
			t.Errorf("%s not found in installed files: %v", want, installed)
		}
	}

	// Verify each file exists on disk and has content.
	baseDir := filepath.Join(dir, ".claude", "skills", "katashiro")
	for _, relPath := range wantFiles {
		fullPath := filepath.Join(baseDir, relPath)
		info, err := os.Stat(fullPath)
		if err != nil {
			t.Errorf("file not found on disk: %s: %v", relPath, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file is empty: %s", relPath)
		}
	}

	// Verify references directory exists.
	refsDir := filepath.Join(baseDir, "references")
	info, err := os.Stat(refsDir)
	if err != nil {
		t.Fatalf("references directory not found: %v", err)
	}
	if !info.IsDir() {
		t.Error("references is not a directory")
	}
}

func TestInstallSkills_ExistingSkills_BackedUp(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	// Create existing skills directory.
	existingDir := filepath.Join(dir, ".claude", "skills", "katashiro")
	if err := os.MkdirAll(existingDir, 0755); err != nil {
		t.Fatalf("create existing dir: %v", err)
	}
	existingFile := filepath.Join(existingDir, "old-skill.md")
	if err := os.WriteFile(existingFile, []byte("old content"), 0644); err != nil {
		t.Fatalf("write existing file: %v", err)
	}

	_, backupPath, err := InstallSkills(dir, now)
	if err != nil {
		t.Fatalf("InstallSkills() error: %v", err)
	}

	if backupPath == "" {
		t.Fatal("expected non-empty backup path for existing skills")
	}

	// Verify backup directory exists and contains old file.
	oldFile := filepath.Join(backupPath, "old-skill.md")
	data, err := os.ReadFile(oldFile)
	if err != nil {
		t.Fatalf("read backup file: %v", err)
	}
	if string(data) != "old content" {
		t.Errorf("backup content = %q, want %q", string(data), "old content")
	}

	// Verify new skills were installed.
	skillPath := filepath.Join(dir, ".claude", "skills", "katashiro", "SKILL.md")
	if _, err := os.Stat(skillPath); err != nil {
		t.Errorf("new skill file not found: %v", err)
	}
}

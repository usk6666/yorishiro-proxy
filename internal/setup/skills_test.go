package setup

import (
	"os"
	"path/filepath"
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
	found := false
	for _, f := range installed {
		if f == "SKILL.md" {
			found = true
			break
		}
	}
	if !found {
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

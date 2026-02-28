package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefault_InsecureSkipVerifyIsFalse(t *testing.T) {
	cfg := Default()
	if cfg.InsecureSkipVerify {
		t.Error("Default().InsecureSkipVerify = true, want false")
	}
}

func TestDefault_FieldsHaveSensibleDefaults(t *testing.T) {
	cfg := Default()

	tests := []struct {
		name string
		got  any
		zero bool // true if the field should be zero/empty
	}{
		{"ListenAddr", cfg.ListenAddr, false},
		{"MCPAddr", cfg.MCPAddr, false},
		{"DBPath", cfg.DBPath, false},
		{"LogLevel", cfg.LogLevel, false},
		{"LogFormat", cfg.LogFormat, false},
		{"PeekTimeout", cfg.PeekTimeout, false},
		{"RequestTimeout", cfg.RequestTimeout, false},
		{"MaxConnections", cfg.MaxConnections, false},
		{"InsecureSkipVerify", cfg.InsecureSkipVerify, true},
		{"CACertPath", cfg.CACertPath, true},
		{"CAKeyPath", cfg.CAKeyPath, true},
		{"LogFile", cfg.LogFile, true},
		{"RetentionMaxSessions", cfg.RetentionMaxSessions, true},
		{"RetentionMaxAge", cfg.RetentionMaxAge, true},
		{"CleanupInterval", cfg.CleanupInterval, false},
		{"MCPHTTPAddr", cfg.MCPHTTPAddr, true},
		{"MCPHTTPToken", cfg.MCPHTTPToken, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isZero := isZeroValue(tt.got)
			if tt.zero && !isZero {
				t.Errorf("%s should be zero value, got %v", tt.name, tt.got)
			}
			if !tt.zero && isZero {
				t.Errorf("%s should not be zero value", tt.name)
			}
		})
	}
}

func isZeroValue(v any) bool {
	switch val := v.(type) {
	case string:
		return val == ""
	case int:
		return val == 0
	case bool:
		return !val
	case time.Duration:
		return val == 0
	default:
		return false
	}
}

func TestDefaultDBPath_ResolvesToHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot resolve home directory: %v", err)
	}

	got := DefaultDBPath()
	want := filepath.Join(home, ".katashiro-proxy", "katashiro.db")
	if got != want {
		t.Errorf("DefaultDBPath() = %q, want %q", got, want)
	}
}

func TestDefault_DBPathUsesHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot resolve home directory: %v", err)
	}

	cfg := Default()
	if !strings.HasPrefix(cfg.DBPath, home) {
		t.Errorf("Default().DBPath = %q, want prefix %q", cfg.DBPath, home)
	}
	if !strings.HasSuffix(cfg.DBPath, filepath.Join(".katashiro-proxy", "katashiro.db")) {
		t.Errorf("Default().DBPath = %q, want suffix %q", cfg.DBPath,
			filepath.Join(".katashiro-proxy", "katashiro.db"))
	}
}

func TestEnsureDBDir_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "subdir", "nested", "test.db")

	if err := EnsureDBDir(dbPath); err != nil {
		t.Fatalf("EnsureDBDir(%q): %v", dbPath, err)
	}

	dir := filepath.Dir(dbPath)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("%q is not a directory", dir)
	}
	// Check permission bits (mask out OS-specific bits).
	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("directory permission = %o, want 0700", perm)
	}
}

func TestEnsureDBDir_ExistingDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Directory already exists (tmpDir).
	if err := EnsureDBDir(dbPath); err != nil {
		t.Fatalf("EnsureDBDir(%q): %v", dbPath, err)
	}
}

func TestEnsureDBDir_AbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "data", "katashiro.db")

	if err := EnsureDBDir(dbPath); err != nil {
		t.Fatalf("EnsureDBDir(%q): %v", dbPath, err)
	}

	dir := filepath.Dir(dbPath)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}

func TestEnsureDBDir_RelativePath(t *testing.T) {
	// Save and restore CWD to avoid test pollution.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	dbPath := filepath.Join("mydata", "test.db")
	if err := EnsureDBDir(dbPath); err != nil {
		t.Fatalf("EnsureDBDir(%q): %v", dbPath, err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "mydata")); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}

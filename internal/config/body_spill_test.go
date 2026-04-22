package config

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newDiscardLogger returns a logger that discards output. Use this when the
// test does not assert on log content.
func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newCaptureLogger returns a logger that writes to the returned buffer.
// The handler level is set to Debug so all levels are captured.
func newCaptureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), &buf
}

// writeFileWithModTime writes data to path and sets ModTime to the given time.
func writeFileWithModTime(t *testing.T, path string, data []byte, modTime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func TestSweepOrphanBodyFiles_RemovesOldPrefixedFile(t *testing.T) {
	dir := t.TempDir()
	oldFile := filepath.Join(dir, BodySpillPrefix+"abc123.tmp")
	writeFileWithModTime(t, oldFile, []byte("stale"), time.Now().Add(-2*time.Hour))

	SweepOrphanBodyFiles(dir, newDiscardLogger())

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Fatalf("old prefixed file should have been removed, stat err = %v", err)
	}
}

func TestSweepOrphanBodyFiles_KeepsRecentPrefixedFile(t *testing.T) {
	dir := t.TempDir()
	recentFile := filepath.Join(dir, BodySpillPrefix+"fresh.tmp")
	writeFileWithModTime(t, recentFile, []byte("live"), time.Now().Add(-time.Minute))

	SweepOrphanBodyFiles(dir, newDiscardLogger())

	if _, err := os.Stat(recentFile); err != nil {
		t.Fatalf("recent prefixed file should be kept, stat err = %v", err)
	}
}

func TestSweepOrphanBodyFiles_KeepsOldNonPrefixedFile(t *testing.T) {
	dir := t.TempDir()
	otherFile := filepath.Join(dir, "other-abcdef.tmp")
	writeFileWithModTime(t, otherFile, []byte("unrelated"), time.Now().Add(-2*time.Hour))

	SweepOrphanBodyFiles(dir, newDiscardLogger())

	if _, err := os.Stat(otherFile); err != nil {
		t.Fatalf("non-prefixed file should be kept, stat err = %v", err)
	}
}

func TestSweepOrphanBodyFiles_SkipsDirectoriesWithMatchingPrefix(t *testing.T) {
	dir := t.TempDir()
	orphanDir := filepath.Join(dir, BodySpillPrefix+"dir")
	if err := os.Mkdir(orphanDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Set the dir mtime to old; the sweep must still skip because IsDir() is true.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(orphanDir, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	SweepOrphanBodyFiles(dir, newDiscardLogger())

	if _, err := os.Stat(orphanDir); err != nil {
		t.Fatalf("directory with matching prefix should be skipped, stat err = %v", err)
	}
}

func TestSweepOrphanBodyFiles_MissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	// Should not panic, should not fatal; just log and return.
	SweepOrphanBodyFiles(missing, newDiscardLogger())
}

func TestSweepOrphanBodyFiles_NilLoggerDefaultsToSlogDefault(t *testing.T) {
	dir := t.TempDir()
	// Empty dir; should not panic when logger is nil.
	SweepOrphanBodyFiles(dir, nil)
}

func TestSweepOrphanBodyFiles_MixedFixtureLogsInfoSummary(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)
	fresh := time.Now().Add(-time.Minute)

	// Two orphans to be swept.
	writeFileWithModTime(t, filepath.Join(dir, BodySpillPrefix+"one.tmp"), []byte("a"), old)
	writeFileWithModTime(t, filepath.Join(dir, BodySpillPrefix+"two.tmp"), []byte("b"), old)

	// One fresh prefixed file (kept).
	writeFileWithModTime(t, filepath.Join(dir, BodySpillPrefix+"three.tmp"), []byte("c"), fresh)

	// One old non-prefixed file (kept).
	writeFileWithModTime(t, filepath.Join(dir, "other.tmp"), []byte("x"), old)

	logger, buf := newCaptureLogger()
	SweepOrphanBodyFiles(dir, logger)

	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("expected INFO summary log, got: %s", out)
	}
	if !strings.Contains(out, "swept=2") {
		t.Errorf("expected swept=2, got: %s", out)
	}

	// Verify file state.
	if _, err := os.Stat(filepath.Join(dir, BodySpillPrefix+"one.tmp")); !os.IsNotExist(err) {
		t.Errorf("one.tmp should be removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, BodySpillPrefix+"two.tmp")); !os.IsNotExist(err) {
		t.Errorf("two.tmp should be removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, BodySpillPrefix+"three.tmp")); err != nil {
		t.Errorf("three.tmp (fresh) should be kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "other.tmp")); err != nil {
		t.Errorf("other.tmp (non-prefixed) should be kept: %v", err)
	}
}

func TestSweepOrphanBodyFiles_NoOrphansLogsDebug(t *testing.T) {
	dir := t.TempDir()

	// One fresh prefixed file (kept) so the dir is not empty.
	writeFileWithModTime(t, filepath.Join(dir, BodySpillPrefix+"fresh.tmp"),
		[]byte("live"), time.Now().Add(-time.Minute))

	logger, buf := newCaptureLogger()
	SweepOrphanBodyFiles(dir, logger)

	out := buf.String()
	if strings.Contains(out, "level=INFO") {
		t.Errorf("expected no INFO summary when swept==0, got: %s", out)
	}
	if !strings.Contains(out, "level=DEBUG") {
		t.Errorf("expected DEBUG summary when swept==0, got: %s", out)
	}
}

func TestResolveBodySpillDir(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"nil config returns TempDir", nil, os.TempDir()},
		{"empty dir returns TempDir", &Config{}, os.TempDir()},
		{"explicit dir returned as-is", &Config{BodySpillDir: "/custom/spill"}, "/custom/spill"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveBodySpillDir(tt.cfg)
			if got != tt.want {
				t.Errorf("ResolveBodySpillDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveBodySpillThreshold(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want int64
	}{
		{"nil config returns default", nil, DefaultBodySpillThreshold},
		{"zero threshold returns default", &Config{}, DefaultBodySpillThreshold},
		{"explicit threshold returned as-is", &Config{BodySpillThreshold: 1 << 20}, 1 << 20},
		{"MaxBodySize returned as-is", &Config{BodySpillThreshold: MaxBodySize}, MaxBodySize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveBodySpillThreshold(tt.cfg)
			if got != tt.want {
				t.Errorf("ResolveBodySpillThreshold() = %d, want %d", got, tt.want)
			}
		})
	}
}

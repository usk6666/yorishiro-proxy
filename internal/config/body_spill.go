package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// BodySpillPrefix is the prefix applied to temp files created by the
	// body-spill mechanism. The startup sweep uses this prefix to identify
	// orphan files from prior crashed or killed runs.
	BodySpillPrefix = "yorishiro-body-"

	// DefaultBodySpillThreshold is the default size threshold above which
	// bodies spill to disk when Config.BodySpillThreshold is zero.
	DefaultBodySpillThreshold int64 = 10 << 20 // 10 MiB

	// orphanSweepAge is the minimum age at which a prefixed temp file is
	// considered an orphan from a prior run (rather than a live body in
	// progress). One hour is comfortably larger than any legitimate body
	// lifetime for the proxy.
	orphanSweepAge = time.Hour
)

// ResolveBodySpillDir returns c.BodySpillDir if non-empty, else os.TempDir().
func ResolveBodySpillDir(c *Config) string {
	if c != nil && c.BodySpillDir != "" {
		return c.BodySpillDir
	}
	return os.TempDir()
}

// ResolveBodySpillThreshold returns c.BodySpillThreshold if positive, else
// DefaultBodySpillThreshold (10 MiB).
func ResolveBodySpillThreshold(c *Config) int64 {
	if c != nil && c.BodySpillThreshold > 0 {
		return c.BodySpillThreshold
	}
	return DefaultBodySpillThreshold
}

// SweepOrphanBodyFiles removes stale yorishiro-body-* temp files from dir.
// Files older than orphanSweepAge are deleted. Errors are logged but never
// returned; startup must not be blocked by cleanup failures.
//
// The sweep intentionally skips directories and does not follow symlinks
// (os.Remove unlinks the symlink itself, not the target). Files younger than
// orphanSweepAge are preserved to avoid racing with a live body in progress.
func SweepOrphanBodyFiles(dir string, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Expected for default TempDir subpaths on fresh hosts.
			logger.Debug("body spill sweep: directory does not exist",
				"dir", dir)
			return
		}
		logger.Warn("body spill sweep: failed to read directory",
			"dir", dir, "err", err)
		return
	}

	cutoff := time.Now().Add(-orphanSweepAge)
	var swept, failed, scanned int
	for _, entry := range entries {
		// Skip directories entirely.
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, BodySpillPrefix) {
			continue
		}
		scanned++
		info, err := entry.Info()
		if err != nil {
			// Race with another process unlinking; skip.
			logger.Debug("body spill sweep: stat failed",
				"name", name, "err", err)
			continue
		}
		if info.ModTime().After(cutoff) {
			// Too young to be an orphan; may be a live body.
			continue
		}
		path := filepath.Join(dir, name)
		if err := os.Remove(path); err != nil {
			// Per-file failure logged at Debug to avoid info-spam.
			logger.Debug("body spill sweep: remove failed",
				"path", path, "err", err)
			failed++
			continue
		}
		swept++
	}

	if swept > 0 {
		logger.Info("body spill sweep: removed orphaned body files",
			"dir", dir, "swept", swept, "failed", failed, "scanned", scanned)
	} else {
		logger.Debug("body spill sweep: no orphans found",
			"dir", dir, "failed", failed, "scanned", scanned)
	}
}

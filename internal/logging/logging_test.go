package logging

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "default config",
			cfg:  Config{},
		},
		{
			name: "level debug",
			cfg:  Config{Level: "debug"},
		},
		{
			name: "level info",
			cfg:  Config{Level: "info"},
		},
		{
			name: "level warn",
			cfg:  Config{Level: "warn"},
		},
		{
			name: "level error",
			cfg:  Config{Level: "error"},
		},
		{
			name: "json format",
			cfg:  Config{Format: "json"},
		},
		{
			name:    "invalid level",
			cfg:     Config{Level: "trace"},
			wantErr: true,
		},
		{
			name:    "invalid format",
			cfg:     Config{Format: "xml"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, cleanup, err := Setup(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer cleanup()
			if logger == nil {
				t.Fatal("logger is nil")
			}
		})
	}
}

func TestSetup_FileOutput(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "test.log")

	logger, cleanup, err := Setup(Config{File: logFile})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	logger.Info("test message", "key", "value")

	cleanup()

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("log file is empty after writing")
	}
}

func TestSetup_FileCleanupCloses(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "test.log")

	logger, cleanup, err := Setup(Config{File: logFile})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// The *os.File is reachable only through the handler, so observe the
	// close through it: writing a record succeeds before cleanup and fails
	// with os.ErrClosed after.
	ctx := context.Background()
	rec := slog.NewRecord(time.Now(), slog.LevelError, "before cleanup", 0)
	if err := logger.Handler().Handle(ctx, rec); err != nil {
		t.Fatalf("Handle before cleanup: %v", err)
	}

	cleanup()

	rec = slog.NewRecord(time.Now(), slog.LevelError, "after cleanup", 0)
	err = logger.Handler().Handle(ctx, rec)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Handle after cleanup: err = %v, want os.ErrClosed (cleanup must close the log file)", err)
	}
}

func TestSetup_InvalidFilePath(t *testing.T) {
	_, _, err := Setup(Config{File: "/nonexistent-dir/sub/test.log"})
	if err == nil {
		t.Fatal("expected error for invalid file path")
	}
}

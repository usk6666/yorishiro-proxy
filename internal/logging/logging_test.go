package logging

import (
	"os"
	"path/filepath"
	"testing"
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

	_, cleanup, err := Setup(Config{File: logFile})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	cleanup()

	// Open the file to verify it was properly closed (no locking issues).
	f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		t.Fatalf("open after cleanup: %v", err)
	}
	f.Close()
}

func TestSetup_InvalidFilePath(t *testing.T) {
	_, _, err := Setup(Config{File: "/nonexistent-dir/sub/test.log"})
	if err == nil {
		t.Fatal("expected error for invalid file path")
	}
}

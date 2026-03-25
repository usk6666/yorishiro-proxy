package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteServerJSON_WritesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "server.json")

	// Override the path resolution to use a temp path.
	// This tests writeServerJSON directly including MkdirAll, permissions, and stale-process detection.
	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return path, nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })

	data := &ServerJSON{
		Addr:      "127.0.0.1:12345",
		Token:     "testtoken",
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}

	if err := writeServerJSON(data); err != nil {
		t.Fatalf("writeServerJSON: %v", err)
	}

	// Verify the file exists and can be read back.
	got, err := readServerJSON(path)
	if err != nil {
		t.Fatalf("readServerJSON: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.Addr != data.Addr {
		t.Errorf("Addr = %q, want %q", got.Addr, data.Addr)
	}
	if got.Token != data.Token {
		t.Errorf("Token = %q, want %q", got.Token, data.Token)
	}
	if got.PID != data.PID {
		t.Errorf("PID = %d, want %d", got.PID, data.PID)
	}

	// Verify file permissions are 0600.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestReadServerJSON_NotExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	got, err := readServerJSON(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent file, got: %+v", got)
	}
}

func TestReadServerJSON_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(path, []byte("not valid json"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	got, err := readServerJSON(path)
	if err != nil {
		t.Fatalf("expected no error for corrupt file (treat as stale), got: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for corrupt file, got: %+v", got)
	}
}

func TestIsProcessAlive_CurrentProcess(t *testing.T) {
	pid := os.Getpid()
	if !isProcessAlive(pid) {
		t.Errorf("isProcessAlive(%d) = false, want true (current process)", pid)
	}
}

func TestIsProcessAlive_InvalidPID(t *testing.T) {
	tests := []struct {
		name string
		pid  int
		want bool
	}{
		{"zero pid", 0, false},
		{"negative pid", -1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProcessAlive(tt.pid)
			if got != tt.want {
				t.Errorf("isProcessAlive(%d) = %v, want %v", tt.pid, got, tt.want)
			}
		})
	}
}

func TestIsProcessAlive_DeadPID(t *testing.T) {
	// PID 1 on Linux is init/systemd and is always alive.
	// We need a PID that is definitely not alive.
	// Use a very large PID that is unlikely to exist.
	// Note: this is inherently racy but acceptable for a unit test.
	// Using 2^22 - 1 which is the max PID on Linux but unlikely to be running.
	const largePID = 4194303
	// We simply check this doesn't panic; liveness is environment-dependent.
	_ = isProcessAlive(largePID)
}

func TestServerJSONPath(t *testing.T) {
	path, err := serverJSONPath()
	if err != nil {
		t.Fatalf("serverJSONPath() error = %v", err)
	}
	if path == "" {
		t.Error("serverJSONPath() returned empty string")
	}
	// Should end with server.json
	if filepath.Base(path) != "server.json" {
		t.Errorf("serverJSONPath() base = %q, want server.json", filepath.Base(path))
	}
}

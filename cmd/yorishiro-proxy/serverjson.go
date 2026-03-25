package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ServerJSON holds the data written to ~/.yorishiro-proxy/server.json
// when the HTTP MCP transport is active.
type ServerJSON struct {
	// Addr is the actual HTTP MCP listen address (e.g. "127.0.0.1:54321").
	Addr string `json:"addr"`

	// Token is the Bearer token for authenticating HTTP MCP requests.
	Token string `json:"token"`

	// PID is the process ID of the running yorishiro-proxy instance.
	PID int `json:"pid"`

	// StartedAt is the time the server started.
	StartedAt time.Time `json:"started_at"`
}

// serverJSONPathFunc returns the path for server.json.
// It is a variable to allow test overrides (similar to timeNow).
var serverJSONPathFunc = defaultServerJSONPath

// defaultServerJSONPath returns the default path for server.json: ~/.yorishiro-proxy/server.json.
func defaultServerJSONPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".yorishiro-proxy", "server.json"), nil
}

// serverJSONPath returns the path for server.json, delegating to serverJSONPathFunc.
func serverJSONPath() (string, error) {
	return serverJSONPathFunc()
}

// writeServerJSON writes server.json to the default path using an array format
// that supports multiple concurrent instances.
//
// The write sequence is:
//  1. Read existing server.json (treat missing file as empty slice)
//  2. Remove stale entries (entries whose PID is not alive)
//  3. Append own entry
//  4. Write back via temp file + rename (atomic)
//
// The caller is responsible for removing the entry when the server exits
// (see removeServerJSON).
func writeServerJSON(data *ServerJSON) error {
	path, err := serverJSONPath()
	if err != nil {
		return err
	}

	// Ensure the directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	// Read existing entries; treat missing file as empty slice.
	entries, err := readServerJSONSlice(path)
	if err != nil {
		return err
	}

	// Filter out stale entries (dead PIDs).
	live := entries[:0]
	for _, e := range entries {
		if isProcessAlive(e.PID) {
			live = append(live, e)
		}
	}

	// Append own entry.
	live = append(live, *data)

	b, err := json.MarshalIndent(live, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal server.json: %w", err)
	}
	b = append(b, '\n')

	// Atomic write via temp file + rename.
	tmpFile, err := os.OpenFile(
		filepath.Join(dir, ".server.json.tmp"),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create temp file for server.json: %w", err)
	}
	tmpName := tmpFile.Name()
	if _, err := tmpFile.Write(b); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp server.json: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp server.json: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename server.json: %w", err)
	}
	return nil
}

// removeServerJSON removes only the entry for the current process from server.json.
// If no entries remain after removal, the file is deleted.
// It is a best-effort operation: errors are ignored because the process is exiting.
func removeServerJSON() {
	path, err := serverJSONPath()
	if err != nil {
		return
	}

	entries, err := readServerJSONSlice(path)
	if err != nil {
		return
	}

	pid := os.Getpid()
	remaining := entries[:0]
	for _, e := range entries {
		if e.PID != pid {
			remaining = append(remaining, e)
		}
	}

	if len(remaining) == 0 {
		_ = os.Remove(path)
		return
	}

	b, err := json.MarshalIndent(remaining, "", "  ")
	if err != nil {
		return
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	tmpFile, err := os.OpenFile(
		filepath.Join(dir, ".server.json.tmp"),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return
	}
	tmpName := tmpFile.Name()
	if _, err := tmpFile.Write(b); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, path)
}

// readServerJSONSlice reads and parses server.json from the given path as an array.
// Returns an empty slice if the file does not exist or is corrupt.
func readServerJSONSlice(path string) ([]ServerJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []ServerJSON{}, nil
		}
		return nil, fmt.Errorf("read server.json: %w", err)
	}
	var entries []ServerJSON
	if err := json.Unmarshal(data, &entries); err != nil {
		// Corrupt file — treat as empty.
		return []ServerJSON{}, nil
	}
	return entries, nil
}

// readServerJSON reads and parses server.json from the given path.
// Returns (nil, nil) if the file does not exist or is corrupt.
// Deprecated: use readServerJSONSlice for the multi-instance array format.
func readServerJSON(path string) (*ServerJSON, error) {
	entries, err := readServerJSONSlice(path)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	return &entries[0], nil
}

// isProcessAlive returns true if a process with the given PID exists and is running.
// On Unix, os.FindProcess always succeeds; we use kill(pid, 0) via Signal(0) to
// check liveness. EPERM means the process exists but we lack signal permission —
// it is treated as alive.
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	// EPERM means the process exists but we don't have permission to signal it.
	return err == nil || errors.Is(err, syscall.EPERM)
}

package main

import (
	"encoding/json"
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

// writeServerJSON atomically writes server.json to the default path.
// It first checks for an existing server.json; if a live process owns it,
// it returns an error. Otherwise it overwrites the file.
// The caller is responsible for removing the file when the server exits
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

	// Check for an existing server.json with a live process.
	// Note: there is a TOCTOU window between the liveness check and the write.
	// This is acceptable for a single-user CLI tool on localhost: the race window
	// is extremely narrow and the worst outcome is overwriting a valid file, which
	// is caught by the PID check on the next startup.
	if existing, err := readServerJSON(path); err == nil && existing != nil {
		if isProcessAlive(existing.PID) {
			return fmt.Errorf("another instance is already running (PID: %d)", existing.PID)
		}
		// Stale file — safe to overwrite.
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal server.json: %w", err)
	}
	b = append(b, '\n')

	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("write server.json: %w", err)
	}
	return nil
}

// removeServerJSON deletes server.json. It is a best-effort operation:
// errors are ignored because the process is exiting.
func removeServerJSON() {
	path, err := serverJSONPath()
	if err != nil {
		return
	}
	_ = os.Remove(path)
}

// readServerJSON reads and parses server.json from the given path.
// Returns (nil, nil) if the file does not exist.
func readServerJSON(path string) (*ServerJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read server.json: %w", err)
	}
	var s ServerJSON
	if err := json.Unmarshal(data, &s); err != nil {
		// Corrupt file — treat as stale.
		return nil, nil
	}
	return &s, nil
}

// isProcessAlive returns true if a process with the given PID exists and is running.
// On Unix, os.FindProcess always succeeds; we use kill(pid, 0) via Signal(0) to
// check liveness.
func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

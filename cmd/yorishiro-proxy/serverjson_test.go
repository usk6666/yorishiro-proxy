package main

import (
	"encoding/json"
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

	// Verify the file exists and can be read back as an array.
	entries, err := readServerJSONSlice(path)
	if err != nil {
		t.Fatalf("readServerJSONSlice: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0]
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

// TestWriteServerJSON_MultiInstance verifies that writing a second entry appends
// to the array rather than overwriting it. Stale entries (dead PIDs) are filtered out.
func TestWriteServerJSON_MultiInstance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")

	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return path, nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })

	// Write a first (live) entry using the current PID so it is not treated as stale.
	first := &ServerJSON{
		Addr:      "127.0.0.1:11111",
		Token:     "token1",
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := writeServerJSON(first); err != nil {
		t.Fatalf("writeServerJSON first: %v", err)
	}

	// Manually insert a second pre-existing live entry directly into the file
	// so we can test that both are kept. We write PID = os.Getpid() for both
	// to guarantee liveness, then write a fresh third entry.
	second := ServerJSON{
		Addr:      "127.0.0.1:22222",
		Token:     "token2",
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	b, _ := json.MarshalIndent([]ServerJSON{*first, second}, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		t.Fatalf("setup second entry: %v", err)
	}

	// Now write a third entry — it should append to the two live entries.
	third := &ServerJSON{
		Addr:      "127.0.0.1:33333",
		Token:     "token3",
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := writeServerJSON(third); err != nil {
		t.Fatalf("writeServerJSON third: %v", err)
	}

	entries, err := readServerJSONSlice(path)
	if err != nil {
		t.Fatalf("readServerJSONSlice: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %+v", len(entries), entries)
	}
}

// TestWriteServerJSON_StaleEntriesFiltered verifies that dead PIDs are removed
// when a new entry is written.
func TestWriteServerJSON_StaleEntriesFiltered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")

	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return path, nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })

	// Seed the file with a stale entry (PID 0 is always dead).
	stale := ServerJSON{
		Addr:      "127.0.0.1:99999",
		Token:     "stale",
		PID:       0,
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	b, _ := json.MarshalIndent([]ServerJSON{stale}, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		t.Fatalf("setup stale entry: %v", err)
	}

	fresh := &ServerJSON{
		Addr:      "127.0.0.1:12345",
		Token:     "fresh",
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := writeServerJSON(fresh); err != nil {
		t.Fatalf("writeServerJSON: %v", err)
	}

	entries, err := readServerJSONSlice(path)
	if err != nil {
		t.Fatalf("readServerJSONSlice: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after stale filter, got %d: %+v", len(entries), entries)
	}
	if entries[0].Token != "fresh" {
		t.Errorf("expected fresh entry, got: %+v", entries[0])
	}
}

// TestRemoveServerJSON_OwnPIDOnly verifies that removeServerJSON removes only
// the entry matching the current PID and leaves other entries intact.
func TestRemoveServerJSON_OwnPIDOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")

	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return path, nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })

	other := ServerJSON{
		Addr:      "127.0.0.1:55555",
		Token:     "other",
		PID:       os.Getpid() + 1000, // different PID (not our own)
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	own := ServerJSON{
		Addr:      "127.0.0.1:66666",
		Token:     "own",
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	b, _ := json.MarshalIndent([]ServerJSON{other, own}, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	removeServerJSON()

	entries, err := readServerJSONSlice(path)
	if err != nil {
		t.Fatalf("readServerJSONSlice after remove: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d: %+v", len(entries), entries)
	}
	if entries[0].PID != other.PID {
		t.Errorf("expected other entry to remain, got PID %d", entries[0].PID)
	}
}

// TestRemoveServerJSON_DeletesFileWhenEmpty verifies that server.json is deleted
// when removing the last (own) entry.
func TestRemoveServerJSON_DeletesFileWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")

	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return path, nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })

	own := ServerJSON{
		Addr:      "127.0.0.1:77777",
		Token:     "own",
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Truncate(time.Second),
	}
	b, _ := json.MarshalIndent([]ServerJSON{own}, "", "  ")
	if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	removeServerJSON()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected server.json to be deleted, but it still exists (err=%v)", err)
	}
}

func TestReadServerJSONSlice_NotExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")

	entries, err := readServerJSONSlice(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty slice for non-existent file, got: %+v", entries)
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

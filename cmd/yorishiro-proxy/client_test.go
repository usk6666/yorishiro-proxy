package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- resolveClientConn tests ---

func withTempServerJSON(t *testing.T, entries []ServerJSON) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")

	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("marshal server.json: %v", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
		t.Fatalf("write server.json: %v", err)
	}

	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return path, nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })
}

func TestResolveClientConn_FlagsTakePriority(t *testing.T) {
	// Set up server.json with one live entry.
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:9999", Token: "from-json", PID: os.Getpid(), StartedAt: time.Now()},
	})
	// Set env vars.
	t.Setenv("YP_CLIENT_ADDR", "127.0.0.1:7777")
	t.Setenv("YP_CLIENT_TOKEN", "from-env")

	// Flags should win over both env and server.json.
	addr, token, err := resolveClientConn("127.0.0.1:1111", "flag-token")
	if err != nil {
		t.Fatalf("resolveClientConn: %v", err)
	}
	if addr != "127.0.0.1:1111" {
		t.Errorf("addr = %q, want 127.0.0.1:1111", addr)
	}
	if token != "flag-token" {
		t.Errorf("token = %q, want flag-token", token)
	}
}

func TestResolveClientConn_EnvVarOverridesServerJSON(t *testing.T) {
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:9999", Token: "from-json", PID: os.Getpid(), StartedAt: time.Now()},
	})
	t.Setenv("YP_CLIENT_ADDR", "127.0.0.1:7777")
	t.Setenv("YP_CLIENT_TOKEN", "from-env")

	addr, token, err := resolveClientConn("", "")
	if err != nil {
		t.Fatalf("resolveClientConn: %v", err)
	}
	if addr != "127.0.0.1:7777" {
		t.Errorf("addr = %q, want 127.0.0.1:7777", addr)
	}
	if token != "from-env" {
		t.Errorf("token = %q, want from-env", token)
	}
}

func TestResolveClientConn_ServerJSONFallback(t *testing.T) {
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:5432", Token: "json-token", PID: os.Getpid(), StartedAt: time.Now()},
	})
	// Ensure env vars are not set.
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	addr, token, err := resolveClientConn("", "")
	if err != nil {
		t.Fatalf("resolveClientConn: %v", err)
	}
	if addr != "127.0.0.1:5432" {
		t.Errorf("addr = %q, want 127.0.0.1:5432", addr)
	}
	if token != "json-token" {
		t.Errorf("token = %q, want json-token", token)
	}
}

func TestResolveClientConn_NoServerJSON_NoEnv_Error(t *testing.T) {
	// Point server.json at a non-existent file.
	dir := t.TempDir()
	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) {
		return filepath.Join(dir, "server.json"), nil
	}
	t.Cleanup(func() { serverJSONPathFunc = orig })

	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	_, _, err := resolveClientConn("", "")
	if err == nil {
		t.Error("expected error when no server address is available, got nil")
	}
}

func TestResolveClientConn_StaleServerJSON_NoLiveEntry(t *testing.T) {
	// All entries are stale (PID 0).
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:9999", Token: "stale-token", PID: 0, StartedAt: time.Now()},
	})
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	_, _, err := resolveClientConn("", "")
	if err == nil {
		t.Error("expected error for stale server.json entries, got nil")
	}
}

func TestResolveClientConn_ExplicitAddrNoMatchingEntry_TokenEmpty(t *testing.T) {
	// server.json has a live entry for a different addr.
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:9999", Token: "other-token", PID: os.Getpid(), StartedAt: time.Now()},
	})
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	// addr explicitly set to a different address — token from the mismatched entry must NOT be used.
	addr, token, err := resolveClientConn("127.0.0.1:8080", "")
	if err != nil {
		t.Fatalf("resolveClientConn: %v", err)
	}
	if addr != "127.0.0.1:8080" {
		t.Errorf("addr = %q, want 127.0.0.1:8080", addr)
	}
	if token != "" {
		t.Errorf("token = %q, want empty (should not take token from a different entry)", token)
	}
}

func TestResolveClientConn_ExplicitAddrMatchingEntry_TokenTaken(t *testing.T) {
	// server.json has a live entry that matches the explicit addr.
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:8080", Token: "correct-token", PID: os.Getpid(), StartedAt: time.Now()},
	})
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	addr, token, err := resolveClientConn("127.0.0.1:8080", "")
	if err != nil {
		t.Fatalf("resolveClientConn: %v", err)
	}
	if addr != "127.0.0.1:8080" {
		t.Errorf("addr = %q, want 127.0.0.1:8080", addr)
	}
	if token != "correct-token" {
		t.Errorf("token = %q, want correct-token", token)
	}
}

// --- runListServers tests ---

func TestRunListServers_JSONOutput(t *testing.T) {
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:8080", Token: "tok1", PID: os.Getpid(), StartedAt: time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)},
		{Addr: "127.0.0.1:8081", Token: "tok2", PID: 0, StartedAt: time.Date(2026, 3, 25, 11, 0, 0, 0, time.UTC)},
	})

	var buf bytes.Buffer
	err := runListServers(&buf, []string{})
	if err != nil {
		t.Fatalf("runListServers: %v", err)
	}

	var entries []listServersEntry
	if err := json.Unmarshal(buf.Bytes(), &entries); err != nil {
		t.Fatalf("parse JSON output: %v\noutput: %s", err, buf.String())
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// First entry: live PID.
	if entries[0].Addr != "127.0.0.1:8080" {
		t.Errorf("entries[0].Addr = %q, want 127.0.0.1:8080", entries[0].Addr)
	}
	if entries[0].Status != "active" {
		t.Errorf("entries[0].Status = %q, want active", entries[0].Status)
	}
	// Token must not appear in output.
	if strings.Contains(buf.String(), "tok1") {
		t.Error("token should not appear in list-servers output")
	}

	// Second entry: dead PID.
	if entries[1].Status != "stale" {
		t.Errorf("entries[1].Status = %q, want stale", entries[1].Status)
	}
}

func TestRunListServers_TableOutput(t *testing.T) {
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:8080", Token: "tok1", PID: os.Getpid(), StartedAt: time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)},
	})

	var buf bytes.Buffer
	err := runListServers(&buf, []string{"--format", "table"})
	if err != nil {
		t.Fatalf("runListServers table: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "ADDR") {
		t.Errorf("table output missing ADDR header: %q", output)
	}
	if !strings.Contains(output, "127.0.0.1:8080") {
		t.Errorf("table output missing address: %q", output)
	}
	if !strings.Contains(output, "active") {
		t.Errorf("table output missing active status: %q", output)
	}
	// Token must not appear.
	if strings.Contains(output, "tok1") {
		t.Error("token should not appear in table output")
	}
}

func TestRunListServers_EmptyJSON(t *testing.T) {
	// Non-existent server.json should produce empty array.
	dir := t.TempDir()
	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) {
		return filepath.Join(dir, "server.json"), nil
	}
	t.Cleanup(func() { serverJSONPathFunc = orig })

	var buf bytes.Buffer
	err := runListServers(&buf, []string{})
	if err != nil {
		t.Fatalf("runListServers empty: %v", err)
	}

	var entries []listServersEntry
	if err := json.Unmarshal(buf.Bytes(), &entries); err != nil {
		t.Fatalf("parse JSON: %v\noutput: %s", err, buf.String())
	}
	if len(entries) != 0 {
		t.Errorf("expected empty array, got %d entries", len(entries))
	}
}

func TestRunListServers_UnknownFormat_Error(t *testing.T) {
	withTempServerJSON(t, []ServerJSON{
		{Addr: "127.0.0.1:8080", Token: "tok1", PID: os.Getpid(), StartedAt: time.Now()},
	})

	var buf bytes.Buffer
	err := runListServers(&buf, []string{"--format", "jsno"})
	if err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error %q should mention 'unsupported format'", err.Error())
	}
}

// --- bearerRoundTripper tests ---

func TestBearerRoundTripper_AddsAuthHeader(t *testing.T) {
	var captured string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rt := &bearerRoundTripper{
		token: "test-token-123",
		base:  http.DefaultTransport,
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	want := "Bearer test-token-123"
	if captured != want {
		t.Errorf("Authorization header = %q, want %q", captured, want)
	}
}

func TestBearerRoundTripper_EmptyTokenNoHeader(t *testing.T) {
	var captured string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rt := &bearerRoundTripper{
		token: "",
		base:  http.DefaultTransport,
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if captured != "" {
		t.Errorf("expected no Authorization header for empty token, got %q", captured)
	}
}

// --- printToolHelp tests ---

func TestPrintToolHelp_KnownTool(t *testing.T) {
	for _, name := range clientToolList {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			err := printToolHelp(&buf, name)
			if err != nil {
				t.Errorf("printToolHelp(%q) error = %v", name, err)
			}
			if buf.Len() == 0 {
				t.Errorf("printToolHelp(%q) produced no output", name)
			}
		})
	}
}

func TestPrintToolHelp_UnknownTool(t *testing.T) {
	var buf bytes.Buffer
	err := printToolHelp(&buf, "nonexistent_tool_xyz")
	if err == nil {
		t.Error("expected error for unknown tool, got nil")
	}
}

// --- runClient tests ---

func TestRunClient_NoArgs_ShowsUsage(t *testing.T) {
	// Should not error; just prints usage.
	err := runClient(context.Background(), []string{})
	if err != nil {
		t.Errorf("runClient with no args: %v", err)
	}
}

func TestRunClient_HelpFlag(t *testing.T) {
	for _, flag := range []string{"--help", "-help", "-h"} {
		t.Run(flag, func(t *testing.T) {
			err := runClient(context.Background(), []string{flag})
			if err != nil {
				t.Errorf("runClient %q: %v", flag, err)
			}
		})
	}
}

func TestRunClient_ToolHelpFlag(t *testing.T) {
	err := runClient(context.Background(), []string{"query", "--help"})
	if err != nil {
		t.Errorf("runClient query --help: %v", err)
	}
}

func TestRunClient_UnknownToolHelp(t *testing.T) {
	err := runClient(context.Background(), []string{"nonexistent_xyz", "--help"})
	if err == nil {
		t.Error("expected error for unknown tool with --help, got nil")
	}
}

// --- MCP client connection tests ---

func TestRunClientTool_ConnectError(t *testing.T) {
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	// Point to a non-existent server.json so no auto-detection occurs.
	dir := t.TempDir()
	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return filepath.Join(dir, "server.json"), nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })

	err := runClientTool(context.Background(), "query", []string{"-server-addr=127.0.0.1:1", "resource=flows"})
	if err == nil {
		t.Error("expected error when connecting to non-existent server, got nil")
	}
}

func TestRunClientTool_SpaceSeparatedServerAddr_Error(t *testing.T) {
	// Verify that space-separated -server-addr 127.0.0.1:1 is parsed (connection fails, not a parse error).
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	dir := t.TempDir()
	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return filepath.Join(dir, "server.json"), nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })

	err := runClientTool(context.Background(), "query", []string{"-server-addr", "127.0.0.1:1", "resource=flows"})
	// Should fail with a connection error, not a flag parse error.
	if err == nil {
		t.Error("expected error when connecting to non-existent server, got nil")
	}
	if strings.Contains(err.Error(), "flag needs an argument") {
		t.Errorf("space-separated flag was not parsed correctly: %v", err)
	}
}

func TestRunClientTool_NoAddress_Error(t *testing.T) {
	t.Setenv("YP_CLIENT_ADDR", "")
	t.Setenv("YP_CLIENT_TOKEN", "")

	dir := t.TempDir()
	orig := serverJSONPathFunc
	serverJSONPathFunc = func() (string, error) { return filepath.Join(dir, "server.json"), nil }
	t.Cleanup(func() { serverJSONPathFunc = orig })

	err := runClientTool(context.Background(), "query", []string{"resource=flows"})
	if err == nil {
		t.Error("expected error when no address, got nil")
	}
	if !strings.Contains(err.Error(), "no server address") {
		t.Errorf("error %q should mention 'no server address'", err.Error())
	}
}

// --- splitClientToolArgs tests ---

func TestSplitClientToolArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantConn     []string
		wantToolArgs []string
	}{
		{
			name:         "mixed flags and params",
			args:         []string{"--server-addr=127.0.0.1:8080", "resource=flows", "--format", "json", "limit=10"},
			wantConn:     []string{"--server-addr=127.0.0.1:8080", "--format", "json"},
			wantToolArgs: []string{"resource=flows", "limit=10"},
		},
		{
			name:         "only tool params",
			args:         []string{"resource=flows", "limit=10"},
			wantConn:     nil,
			wantToolArgs: []string{"resource=flows", "limit=10"},
		},
		{
			name:         "quiet flag",
			args:         []string{"--quiet", "resource=flows"},
			wantConn:     []string{"--quiet"},
			wantToolArgs: []string{"resource=flows"},
		},
		{
			name:         "raw flag",
			args:         []string{"--raw", "resource=flows"},
			wantConn:     []string{"--raw"},
			wantToolArgs: []string{"resource=flows"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConn, gotTool := splitClientToolArgs(tt.args)
			if !sliceEqual(gotConn, tt.wantConn) {
				t.Errorf("connFlagArgs = %v, want %v", gotConn, tt.wantConn)
			}
			if !sliceEqual(gotTool, tt.wantToolArgs) {
				t.Errorf("toolParamArgs = %v, want %v", gotTool, tt.wantToolArgs)
			}
		})
	}
}

// sliceEqual compares two string slices for equality (nil and empty are treated as equal).
func sliceEqual(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

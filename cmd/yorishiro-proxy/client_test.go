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

// --- parseToolArgs tests ---

func TestParseToolArgs_KeyValue(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want map[string]any
	}{
		{
			name: "simple key=value",
			args: []string{"resource=flows", "limit=10"},
			want: map[string]any{"resource": "flows", "limit": "10"},
		},
		{
			name: "double-dash prefix",
			args: []string{"--resource=flows", "--limit=10"},
			want: map[string]any{"resource": "flows", "limit": "10"},
		},
		{
			name: "single-dash prefix",
			args: []string{"-resource=flows"},
			want: map[string]any{"resource": "flows"},
		},
		{
			name: "bare flag becomes true",
			args: []string{"verbose"},
			want: map[string]any{"verbose": true},
		},
		{
			name: "empty args",
			args: []string{},
			want: map[string]any{},
		},
		{
			name: "empty key skipped",
			args: []string{"=value"},
			want: map[string]any{},
		},
		{
			name: "value with equals sign",
			args: []string{"url=http://example.com?a=1"},
			want: map[string]any{"url": "http://example.com?a=1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseToolArgs(tt.args)
			if len(got) != len(tt.want) {
				t.Errorf("len(got)=%d, want %d: got=%v want=%v", len(got), len(tt.want), got, tt.want)
				return
			}
			for k, wv := range tt.want {
				gv, ok := got[k]
				if !ok {
					t.Errorf("key %q missing from result", k)
					continue
				}
				if gv != wv {
					t.Errorf("key %q: got=%v (%T), want=%v (%T)", k, gv, gv, wv, wv)
				}
			}
		})
	}
}

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

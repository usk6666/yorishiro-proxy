package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefault_InsecureSkipVerifyIsFalse(t *testing.T) {
	cfg := Default()
	if cfg.InsecureSkipVerify {
		t.Error("Default().InsecureSkipVerify = true, want false")
	}
}

func TestDefault_FieldsHaveSensibleDefaults(t *testing.T) {
	cfg := Default()

	tests := []struct {
		name string
		got  any
		zero bool // true if the field should be zero/empty
	}{
		{"ListenAddr", cfg.ListenAddr, false},
		{"MCPAddr", cfg.MCPAddr, false},
		{"DBPath", cfg.DBPath, false},
		{"LogLevel", cfg.LogLevel, false},
		{"LogFormat", cfg.LogFormat, false},
		{"PeekTimeout", cfg.PeekTimeout, false},
		{"RequestTimeout", cfg.RequestTimeout, false},
		{"MaxConnections", cfg.MaxConnections, false},
		{"InsecureSkipVerify", cfg.InsecureSkipVerify, true},
		{"CACertPath", cfg.CACertPath, true},
		{"CAKeyPath", cfg.CAKeyPath, true},
		{"LogFile", cfg.LogFile, true},
		{"RetentionMaxSessions", cfg.RetentionMaxSessions, true},
		{"RetentionMaxAge", cfg.RetentionMaxAge, true},
		{"CleanupInterval", cfg.CleanupInterval, false},
		{"MCPHTTPAddr", cfg.MCPHTTPAddr, true},
		{"MCPHTTPToken", cfg.MCPHTTPToken, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isZero := isZeroValue(tt.got)
			if tt.zero && !isZero {
				t.Errorf("%s should be zero value, got %v", tt.name, tt.got)
			}
			if !tt.zero && isZero {
				t.Errorf("%s should not be zero value", tt.name)
			}
		})
	}
}

func isZeroValue(v any) bool {
	switch val := v.(type) {
	case string:
		return val == ""
	case int:
		return val == 0
	case bool:
		return !val
	case time.Duration:
		return val == 0
	default:
		return false
	}
}

func TestDefaultDBPath_ResolvesToHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot resolve home directory: %v", err)
	}

	got := DefaultDBPath()
	want := filepath.Join(home, ".katashiro-proxy", "katashiro.db")
	if got != want {
		t.Errorf("DefaultDBPath() = %q, want %q", got, want)
	}
}

func TestDefault_DBPathUsesHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot resolve home directory: %v", err)
	}

	cfg := Default()
	if !strings.HasPrefix(cfg.DBPath, home) {
		t.Errorf("Default().DBPath = %q, want prefix %q", cfg.DBPath, home)
	}
	if !strings.HasSuffix(cfg.DBPath, filepath.Join(".katashiro-proxy", "katashiro.db")) {
		t.Errorf("Default().DBPath = %q, want suffix %q", cfg.DBPath,
			filepath.Join(".katashiro-proxy", "katashiro.db"))
	}
}

func TestEnsureDBDir_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "subdir", "nested", "test.db")

	if err := EnsureDBDir(dbPath); err != nil {
		t.Fatalf("EnsureDBDir(%q): %v", dbPath, err)
	}

	dir := filepath.Dir(dbPath)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("%q is not a directory", dir)
	}
	// Check permission bits (mask out OS-specific bits).
	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("directory permission = %o, want 0700", perm)
	}
}

func TestEnsureDBDir_ExistingDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Directory already exists (tmpDir).
	if err := EnsureDBDir(dbPath); err != nil {
		t.Fatalf("EnsureDBDir(%q): %v", dbPath, err)
	}
}

func TestEnsureDBDir_AbsolutePath(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "data", "katashiro.db")

	if err := EnsureDBDir(dbPath); err != nil {
		t.Fatalf("EnsureDBDir(%q): %v", dbPath, err)
	}

	dir := filepath.Dir(dbPath)
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}

func TestEnsureDBDir_RelativePath(t *testing.T) {
	// Save and restore CWD to avoid test pollution.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	dbPath := filepath.Join("mydata", "test.db")
	if err := EnsureDBDir(dbPath); err != nil {
		t.Fatalf("EnsureDBDir(%q): %v", dbPath, err)
	}

	if _, err := os.Stat(filepath.Join(tmpDir, "mydata")); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}

func TestLoadFile_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	content := `{
		"listen_addr": "127.0.0.1:9090",
		"capture_scope": {
			"includes": [{"hostname": "*.target.com"}],
			"excludes": [{"hostname": "cdn.example.com"}]
		},
		"tls_passthrough": ["pinned-service.com"],
		"intercept_rules": [],
		"auto_transform": [],
		"tcp_forwards": {"3306": "db.example.com:3306"},
		"upstream_proxy": ""
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, "127.0.0.1:9090")
	}
	if len(cfg.TLSPassthrough) != 1 || cfg.TLSPassthrough[0] != "pinned-service.com" {
		t.Errorf("TLSPassthrough = %v, want [pinned-service.com]", cfg.TLSPassthrough)
	}
	if cfg.TCPForwards["3306"] != "db.example.com:3306" {
		t.Errorf("TCPForwards[3306] = %q, want %q", cfg.TCPForwards["3306"], "db.example.com:3306")
	}
	if cfg.CaptureScope == nil {
		t.Fatal("CaptureScope is nil, want non-nil")
	}
}

func TestLoadFile_MinimalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "minimal.json")

	if err := os.WriteFile(path, []byte(`{"listen_addr": "127.0.0.1:8888"}`), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.ListenAddr != "127.0.0.1:8888" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, "127.0.0.1:8888")
	}
	if len(cfg.TLSPassthrough) != 0 {
		t.Errorf("TLSPassthrough = %v, want empty", cfg.TLSPassthrough)
	}
	if len(cfg.TCPForwards) != 0 {
		t.Errorf("TCPForwards = %v, want empty", cfg.TCPForwards)
	}
}

func TestLoadFile_EmptyJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")

	if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.ListenAddr != "" {
		t.Errorf("ListenAddr = %q, want empty", cfg.ListenAddr)
	}
}

func TestLoadFile_FileNotFound(t *testing.T) {
	_, err := LoadFile("/nonexistent/path/config.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "read config file") {
		t.Errorf("error = %q, want substring %q", err.Error(), "read config file")
	}
}

func TestLoadFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.json")

	if err := os.WriteFile(path, []byte(`{not valid json`), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "invalid JSON") {
		t.Errorf("error = %q, want substring %q", err.Error(), "invalid JSON")
	}
}

func TestLoadFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")

	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected error for empty file, got nil")
	}
}

func TestLoadFile_CaptureScope_RawMessage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.json")

	content := `{
		"capture_scope": {
			"includes": [{"hostname": "api.example.com", "url_prefix": "/v1/", "method": "POST"}],
			"excludes": [{"hostname": "static.example.com"}]
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	// Verify capture_scope is stored as raw JSON and can be unmarshalled.
	var scope struct {
		Includes []struct {
			Hostname  string `json:"hostname"`
			URLPrefix string `json:"url_prefix"`
			Method    string `json:"method"`
		} `json:"includes"`
		Excludes []struct {
			Hostname string `json:"hostname"`
		} `json:"excludes"`
	}
	if err := json.Unmarshal(cfg.CaptureScope, &scope); err != nil {
		t.Fatalf("unmarshal CaptureScope: %v", err)
	}
	if len(scope.Includes) != 1 {
		t.Fatalf("includes = %d, want 1", len(scope.Includes))
	}
	if scope.Includes[0].Hostname != "api.example.com" {
		t.Errorf("includes[0].hostname = %q, want %q", scope.Includes[0].Hostname, "api.example.com")
	}
	if scope.Includes[0].URLPrefix != "/v1/" {
		t.Errorf("includes[0].url_prefix = %q, want %q", scope.Includes[0].URLPrefix, "/v1/")
	}
	if len(scope.Excludes) != 1 {
		t.Fatalf("excludes = %d, want 1", len(scope.Excludes))
	}
}

func TestResolveDBPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot resolve home directory: %v", err)
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
		errSub  string // substring expected in error message
	}{
		// Empty input -> default path.
		{
			name:  "empty returns default path",
			input: "",
			want:  filepath.Join(home, ".katashiro-proxy", "katashiro.db"),
		},
		// Absolute paths: used as-is.
		{
			name:  "absolute path with .db extension",
			input: "/data/project.db",
			want:  "/data/project.db",
		},
		{
			name:  "absolute path without extension",
			input: "/data/myproject",
			want:  "/data/myproject",
		},
		{
			name:  "absolute path nested",
			input: "/home/user/katashiro-data/test.sqlite",
			want:  "/home/user/katashiro-data/test.sqlite",
		},
		// Project names: no extension, no path separator.
		{
			name:  "simple project name",
			input: "pentest-2026",
			want:  filepath.Join(home, ".katashiro-proxy", "pentest-2026.db"),
		},
		{
			name:  "project name with underscores",
			input: "client_audit_2026",
			want:  filepath.Join(home, ".katashiro-proxy", "client_audit_2026.db"),
		},
		{
			name:  "project name alphanumeric",
			input: "project123",
			want:  filepath.Join(home, ".katashiro-proxy", "project123.db"),
		},
		// Names with dots have an extension, so they are CWD-relative (not project names).
		{
			name:  "name with dot is CWD-relative (has extension)",
			input: "pentest.v2",
			want:  "pentest.v2",
		},
		// Relative paths with extensions: CWD-relative (backward compat).
		{
			name:  "relative path with .db extension",
			input: "my-data.db",
			want:  "my-data.db",
		},
		{
			name:  "relative path with subdirectory and extension",
			input: "subdir/data.db",
			want:  "subdir/data.db",
		},
		{
			name:  "relative path with .sqlite extension",
			input: "test.sqlite",
			want:  "test.sqlite",
		},
		{
			name:  "relative path dot-slash prefix",
			input: "./local.db",
			want:  "./local.db",
		},
		// Dot-prefixed names have extensions, so they fall to CWD-relative (not project names).
		{
			name:  "dot-dot treated as CWD-relative (has extension)",
			input: "..",
			want:  "..",
		},
		{
			name:  "single dot treated as CWD-relative (has extension)",
			input: ".",
			want:  ".",
		},
		{
			name:  "leading dot treated as CWD-relative (has extension)",
			input: ".secret",
			want:  ".secret",
		},
		{
			name:  "double dot in name treated as CWD-relative (has extension)",
			input: "foo..bar",
			want:  "foo..bar",
		},
		// Invalid project names: no extension, no path separator, but bad characters.
		{
			name:    "contains space",
			input:   "my project",
			wantErr: true,
			errSub:  "not allowed",
		},
		{
			name:    "contains special characters",
			input:   "proj@2026",
			wantErr: true,
			errSub:  "not allowed",
		},
		{
			name:    "contains shell metacharacter",
			input:   "proj;rm",
			wantErr: true,
			errSub:  "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveDBPath(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveDBPath(%q) = %q, want error", tt.input, got)
				}
				if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveDBPath(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ResolveDBPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateProjectName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "myproject", false},
		{"valid with hyphens", "my-project", false},
		{"valid with underscores", "my_project", false},
		{"valid with digits", "project2026", false},
		{"valid with dots", "v1.0.0", false},
		{"valid mixed", "client-audit_2026.v2", false},
		{"valid uppercase", "MyProject", false},

		{"invalid empty", "", true},
		{"invalid dot", ".", true},
		{"invalid dotdot", "..", true},
		{"invalid leading dot", ".hidden", true},
		{"invalid double dot", "foo..bar", true},
		{"invalid space", "my project", true},
		{"invalid slash", "path/name", true},   // won't reach here (has separator)
		{"invalid at sign", "user@host", true},
		{"invalid dollar", "price$100", true},
		{"invalid unicode", "proje\u00e9t", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProjectName(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("validateProjectName(%q) = nil, want error", tt.input)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateProjectName(%q) = %v, want nil", tt.input, err)
			}
		})
	}
}

func TestLoadFile_UnknownFieldsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "extra.json")

	content := `{
		"listen_addr": "127.0.0.1:9090",
		"unknown_field": "should be ignored",
		"another_unknown": 42
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, "127.0.0.1:9090")
	}
}

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

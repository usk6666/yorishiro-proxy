package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMCPConfigPath(t *testing.T) {
	tests := []struct {
		name       string
		scope      string
		projectDir string
		wantSuffix string
		wantErr    bool
	}{
		{
			name:       "project scope returns .mcp.json in project dir",
			scope:      "project",
			projectDir: "/some/project",
			wantSuffix: filepath.Join("/some/project", ".mcp.json"),
		},
		{
			name:       "user scope returns settings.json in home",
			scope:      "user",
			projectDir: "/some/project",
			wantSuffix: filepath.Join(".claude", "settings.json"),
		},
		{
			name:    "invalid scope returns error",
			scope:   "invalid",
			wantErr: true,
		},
		{
			name:    "empty scope returns error",
			scope:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MCPConfigPath(tt.scope, tt.projectDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("MCPConfigPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if tt.scope == "project" && got != tt.wantSuffix {
				t.Errorf("MCPConfigPath() = %q, want %q", got, tt.wantSuffix)
			}
			if tt.scope == "user" {
				// Just check it ends with the expected suffix.
				if !containsPath(got, tt.wantSuffix) {
					t.Errorf("MCPConfigPath() = %q, want path containing %q", got, tt.wantSuffix)
				}
			}
		})
	}
}

func containsPath(full, suffix string) bool {
	return len(full) >= len(suffix) && full[len(full)-len(suffix):] == suffix
}

func TestBackupPath(t *testing.T) {
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "standard file",
			path: "/tmp/.mcp.json",
			want: "/tmp/.mcp.json.bak.20260301-143045",
		},
		{
			name: "settings.json",
			path: "/home/user/.claude/settings.json",
			want: "/home/user/.claude/settings.json.bak.20260301-143045",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BackupPath(tt.path, now)
			if got != tt.want {
				t.Errorf("BackupPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCreateBackup(t *testing.T) {
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	t.Run("creates backup of existing file", func(t *testing.T) {
		dir := t.TempDir()
		srcPath := filepath.Join(dir, "test.json")
		content := `{"key": "value"}`
		if err := os.WriteFile(srcPath, []byte(content), 0644); err != nil {
			t.Fatalf("write source: %v", err)
		}

		backupFile, err := CreateBackup(srcPath, now)
		if err != nil {
			t.Fatalf("CreateBackup() error: %v", err)
		}

		if backupFile == "" {
			t.Fatal("expected non-empty backup path")
		}

		data, err := os.ReadFile(backupFile)
		if err != nil {
			t.Fatalf("read backup: %v", err)
		}
		if string(data) != content {
			t.Errorf("backup content = %q, want %q", string(data), content)
		}

		// Verify restrictive permissions.
		info, err := os.Stat(backupFile)
		if err != nil {
			t.Fatalf("stat backup: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("backup permissions = %o, want 0600", perm)
		}
	})

	t.Run("returns empty for non-existent file", func(t *testing.T) {
		backupFile, err := CreateBackup("/nonexistent/file.json", now)
		if err != nil {
			t.Fatalf("CreateBackup() error: %v", err)
		}
		if backupFile != "" {
			t.Errorf("expected empty backup path, got %q", backupFile)
		}
	})
}

func TestBuildMCPEntry(t *testing.T) {
	entry := BuildMCPEntry("/usr/local/bin/yorishiro-proxy")

	if entry.Command != "/usr/local/bin/yorishiro-proxy" {
		t.Errorf("Command = %q, want %q", entry.Command, "/usr/local/bin/yorishiro-proxy")
	}

	if len(entry.Args) == 0 {
		t.Fatal("expected non-empty Args")
	}

	// Check that -log-file is in args and points to user-scoped path.
	argsStr := joinArgs(entry.Args)
	if !containsStr(argsStr, "-log-file") {
		t.Error("expected -log-file in args")
	}
	if containsStr(argsStr, "/tmp/") {
		t.Error("-log-file should not use /tmp")
	}
	if containsStr(argsStr, "-insecure") {
		t.Error("-insecure should not be included by default")
	}
	if !containsStr(argsStr, ".yorishiro-proxy") {
		t.Error("expected log path under .yorishiro-proxy")
	}
}

func joinArgs(args []string) string {
	return strings.Join(args, " ")
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}

func TestWriteMCPConfig_NewFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	backupPath, err := WriteMCPConfig(configPath, "/usr/bin/yorishiro-proxy", now)
	if err != nil {
		t.Fatalf("WriteMCPConfig() error: %v", err)
	}

	// No backup for new file.
	if backupPath != "" {
		t.Errorf("expected empty backup path for new file, got %q", backupPath)
	}

	// Read and verify.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	serversRaw, ok := cfg["mcpServers"]
	if !ok {
		t.Fatal("missing mcpServers key")
	}

	var servers map[string]mcpServerEntry
	if err := json.Unmarshal(serversRaw, &servers); err != nil {
		t.Fatalf("parse mcpServers: %v", err)
	}

	entry, ok := servers["yorishiro-proxy"]
	if !ok {
		t.Fatal("missing yorishiro-proxy entry")
	}

	if entry.Command != "/usr/bin/yorishiro-proxy" {
		t.Errorf("command = %q, want %q", entry.Command, "/usr/bin/yorishiro-proxy")
	}
}

func TestWriteMCPConfig_ExistingFile_PreservesOtherServers(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	// Create existing config with another MCP server.
	existing := `{
  "mcpServers": {
    "other-server": {
      "command": "/usr/bin/other-server",
      "args": ["--flag"]
    }
  }
}
`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	backupPath, err := WriteMCPConfig(configPath, "/usr/bin/yorishiro-proxy", now)
	if err != nil {
		t.Fatalf("WriteMCPConfig() error: %v", err)
	}

	// Should have a backup.
	if backupPath == "" {
		t.Error("expected non-empty backup path for existing file")
	}

	// Read and verify both servers exist.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	var servers map[string]json.RawMessage
	if err := json.Unmarshal(cfg["mcpServers"], &servers); err != nil {
		t.Fatalf("parse mcpServers: %v", err)
	}

	if _, ok := servers["other-server"]; !ok {
		t.Error("existing other-server entry was lost")
	}
	if _, ok := servers["yorishiro-proxy"]; !ok {
		t.Error("yorishiro-proxy entry not added")
	}
}

func TestWriteMCPConfig_ExistingFile_UpdatesYorishiroEntry(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	// Create existing config with an old yorishiro-proxy entry.
	existing := `{
  "mcpServers": {
    "yorishiro-proxy": {
      "command": "/old/path/yorishiro-proxy",
      "args": []
    }
  }
}
`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	_, err := WriteMCPConfig(configPath, "/new/path/yorishiro-proxy", now)
	if err != nil {
		t.Fatalf("WriteMCPConfig() error: %v", err)
	}

	// Read and verify the entry was updated.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	var servers map[string]mcpServerEntry
	if err := json.Unmarshal(cfg["mcpServers"], &servers); err != nil {
		t.Fatalf("parse mcpServers: %v", err)
	}

	if servers["yorishiro-proxy"].Command != "/new/path/yorishiro-proxy" {
		t.Errorf("command not updated: got %q", servers["yorishiro-proxy"].Command)
	}
}

func TestWriteMCPConfig_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "subdir", "config.json")
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	_, err := WriteMCPConfig(configPath, "/usr/bin/yorishiro-proxy", now)
	if err != nil {
		t.Fatalf("WriteMCPConfig() error: %v", err)
	}

	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("config file not created: %v", err)
	}
}

func TestWriteMCPConfig_PreservesExtraFields(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	// Create existing config with extra top-level fields.
	existing := `{
  "version": "1.0",
  "mcpServers": {}
}
`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	_, err := WriteMCPConfig(configPath, "/usr/bin/yorishiro-proxy", now)
	if err != nil {
		t.Fatalf("WriteMCPConfig() error: %v", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if _, ok := cfg["version"]; !ok {
		t.Error("extra field 'version' was lost")
	}
}

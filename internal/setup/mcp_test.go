package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	entry := BuildMCPEntry("/usr/local/bin/katashiro-proxy", "127.0.0.1:8080")

	if entry.Command != "/usr/local/bin/katashiro-proxy" {
		t.Errorf("Command = %q, want %q", entry.Command, "/usr/local/bin/katashiro-proxy")
	}

	if len(entry.Args) == 0 {
		t.Fatal("expected non-empty Args")
	}

	// Check that -insecure and -log-file are in args.
	argsStr := joinArgs(entry.Args)
	if !containsStr(argsStr, "-insecure") {
		t.Error("expected -insecure in args")
	}
	if !containsStr(argsStr, "-log-file") {
		t.Error("expected -log-file in args")
	}
}

func joinArgs(args []string) string {
	result := ""
	for _, a := range args {
		result += a + " "
	}
	return result
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestWriteMCPConfig_NewFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	backupPath, err := WriteMCPConfig(configPath, "/usr/bin/katashiro-proxy", "127.0.0.1:8080", now)
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

	entry, ok := servers["katashiro-proxy"]
	if !ok {
		t.Fatal("missing katashiro-proxy entry")
	}

	if entry.Command != "/usr/bin/katashiro-proxy" {
		t.Errorf("command = %q, want %q", entry.Command, "/usr/bin/katashiro-proxy")
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

	backupPath, err := WriteMCPConfig(configPath, "/usr/bin/katashiro-proxy", "127.0.0.1:8080", now)
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
	if _, ok := servers["katashiro-proxy"]; !ok {
		t.Error("katashiro-proxy entry not added")
	}
}

func TestWriteMCPConfig_ExistingFile_UpdatesKatashiroEntry(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	// Create existing config with an old katashiro-proxy entry.
	existing := `{
  "mcpServers": {
    "katashiro-proxy": {
      "command": "/old/path/katashiro-proxy",
      "args": []
    }
  }
}
`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	_, err := WriteMCPConfig(configPath, "/new/path/katashiro-proxy", "127.0.0.1:8080", now)
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

	if servers["katashiro-proxy"].Command != "/new/path/katashiro-proxy" {
		t.Errorf("command not updated: got %q", servers["katashiro-proxy"].Command)
	}
}

func TestWriteMCPConfig_CreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "subdir", "config.json")
	now := time.Date(2026, 3, 1, 14, 30, 45, 0, time.UTC)

	_, err := WriteMCPConfig(configPath, "/usr/bin/katashiro-proxy", "127.0.0.1:8080", now)
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

	_, err := WriteMCPConfig(configPath, "/usr/bin/katashiro-proxy", "127.0.0.1:8080", now)
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

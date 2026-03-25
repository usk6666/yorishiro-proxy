package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// mcpServerEntry represents a single MCP server entry in .mcp.json or settings.json.
type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// MCPConfigPath returns the file path for MCP configuration based on the scope.
// "project" returns .mcp.json in the given directory.
// "user" returns ~/.claude/settings.json.
func MCPConfigPath(scope, projectDir string) (string, error) {
	switch scope {
	case "project":
		return filepath.Join(projectDir, ".mcp.json"), nil
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return filepath.Join(home, ".claude", "settings.json"), nil
	default:
		return "", fmt.Errorf("invalid scope %q: must be \"project\" or \"user\"", scope)
	}
}

// BackupPath returns a backup file path with a timestamp suffix.
// Format: <filename>.bak.<YYYYMMDD-HHMMSS>
func BackupPath(path string, now time.Time) string {
	stamp := now.Format("20060102-150405")
	return path + ".bak." + stamp
}

// CreateBackup copies the content of an existing file to a backup path.
// If the source file does not exist, no backup is created and nil is returned.
func CreateBackup(path string, now time.Time) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read file for backup: %w", err)
	}

	backupFile := BackupPath(path, now)
	if err := os.WriteFile(backupFile, data, 0600); err != nil {
		return "", fmt.Errorf("write backup file: %w", err)
	}
	return backupFile, nil
}

// defaultLogFilePath returns the default log file path under ~/.yorishiro-proxy/.
func defaultLogFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".yorishiro-proxy", "yorishiro-proxy.log")
	}
	return filepath.Join(home, ".yorishiro-proxy", "yorishiro-proxy.log")
}

// BuildMCPEntry creates a yorishiro-proxy MCP server entry for the given binary path.
// The entry uses the "server" subcommand with "-stdio-mcp" to enable stdio MCP
// in addition to the default HTTP MCP transport. This is the expected configuration
// when launched by MCP clients such as Claude Code.
func BuildMCPEntry(binaryPath string) mcpServerEntry {
	args := []string{
		"server",
		"-stdio-mcp",
		"-log-file", defaultLogFilePath(),
	}
	return mcpServerEntry{
		Command: binaryPath,
		Args:    args,
	}
}

// WriteMCPConfig writes or updates the MCP configuration file at the given path.
// If the file already exists, the yorishiro-proxy entry is added or updated
// while preserving other MCP server entries.
func WriteMCPConfig(path, binaryPath string, now time.Time) (backupPath string, err error) {
	entry := BuildMCPEntry(binaryPath)

	// Read existing config if present.
	existingData, readErr := os.ReadFile(path)
	var existing map[string]json.RawMessage

	if readErr == nil {
		// File exists — back it up.
		bp, bErr := CreateBackup(path, now)
		if bErr != nil {
			return "", fmt.Errorf("backup existing config: %w", bErr)
		}
		backupPath = bp

		if err := json.Unmarshal(existingData, &existing); err != nil {
			return backupPath, fmt.Errorf("parse existing config: %w", err)
		}
	} else if !os.IsNotExist(readErr) {
		return "", fmt.Errorf("read existing config: %w", readErr)
	}

	if existing == nil {
		existing = make(map[string]json.RawMessage)
	}

	// Get or create mcpServers section.
	var servers map[string]json.RawMessage
	if raw, ok := existing["mcpServers"]; ok {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return backupPath, fmt.Errorf("parse mcpServers: %w", err)
		}
	}
	if servers == nil {
		servers = make(map[string]json.RawMessage)
	}

	// Add/update yorishiro-proxy entry.
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return backupPath, fmt.Errorf("marshal yorishiro-proxy entry: %w", err)
	}
	servers["yorishiro-proxy"] = entryJSON

	// Write back servers.
	serversJSON, err := json.Marshal(servers)
	if err != nil {
		return backupPath, fmt.Errorf("marshal mcpServers: %w", err)
	}
	existing["mcpServers"] = serversJSON

	// Marshal the full config with indentation.
	output, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return backupPath, fmt.Errorf("marshal config: %w", err)
	}
	output = append(output, '\n')

	// Ensure parent directory exists.
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return backupPath, fmt.Errorf("create config directory: %w", err)
		}
	}

	if err := os.WriteFile(path, output, 0644); err != nil {
		return backupPath, fmt.Errorf("write config file: %w", err)
	}

	return backupPath, nil
}

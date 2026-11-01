package config

import (
	"fmt"
	"strings"
)

// ParseMCPTools splits the comma-separated -mcp-tools / YP_MCP_TOOLS value
// into tool names, trimming the space around each one (USK-1120). An empty
// (or all-whitespace) value returns nil, meaning "no allowlist: expose
// every tool". Empty elements ("a,,b", " , ") are kept so Validate can
// refuse them instead of silently dropping a typo.
func ParseMCPTools(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

// validateMCPTools checks the shape of the MCP tool allowlist: no element
// may be empty. Whether each name is a real tool is checked by the MCP
// server package at boot (it owns the tool vocabulary, and importing it
// here would be a cycle).
func (c *Config) validateMCPTools() error {
	for i, n := range c.MCPTools {
		if n == "" {
			return fmt.Errorf("mcp_tools: element %d is empty (check -mcp-tools / YP_MCP_TOOLS for a stray comma)", i)
		}
	}
	return nil
}

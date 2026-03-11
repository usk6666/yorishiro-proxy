// Package setup provides the logic for the `yorishiro-proxy install` command.
//
// It automates configuration of yorishiro-proxy with Claude Code,
// including MCP server configuration, CA certificate generation and trust store
// registration, playwright-cli integration, and yorishiro skill installation.
//
// The install command supports per-target execution (mcp, ca, skills, playwright)
// and is non-interactive by default for CI compatibility.
package setup

package mcp

import (
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolNames returns the names of every MCP tool this server can register.
func ToolNames() []string {
	return nil
}

// WithToolAllowlist restricts the registered MCP tools to names.
func WithToolAllowlist(names []string) ServerOption {
	return func(s *Server) {}
}

// ValidateToolAllowlist reports an error when names contains an entry that
// is not one of ToolNames().
func ValidateToolAllowlist(names []string) error {
	return nil
}

// addTool registers a tool on s.
func addTool[In, Out any](s *Server, t *gomcp.Tool, h gomcp.ToolHandlerFor[In, Out]) {
	gomcp.AddTool(s.server, t, h)
}

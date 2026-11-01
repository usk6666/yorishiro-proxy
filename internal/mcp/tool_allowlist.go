package mcp

import (
	"fmt"
	"slices"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolNames returns the name of every MCP tool this server registers when
// no allowlist is set, in registration order. It is the vocabulary of
// WithToolAllowlist / ValidateToolAllowlist (the -mcp-tools flag). The
// returned slice is a copy.
func ToolNames() []string {
	return slices.Clone(toolNames)
}

// WithToolAllowlist restricts the MCP tools the server registers to names
// (USK-1120). A tool outside the list is never registered, so it is absent
// from tools/list and a tools/call to it fails exactly like a call to a
// tool that does not exist (JSON-RPC invalid params, `unknown tool "X"`).
//
// A nil names leaves every tool registered (the default). A non-nil list is
// fail-closed: only the named tools are registered, and a tool added to the
// server later stays hidden until it is named. Names are exact and
// case-sensitive; duplicates are harmless. Membership is not checked here —
// callers validate with ValidateToolAllowlist first.
//
// The allowlist is read once, before tool registration in NewServer; no
// MCP tool can change it at runtime.
func WithToolAllowlist(names []string) ServerOption {
	return func(s *Server) {
		if names == nil {
			s.toolAllowlist = nil
			return
		}
		s.toolAllowlist = make(map[string]bool, len(names))
		for _, n := range names {
			s.toolAllowlist[n] = true
		}
	}
}

// ValidateToolAllowlist returns an error naming the first entry of names
// that is not one of ToolNames(). The error lists the valid names.
func ValidateToolAllowlist(names []string) error {
	for _, n := range names {
		if !slices.Contains(toolNames, n) {
			return fmt.Errorf("mcp_tools: unknown MCP tool %q (valid tools: %s)", n, strings.Join(toolNames, ", "))
		}
	}
	return nil
}

// addTool registers t on s unless the tool allowlist excludes it. Every
// tool registration goes through here so a registerX function cannot
// bypass the allowlist.
func addTool[In, Out any](s *Server, t *gomcp.Tool, h gomcp.ToolHandlerFor[In, Out]) {
	if s.toolAllowlist != nil && !s.toolAllowlist[t.Name] {
		return
	}
	gomcp.AddTool(s.server, t, h)
}

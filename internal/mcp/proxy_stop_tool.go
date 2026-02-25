package mcp

import (
	"context"
	"fmt"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// proxyStopResult is the structured output of the proxy_stop tool.
type proxyStopResult struct {
	// Status indicates the proxy state after the operation.
	Status string `json:"status"`
}

// registerProxyStop registers the proxy_stop MCP tool.
func (s *Server) registerProxyStop() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "proxy_stop",
		Description: "Stop the proxy server. Performs a graceful shutdown, waiting for existing connections to complete before stopping.",
	}, s.handleProxyStop)
}

// handleProxyStop handles the proxy_stop tool invocation.
func (s *Server) handleProxyStop(ctx context.Context, _ *gomcp.CallToolRequest, _ any) (*gomcp.CallToolResult, *proxyStopResult, error) {
	if s.manager == nil {
		return nil, nil, fmt.Errorf("proxy manager is not initialized")
	}

	if err := s.manager.Stop(ctx); err != nil {
		return nil, nil, fmt.Errorf("proxy stop: %w", err)
	}

	result := &proxyStopResult{
		Status: "stopped",
	}
	return nil, result, nil
}

package mcp

import (
	"context"
	"fmt"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// proxyStopInput is the input for the proxy_stop tool.
type proxyStopInput struct {
	// Name is the name of the listener to stop.
	// If empty, all running listeners are stopped.
	Name string `json:"name,omitempty" jsonschema:"listener name to stop; if omitted, all listeners are stopped"`
}

// proxyStopResult is the structured output of the proxy_stop tool.
type proxyStopResult struct {
	// Status indicates the proxy state after the operation.
	Status string `json:"status"`
	// Stopped lists the names of listeners that were stopped.
	Stopped []string `json:"stopped,omitempty"`
}

// registerProxyStop registers the proxy_stop MCP tool.
func (s *Server) registerProxyStop() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "proxy_stop",
		Description: "Stop proxy listener(s). If 'name' is specified, stops only that listener. " +
			"If 'name' is omitted, stops all running listeners. " +
			"Performs a graceful shutdown, waiting for existing connections to complete before stopping.",
	}, s.handleProxyStop)
}

// handleProxyStop handles the proxy_stop tool invocation.
func (s *Server) handleProxyStop(ctx context.Context, _ *gomcp.CallToolRequest, input proxyStopInput) (*gomcp.CallToolResult, *proxyStopResult, error) {
	if s.manager == nil {
		return nil, nil, fmt.Errorf("proxy manager is not initialized")
	}

	if input.Name != "" {
		// Stop a specific named listener.
		if err := s.manager.StopNamed(ctx, input.Name); err != nil {
			return nil, nil, fmt.Errorf("proxy stop: %w", err)
		}
		result := &proxyStopResult{
			Status:  "stopped",
			Stopped: []string{input.Name},
		}
		return nil, result, nil
	}

	// Stop all listeners.
	// Collect names before stopping for the response.
	statuses := s.manager.ListenerStatuses()
	if len(statuses) == 0 {
		return nil, nil, fmt.Errorf("proxy stop: %w", proxy.ErrNotRunning)
	}

	names := make([]string, 0, len(statuses))
	for _, st := range statuses {
		names = append(names, st.Name)
	}

	if err := s.manager.StopAll(ctx); err != nil {
		return nil, nil, fmt.Errorf("proxy stop: %w", err)
	}

	result := &proxyStopResult{
		Status:  "stopped",
		Stopped: names,
	}
	return nil, result, nil
}

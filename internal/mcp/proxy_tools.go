package mcp

import (
	"context"
	"fmt"
	"net"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// proxyStartInput is the input for the proxy_start tool.
type proxyStartInput struct {
	// ListenAddr is the TCP address to listen on (e.g. "127.0.0.1:8080", "127.0.0.1:9090").
	// Defaults to "127.0.0.1:8080" if empty.
	ListenAddr string `json:"listen_addr,omitempty" jsonschema:"TCP address to listen on, defaults to 127.0.0.1:8080 if omitted"`
}

// proxyStartResult is the structured output of the proxy_start tool.
type proxyStartResult struct {
	// ListenAddr is the actual address the proxy is listening on.
	ListenAddr string `json:"listen_addr"`
	// Status indicates the proxy state after the operation.
	Status string `json:"status"`
}

// proxyStopResult is the structured output of the proxy_stop tool.
type proxyStopResult struct {
	// Status indicates the proxy state after the operation.
	Status string `json:"status"`
}

// registerProxyStart registers the proxy_start MCP tool.
func (s *Server) registerProxyStart() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "proxy_start",
		Description: "Start the proxy server. The proxy listens on the specified address and begins intercepting HTTP/HTTPS traffic. If no address is provided, it defaults to 127.0.0.1:8080.",
	}, s.handleProxyStart)
}

// registerProxyStop registers the proxy_stop MCP tool.
func (s *Server) registerProxyStop() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "proxy_stop",
		Description: "Stop the proxy server. Performs a graceful shutdown, waiting for existing connections to complete before stopping.",
	}, s.handleProxyStop)
}

// handleProxyStart handles the proxy_start tool invocation.
func (s *Server) handleProxyStart(ctx context.Context, _ *gomcp.CallToolRequest, input proxyStartInput) (*gomcp.CallToolResult, *proxyStartResult, error) {
	if s.manager == nil {
		return nil, nil, fmt.Errorf("proxy manager is not initialized")
	}

	// Validate listen address format if provided.
	if input.ListenAddr != "" {
		host, _, err := net.SplitHostPort(input.ListenAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid listen_addr %q: %w", input.ListenAddr, err)
		}
		// Restrict to loopback addresses for security.
		if host != "" && host != "localhost" {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return nil, nil, fmt.Errorf("invalid listen_addr %q: only loopback addresses are allowed", input.ListenAddr)
			}
		}
	}

	if err := s.manager.Start(context.Background(), input.ListenAddr); err != nil {
		return nil, nil, fmt.Errorf("proxy start: %w", err)
	}

	_, addr := s.manager.Status()

	result := &proxyStartResult{
		ListenAddr: addr,
		Status:     "running",
	}
	return nil, result, nil
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

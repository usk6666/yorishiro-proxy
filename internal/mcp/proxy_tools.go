package mcp

import (
	"context"
	"fmt"
	"os"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
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

// proxyStatusResult is the structured output of the proxy_status tool.
type proxyStatusResult struct {
	// Running indicates whether the proxy is currently running.
	Running bool `json:"running"`
	// ListenAddr is the address the proxy is listening on. Empty if not running.
	ListenAddr string `json:"listen_addr"`
	// ActiveConnections is the number of connections currently being handled.
	ActiveConnections int `json:"active_connections"`
	// TotalSessions is the total number of recorded session entries.
	TotalSessions int `json:"total_sessions"`
	// DBSizeBytes is the size of the session database file in bytes. -1 if unavailable.
	DBSizeBytes int64 `json:"db_size_bytes"`
	// UptimeSeconds is the number of seconds since the proxy was started. 0 if not running.
	UptimeSeconds int64 `json:"uptime_seconds"`
	// CAInitialized indicates whether the CA certificate has been loaded or generated.
	CAInitialized bool `json:"ca_initialized"`
}

// registerProxyStatus registers the proxy_status MCP tool.
func (s *Server) registerProxyStatus() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "proxy_status",
		Description: "Get the current status of the proxy server including health metrics. Returns whether the proxy is running, listen address, active connection count, total recorded sessions, database size, uptime, and CA initialization state.",
	}, s.handleProxyStatus)
}

// handleProxyStatus handles the proxy_status tool invocation.
func (s *Server) handleProxyStatus(ctx context.Context, _ *gomcp.CallToolRequest, _ any) (*gomcp.CallToolResult, *proxyStatusResult, error) {
	result := &proxyStatusResult{
		DBSizeBytes: -1,
	}

	// Proxy running state and listen address.
	if s.manager != nil {
		running, addr := s.manager.Status()
		result.Running = running
		result.ListenAddr = addr
		result.ActiveConnections = s.manager.ActiveConnections()
		result.UptimeSeconds = int64(s.manager.Uptime().Seconds())
	}

	// Total session count.
	if s.store != nil {
		count, err := s.store.CountSessions(ctx, session.ListOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("count sessions: %w", err)
		}
		result.TotalSessions = count
	}

	// Database file size.
	if s.dbPath != "" {
		info, err := os.Stat(s.dbPath)
		if err == nil {
			result.DBSizeBytes = info.Size()
		}
		// If the file doesn't exist or stat fails, leave -1 (unavailable).
	}

	// CA initialization state.
	if s.ca != nil && s.ca.Certificate() != nil {
		result.CAInitialized = true
	}

	return nil, result, nil
}

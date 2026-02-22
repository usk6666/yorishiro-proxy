package mcp

import (
	"context"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP server and registers proxy-related tools.
type Server struct {
	server *gomcp.Server
}

// NewServer creates a new MCP server with proxy tools registered.
func NewServer() *Server {
	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "katashiro-proxy",
		Version: "0.0.1",
	}, nil)

	s := &Server{server: server}
	s.registerTools()
	return s
}

// Run starts the MCP server on the given transport.
func (s *Server) Run(ctx context.Context, transport gomcp.Transport) error {
	return s.server.Run(ctx, transport)
}

func (s *Server) registerTools() {
	// TODO: Register proxy tools (intercept, replay, list sessions, etc.)
}

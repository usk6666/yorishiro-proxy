package mcp

import (
	"context"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/cert"
)

// Server wraps the MCP server and registers proxy-related tools.
type Server struct {
	server *gomcp.Server
	ca     *cert.CA
}

// NewServer creates a new MCP server with proxy tools registered.
// The ca parameter provides the CA certificate for the export_ca_cert tool.
// If ca is nil, the export_ca_cert tool will return an error when called.
func NewServer(ca *cert.CA) *Server {
	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "katashiro-proxy",
		Version: "0.0.1",
	}, nil)

	s := &Server{server: server, ca: ca}
	s.registerTools()
	return s
}

// Run starts the MCP server on the given transport.
func (s *Server) Run(ctx context.Context, transport gomcp.Transport) error {
	return s.server.Run(ctx, transport)
}

func (s *Server) registerTools() {
	s.registerExportCACert()
}

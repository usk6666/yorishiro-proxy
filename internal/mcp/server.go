package mcp

import (
	"context"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// Server wraps the MCP server and registers proxy-related tools.
type Server struct {
	server     *gomcp.Server
	ca         *cert.CA
	store      session.Store
	manager    *proxy.Manager
	replayDoer httpDoer // injectable HTTP client for replay_request testing
}

// NewServer creates a new MCP server with proxy tools registered.
// The ca parameter provides the CA certificate for the export_ca_cert tool.
// If ca is nil, the export_ca_cert tool will return an error when called.
// The store parameter provides session storage for session-related tools.
// If store is nil, session-related tools will return an error when called.
// The manager parameter controls the proxy lifecycle for proxy_start/proxy_stop tools.
// If manager is nil, those tools will return an error when called.
func NewServer(ca *cert.CA, store session.Store, manager *proxy.Manager) *Server {
	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "katashiro-proxy",
		Version: "0.0.1",
	}, nil)

	s := &Server{server: server, ca: ca, store: store, manager: manager}
	s.registerTools()
	return s
}

// Run starts the MCP server on the given transport.
func (s *Server) Run(ctx context.Context, transport gomcp.Transport) error {
	return s.server.Run(ctx, transport)
}

func (s *Server) registerTools() {
	s.registerDeleteSession()
	s.registerExportCACert()
	s.registerGetSession()
	s.registerListSessions()
	s.registerReplayRequest()
	s.registerProxyStart()
	s.registerProxyStop()
}

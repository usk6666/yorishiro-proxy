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
	server          *gomcp.Server
	appCtx          context.Context
	ca              *cert.CA
	store           session.Store
	manager         *proxy.Manager
	passthrough     *proxy.PassthroughList
	scope           *proxy.CaptureScope
	dbPath          string    // path to the SQLite database file for status reporting
	replayDoer      httpDoer  // injectable HTTP client for replay_request testing
	rawReplayDialer rawDialer // injectable dialer for replay_raw testing
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithDBPath sets the path to the SQLite database file for status reporting.
func WithDBPath(path string) ServerOption {
	return func(s *Server) {
		s.dbPath = path
	}
}

// WithPassthroughList sets the TLS passthrough list for the MCP server,
// enabling the add/remove/list TLS passthrough tools.
func WithPassthroughList(pl *proxy.PassthroughList) ServerOption {
	return func(s *Server) {
		s.passthrough = pl
	}
}

// WithCaptureScope sets the capture scope for the set/get/clear_capture_scope tools.
func WithCaptureScope(scope *proxy.CaptureScope) ServerOption {
	return func(s *Server) {
		s.scope = scope
	}
}

// NewServer creates a new MCP server with proxy tools registered.
// The ctx parameter is the application-level context that controls the proxy lifecycle;
// when ctx is cancelled, the proxy started via proxy_start will shut down.
// The ca parameter provides the CA certificate for the export_ca_cert tool.
// If ca is nil, the export_ca_cert tool will return an error when called.
// The store parameter provides session storage for session-related tools.
// If store is nil, session-related tools will return an error when called.
// The manager parameter controls the proxy lifecycle for proxy_start/proxy_stop tools.
// If manager is nil, those tools will return an error when called.
func NewServer(ctx context.Context, ca *cert.CA, store session.Store, manager *proxy.Manager, opts ...ServerOption) *Server {
	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "katashiro-proxy",
		Version: "0.0.1",
	}, nil)

	s := &Server{server: server, appCtx: ctx, ca: ca, store: store, manager: manager}
	for _, opt := range opts {
		opt(s)
	}
	s.registerTools()
	s.registerResources()
	return s
}

// Run starts the MCP server on the given transport.
func (s *Server) Run(ctx context.Context, transport gomcp.Transport) error {
	return s.server.Run(ctx, transport)
}

func (s *Server) registerTools() {
	s.registerClearSessions()
	s.registerDeleteSession()
	s.registerExportCACert()
	s.registerGetSession()
	s.registerListSessions()
	s.registerReplayRequest()
	s.registerReplayRaw()
	s.registerProxyStart()
	s.registerProxyStop()
	s.registerProxyStatus()
	s.registerAddTLSPassthrough()
	s.registerRemoveTLSPassthrough()
	s.registerListTLSPassthrough()
	s.registerSetCaptureScope()
	s.registerGetCaptureScope()
	s.registerClearCaptureScope()
	s.registerConfigure()
	s.registerQuery()
	s.registerExecute()
}

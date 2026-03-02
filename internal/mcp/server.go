package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/mcp/webui"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// Server wraps the MCP server and registers proxy-related tools.
type Server struct {
	server            *gomcp.Server
	appCtx            context.Context
	ca                *cert.CA
	issuer            *cert.Issuer
	store             session.Store
	manager           *proxy.Manager
	passthrough       *proxy.PassthroughList
	scope             *proxy.CaptureScope
	interceptEngine   *intercept.Engine
	interceptQueue    *intercept.Queue
	transformPipeline *rules.Pipeline
	fuzzRunner        *fuzzer.Runner      // async fuzz job runner
	fuzzStore         session.FuzzStore   // fuzz job/result persistence for query tool
	dbPath            string              // path to the SQLite database file for status reporting
	replayDoer        httpDoer       // injectable HTTP client for execute(replay) testing
	rawReplayDialer   rawDialer      // injectable dialer for replay_raw testing
	tcpForwards       map[string]string    // TCP forward mappings (port -> target)
	tcpHandler        tcpForwardHandler    // TCP handler for forward listeners
	enabledProtocols       []string              // enabled protocols for detection
	httpMiddleware         func(http.Handler) http.Handler // optional middleware wrapping the HTTP handler
	proxyDefaults          *config.ProxyConfig  // default proxy config from config file
	upstreamProxySetters   []upstreamProxySetter // protocol handlers to update when upstream proxy changes
	requestTimeoutSetters  []requestTimeoutSetter // protocol handlers to update when request timeout changes
	targetScopeSetters     []targetScopeSetter    // protocol handlers to update when target scope changes
	uiDir                  string               // optional filesystem path for WebUI static files
	targetScope            *proxy.TargetScope   // target scope rules for security tool
	version                string               // build version reported via MCP implementation
}

// tcpForwardHandler extends proxy.ProtocolHandler with the ability to update
// forward mappings at runtime. This interface is satisfied by tcp.Handler.
type tcpForwardHandler interface {
	proxy.ProtocolHandler
	SetForwards(forwards map[string]string)
}

// upstreamProxySetter is implemented by protocol handlers that support upstream
// proxy configuration (HTTP/1.x and HTTP/2 handlers).
type upstreamProxySetter interface {
	SetUpstreamProxy(proxyURL *url.URL)
}

// requestTimeoutSetter is implemented by protocol handlers that support
// request timeout configuration (HTTP/1.x and HTTP/2 handlers).
type requestTimeoutSetter interface {
	SetRequestTimeout(d time.Duration)
	RequestTimeout() time.Duration
}

// targetScopeSetter is implemented by protocol handlers that support
// target scope enforcement (HTTP/1.x and HTTP/2 handlers).
type targetScopeSetter interface {
	SetTargetScope(scope *proxy.TargetScope)
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
// enabling TLS passthrough configuration via the configure tool.
func WithPassthroughList(pl *proxy.PassthroughList) ServerOption {
	return func(s *Server) {
		s.passthrough = pl
	}
}

// WithCaptureScope sets the capture scope for the configure and query tools.
func WithCaptureScope(scope *proxy.CaptureScope) ServerOption {
	return func(s *Server) {
		s.scope = scope
	}
}

// WithInterceptEngine sets the intercept rule engine for the MCP server,
// enabling intercept rule configuration via proxy_start and configure tools.
func WithInterceptEngine(engine *intercept.Engine) ServerOption {
	return func(s *Server) {
		s.interceptEngine = engine
	}
}

// WithInterceptQueue sets the intercept queue for the MCP server,
// enabling intercept queue query and action execution via query and execute tools.
func WithInterceptQueue(queue *intercept.Queue) ServerOption {
	return func(s *Server) {
		s.interceptQueue = queue
	}
}

// WithTransformPipeline sets the auto-transform rule pipeline for the MCP server,
// enabling auto-transform rule configuration via proxy_start and configure tools.
func WithTransformPipeline(pipeline *rules.Pipeline) ServerOption {
	return func(s *Server) {
		s.transformPipeline = pipeline
	}
}

// WithFuzzRunner sets the async fuzz runner for the MCP server,
// enabling asynchronous fuzz job execution, pause, resume, and cancel.
func WithFuzzRunner(runner *fuzzer.Runner) ServerOption {
	return func(s *Server) {
		s.fuzzRunner = runner
	}
}

// WithFuzzStore sets the fuzz store for the MCP server,
// enabling fuzz_jobs and fuzz_results query resources.
func WithFuzzStore(fs session.FuzzStore) ServerOption {
	return func(s *Server) {
		s.fuzzStore = fs
	}
}

// WithIssuer sets the certificate issuer for the MCP server,
// enabling cache clearing on CA regeneration.
func WithIssuer(iss *cert.Issuer) ServerOption {
	return func(s *Server) {
		s.issuer = iss
	}
}

// WithTCPHandler sets the TCP handler for the MCP server, enabling TCP
// forward listener creation via the proxy_start tool's tcp_forwards parameter.
func WithTCPHandler(h tcpForwardHandler) ServerOption {
	return func(s *Server) {
		s.tcpHandler = h
	}
}

// WithMiddleware sets an HTTP middleware that wraps the Streamable HTTP
// handler in RunHTTP. This is used to inject Bearer token authentication
// or other request-level middleware around the MCP HTTP transport.
func WithMiddleware(mw func(http.Handler) http.Handler) ServerOption {
	return func(s *Server) {
		s.httpMiddleware = mw
	}
}

// WithUIDir sets a filesystem directory from which to serve WebUI static files,
// overriding the default embedded assets.
func WithUIDir(dir string) ServerOption {
	return func(s *Server) {
		s.uiDir = dir
	}
}

// WithTargetScope sets the target scope for the security tool,
// enabling target scope rule management via the security MCP tool.
func WithTargetScope(ts *proxy.TargetScope) ServerOption {
	return func(s *Server) {
		s.targetScope = ts
	}
}

// WithVersion sets the version string reported in the MCP server implementation.
// If not set, defaults to "dev".
func WithVersion(v string) ServerOption {
	return func(s *Server) {
		s.version = v
	}
}

// WithProxyDefaults sets the default proxy configuration loaded from a config file.
// These defaults are applied to proxy_start invocations when the caller does not
// explicitly provide a value for a given field.
func WithProxyDefaults(cfg *config.ProxyConfig) ServerOption {
	return func(s *Server) {
		s.proxyDefaults = cfg
	}
}

// WithUpstreamProxySetter registers a protocol handler that should be updated
// when the upstream proxy configuration changes. Call this for each handler
// that implements the upstreamProxySetter interface (e.g., HTTP/1.x, HTTP/2).
func WithUpstreamProxySetter(setter upstreamProxySetter) ServerOption {
	return func(s *Server) {
		s.upstreamProxySetters = append(s.upstreamProxySetters, setter)
	}
}

// WithRequestTimeoutSetters registers protocol handlers that support request
// timeout configuration. When request_timeout_ms is changed via proxy_start
// or configure, all registered setters are updated.
func WithRequestTimeoutSetters(setters ...requestTimeoutSetter) ServerOption {
	return func(s *Server) {
		s.requestTimeoutSetters = append(s.requestTimeoutSetters, setters...)
	}
}

// WithTargetScopeSetter registers a protocol handler that should be updated
// when the target scope changes. Call this for each handler that implements
// the targetScopeSetter interface (e.g., HTTP/1.x, HTTP/2).
func WithTargetScopeSetter(setter targetScopeSetter) ServerOption {
	return func(s *Server) {
		s.targetScopeSetters = append(s.targetScopeSetters, setter)
	}
}

// NewServer creates a new MCP server with proxy tools registered.
// The ctx parameter is the application-level context that controls the proxy lifecycle;
// when ctx is cancelled, the proxy started via proxy_start will shut down.
// The ca parameter provides the CA certificate for the query tool's ca_cert resource.
// If ca is nil, querying ca_cert will return an error.
// The store parameter provides session storage for session and replay operations.
// If store is nil, session-related operations will return an error.
// The manager parameter controls the proxy lifecycle for proxy_start/proxy_stop tools.
// If manager is nil, those tools will return an error when called.
func NewServer(ctx context.Context, ca *cert.CA, store session.Store, manager *proxy.Manager, opts ...ServerOption) *Server {
	s := &Server{appCtx: ctx, ca: ca, store: store, manager: manager, version: "dev"}
	for _, opt := range opts {
		opt(s)
	}

	server := gomcp.NewServer(&gomcp.Implementation{
		Name:    "yorishiro-proxy",
		Version: s.version,
	}, nil)
	s.server = server
	// Initialize default TargetScope if not provided via WithTargetScope.
	if s.targetScope == nil {
		s.targetScope = proxy.NewTargetScope()
	}
	// Propagate target scope to all registered protocol handlers.
	for _, setter := range s.targetScopeSetters {
		setter.SetTargetScope(s.targetScope)
	}
	s.registerTools()
	s.registerResources()
	return s
}

// Run starts the MCP server on the given transport.
func (s *Server) Run(ctx context.Context, transport gomcp.Transport) error {
	return s.server.Run(ctx, transport)
}

// shutdownTimeout is the maximum time to wait for the HTTP server to shut
// down gracefully. Exported as a variable for testing.
var shutdownTimeout = 30 * time.Second

// RunHTTP starts the MCP server as a Streamable HTTP endpoint on the given address.
// It creates a StreamableHTTPHandler backed by the underlying gomcp.Server and
// serves it via http.Server. The server shuts down gracefully when ctx is cancelled,
// waiting up to 30 seconds for active MCP sessions to complete.
//
// The addr must be a loopback address (e.g. "127.0.0.1:3000") to prevent
// unauthenticated exposure on the network.
func (s *Server) RunHTTP(ctx context.Context, addr string) error {
	if err := validateLoopbackAddr(addr); err != nil {
		return fmt.Errorf("MCP HTTP server: %w", err)
	}

	// Build MCP handler with auth middleware.
	var mcpHandler http.Handler = gomcp.NewStreamableHTTPHandler(func(_ *http.Request) *gomcp.Server {
		return s.server
	}, nil)
	if s.httpMiddleware != nil {
		mcpHandler = s.httpMiddleware(mcpHandler)
	}

	// Build WebUI handler.
	var uiHandler http.Handler
	if s.uiDir != "" {
		var err error
		uiHandler, err = webui.NewFSHandler(s.uiDir)
		if err != nil {
			return fmt.Errorf("MCP HTTP server: %w", err)
		}
	} else {
		uiHandler = webui.DefaultHandler()
	}

	// Route: /mcp -> MCP handler, / -> WebUI handler.
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/", uiHandler)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
		// ReadHeaderTimeout protects against Slowloris attacks (CWE-400).
		// ReadTimeout is intentionally not set to avoid breaking SSE streams.
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// Start shutdown goroutine that waits for context cancellation.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		slog.Info("shutting down MCP HTTP server", "addr", addr)
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Warn("MCP HTTP server shutdown error", "error", err)
		}
	}()

	slog.Info("starting MCP HTTP server", "addr", addr)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("MCP HTTP server: %w", err)
	}

	// Wait for the shutdown goroutine to finish.
	<-shutdownDone
	return nil
}

func (s *Server) registerTools() {
	s.registerProxyStart()
	s.registerProxyStop()
	s.registerConfigure()
	s.registerQuery()
	s.registerExecute()
	s.registerManage()
	s.registerFuzz()
	s.registerMacro()
	s.registerIntercept()
	s.registerSecurity()
}

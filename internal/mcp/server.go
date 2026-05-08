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
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/mcp/webui"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// schemaCache is a process-wide cache of resolved JSON schemas, shared by
// every MCP Server instance built in this process.
//
// The 17 tool input/output struct types registered by registerTools are
// fixed at compile time, so caching by reflect.Type is unconditionally
// correct. The cache is concurrent-safe (gomcp.SchemaCache uses sync.Map
// internally) and cheaply amortises a 1+ second per-server reflection cost
// that otherwise dominates the fast-tier test suite — every test that
// constructs an mcp.Server pays that cost without the cache, and the
// internal/mcp package alone has 100+ such call sites (USK-778).
var schemaCache = gomcp.NewSchemaCache()

// Server wraps the MCP server and registers proxy-related tools.
//
// The dependency surface is split into seven coherent components defined in
// components.go: Pipeline, Connector, JobRunner, FlowStore, MacroEngine,
// PluginEngine, and Misc. Tool handler files reach in via the matching field
// (s.pipeline.X, s.connector.Y, ...). The convention is that any single
// handler should access at most three components; the two documented
// exceptions are proxy_start_tool.go (the assembly handler) and
// query_tool.go (the unified query dispatcher).
type Server struct {
	server         *gomcp.Server
	pipeline       *Pipeline
	connector      *Connector
	jobRunner      *JobRunner
	flowStore      *FlowStore
	macroEngine    *MacroEngine
	pluginEngine   *PluginEngine
	misc           *Misc
	httpMiddleware func(http.Handler) http.Handler
	uiDir          string
	version        string
}

// tcpForwardHandler is the legacy TCP-forward dispatcher interface, kept
// only for legacy_options_test.go scaffolding. The live data path no
// longer touches this surface (USK-707); USK-708 retires the test
// helpers. Body inlined from the legacy proxy.ProtocolHandler so this
// package no longer imports internal/proxy.
type tcpForwardHandler interface {
	Name() string
	Detect(peek []byte) bool
	Handle(ctx context.Context, conn net.Conn) error
	SetForwards(forwards map[string]*config.ForwardConfig)
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
	SetTargetScope(scope *connector.TargetScope)
}

// rateLimiterSetter is implemented by protocol handlers that support
// rate limiting (HTTP/1.x, HTTP/2, and SOCKS5 handlers).
type rateLimiterSetter interface {
	SetRateLimiter(rl *connector.RateLimiter)
}

// safetyEngineSetter is implemented by protocol handlers that support
// safety filter enforcement (HTTP/1.x and HTTP/2 handlers).
type safetyEngineSetter interface {
	SetSafetyEngine(engine *safety.Engine)
}

// tlsFingerprintSetter is implemented by protocol handlers that support
// TLS fingerprint profile configuration (HTTP/1.x and HTTP/2 handlers).
// SetTLSTransport is required so that changing the profile also updates the
// actual TLS transport used for upstream connections (USK-467).
type tlsFingerprintSetter interface {
	SetTLSFingerprint(profile string)
	TLSFingerprint() string
	SetTLSTransport(transport.TLSTransport)
}

// socks5AuthSetter is implemented by a wrapper around the SOCKS5 handler
// to configure authentication at runtime. The SetPasswordAuth method enables
// username/password authentication with the given credentials. ClearAuth
// resets to no-authentication mode.
// The ForListener variants configure authentication for a specific named listener,
// allowing independent auth settings per listener in multi-listener setups.
type socks5AuthSetter interface {
	SetPasswordAuth(username, password string)
	ClearAuth()
	SetPasswordAuthForListener(listenerName, username, password string)
	ClearAuthForListener(listenerName string)
}

// socks5AuthQuerier is an optional extension implemented by a socks5AuthSetter
// that can also report whether any authenticator is currently configured.
// The MCP `query resource=status` tool uses this to populate `socks5_enabled`
// with the actual runtime auth state — falling back to "is the wire-up
// present" when the setter does not implement this extension. (USK-770)
type socks5AuthQuerier interface {
	HasAnyAuth() bool
}

// ServerOption configures a Server. The remaining options are limited to
// settings that are not part of the seven dependency components themselves
// (HTTP middleware, WebUI directory, version string). All component values
// are passed directly to NewServer; there are no With<Component> options.
type ServerOption func(*Server)

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

// WithVersion sets the version string reported in the MCP server implementation.
// If not set, defaults to "dev".
func WithVersion(v string) ServerOption {
	return func(s *Server) {
		s.version = v
	}
}

// NewServer creates a new MCP server with proxy tools registered.
//
// Each *<Component> argument is required (use the New<Component>(nil…)
// constructor to pass empty components in tests). The Connector's
// targetScope and the Misc rateLimiter / budgetManager are initialised to
// sensible defaults if nil; the Connector's targetScopeSetters and
// rateLimiterSetters are then notified once those defaults exist. The
// safetyEngineSetters in Pipeline are notified only when safetyEngine is
// non-nil.
func NewServer(
	misc *Misc,
	pipeline *Pipeline,
	connector *Connector,
	jobRunner *JobRunner,
	flowStore *FlowStore,
	macroEngine *MacroEngine,
	pluginEngine *PluginEngine,
	opts ...ServerOption,
) *Server {
	s := &Server{
		misc:         orDefaultMisc(misc),
		pipeline:     orDefaultPipeline(pipeline),
		connector:    orDefaultConnector(connector),
		jobRunner:    orDefaultJobRunner(jobRunner),
		flowStore:    orDefaultFlowStore(flowStore),
		macroEngine:  orDefaultMacroEngine(macroEngine),
		pluginEngine: orDefaultPluginEngine(pluginEngine),
		version:      "dev",
	}
	for _, opt := range opts {
		opt(s)
	}

	s.server = gomcp.NewServer(&gomcp.Implementation{
		Name:    "yorishiro-proxy",
		Version: s.version,
	}, &gomcp.ServerOptions{SchemaCache: schemaCache})

	finalizeDefaults(s)
	s.registerTools()
	s.registerResources()
	return s
}

// finalizeDefaults fills in optional shared services (TargetScope,
// RateLimiter, BudgetManager) with package defaults when they were not
// explicitly provided, then propagates them to every registered handler
// setter. Split out from NewServer so the constructor's cyclomatic
// complexity stays under the project's lint threshold.
func finalizeDefaults(s *Server) {
	if s.connector.targetScope == nil {
		s.connector.targetScope = connector.NewTargetScope()
	}
	for _, setter := range s.connector.targetScopeSetters {
		setter.SetTargetScope(s.connector.targetScope)
	}
	if s.misc.rateLimiter == nil {
		s.misc.rateLimiter = connector.NewRateLimiter()
	}
	for _, setter := range s.connector.rateLimiterSetters {
		setter.SetRateLimiter(s.misc.rateLimiter)
	}
	if s.pipeline.safetyEngine != nil {
		for _, setter := range s.pipeline.safetyEngineSetters {
			setter.SetSafetyEngine(s.pipeline.safetyEngine)
		}
	}
	if s.misc.budgetManager == nil {
		s.misc.budgetManager = connector.NewBudgetManager()
	}
	// USK-776: install an empty RecordScope when nil so configure /
	// proxy_start can mutate the same pointer that is also handed to
	// proxybuild.Deps.RecordScope. Live wiring populates this; tests
	// that omit it pass nil and get an empty (capture-all) default.
	if s.flowStore.recordScope == nil {
		s.flowStore.recordScope = flow.NewRecordScope()
	}
}

// orDefault* tiny helpers return the input when non-nil and an empty
// component when nil. Used by NewServer to keep its body linear.

func orDefaultMisc(m *Misc) *Misc {
	if m != nil {
		return m
	}
	return NewMisc(context.Background(), nil, nil, "", nil, nil)
}

func orDefaultPipeline(p *Pipeline) *Pipeline {
	if p != nil {
		return p
	}
	return NewPipeline(nil, nil, nil, nil, nil, nil, nil)
}

func orDefaultConnector(c *Connector) *Connector {
	if c != nil {
		return c
	}
	return NewConnector(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
}

func orDefaultJobRunner(j *JobRunner) *JobRunner {
	if j != nil {
		return j
	}
	return NewJobRunner(nil, nil, nil)
}

func orDefaultFlowStore(f *FlowStore) *FlowStore {
	if f != nil {
		return f
	}
	return NewFlowStore(nil, nil)
}

func orDefaultMacroEngine(m *MacroEngine) *MacroEngine {
	if m != nil {
		return m
	}
	return NewMacroEngine()
}

func orDefaultPluginEngine(p *PluginEngine) *PluginEngine {
	if p != nil {
		return p
	}
	return NewPluginEngine(nil)
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
//
// The optional onListening callback is invoked once the server is listening
// and ready to accept connections. The callback receives the resolved listen
// address (useful when the port is assigned dynamically). If onListening is
// nil it is silently ignored.
func (s *Server) RunHTTP(ctx context.Context, addr string, onListening ...func(addr string)) error {
	if err := validateLoopbackAddr(addr); err != nil {
		return fmt.Errorf("MCP HTTP server: %w", err)
	}

	// Snapshot shutdownTimeout at function entry so the shutdown goroutine
	// closes over a local copy. Without this, the goroutine reads the
	// package-level variable at shutdown time, which races with tests that
	// reset shutdownTimeout via t.Cleanup (see USK-778: schema cache
	// shortens RunHTTP startup enough that overlapping test goroutines
	// surfaced the latent race).
	shutdownDeadline := shutdownTimeout

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
		Handler: mux,
		// ReadHeaderTimeout protects against Slowloris attacks (CWE-400).
		// ReadTimeout is intentionally not set to avoid breaking SSE streams.
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// Bind the listener explicitly so we can notify the caller before serving.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("MCP HTTP server: %w", err)
	}

	listenAddr := ln.Addr().String()

	// Start shutdown goroutine that waits for context cancellation.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownDeadline)
		defer cancel()

		slog.Info("shutting down MCP HTTP server", "addr", listenAddr)
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Warn("MCP HTTP server shutdown error", "error", err)
		}
	}()

	slog.Info("starting MCP HTTP server", "addr", listenAddr)

	// Notify caller that the server is listening and ready to accept connections.
	for _, cb := range onListening {
		if cb != nil {
			cb(listenAddr)
		}
	}

	if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
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
	s.registerResendHTTP()
	s.registerResendWS()
	s.registerResendGRPC()
	s.registerResendRaw()
	s.registerManage()
	s.registerFuzzHTTP()
	s.registerFuzzWS()
	s.registerFuzzGRPC()
	s.registerFuzzRaw()
	s.registerMacro()
	s.registerIntercept()
	s.registerSecurity()
	s.registerPluginIntrospect()
}

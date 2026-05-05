package mcp

// legacy_options_test.go provides test-only helpers that retain the pre
// USK-664 NewServer (ctx, ca, store, manager, opts...) shape and the
// associated With* options. The production NewServer signature was redesigned
// to take seven explicit component pointers; rewriting all 100+ test call
// sites was out of scope for the refactor, so this file keeps the legacy
// shape behind a *_test.go file so it cannot leak into production callers.
//
// Each WithX helper mutates the appropriate component on Server after
// construction, mirroring what the old options did via a single deps bag.
// New tests SHOULD construct components directly via mcp.NewPipeline /
// mcp.NewConnector / etc., but existing tests continue to use this API.
// The plumbing types (PassthroughList, TargetScope, RateLimiter,
// BudgetManager) were rehomed to internal/connector during USK-704/USK-707;
// this file consumes those connector.* types directly.

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// newServer is the test-only constructor that mirrors the pre-refactor
// NewServer(ctx, ca, store, manager, opts...) signature. It builds the
// seven component pointers from the legacy parameters, then forwards to
// the production NewServer to apply ServerOption mutators.
func newServer(ctx context.Context, ca *cert.CA, store flow.Store, manager proxyManager, opts ...ServerOption) *Server {
	misc := NewMisc(ctx, ca, nil, "", nil, nil)
	pipe := NewPipeline(nil, nil, nil, nil, nil, nil, nil)
	conn := NewConnector(manager, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	jr := NewJobRunner(nil, nil, nil)
	fs := NewFlowStore(store)
	me := NewMacroEngine()
	pe := NewPluginEngine(nil)
	return NewServer(misc, pipe, conn, jr, fs, me, pe, opts...)
}

// legacyDeps is a test-only helper struct that mirrors the pre-USK-664
// monolithic deps bag. Existing tests construct one of these and use
// mkServerFromLegacyDeps to obtain a *Server with the matching components
// populated. New tests should construct components directly.
type legacyDeps struct {
	appCtx                context.Context
	ca                    *cert.CA
	issuer                *cert.Issuer
	store                 flow.Store
	manager               proxyManager
	passthrough           *connector.PassthroughList
	httpInterceptEngine   *httprules.InterceptEngine
	wsInterceptEngine     *wsrules.InterceptEngine
	grpcInterceptEngine   *grpcrules.InterceptEngine
	holdQueue             *common.HoldQueue
	transformHTTPEngine   *httprules.TransformEngine
	fuzzStore             flow.FuzzStore
	dbPath                string
	replayDoer            httpDoer
	rawReplayDialer       rawDialer
	tcpForwards           map[string]*config.ForwardConfig
	tcpHandler            tcpForwardHandler
	enabledProtocols      []string
	proxyDefaults         *config.ProxyConfig
	upstreamProxySetters  []upstreamProxySetter
	requestTimeoutSetters []requestTimeoutSetter
	targetScopeSetters    []targetScopeSetter
	targetScope           *connector.TargetScope
	rateLimiter           *connector.RateLimiter
	rateLimiterSetters    []rateLimiterSetter
	safetyEngine          *safety.Engine
	safetyEngineSetters   []safetyEngineSetter
	budgetManager         *connector.BudgetManager
	socks5AuthSetter      socks5AuthSetter
	tlsTransport          transport.TLSTransport
	tlsFingerprintSetters []tlsFingerprintSetter
	hostTLSRegistry       *transport.HostTLSRegistry
}

// mkServerFromLegacyDeps builds a *Server whose component pointers are
// populated from the given legacyDeps. Tests previously did
// `&Server{deps: &deps{X: y}}`; rewriting them to use this helper avoids
// duplicating the components.go field-distribution logic in each test.
//
// Unlike NewServer, this helper does NOT register MCP tools or initialise
// the underlying gomcp.Server — it returns a "bare" *Server whose
// component fields are populated. Tests that need tool registration
// should call newServer(ctx, ca, store, manager, opts...) instead.
func mkServerFromLegacyDeps(d legacyDeps) *Server {
	s := &Server{
		misc: &Misc{
			appCtx:        d.appCtx,
			ca:            d.ca,
			issuer:        d.issuer,
			dbPath:        d.dbPath,
			rateLimiter:   d.rateLimiter,
			budgetManager: d.budgetManager,
		},
		pipeline: &Pipeline{
			httpInterceptEngine: d.httpInterceptEngine,
			wsInterceptEngine:   d.wsInterceptEngine,
			grpcInterceptEngine: d.grpcInterceptEngine,
			holdQueue:           d.holdQueue,
			transformHTTPEngine: d.transformHTTPEngine,
			safetyEngine:        d.safetyEngine,
			safetyEngineSetters: d.safetyEngineSetters,
		},
		connector: &Connector{
			manager:               d.manager,
			passthrough:           d.passthrough,
			targetScope:           d.targetScope,
			targetScopeSetters:    d.targetScopeSetters,
			hostTLSRegistry:       d.hostTLSRegistry,
			tlsTransport:          d.tlsTransport,
			tlsFingerprintSetters: d.tlsFingerprintSetters,
			socks5AuthSetter:      d.socks5AuthSetter,
			tcpForwards:           d.tcpForwards,
			tcpHandler:            d.tcpHandler,
			enabledProtocols:      d.enabledProtocols,
			proxyDefaults:         d.proxyDefaults,
			upstreamProxySetters:  d.upstreamProxySetters,
			requestTimeoutSetters: d.requestTimeoutSetters,
			rateLimiterSetters:    d.rateLimiterSetters,
		},
		jobRunner: &JobRunner{
			fuzzStore:       d.fuzzStore,
			replayDoer:      d.replayDoer,
			rawReplayDialer: d.rawReplayDialer,
		},
		flowStore:    &FlowStore{store: d.store},
		macroEngine:  &MacroEngine{},
		pluginEngine: &PluginEngine{},
		version:      "dev",
	}
	return s
}

// WithDBPath sets the SQLite db path on Misc. Test-only.
func WithDBPath(path string) ServerOption {
	return func(s *Server) {
		s.misc.dbPath = path
	}
}

// WithPassthroughList sets the TLS passthrough list. Test-only.
func WithPassthroughList(pl *connector.PassthroughList) ServerOption {
	return func(s *Server) {
		s.connector.passthrough = pl
	}
}

// WithHTTPInterceptEngine sets the per-protocol HTTP intercept engine. Test-only.
func WithHTTPInterceptEngine(engine *httprules.InterceptEngine) ServerOption {
	return func(s *Server) {
		s.pipeline.httpInterceptEngine = engine
	}
}

// WithWSInterceptEngine sets the per-protocol WebSocket intercept engine. Test-only.
func WithWSInterceptEngine(engine *wsrules.InterceptEngine) ServerOption {
	return func(s *Server) {
		s.pipeline.wsInterceptEngine = engine
	}
}

// WithGRPCInterceptEngine sets the per-protocol gRPC intercept engine. Test-only.
func WithGRPCInterceptEngine(engine *grpcrules.InterceptEngine) ServerOption {
	return func(s *Server) {
		s.pipeline.grpcInterceptEngine = engine
	}
}

// WithHoldQueue sets the RFC-001 HoldQueue used by the intercept tool. Test-only.
func WithHoldQueue(queue *common.HoldQueue) ServerOption {
	return func(s *Server) {
		s.pipeline.holdQueue = queue
	}
}

// WithPluginv2Engine sets the pluginv2 engine on the PluginEngine
// component. Used by plugin_introspect tests. Test-only.
func WithPluginv2Engine(engine *pluginv2.Engine) ServerOption {
	return func(s *Server) {
		s.pluginEngine.pluginv2 = engine
	}
}

// WithHTTPTransformEngine sets the per-protocol HTTP transform engine. Test-only.
func WithHTTPTransformEngine(e *httprules.TransformEngine) ServerOption {
	return func(s *Server) {
		s.pipeline.transformHTTPEngine = e
	}
}

// WithFuzzStore sets the fuzz store. Test-only.
func WithFuzzStore(fs flow.FuzzStore) ServerOption {
	return func(s *Server) {
		s.jobRunner.fuzzStore = fs
	}
}

// WithIssuer sets the certificate issuer. Test-only.
func WithIssuer(iss *cert.Issuer) ServerOption {
	return func(s *Server) {
		s.misc.issuer = iss
	}
}

// WithTCPHandler sets the TCP handler. Test-only.
func WithTCPHandler(h tcpForwardHandler) ServerOption {
	return func(s *Server) {
		s.connector.tcpHandler = h
	}
}

// WithTargetScope sets the target scope. Test-only.
// Note: NewServer initialises a default TargetScope before applying options;
// this option overrides it. Re-running registered targetScopeSetters is the
// caller's responsibility (tests rarely need this).
func WithTargetScope(ts *connector.TargetScope) ServerOption {
	return func(s *Server) {
		s.connector.targetScope = ts
	}
}

// WithProxyDefaults sets the default proxy configuration. Test-only.
func WithProxyDefaults(cfg *config.ProxyConfig) ServerOption {
	return func(s *Server) {
		s.connector.proxyDefaults = cfg
	}
}

// WithUpstreamProxySetter registers an upstream proxy setter handler. Test-only.
func WithUpstreamProxySetter(setter upstreamProxySetter) ServerOption {
	return func(s *Server) {
		s.connector.upstreamProxySetters = append(s.connector.upstreamProxySetters, setter)
	}
}

// WithRequestTimeoutSetters registers request-timeout setter handlers. Test-only.
func WithRequestTimeoutSetters(setters ...requestTimeoutSetter) ServerOption {
	return func(s *Server) {
		s.connector.requestTimeoutSetters = append(s.connector.requestTimeoutSetters, setters...)
	}
}

// WithTargetScopeSetter registers a target scope setter handler. Test-only.
func WithTargetScopeSetter(setter targetScopeSetter) ServerOption {
	return func(s *Server) {
		s.connector.targetScopeSetters = append(s.connector.targetScopeSetters, setter)
	}
}

// WithRateLimiter sets the rate limiter. Test-only.
func WithRateLimiter(rl *connector.RateLimiter) ServerOption {
	return func(s *Server) {
		s.misc.rateLimiter = rl
	}
}

// WithRateLimiterSetter registers a rate-limiter setter handler. Test-only.
func WithRateLimiterSetter(setter rateLimiterSetter) ServerOption {
	return func(s *Server) {
		s.connector.rateLimiterSetters = append(s.connector.rateLimiterSetters, setter)
	}
}

// WithSafetyEngine sets the safety filter engine. Test-only.
func WithSafetyEngine(engine *safety.Engine) ServerOption {
	return func(s *Server) {
		s.pipeline.safetyEngine = engine
	}
}

// WithSafetyEngineSetter registers a safety engine setter handler. Test-only.
func WithSafetyEngineSetter(setter safetyEngineSetter) ServerOption {
	return func(s *Server) {
		s.pipeline.safetyEngineSetters = append(s.pipeline.safetyEngineSetters, setter)
	}
}

// WithBudgetManager sets the budget manager. Test-only.
func WithBudgetManager(bm *connector.BudgetManager) ServerOption {
	return func(s *Server) {
		s.misc.budgetManager = bm
	}
}

// WithTLSFingerprintSetter registers a TLS fingerprint setter handler. Test-only.
func WithTLSFingerprintSetter(setter tlsFingerprintSetter) ServerOption {
	return func(s *Server) {
		s.connector.tlsFingerprintSetters = append(s.connector.tlsFingerprintSetters, setter)
	}
}

// WithSOCKS5Handler sets the SOCKS5 auth setter. Test-only.
func WithSOCKS5Handler(setter socks5AuthSetter) ServerOption {
	return func(s *Server) {
		s.connector.socks5AuthSetter = setter
	}
}

// WithTLSTransport sets the TLS transport. Test-only.
func WithTLSTransport(t transport.TLSTransport) ServerOption {
	return func(s *Server) {
		s.connector.tlsTransport = t
	}
}

// WithHostTLSRegistry sets the host TLS registry. Test-only.
func WithHostTLSRegistry(r *transport.HostTLSRegistry) ServerOption {
	return func(s *Server) {
		s.connector.hostTLSRegistry = r
	}
}

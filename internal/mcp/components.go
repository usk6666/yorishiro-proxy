// Package mcp components.go defines the seven coherent dependency components
// that replace the former monolithic deps "bag" struct (USK-664, RFC-001 N8).
//
// Background.
// Prior to this refactor, every MCP tool handler accessed shared state via a
// 28-field deps bag attached to Server. That bag accreted across milestones
// and made it impossible to reason about which dependencies a given handler
// actually needed. The N8 milestone introduces per-protocol legacy/new tool
// pairs (resend_http, resend_ws, …) which would only have made the bag worse.
//
// Solution.
// Split deps into seven small, plain structs. Each struct groups dependencies
// that move together. Server holds one pointer to each component. Tool
// handlers reach in via s.<component>.<field>; the convention is that a
// well-factored handler touches at most three components. Two handlers are
// authorised exceptions and are documented inline.
//
// The seven components are:
//
//   - Pipeline      — intercept / transform / safety request pipeline
//   - Connector     — network listeners, scope, TLS, protocol handler setters
//   - JobRunner     — raw replay + macro HTTP machinery
//   - FlowStore     — sqlite-backed Stream/Flow storage
//   - MacroEngine   — placeholder for future macro engine state
//   - PluginEngine  — Starlark plugin engine
//   - Misc          — application context, CA/issuer, db path, rate-limiter,
//     budget manager (cross-cutting items that don't fit a
//     single domain)
//
// All components are plain structs (not interfaces); fields are unexported
// because every consumer lives in the mcp package.
package mcp

import (
	"context"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// Pipeline groups the request-processing pipeline dependencies:
// per-protocol intercept rule engines, the HoldQueue that blocks matched
// envelopes for external action, the auto-transform pipeline, and the
// SafetyFilter engine (plus the protocol-handler setters that need to be
// notified when the safety engine is configured).
//
// httpInterceptEngine / wsInterceptEngine / grpcInterceptEngine are the
// per-protocol rule engines consumed by pipeline.InterceptStep. The
// configure_tool's intercept_rules surface dispatches to these via a
// per-rule protocol discriminator.
//
// holdQueue is the only queue: the legacy interceptQueue (pre-N8) was
// removed in USK-692 along with its dual-path fallback. Matched envelopes
// land here from InterceptStep; the intercept MCP tool dispatches
// release / drop / modify_and_forward against the held entry using the
// per-Message-type modify schemas defined in intercept_typed.go.
type Pipeline struct {
	httpInterceptEngine *httprules.InterceptEngine
	wsInterceptEngine   *wsrules.InterceptEngine
	grpcInterceptEngine *grpcrules.InterceptEngine
	holdQueue           *common.HoldQueue
	transformPipeline   *rules.Pipeline
	safetyEngine        *safety.Engine
	safetyEngineSetters []safetyEngineSetter
}

// NewPipeline constructs a Pipeline component. All fields are optional;
// nil fields are tolerated by handlers that guard with nil checks.
func NewPipeline(
	httpInterceptEngine *httprules.InterceptEngine,
	wsInterceptEngine *wsrules.InterceptEngine,
	grpcInterceptEngine *grpcrules.InterceptEngine,
	holdQueue *common.HoldQueue,
	transformPipeline *rules.Pipeline,
	safetyEngine *safety.Engine,
	safetyEngineSetters []safetyEngineSetter,
) *Pipeline {
	return &Pipeline{
		httpInterceptEngine: httpInterceptEngine,
		wsInterceptEngine:   wsInterceptEngine,
		grpcInterceptEngine: grpcInterceptEngine,
		holdQueue:           holdQueue,
		transformPipeline:   transformPipeline,
		safetyEngine:        safetyEngine,
		safetyEngineSetters: safetyEngineSetters,
	}
}

// proxyManager is the connector-manager interface satisfied by both the
// legacy *proxy.Manager and the RFC-001 *proxybuild.Manager. The interface
// covers exactly the methods MCP tools (proxy_start_tool, proxy_stop_tool,
// configure_tool, query_tool) reach through Connector.manager.
//
// Two managers expose this surface for the duration of the N9 transition
// (USK-690 wiring → USK-691 parity → USK-697 legacy delete). Internal mcp
// tests still construct *proxy.Manager directly because the legacy package
// will not be deleted until USK-697; cmd/main.go installs *proxybuild.Manager
// for the live data path.
//
// StartTCPForwardsNamedAny accepts `any` for the params argument so both
// manager types satisfy the same signature. proxy.Manager type-asserts to
// proxy.TCPForwardParams internally; proxybuild.Manager returns
// proxybuild.ErrTCPForwardsNotSupported (real TCP-forward orchestration is
// owned by USK-697 or a follow-up).
//
// ListenerStatuses is intentionally NOT on this interface — its concrete
// return type differs between the two managers (proxy.ListenerStatus vs
// proxybuild.ListenerStatus, structurally identical 4-field shapes). Use
// the listenerStatuses free function to read uniformly via type-switch.
type proxyManager interface {
	Start(ctx context.Context, listenAddr string) error
	StartNamed(ctx context.Context, name, listenAddr string) error
	Stop(ctx context.Context) error
	StopNamed(ctx context.Context, name string) error
	StopAll(ctx context.Context) error
	Status() (running bool, listenAddr string)
	ListenerCount() int
	ActiveConnections() int
	Uptime() time.Duration
	SetMaxConnections(n int)
	MaxConnections() int
	SetPeekTimeout(d time.Duration)
	PeekTimeout() time.Duration
	SetUpstreamProxy(proxyURL string)
	UpstreamProxy() string
	StartTCPForwardsNamedAny(ctx context.Context, name string, params any) error
}

// ListenerStatus is the mcp-package shape of per-listener status used by
// query_tool / proxy_start_tool / proxy_stop_tool. Mirrors both
// proxy.ListenerStatus and proxybuild.ListenerStatus (identical 4-field
// shape); the listenerStatuses helper converts from either.
type ListenerStatus struct {
	Name              string `json:"name"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections int    `json:"active_connections"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
}

// managerIsNil reports whether m is either a nil interface or wraps a
// typed-nil pointer. configure / proxy_start / proxy_stop / query
// handlers use this in place of direct `m == nil` because Go's
// interface-typed nil semantics make `m == nil` false when m wraps a
// (nil *proxy.Manager) — easy to hit from test helpers that pass a
// pre-construction nil sentinel.
func managerIsNil(m proxyManager) bool {
	if m == nil {
		return true
	}
	switch x := m.(type) {
	case *proxy.Manager:
		return x == nil
	case *proxybuild.Manager:
		return x == nil
	default:
		return false
	}
}

// listenerStatuses returns the per-listener status snapshot from m as
// []ListenerStatus, regardless of whether m is the legacy *proxy.Manager
// or the RFC-001 *proxybuild.Manager. Returns nil when no listeners are
// running or when m is nil.
func listenerStatuses(m proxyManager) []ListenerStatus {
	if managerIsNil(m) {
		return nil
	}
	switch x := m.(type) {
	case *proxy.Manager:
		in := x.ListenerStatuses()
		if len(in) == 0 {
			return nil
		}
		out := make([]ListenerStatus, len(in))
		for i, s := range in {
			out[i] = ListenerStatus{
				Name:              s.Name,
				ListenAddr:        s.ListenAddr,
				ActiveConnections: s.ActiveConnections,
				UptimeSeconds:     s.UptimeSeconds,
			}
		}
		return out
	case *proxybuild.Manager:
		in := x.ListenerStatuses()
		if len(in) == 0 {
			return nil
		}
		out := make([]ListenerStatus, len(in))
		for i, s := range in {
			out[i] = ListenerStatus{
				Name:              s.Name,
				ListenAddr:        s.ListenAddr,
				ActiveConnections: s.ActiveConnections,
				UptimeSeconds:     s.UptimeSeconds,
			}
		}
		return out
	default:
		return nil
	}
}

// Connector groups network/transport-level dependencies: the manager that
// owns listeners, the capture/target scopes, TLS plumbing, the SOCKS5
// authentication setter, the TCP-forward map and handler, the protocol
// detector, and the per-handler "setter" slices that propagate runtime
// configuration changes (upstream proxy, request timeout, target scope, rate
// limiter, TLS fingerprint) to every protocol handler that supports them.
type Connector struct {
	manager               proxyManager
	passthrough           *proxy.PassthroughList
	scope                 *proxy.CaptureScope
	targetScope           *proxy.TargetScope
	targetScopeSetters    []targetScopeSetter
	hostTLSRegistry       *httputil.HostTLSRegistry
	tlsTransport          httputil.TLSTransport
	tlsFingerprintSetters []tlsFingerprintSetter
	socks5AuthSetter      socks5AuthSetter
	tcpForwards           map[string]*config.ForwardConfig
	tcpHandler            tcpForwardHandler
	detector              proxy.ProtocolDetector
	enabledProtocols      []string
	proxyDefaults         *config.ProxyConfig
	upstreamProxySetters  []upstreamProxySetter
	requestTimeoutSetters []requestTimeoutSetter
	rateLimiterSetters    []rateLimiterSetter
}

// NewConnector constructs a Connector. Most fields are optional; the manager
// is required for proxy_start/proxy_stop tools to function. proxyDefaults
// may be nil when no config file is loaded.
//
// manager accepts either the legacy *proxy.Manager (test paths and the
// transition window) or the RFC-001 *proxybuild.Manager (cmd live data
// path) — both satisfy the proxyManager interface.
func NewConnector(
	manager proxyManager,
	passthrough *proxy.PassthroughList,
	scope *proxy.CaptureScope,
	targetScope *proxy.TargetScope,
	hostTLSRegistry *httputil.HostTLSRegistry,
	tlsTransport httputil.TLSTransport,
	socks5AuthSetter socks5AuthSetter,
	tcpHandler tcpForwardHandler,
	detector proxy.ProtocolDetector,
	proxyDefaults *config.ProxyConfig,
	targetScopeSetters []targetScopeSetter,
	tlsFingerprintSetters []tlsFingerprintSetter,
	upstreamProxySetters []upstreamProxySetter,
	requestTimeoutSetters []requestTimeoutSetter,
	rateLimiterSetters []rateLimiterSetter,
) *Connector {
	return &Connector{
		manager:               manager,
		passthrough:           passthrough,
		scope:                 scope,
		targetScope:           targetScope,
		hostTLSRegistry:       hostTLSRegistry,
		tlsTransport:          tlsTransport,
		socks5AuthSetter:      socks5AuthSetter,
		tcpHandler:            tcpHandler,
		detector:              detector,
		proxyDefaults:         proxyDefaults,
		targetScopeSetters:    targetScopeSetters,
		tlsFingerprintSetters: tlsFingerprintSetters,
		upstreamProxySetters:  upstreamProxySetters,
		requestTimeoutSetters: requestTimeoutSetters,
		rateLimiterSetters:    rateLimiterSetters,
	}
}

// JobRunner groups outbound-traffic generation dependencies used by the
// raw replay tools and macro HTTP calls.
//
// replayDoer is a legacy net/http.Client-based HTTP doer used by macro HTTP
// calls. It will be removed once those paths migrate to UpstreamRouter
// (see USK-* roadmap).
type JobRunner struct {
	fuzzStore       flow.FuzzStore
	replayDoer      httpDoer
	rawReplayDialer rawDialer
}

// NewJobRunner constructs a JobRunner.
func NewJobRunner(
	fuzzStore flow.FuzzStore,
	replayDoer httpDoer,
	rawReplayDialer rawDialer,
) *JobRunner {
	return &JobRunner{
		fuzzStore:       fuzzStore,
		replayDoer:      replayDoer,
		rawReplayDialer: rawReplayDialer,
	}
}

// FlowStore wraps the persistent Stream/Flow store. Kept as a single-field
// component for symmetry with the other components and to give a name to
// the dependency that handlers like compare_tool / query_technologies /
// macro_handlers need for read access.
type FlowStore struct {
	store flow.Store
}

// NewFlowStore constructs a FlowStore wrapping the given store. A nil store
// is permitted; tool handlers will return errors when invoked.
func NewFlowStore(store flow.Store) *FlowStore {
	return &FlowStore{store: store}
}

// MacroEngine is a placeholder component for future macro-engine state
// (USK-671 and successors will populate it). The macro tool handler
// currently constructs a macro.Engine on demand from JobRunner.replayDoer
// + FlowStore.store + Connector.targetScope; once a persistent engine is
// added, its dependencies will live here.
//
// Intentionally empty for now — do NOT add a fake "engine" field. The empty
// struct exists so that Server has a stable component slot that later N8
// issues can extend without changing the constructor signature shape.
type MacroEngine struct{}

// NewMacroEngine constructs a MacroEngine. Currently returns an empty
// component; see the type doc for the rationale.
func NewMacroEngine() *MacroEngine {
	return &MacroEngine{}
}

// PluginEngine wraps the Starlark plugin engines. Used by the plugin tool
// handler (legacy engine) and the plugin_introspect tool (pluginv2 engine).
//
// The legacy engine is retained until RFC-001 N9 completes; tools that
// inspect runtime hooks should use pluginv2 instead.
type PluginEngine struct {
	engine   *plugin.Engine
	pluginv2 *pluginv2.Engine
}

// NewPluginEngine constructs a PluginEngine. Either engine may be nil; the
// plugin tool returns an error when the legacy engine is unset, and
// plugin_introspect returns an empty list when the pluginv2 engine is unset.
func NewPluginEngine(engine *plugin.Engine, pluginv2Engine *pluginv2.Engine) *PluginEngine {
	return &PluginEngine{engine: engine, pluginv2: pluginv2Engine}
}

// Misc holds cross-cutting dependencies that do not fit a single domain
// component: the application-level context that controls proxy lifecycle,
// the CA + Issuer used by certificate query/regenerate tools, the database
// file path used for status reporting, the rate limiter, and the budget
// manager. These do not move together but are too small individually to
// warrant their own components.
type Misc struct {
	appCtx        context.Context
	ca            *cert.CA
	issuer        *cert.Issuer
	dbPath        string
	rateLimiter   *proxy.RateLimiter
	budgetManager *proxy.BudgetManager
}

// NewMisc constructs a Misc component. ctx should be the application
// lifecycle context (used to cancel long-running proxy_start operations).
func NewMisc(
	ctx context.Context,
	ca *cert.CA,
	issuer *cert.Issuer,
	dbPath string,
	rateLimiter *proxy.RateLimiter,
	budgetManager *proxy.BudgetManager,
) *Misc {
	return &Misc{
		appCtx:        ctx,
		ca:            ca,
		issuer:        issuer,
		dbPath:        dbPath,
		rateLimiter:   rateLimiter,
		budgetManager: budgetManager,
	}
}

// Setter slice constructors.
//
// The setter interfaces (upstreamProxySetter, targetScopeSetter, ...) are
// unexported because they are internal wiring details. Callers outside the
// mcp package (notably cmd/yorishiro-proxy/main.go) need a way to assemble
// the slices that get stored on Connector / Pipeline. The functions below
// accept the concrete protocol handler types (which already implement these
// interfaces) and return slices typed at the unexported interface; this
// keeps the abstraction private while letting main.go wire components.

// UpstreamProxySetters builds an upstream-proxy setter slice from the given
// handlers. nil entries are skipped.
func UpstreamProxySetters(handlers ...upstreamProxySetter) []upstreamProxySetter {
	out := make([]upstreamProxySetter, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			out = append(out, h)
		}
	}
	return out
}

// TargetScopeSetters builds a target-scope setter slice from the given
// handlers. nil entries are skipped.
func TargetScopeSetters(handlers ...targetScopeSetter) []targetScopeSetter {
	out := make([]targetScopeSetter, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			out = append(out, h)
		}
	}
	return out
}

// TLSFingerprintSetters builds a TLS-fingerprint setter slice from the given
// handlers. nil entries are skipped.
func TLSFingerprintSetters(handlers ...tlsFingerprintSetter) []tlsFingerprintSetter {
	out := make([]tlsFingerprintSetter, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			out = append(out, h)
		}
	}
	return out
}

// RateLimiterSetters builds a rate-limiter setter slice from the given
// handlers. nil entries are skipped.
func RateLimiterSetters(handlers ...rateLimiterSetter) []rateLimiterSetter {
	out := make([]rateLimiterSetter, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			out = append(out, h)
		}
	}
	return out
}

// SafetyEngineSetters builds a safety-engine setter slice from the given
// handlers. nil entries are skipped.
func SafetyEngineSetters(handlers ...safetyEngineSetter) []safetyEngineSetter {
	out := make([]safetyEngineSetter, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			out = append(out, h)
		}
	}
	return out
}

// RequestTimeoutSetters builds a request-timeout setter slice from the given
// handlers. nil entries are skipped.
func RequestTimeoutSetters(handlers ...requestTimeoutSetter) []requestTimeoutSetter {
	out := make([]requestTimeoutSetter, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			out = append(out, h)
		}
	}
	return out
}

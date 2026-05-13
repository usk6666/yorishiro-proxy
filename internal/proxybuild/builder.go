package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// Deps carries every dependency BuildLiveStack needs. Required fields are
// validated; optional fields default to nil-safe behavior (the corresponding
// Pipeline Step or handler hook is a no-op).
//
// Engines (HTTPSafety/HTTPIntercept/HTTPTransform, WS variants, GRPC variants)
// are passed in rather than constructed here so proxybuild stays import-thin
// and the caller (USK-690 production wiring) owns engine lifecycle.
type Deps struct {
	// --- Required ---

	// Logger is used by the listener, manager, and pipeline Steps.
	Logger *slog.Logger

	// ListenerName is the listener's logical name. Empty string is
	// treated as DefaultListenerName.
	ListenerName string

	// ListenAddr is the TCP listen address, e.g. "127.0.0.1:8080".
	ListenAddr string

	// FlowStore receives Stream + Flow records from RecordStep. nil
	// disables Pipeline-level recording.
	FlowStore flow.Writer

	// PluginV2Engine drives RFC §9.3 plugin hooks. nil disables all
	// pluginv2 hook firing.
	PluginV2Engine *pluginv2.Engine

	// --- Stack-builder configuration (passes into connector.BuildConfig) ---

	// BuildConfig configures per-connection ConnectionStack construction
	// (TLS MITM, ALPN cache, HTTP/2 pool, host TLS overrides, body spill,
	// etc.). proxybuild ensures BuildConfig.PluginV2Engine is set to
	// PluginV2Engine before stack construction so tls.on_handshake fires
	// at the existing wire site.
	BuildConfig *connector.BuildConfig

	// --- Optional listener tunables (zero = defaults) ---

	// PeekTimeout overrides connector.DefaultPeekTimeout. Zero = default.
	PeekTimeout time.Duration

	// RequestTimeout bounds the HTTP request header read deadline once
	// protocol detection completes (USK-844). It is the configurable
	// override for the hardcoded forward-handler defaults
	// (connector.forwardPeekTimeout, connector.DefaultInnerPeekTimeout)
	// used by:
	//   - the plain-HTTP forward handler waiting for the first request's
	//     header section, and
	//   - the CONNECT / SOCKS5 inner-byte peek that waits for the first
	//     client byte after the tunnel reply.
	// Zero means the handler-side defaults remain in effect. Mirrors the
	// PeekTimeout fan-out: a runtime SetRequestTimeout on the Manager
	// reaches every wrapped listener via the same atomic-Int64 plumbing
	// (see Manager.SetRequestTimeout / FullListener.SetRequestTimeout).
	RequestTimeout time.Duration

	// MaxConnections overrides connector.DefaultMaxConnections. Zero =
	// default. Negative = unlimited.
	MaxConnections int

	// --- Optional connector policy ---

	// Scope is the per-target capture/pass policy applied to CONNECT and
	// SOCKS5 negotiations. nil = allow all.
	Scope *connector.TargetScope

	// RecordScope is the recording-only observability filter applied by
	// RecordStep (USK-776). nil = capture every flow (current default).
	// When non-nil, the same pointer is shared with the MCP control
	// plane (proxy_start_tool / configure_tool / query_tool) so runtime
	// updates take effect on the live data path without rebuilding the
	// Pipeline.
	RecordScope *flow.RecordScope

	// RateLimiter is the per-host rate-limit policy applied to CONNECT
	// and SOCKS5 negotiations. nil = unlimited.
	RateLimiter *connector.RateLimiter

	// BudgetManager enforces the diagnostic-session budget
	// (MaxTotalRequests / MaxDuration) on every Send envelope flowing
	// through the live data path's Pipeline. nil = no budget enforcement
	// (BudgetStep no-ops). Wired by the MCP control plane (mcpserver)
	// so the same instance is shared with the security-tool reads and
	// the resend/fuzz dispatch helpers; runtime mutations via
	// `security set_budget` therefore reach the live Pipeline without
	// rebuilding the Stack (USK-818).
	BudgetManager *connector.BudgetManager

	// PassthroughList lists hosts whose TLS traffic is relayed without
	// MITM (bidirectional io.Copy). nil = no passthrough.
	PassthroughList *connector.PassthroughList

	// SOCKS5Negotiator is the process-singleton SOCKS5 handshake driver
	// used by every SOCKS5 listener built from this Deps. When non-nil,
	// BuildLiveStack uses the supplied negotiator instead of constructing
	// a fresh one — so the MCP control plane (mcpserver) can hold a
	// reference and mutate Authenticator / ListenerAuthOverride at runtime
	// via SOCKS5Negotiator.SetAuthenticator / SetListenerAuth /
	// ClearListenerAuth (USK-770). When nil, BuildLiveStack constructs a
	// negotiator scoped to this listener (legacy single-listener path
	// retained for tests).
	SOCKS5Negotiator *connector.SOCKS5Negotiator

	// --- Optional Pipeline rule engines ---

	HTTPSafetyEngine    *httprules.SafetyEngine
	HTTPInterceptEngine *httprules.InterceptEngine
	HTTPTransformEngine *httprules.TransformEngine
	WSSafetyEngine      *wsrules.SafetyEngine
	WSInterceptEngine   *wsrules.InterceptEngine
	WSTransformEngine   *wsrules.TransformEngine
	GRPCSafetyEngine    *grpcrules.SafetyEngine
	GRPCInterceptEngine *grpcrules.InterceptEngine
	GRPCTransformEngine *grpcrules.TransformEngine

	// HoldQueue receives held envelopes from InterceptStep. nil disables
	// hold-and-dispatch (matched envelopes still drop, but no async
	// resolution from MCP intercept tools).
	HoldQueue *common.HoldQueue

	// InterceptReleaseTracker records the timestamps the MCP intercept
	// tool's Release path stamps each time a held envelope is unblocked.
	// The same pointer is shared with mcp.Pipeline (so the MCP tool can
	// MarkRelease) and threaded into session.SessionOptions (so the relay
	// goroutines can detect upstream EOF shortly after a long hold). nil
	// disables the USK-851 detection without affecting wire behaviour.
	InterceptReleaseTracker *common.ReleaseTracker

	// InterceptHoldTracker is the shared HoldTracker stamped by
	// InterceptStep on hold-enter and consulted by the session's USK-854
	// WS hold-window keepalive goroutine on each tick. Wired via
	// pipeline.InterceptStep.WithHoldTracker during Pipeline construction
	// (the same pointer flows into SessionOptions for the keepalive). nil
	// disables the USK-854 feature without affecting wire behaviour.
	InterceptHoldTracker *common.HoldTracker

	// --- Optional wire encoder registries ---

	// WireEncoderRegistry is shared between PluginStepPost and RecordStep
	// for the **non-h2** route (OnStack callback) — its HTTP encoder slot
	// holds http1.EncodeWireBytes. When nil, BuildLiveStack constructs a
	// default registry that registers the 4 non-conflicting encoders
	// (ws / grpc / grpc-web / sse) plus http1.EncodeWireBytes for
	// envelope.ProtocolHTTP.
	WireEncoderRegistry *pipeline.WireEncoderRegistry

	// WireEncoderRegistryH2 is the parallel registry used for the **h2**
	// route (OnHTTP2Stack callback). Its HTTP encoder slot holds
	// httpaggregator.EncodeWireBytes (HPACK re-emission via offline
	// streamID=1) so plugin-mutated HTTPMessage envelopes round-trip back
	// to wire as H2 frames. When nil, BuildLiveStack constructs a default
	// registry registering the 4 non-conflicting encoders plus
	// httpaggregator.EncodeWireBytes for envelope.ProtocolHTTP. Two
	// registries are required because http1.EncodeWireBytes and
	// httpaggregator.EncodeWireBytes are mutually exclusive in a single
	// registry (both target envelope.ProtocolHTTP).
	WireEncoderRegistryH2 *pipeline.WireEncoderRegistry

	// --- Optional record options ---

	// RecordMaxBodySize caps the body bytes RecordStep persists. Zero
	// uses the RecordStep default.
	RecordMaxBodySize int64

	// RecordGRPCMaxMessagesPerStream caps the number of GRPCDataMessage
	// envelopes RecordStep persists per stream (USK-802). Zero uses the
	// RecordStep default (config.MaxGRPCMessagesPerStream). Wire forwarding
	// is unaffected — the Channel layer is untouched.
	RecordGRPCMaxMessagesPerStream int

	// RecordSSEMaxEventsPerStream caps the number of SSEMessage envelopes
	// RecordStep persists per stream (USK-802). Zero uses the RecordStep
	// default (config.MaxSSEEventsPerStream). Wire forwarding is unaffected.
	RecordSSEMaxEventsPerStream int

	// --- Optional manager-level state (consumed by Manager wiring) ---

	// UpstreamProxy is the initial upstream proxy URL. Stored on the
	// stack for read-back via Manager.UpstreamProxy(). Runtime updates
	// installed via Manager.SetUpstreamProxy now flow into
	// BuildConfig's dynamic slot so the live dial path picks them up
	// (USK-734).
	UpstreamProxy *url.URL
}

// Stack holds the per-listener live RFC-001 assembly produced by
// BuildLiveStack. Lifetime is tied to the Manager entry that owns it.
//
// PluginV2Engine, WireEncoderRegistry, and HoldQueue are typically
// process-singletons supplied via Deps (not owned by the Stack). The
// Stack holds references so callers (and tests) can introspect them
// without re-discovery from elsewhere.
type Stack struct {
	// Listener is the per-listener wrapper exposing PluginV2Engine() and
	// the underlying connector.FullListener.
	Listener *Listener

	// Pipeline is the canonical 8-step Pipeline (HostScope → HTTPScope →
	// Safety → PluginPre → Intercept → Transform → PluginPost → Record),
	// followed by UpgradeStep for the WS/SSE layer-swap path, applied to
	// non-h2 routes (OnStack callback). HTTP wire encoder is
	// http1.EncodeWireBytes. Steps with nil engines act as no-ops.
	Pipeline *pipeline.Pipeline

	// PipelineH2 is the parallel Pipeline applied to h2 routes
	// (OnHTTP2Stack callback). Composition matches Pipeline; the only
	// difference is the HTTP wire encoder slot which holds
	// httpaggregator.EncodeWireBytes.
	PipelineH2 *pipeline.Pipeline

	// PluginV2Engine is the engine wired into the Listener and Pipeline
	// Steps. May be nil.
	PluginV2Engine *pluginv2.Engine

	// WireEncoderRegistry is the registry consumed by Pipeline (non-h2
	// route). May be nil.
	WireEncoderRegistry *pipeline.WireEncoderRegistry

	// WireEncoderRegistryH2 is the registry consumed by PipelineH2 (h2
	// route). May be nil.
	WireEncoderRegistryH2 *pipeline.WireEncoderRegistry

	// HoldQueue receives held envelopes from InterceptStep. May be nil.
	HoldQueue *common.HoldQueue

	// BuildConfig is the per-connection stack-construction configuration
	// passed to connector.BuildConnectionStack inside the per-protocol
	// handlers.
	BuildConfig *connector.BuildConfig

	// FlowStore is the flow.Writer wired into the canonical RecordStep.
	// Held on the Stack so collaborators that share this Stack's Pipeline
	// (notably TCP forward listeners — USK-711 — which piggyback on the
	// parent Stack's recording surface) can build SessionOptions.OnComplete
	// callbacks that finalise Stream state. May be nil when no recording
	// is configured.
	FlowStore flow.Writer
}

// BuildLiveStack assembles a per-listener Stack from deps. Validates
// required fields, constructs the WireEncoderRegistry default when needed,
// builds the canonical Pipeline, wires CONNECT/SOCKS5 handlers with
// pluginv2 lifecycle hooks, and returns the assembled *Stack.
//
// BuildLiveStack does NOT start the listener — call (*Manager).StartNamed
// (or directly stack.Listener.Start) to begin accepting connections.
func BuildLiveStack(_ context.Context, deps Deps) (*Stack, error) {
	if err := validateDeps(deps); err != nil {
		return nil, err
	}

	logger := deps.Logger
	listenerName := deps.ListenerName
	if listenerName == "" {
		listenerName = DefaultListenerName
	}

	// Wire pluginv2.Engine into BuildConfig so the existing
	// tls.on_handshake hook site fires (already wired in
	// connector.fireTLSHandshakeHook). Mutating the caller's BuildConfig
	// is acceptable here because BuildConfig is a per-listener
	// configuration value owned by Deps.
	deps.BuildConfig.PluginV2Engine = deps.PluginV2Engine

	// Select / construct the per-route WireEncoderRegistries. Defaults
	// register the 4 non-conflicting encoders (ws/grpc/grpc-web/sse) plus
	// the route-appropriate HTTP encoder for envelope.ProtocolHTTP.
	encodersH1 := deps.WireEncoderRegistry
	if encodersH1 == nil {
		encodersH1 = defaultHTTP1WireEncoderRegistry()
	}
	encodersH2 := deps.WireEncoderRegistryH2
	if encodersH2 == nil {
		encodersH2 = defaultHTTP2WireEncoderRegistry()
	}

	// Build the canonical Pipeline twice — once per route. Both pipelines
	// share Steps but bind different WireEncoderRegistry instances so the
	// HTTP encoder slot resolves to the correct (http1.EncodeWireBytes vs
	// httpaggregator.EncodeWireBytes) implementation.
	p := buildPipeline(deps, encodersH1, logger)
	pH2 := buildPipeline(deps, encodersH2, logger)

	// USK-784: shared upstream-TLS-error recorder for the CONNECT and
	// SOCKS5 handlers so HTTPS-path stack-build failures (most commonly
	// upstream cert reject) land in the flow store as state="error" rather
	// than disappearing silently. Nil store yields a nil callback so the
	// connector's drop path engages — matches the pre-USK-784 behaviour
	// for tests that omit a flow store.
	//
	// USK-791: the recorder also consults RecordScope so out-of-scope hosts
	// (e.g. HSTS-pinned services the browser tries on its own) are not
	// recorded when the operator scoped capture to a specific host. The
	// CONNECT/SOCKS5 authority carries the host even when no L7 message
	// reached the proxy.
	upstreamTLSErrorRecorder := buildUpstreamTLSErrorRecorder(deps.FlowStore, deps.RecordScope, listenerName, logger)

	// USK-790: passthrough audit-flow observer. Persists a Stream + Flow
	// per TLS passthrough connection with SNI / 4-tuple / byte counters
	// so the audit trail surfaces pinned-host contacts even when MITM is
	// disabled. Nil store yields a nil observer; the connector then uses
	// the no-observer io.Copy hot path.
	passthroughObserver := newPassthroughRecorder(deps.FlowStore, listenerName, logger, deps.RecordScope)

	// proxybuild.Listener wraps the FullListener so it can interpose
	// connection.on_connect / on_disconnect lifecycle hooks AND host the
	// runtime request_timeout_ms slot (USK-844). The wrapper is
	// constructed BEFORE the per-protocol handlers so each handler's
	// timeout-provider closure can capture the same atomic Int64 state.
	wrapper := &Listener{
		engine: deps.PluginV2Engine,
		name:   listenerName,
		logger: logger,
	}
	// Seed the runtime request-timeout slot from Deps so the config-file /
	// boot-time value reaches handler invocations until a runtime
	// SetRequestTimeout overrides it.
	if deps.RequestTimeout > 0 {
		wrapper.SetRequestTimeout(deps.RequestTimeout)
	}

	// Construct the per-protocol HandlerFunc closures.
	connectHandler := connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
		Negotiator:          connector.NewCONNECTNegotiator(logger),
		BuildCfg:            deps.BuildConfig,
		Scope:               deps.Scope,
		RateLimiter:         deps.RateLimiter,
		PassthroughList:     deps.PassthroughList,
		PassthroughObserver: passthroughObserver,
		OnStack:             buildOnStack(p, deps, logger),
		OnHTTP2Stack:        buildOnHTTP2Stack(pH2, deps, logger),
		OnUpstreamTLSError:  upstreamTLSErrorRecorder,
		// USK-844: thread the configured request timeout into the inner-byte
		// peek deadline. The provider closure reads the wrapper's atomic
		// slot so a runtime configure { request_timeout_ms } reaches the
		// next CONNECT without rebuilding the handler. Zero from the
		// provider falls back to InnerPeekTimeout → DefaultInnerPeekTimeout
		// inside resolveInnerPeekTimeout. Setting both InnerPeekTimeout
		// and InnerPeekTimeoutProvider is intentional belt-and-suspenders:
		// the wrapper atomic is also seeded with deps.RequestTimeout so
		// the provider tier normally wins, but the static field preserves
		// the boot-time value as a fallback if the atomic is ever cleared
		// to zero by a future caller.
		InnerPeekTimeout:         deps.RequestTimeout,
		InnerPeekTimeoutProvider: wrapper.RequestTimeout,
		Logger:                   logger,
	})
	// USK-770: prefer the process-singleton SOCKS5Negotiator supplied via
	// Deps (owned by mcpserver) so MCP control-plane Set*Auth calls reach
	// the live data path. Fresh construction is retained for tests that
	// build a Stack without going through mcpserver.
	socks5Negotiator := deps.SOCKS5Negotiator
	if socks5Negotiator == nil {
		socks5Negotiator = connector.NewSOCKS5Negotiator(logger)
	}
	socks5Negotiator.Scope = deps.Scope
	socks5Negotiator.RateLimiter = deps.RateLimiter
	socks5Handler := connector.NewSOCKS5Handler(connector.SOCKS5HandlerConfig{
		Negotiator:          socks5Negotiator,
		BuildCfg:            deps.BuildConfig,
		PassthroughList:     deps.PassthroughList,
		PassthroughObserver: passthroughObserver,
		OnStack:             buildOnStack(p, deps, logger),
		OnHTTP2Stack:        buildOnHTTP2Stack(pH2, deps, logger),
		OnUpstreamTLSError:  upstreamTLSErrorRecorder,
		// USK-844: thread the configured request timeout into the inner-byte
		// peek deadline (SOCKS5 mirrors CONNECT). See the comment above
		// CONNECTHandlerConfig.InnerPeekTimeoutProvider for the precedence.
		InnerPeekTimeout:         deps.RequestTimeout,
		InnerPeekTimeoutProvider: wrapper.RequestTimeout,
		Logger:                   logger,
		PluginV2Engine:           deps.PluginV2Engine,
	})
	// USK-710: plain-HTTP forward proxy. Plain HTTP cannot route to h2 (no
	// ALPN, no TLS), so OnHTTP2Stack is intentionally omitted — the handler
	// always invokes OnStack.
	// USK-844: thread the configured request timeout via the same
	// wrapper-slot provider used for CONNECT/SOCKS5 inner peek.
	http1ForwardHandler := connector.NewHTTP1ForwardHandler(connector.HTTP1ForwardHandlerConfig{
		BuildCfg:               deps.BuildConfig,
		Scope:                  deps.Scope,
		RateLimiter:            deps.RateLimiter,
		OnStack:                buildOnStack(p, deps, logger),
		RequestTimeout:         deps.RequestTimeout,
		RequestTimeoutProvider: wrapper.RequestTimeout,
		Logger:                 logger,
	})

	flCfg := connector.FullListenerConfig{
		Name:               listenerName,
		Addr:               deps.ListenAddr,
		Logger:             logger,
		PeekTimeout:        deps.PeekTimeout,
		MaxConnections:     deps.MaxConnections,
		OnCONNECT:          wrapper.wrapHandler(connectHandler),
		OnSOCKS5:           wrapper.wrapHandler(socks5Handler),
		OnHTTP1:            wrapper.wrapHandler(http1ForwardHandler),
		OnProtocolRejected: buildProtocolRejectedRecorder(deps.FlowStore, listenerName, logger),
		// USK-710: OnHTTP1 wired for plain-HTTP forward proxy. OnHTTP2
		// (h2c) and OnTCP (raw TCP forward) remain scaffold-deferred —
		// the h2c entry point has no Linear issue today and TCP forward
		// orchestration belongs to USK-711.
	}
	wrapper.full = connector.NewFullListener(flCfg)

	return &Stack{
		Listener:              wrapper,
		Pipeline:              p,
		PipelineH2:            pH2,
		PluginV2Engine:        deps.PluginV2Engine,
		WireEncoderRegistry:   encodersH1,
		WireEncoderRegistryH2: encodersH2,
		HoldQueue:             deps.HoldQueue,
		BuildConfig:           deps.BuildConfig,
		FlowStore:             deps.FlowStore,
	}, nil
}

// validateDeps enforces the required-field contract.
func validateDeps(deps Deps) error {
	switch {
	case deps.Logger == nil:
		return errors.New("proxybuild: BuildLiveStack: Logger is required")
	case deps.ListenAddr == "":
		return errors.New("proxybuild: BuildLiveStack: ListenAddr is required")
	case deps.BuildConfig == nil:
		return errors.New("proxybuild: BuildLiveStack: BuildConfig is required")
	case deps.BuildConfig.ProxyConfig == nil:
		return errors.New("proxybuild: BuildLiveStack: BuildConfig.ProxyConfig is required")
	case deps.BuildConfig.Issuer == nil:
		return errors.New("proxybuild: BuildLiveStack: BuildConfig.Issuer is required")
	}
	return nil
}

// defaultSharedEncoders registers the 4 non-conflicting per-protocol
// encoders (ws / grpc / grpc-web / sse) on r. The HTTP encoder is left
// unset; route-specific helpers add it.
func defaultSharedEncoders(r *pipeline.WireEncoderRegistry) {
	r.Register(envelope.ProtocolWebSocket, ws.EncodeWireBytes)
	r.Register(envelope.ProtocolGRPC, grpc.EncodeWireBytes)
	r.Register(envelope.ProtocolGRPCWeb, grpcweb.EncodeWireBytes)
	r.Register(envelope.ProtocolSSE, sse.EncodeWireBytes)
}

// defaultHTTP1WireEncoderRegistry returns a registry for the non-h2 route:
// 4 shared encoders plus http1.EncodeWireBytes for envelope.ProtocolHTTP.
func defaultHTTP1WireEncoderRegistry() *pipeline.WireEncoderRegistry {
	r := pipeline.NewWireEncoderRegistry()
	defaultSharedEncoders(r)
	r.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)
	return r
}

// defaultHTTP2WireEncoderRegistry returns a registry for the h2 route:
// 4 shared encoders plus httpaggregator.EncodeWireBytes for
// envelope.ProtocolHTTP. Plugin-mutated HTTPMessage envelopes round-trip
// to wire as HPACK-encoded H2 frames.
func defaultHTTP2WireEncoderRegistry() *pipeline.WireEncoderRegistry {
	r := pipeline.NewWireEncoderRegistry()
	defaultSharedEncoders(r)
	r.Register(envelope.ProtocolHTTP, httpaggregator.EncodeWireBytes)
	return r
}

// buildPipeline assembles the canonical 8-step RFC-001 Pipeline followed
// by UpgradeStep for the WS/SSE layer-swap path. Steps tolerate nil
// engines and degrade to no-ops; no conditional skipping is required at
// assembly time.
func buildPipeline(deps Deps, encoders *pipeline.WireEncoderRegistry, logger *slog.Logger) *pipeline.Pipeline {
	recordOpts := []pipeline.Option{
		pipeline.WithWireEncoderRegistry(encoders),
	}
	if deps.RecordMaxBodySize > 0 {
		recordOpts = append(recordOpts, pipeline.WithMaxBodySize(deps.RecordMaxBodySize))
	}
	if deps.RecordScope != nil {
		recordOpts = append(recordOpts, pipeline.WithRecordScope(deps.RecordScope))
	}
	// USK-802: per-Stream record caps for streaming protocols. The Options
	// silently no-op on zero / negative input, so passing the unresolved
	// Deps fields directly is safe — the production wiring in
	// mcpserver/init.go always resolves to a positive default through
	// config.Resolve*PerStream helpers.
	if deps.RecordGRPCMaxMessagesPerStream > 0 {
		recordOpts = append(recordOpts, pipeline.WithGRPCMaxMessagesPerStream(deps.RecordGRPCMaxMessagesPerStream))
	}
	if deps.RecordSSEMaxEventsPerStream > 0 {
		recordOpts = append(recordOpts, pipeline.WithSSEMaxEventsPerStream(deps.RecordSSEMaxEventsPerStream))
	}

	safetyStep := pipeline.NewSafetyStep(deps.HTTPSafetyEngine, deps.WSSafetyEngine, deps.GRPCSafetyEngine, logger)
	return pipeline.New(
		pipeline.NewHostScopeStep(deps.Scope),
		pipeline.NewHTTPScopeStep(deps.Scope),
		// USK-818: BudgetStep at position #3 — after the scope checks
		// (those are operator-policy denials, not chargeable) and
		// before SafetyStep / Intercept / Transform / PluginPost / Record
		// (so over-budget envelopes short-circuit the expensive Steps
		// and the audit Stream is recorded by the session
		// OnPipelineDrop callback).
		pipeline.NewBudgetStep(deps.BudgetManager),
		safetyStep,
		pipeline.NewPluginStepPre(deps.PluginV2Engine, encoders, logger),
		// safetyStep is shared with InterceptStep so a modify_and_forward
		// release re-runs the same per-protocol input checks (USK-702).
		pipeline.NewInterceptStep(deps.HTTPInterceptEngine, deps.WSInterceptEngine, deps.GRPCInterceptEngine, deps.HoldQueue, safetyStep, logger).
			WithHoldTracker(deps.InterceptHoldTracker),
		pipeline.NewTransformStep(deps.HTTPTransformEngine, deps.WSTransformEngine, deps.GRPCTransformEngine),
		pipeline.NewPluginStepPost(deps.PluginV2Engine, encoders, logger),
		pipeline.NewRecordStep(deps.FlowStore, logger, recordOpts...),
		// UpgradeStep MUST run AFTER RecordStep so the 101 response is
		// recorded as a normal HTTP envelope before the layer swap (RFC-001
		// §3.5). Without it, runUpgradeWS / runUpgradeSSE never fire and
		// (ws, on_message) / (sse, on_event) plugin hooks never reach the
		// pipeline. USK-690 omitted this step; USK-691 AC 1.4 surfaces the gap.
		session.NewUpgradeStep(),
	)
}

// buildOnStack returns the OnStackFunc invoked for non-h2 ConnectionStack
// routes (http1, bytechunk, ws-via-http1-upgrade). The closure runs the
// canonical session loop wired to the supplied Pipeline. The session
// receives SessionOptions carrying the pluginv2.Engine so post-Upgrade
// Layer constructors (runUpgradeWS) attach WithLifecycleEngine /
// WithStateReleaser. h2 routes are dispatched separately via
// buildOnHTTP2Stack.
//
// USK-710 ctx-cancellation cleanup: a watcher goroutine closes the stack
// (and therefore the underlying client + upstream conns) when ctx is
// cancelled. http1.Channel.Next is parked in conn.Read which does not
// observe ctx; without this active close the Read stays parked until the
// peer closes the socket, and listener shutdown via Manager.shutdownEntry
// times out (30 s) waiting for the handler goroutine to exit. The CONNECT
// integration tests don't exercise this because they send Connection:
// close, but a normal HTTP keep-alive client (Go's default http.Transport)
// hits this every time. Closing the stack on ctx.Done is idempotent —
// stack.Close is also called from this function's defer when the session
// returns normally.
//
// Pattern mirrors the proven recipe in
// internal/connector/full_listener_integration_test.go.
func buildOnStack(p *pipeline.Pipeline, deps Deps, logger *slog.Logger) connector.OnStackFunc {
	sessOpts := buildSessionOptions(deps, deps.ListenerName)
	return func(ctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, target string) {
		defer stack.Close()

		// Watcher: close the stack when the parent ctx is cancelled so that
		// any goroutine parked inside http1.Channel.Next (conn.Read) is
		// unblocked. doneCh is closed by the deferred wg.Wait below before
		// stack.Close runs again, so the watcher exits cleanly even when
		// the session returns naturally.
		doneCh := make(chan struct{})
		var watcherWG sync.WaitGroup
		watcherWG.Add(1)
		go func() {
			defer watcherWG.Done()
			select {
			case <-ctx.Done():
				_ = stack.Close()
			case <-doneCh:
			}
		}()
		defer func() {
			close(doneCh)
			watcherWG.Wait()
		}()

		// USK-730: HTTP/1.x keep-alive runs one session per request-response
		// exchange, mirroring the H2 per-stream pattern. Other routes
		// (bytechunk Raw TCP) fall back to the single-Channel RunStackSession.
		if clientH1, ok := stack.ClientTopmost().(*http1.Layer); ok {
			upstreamH1, ok := stack.UpstreamTopmost().(*http1.Layer)
			if !ok {
				logger.Debug("proxybuild: http1 client topmost without http1 upstream", "target", target,
					"upstream_type", fmt.Sprintf("%T", stack.UpstreamTopmost()))
				return
			}
			runHTTP1ExchangeLoop(ctx, stack, clientH1, upstreamH1, p, sessOpts, target, logger)
			return
		}

		dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			ch, ok := <-stack.UpstreamTopmost().Channels()
			if !ok {
				return nil, fmt.Errorf("proxybuild: upstream topmost closed before yielding a channel for %s", target)
			}
			return ch, nil
		}
		if err := session.RunStackSession(ctx, stack, dial, p, sessOpts); err != nil && !errors.Is(err, context.Canceled) {
			logger.Debug("proxybuild: session ended with error", "target", target, "error", err)
		}
	}
}

// runHTTP1ExchangeLoop iterates the HTTP/1.x client Layer's Channels()
// (one per request-response exchange) and spawns one goroutine per
// exchange running session.RunStackSessionExchange. Mirrors the H2
// per-stream dispatch (buildOnHTTP2Stack). The upstream HTTP/1.x Layer is
// shared across all exchanges; each goroutine's dial closure calls
// upstreamH1.OpenExchange() to register its per-exchange response slot.
//
// Upgrade flow (WS / SSE) is owned by RunStackSessionExchange; on detach
// the http1 Layer's spawn loop closes Channels() and the loop exits.
func runHTTP1ExchangeLoop(
	ctx context.Context,
	stack *connector.ConnectionStack,
	clientH1, upstreamH1 *http1.Layer,
	p *pipeline.Pipeline,
	sessOpts session.SessionOptions,
	target string,
	logger *slog.Logger,
) {
	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case clientCh, ok := <-clientH1.Channels():
			if !ok {
				wg.Wait()
				return
			}
			wg.Add(1)
			go func(ch layer.Channel) {
				defer wg.Done()
				dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
					upCh := upstreamH1.OpenExchange()
					if upCh == nil {
						return nil, fmt.Errorf("proxybuild: upstream http1 layer closed before opening exchange for %s", target)
					}
					return upCh, nil
				}
				if err := session.RunStackSessionExchange(ctx, stack, ch, dial, p, sessOpts); err != nil && !errors.Is(err, context.Canceled) {
					logger.Debug("proxybuild: http1 exchange ended with error", "target", target, "error", err)
				}
			}(clientCh)
		}
	}
}

// buildOnHTTP2Stack handles the h2 ALPN route. Per the recipe in
// internal/layer/http2/http2_integration_test.go, it iterates the client
// HTTP/2 Layer's Channels(), dispatches each stream through
// connector.DispatchH2StreamWithOpts (so plugin lifecycle hooks reach
// grpc / grpcweb / httpaggregator wrappers), and runs
// session.RunStackSessionExchange per stream against the upstream Layer's
// OpenStream-issued Channel. RunStackSessionExchange is the upgrade-aware
// entry point — it detects ErrUpgradePending and dispatches to
// runUpgradeWSOverH2 (RFC 8441 extended CONNECT → per-stream WS swap) so
// the wss-over-h2 swap orchestrator (USK-765) is reachable on the live
// data path. Mirrors the per-exchange h1 dispatch in runHTTP1ExchangeLoop.
//
// The connector's dispatch path returns the h2 Layer to the HTTP/2 pool on
// exit (handler-config-level guarantee), so this closure must not Close
// upstreamH2; only the per-stream channels and the WaitGroup ordering matter.
func buildOnHTTP2Stack(p *pipeline.Pipeline, deps Deps, logger *slog.Logger) connector.OnHTTP2StackFunc {
	sessOpts := buildSessionOptions(deps, deps.ListenerName)
	grpcOpts := connector.GRPCOptionsFromBuildConfig(deps.BuildConfig)
	grpcwebOpts := connector.GRPCWebOptionsFromBuildConfig(deps.BuildConfig)
	return func(ctx context.Context, stack *connector.ConnectionStack, upstreamH2 *http2.Layer, _, _ *envelope.TLSSnapshot, target string) {
		clientL, ok := stack.ClientTopmost().(*http2.Layer)
		if !ok {
			logger.Debug("proxybuild: h2 OnStack: client topmost is not *http2.Layer",
				"target", target, "type", fmt.Sprintf("%T", stack.ClientTopmost()))
			return
		}
		clientLOpts := httpaggregator.OptionsFromLayer(clientL)
		clientLOpts.StateReleaser = deps.PluginV2Engine
		upstreamLOpts := httpaggregator.OptionsFromLayer(upstreamH2)
		upstreamLOpts.StateReleaser = deps.PluginV2Engine

		// USK-816: when the pooled upstreamH2 goes stale during a long
		// intercept hold (server GOAWAY / idle FIN), per-stream dial closures
		// fall back to a fresh dial. The fresh Layer is shared across all
		// subsequent streams in this CONNECT lifecycle via redial.Load +
		// mutex-serialised redial.Store, so concurrent streams do not each
		// open a new upstream conn. The fresh Layer is owned by this handler
		// — it is closed in the deferred cleanup below.
		var redial atomic.Pointer[http2.Layer]
		// Single-writer close: only the goroutine that wins the redialDial
		// mutex and stores into redial owns its Close. Subsequent loads
		// observe the pointer and reuse without taking ownership.
		var redialDial sync.Mutex
		redialFn := func(dctx context.Context, t string, stale *http2.Layer) (*http2.Layer, error) {
			return connector.RedialUpstreamH2(dctx, t, stale, deps.BuildConfig)
		}
		defer func() {
			if l := redial.Load(); l != nil {
				_ = l.Close()
			}
		}()

		var wg sync.WaitGroup
		for {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			case clientCh, ok := <-clientL.Channels():
				if !ok {
					wg.Wait()
					return
				}
				wg.Add(1)
				go func(ch layer.Channel) {
					defer wg.Done()
					aggCh, derr := connector.DispatchH2StreamWithOpts(
						ctx, ch, httpaggregator.RoleServer,
						clientLOpts, logger, grpcOpts, grpcwebOpts,
					)
					if derr != nil {
						logger.Debug("proxybuild: h2 dispatch failed",
							"target", target, "stream_id", ch.StreamID(), "error", derr)
						_ = ch.Close()
						return
					}
					dial := func(dctx context.Context, env *envelope.Envelope) (layer.Channel, error) {
						upL := selectUpstreamForDial(dctx, target, upstreamH2, &redial, &redialDial, redialFn, logger)
						upCh, oerr := upL.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						// Project the upstream Layer's BodyOpts onto the
						// per-stream wrap so a fresh-dialed Layer's body
						// configuration matches the original.
						lopts := upstreamLOpts
						if upL != upstreamH2 {
							lopts = httpaggregator.OptionsFromLayer(upL)
							lopts.StateReleaser = deps.PluginV2Engine
						}
						// USK-771: wrap the upstream channel with the same
						// per-protocol layer the client side chose. Without
						// this dispatch the upstream stayed httpaggregator-
						// wrapped and rejected GRPCStartMessage on the first
						// Send, which the session translated into an upstream
						// stream Close → RST_STREAM(CANCEL) before any
						// envelope reached the Pipeline.
						var reqProto envelope.Protocol
						if env != nil {
							reqProto = env.Protocol
						}
						return connector.WrapH2UpstreamForDispatch(
							upCh, reqProto, lopts, grpcOpts, grpcwebOpts,
						), nil
					}
					if err := session.RunStackSessionExchange(ctx, stack, aggCh, dial, p, sessOpts); err != nil && !errors.Is(err, context.Canceled) {
						logger.Debug("proxybuild: h2 stream exchange ended with error",
							"target", target, "stream_id", ch.StreamID(), "error", err)
					}
				}(clientCh)
			}
		}
	}
}

// selectUpstreamForDial returns the *http2.Layer to use for OpenStream on
// this dial attempt. It re-checks the pooled upstreamH2's liveness via
// GoAwayClosed / IsShutdown (USK-816). When stale, it fresh-dials a
// replacement Layer atomically, sharing the result with concurrent streams
// in the same CONNECT lifecycle.
//
// Why GoAwayClosed/IsShutdown at dial-closure time: USK-796 added the same
// check at Pool.Get to evict stale entries before handing them out, but
// that check fires when the CONNECT begins. A long intercept hold can
// span server GOAWAY / idle-close mid-CONNECT — the pool already gave us
// the Layer, so the dial closure must re-check.
//
// Why we do NOT Pool.Evict the stale Layer here: the surrounding
// dispatchStack flow runs `Pool.Put(poolKey, upstreamH2)` deferred at
// handler exit, and the still-running clientToUpstream goroutines on
// other concurrent streams may still hold references. Single-writer
// close ownership (CLAUDE.md Concurrency Checklist) belongs to the
// pool's selectLocked path on the next Pool.Get — it is the canonical
// stale-entry evictor (USK-796) and runs after our handler has returned.
//
// The redialDial mutex serialises the fresh-dial attempt so concurrent
// streams observing staleness produce one upstream conn (not N). On
// dial failure, the original (stale) upstreamH2 is returned — OpenStream
// will then surface the underlying error to the caller, so failure
// propagates naturally (state=error / failure_reason=refused).
func selectUpstreamForDial(
	dctx context.Context,
	target string,
	upstreamH2 *http2.Layer,
	redial *atomic.Pointer[http2.Layer],
	redialDial *sync.Mutex,
	redialFn func(context.Context, string, *http2.Layer) (*http2.Layer, error),
	logger *slog.Logger,
) *http2.Layer {
	if l := redial.Load(); l != nil {
		return l
	}
	if !(upstreamH2.GoAwayClosed() || upstreamH2.IsShutdown()) {
		return upstreamH2
	}

	redialDial.Lock()
	defer redialDial.Unlock()
	if l := redial.Load(); l != nil {
		return l
	}

	fresh, err := redialFn(dctx, target, upstreamH2)
	if err != nil {
		logger.Warn("proxybuild: upstream h2 redial failed",
			"target", target, "error", err)
		return upstreamH2
	}
	redial.Store(fresh)
	logger.Debug("proxybuild: upstream h2 redialed after stale-conn detection",
		"target", target)
	return fresh
}

// buildSessionOptions populates the SessionOptions threaded into every
// session.RunSession / RunStackSession call from the live data path:
//
//   - LifecycleEngine + StateReleaser carry the pluginv2 Engine so that
//     post-Upgrade Layer constructors (currently runUpgradeWS) attach
//     WithLifecycleEngine / WithStateReleaser. Both fields are nil when
//     deps.PluginV2Engine is nil (matches the pre-USK-690 behavior).
//
//   - OnComplete finalises the recorded Stream's State + FailureReason via
//     deps.FlowStore. RecordStep is documented as not managing Stream state
//     transitions ("That is Session's responsibility via OnComplete" — see
//     internal/pipeline/record_step.go), so without this callback every
//     Stream recorded via the live path would stay at State="active"
//     indefinitely. Mirrors the pattern in
//     internal/layer/http2/http2_integration_test.go.
//     OnComplete is omitted when FlowStore is nil (e.g. test stacks that do
//     not record).
//
//   - OnPipelineDrop persists an audit Stream when the Pipeline Drops an
//     envelope with a BlockedBy attribution (USK-782). This bypasses the
//     RecordScope filter — blocked envelopes are always recorded so the
//     operator can see what was rejected even when capture_scope hides
//     normal traffic.
func buildSessionOptions(deps Deps, listenerName string) session.SessionOptions {
	opts := session.SessionOptions{}
	if deps.PluginV2Engine != nil {
		opts.LifecycleEngine = deps.PluginV2Engine
		opts.StateReleaser = deps.PluginV2Engine
	}
	// USK-851: thread the intercept-release tracker + a Stream-tag-append
	// callback into every session built by this listener. The tracker is
	// stamped by the MCP intercept tool's Release path; the callback fires
	// inside the relay goroutine when src.Next returns EOF within the
	// detection window of a recent release on the OPPOSITE direction. The
	// tag value is appended via flow.Store.UpdateStream.AppendTags so any
	// tags previously written (TLS metadata, RecordStep cap markers) are
	// preserved. nil store or nil tracker disables detection silently.
	if deps.InterceptReleaseTracker != nil {
		opts.InterceptReleaseTracker = deps.InterceptReleaseTracker
		if deps.FlowStore != nil {
			store := deps.FlowStore
			opts.OnInterceptReleaseEOF = func(ctx context.Context, streamID string) {
				if streamID == "" {
					return
				}
				_ = store.UpdateStream(ctx, streamID, flow.StreamUpdate{
					AppendTags: map[string]string{
						"intercept_hold_outcome": "upstream_closed_after_intercept_release",
					},
				})
			}
		}
	}
	// USK-806: bridge the post-Upgrade ws.Layer / sse Channel wire caps
	// from BuildConfig (resolved at boot from ProxyConfig.WebSocket /
	// ProxyConfig.SSE) into SessionOptions, so runUpgradeWS,
	// runUpgradeWSOverH2, and runUpgradeSSE apply the operator setting
	// to the new Layer/Channel they construct. nil-guarded because
	// buildSessionOptions is also called from test stacks that may not
	// populate BuildConfig (BuildLiveStack rejects deps.BuildConfig==nil
	// in production).
	if deps.BuildConfig != nil {
		opts.WSMaxFrameSize = deps.BuildConfig.WSMaxFrameSize
		opts.SSEMaxEventSize = deps.BuildConfig.SSEMaxEventSize
		// USK-854: thread the WS hold-window keepalive config into
		// SessionOptions. The serialiser + per-Stream goroutine spawn at
		// the relay site (internal/session/session.go) is gated on these
		// fields; nil pluginv2 engine and nil hold tracker disable the
		// feature implicitly.
		opts.WSHoldKeepaliveEnabled = deps.BuildConfig.WSHoldKeepaliveEnabled
		opts.WSHoldKeepaliveInterval = deps.BuildConfig.WSHoldKeepaliveInterval
	}
	// USK-854: thread the InterceptHoldTracker (shared with InterceptStep)
	// so the keepalive goroutine can poll for in-flight holds. A nil
	// tracker disables the feature regardless of WSHoldKeepaliveEnabled.
	if deps.InterceptHoldTracker != nil {
		opts.InterceptHoldTracker = deps.InterceptHoldTracker
	}
	// USK-854: expose the pluginv2 Engine on SessionOptions.PluginEngine
	// so the keepalive goroutine's per-Stream opt-out lookup (the canonical
	// stream_state["ws_hold_keepalive"] key) finds the same Engine used by
	// PluginPre/Post. The LifecycleEngine field cannot be reused for this
	// purpose because it has a narrower contractual surface (StateReleaser
	// only). The pointers typically refer to the same *pluginv2.Engine.
	if deps.PluginV2Engine != nil {
		opts.PluginEngine = deps.PluginV2Engine
	}
	if deps.FlowStore != nil {
		store := deps.FlowStore
		// USK-782: shared state between OnPipelineDrop and OnComplete so
		// the session's terminal state-finaliser does not clobber the
		// audit Stream that OnPipelineDrop wrote. OnComplete fires with
		// err=nil on a clean client disconnect after a Drop, which would
		// otherwise rewrite State="error"+BlockedBy=* to State="complete".
		blocked := newBlockedStreamSet()
		opts.OnComplete = func(ctx context.Context, streamID string, err error) {
			if streamID == "" {
				return
			}
			if blocked.contains(streamID) {
				// The stream was already finalised by the audit recorder;
				// skip the normal completion update. Evict the marker now
				// that we've consumed it so the per-listener set does not
				// accumulate entries for the proxy's lifetime (USK-782
				// review fix; CWE-400). OnComplete fires after RunSession's
				// errgroup.Wait, so no further references to streamID exist
				// past this point.
				blocked.remove(streamID)
				return
			}
			state := "complete"
			if err != nil && !errors.Is(err, io.EOF) {
				state = "error"
			}
			update := flow.StreamUpdate{
				State:         state,
				FailureReason: session.ClassifyError(err),
			}
			// USK-797: persist the raw err string under tags["error"] so
			// operators can distinguish e.g. "dial: stream error refused:
			// layer shutdown" from "client.Next: read tcp ...: use of
			// closed network connection" without re-deriving it from the
			// log stream. ClassifyError only returns the canonical
			// taxonomy label (refused / canceled / aborted / ...); the
			// full message is what makes the row actionable. AppendTags
			// preserves any tags previously written by RecordStep / TLS
			// metadata projections (CLAUDE.md MITM principle: do not
			// clobber what the wire / earlier steps already recorded).
			if state == "error" && err != nil {
				update.AppendTags = map[string]string{
					"error": truncateErrorTag(err.Error()),
				}
			}
			_ = store.UpdateStream(ctx, streamID, update)
		}
		opts.OnPipelineDrop = buildPipelineDropRecorder(store, listenerName, deps.Logger, blocked)
	}
	return opts
}

// errorTagMaxLen caps the size of the err.Error() string persisted under
// tags["error"] (USK-797). Stream tags are loaded into memory and shipped
// over MCP per query — a runaway nested-wrap chain or a multi-MB
// transport-layer error message must not be allowed to balloon the row.
// 1 KiB is large enough for "dial: stream error refused: ..." patterns
// (~40 chars) plus several layers of fmt.Errorf wrap context, which is
// the actionable information; anything beyond that is structural noise.
const errorTagMaxLen = 1024

// truncateErrorTag returns msg, or msg truncated to errorTagMaxLen with
// a marker suffix when the source exceeds the cap. The marker uses the
// ASCII ellipsis sequence so the output remains valid UTF-8 even if the
// truncation lands mid-rune (multi-byte runes are dropped wholesale).
func truncateErrorTag(msg string) string {
	if len(msg) <= errorTagMaxLen {
		return msg
	}
	const marker = "...[truncated]"
	if errorTagMaxLen <= len(marker) {
		return msg[:errorTagMaxLen]
	}
	cut := errorTagMaxLen - len(marker)
	// Walk back to a rune boundary so we don't slice in the middle of a
	// multi-byte UTF-8 sequence.
	for cut > 0 && (msg[cut]&0xC0) == 0x80 {
		cut--
	}
	return msg[:cut] + marker
}

// blockedStreamSet is a tiny concurrent-safe set of streamIDs that have
// been finalised as blocked audit Streams. OnPipelineDrop writes; OnComplete
// reads. Both fire from the session goroutines so contention is bounded by
// the per-session envelope rate.
type blockedStreamSet struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

func newBlockedStreamSet() *blockedStreamSet {
	return &blockedStreamSet{ids: make(map[string]struct{})}
}

func (b *blockedStreamSet) add(id string) {
	if id == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ids[id] = struct{}{}
}

func (b *blockedStreamSet) contains(id string) bool {
	if id == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.ids[id]
	return ok
}

// remove evicts the streamID from the set. OnComplete calls this once it
// has observed the contains() guard so the entry does not accumulate for
// the lifetime of the listener — the session is terminating and no further
// references to streamID survive past OnComplete. Without this eviction the
// per-listener blockedStreamSet grew unboundedly across an attacker-driven
// stream of Pipeline-Drops (USK-782 review fix; CWE-400).
func (b *blockedStreamSet) remove(id string) {
	if id == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.ids, id)
}

// buildPipelineDropRecorder returns a callback that persists a Pipeline-Drop
// envelope as a flow.Stream with State="error" and BlockedBy=<reason>. It
// mirrors buildProtocolRejectedRecorder for the Pipeline-Drop path: the
// Stream is intentionally minimal (no Flow rows) for envelopes whose
// Drop happened before any L7 message could be projected — but when an
// HTTPMessage is available (the common case for HostScope/HTTPScope/Safety
// drops on Send), the Stream's Scheme is populated so MCP query tools can
// distinguish https vs http audit Streams. Flow rows are never written
// from this path: blocked envelopes are recorded for audit, not for replay.
//
// The recorder always overwrites an existing Stream identified by env.StreamID
// — Pipeline-Drop emits the audit Stream BEFORE the live path would have
// otherwise saved a "normal" one, so SaveStream's primary-key conflict on a
// concurrent reuse is impossible in practice (Drop short-circuits the
// Pipeline; no Continue path runs after).
func buildPipelineDropRecorder(store flow.Writer, listenerName string, logger *slog.Logger, blocked *blockedStreamSet) func(context.Context, *envelope.Envelope, string) {
	if store == nil {
		return nil
	}
	if listenerName == "" {
		listenerName = DefaultListenerName
	}
	return func(ctx context.Context, env *envelope.Envelope, blockedBy string) {
		if env == nil || blockedBy == "" {
			return
		}

		streamID := env.StreamID
		if streamID == "" {
			streamID = uuid.New().String()
		}
		// Mark this stream as finalised so the session OnComplete callback
		// does not overwrite our audit attribution. Add up-front so the
		// guard fires even if SaveStream/UpdateStream below errors.
		if blocked != nil {
			blocked.add(streamID)
		}
		connID := env.Context.ConnID
		if connID == "" {
			connID = connector.ConnIDFromContext(ctx)
		}
		clientAddr := connector.ClientAddrFromContext(ctx)

		st := &flow.Stream{
			ID:        streamID,
			ConnID:    connID,
			Protocol:  string(env.Protocol),
			State:     "error",
			BlockedBy: blockedBy,
			Timestamp: time.Now(),
		}
		// Project HTTP-typed identity fields when available. Following the
		// "do not unify across protocols" principle (CLAUDE.md), the Stream
		// is left minimal for non-HTTP envelopes — RawMessage, WSMessage,
		// gRPC have no notion of a request URL/method that maps to Stream
		// fields. Scheme is the only HTTP-derived field on Stream.
		if msg, ok := env.Message.(*envelope.HTTPMessage); ok && msg != nil {
			if msg.Scheme != "" {
				st.Scheme = msg.Scheme
			}
		}
		if clientAddr != "" {
			st.ConnInfo = &flow.ConnectionInfo{ClientAddr: clientAddr}
		}

		// Use a background-derived context so a cancelled handler ctx does
		// not abort the audit record — matches buildProtocolRejectedRecorder.
		recordCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Try SaveStream first. The common path (first Send dropped by
		// HostScope/HTTPScope/Safety) has no prior Stream row, so this
		// succeeds. For mid-stream Drops on streaming protocols (gRPC /
		// WS data frame blocked by SafetyStep) RecordStep already created
		// a Stream on the first Send; the INSERT then fails with a
		// constraint violation and we fall back to UpdateStream so the
		// audit fields (State, BlockedBy) overwrite the active state.
		if err := store.SaveStream(recordCtx, st); err == nil {
			return
		}
		// Fallback: update the existing Stream with the audit attribution.
		// We never know upfront which path we're on, so always attempt
		// SaveStream first to keep the no-prior-row path single-statement.
		// On a streaming protocol mid-Drop (gRPC / WS data frame blocked
		// by SafetyStep) the first Send has already created an active
		// Stream; this UpdateStream rewrites it as a blocked audit record.
		if uerr := store.UpdateStream(recordCtx, streamID, flow.StreamUpdate{
			State:     "error",
			BlockedBy: blockedBy,
		}); uerr != nil {
			if logger != nil {
				logger.Error("proxybuild: pipeline-drop stream save failed",
					"listener", listenerName,
					"stream_id", streamID,
					"blocked_by", blockedBy,
					"protocol", string(env.Protocol),
					"error", uerr,
				)
			}
		}
	}
}

// buildProtocolRejectedRecorder returns a connector.ProtocolRejectedFunc
// that persists a rejected connection as a Stream with State="error" and
// BlockedBy="enabled_protocols" so the rejection is observable via the
// MCP query("flows") tool. nil store yields a nil callback so the
// listener's silent-close fallback path engages — keeping behaviour
// unchanged for tests/builds that omit a FlowStore.
//
// The recorded Stream is intentionally minimal: there is no L7 message
// to attach (the connection was refused before any handler ran), so no
// Flow rows are saved. The Stream alone is enough to surface the event
// in query results, satisfying the USK-732 acceptance criterion that
// rejection must not be a silent close.
func buildProtocolRejectedRecorder(store flow.Writer, listenerName string, logger *slog.Logger) connector.ProtocolRejectedFunc {
	if store == nil {
		return nil
	}
	if listenerName == "" {
		listenerName = DefaultListenerName
	}
	return func(ctx context.Context, pc *connector.PeekConn, kind connector.ProtocolKind, name string) {
		if pc == nil {
			return
		}
		// Resolve the connection identity. ConnIDFromContext is populated
		// by FullListener.handleConn before it dispatches to the handler
		// or invokes the rejection callback, so this is non-empty in the
		// production path.
		connID := connector.ConnIDFromContext(ctx)
		if connID == "" {
			connID = uuid.New().String()
		}
		clientAddr := connector.ClientAddrFromContext(ctx)
		if clientAddr == "" {
			if remote := pc.RemoteAddr(); remote != nil {
				clientAddr = remote.String()
			}
		}
		protoLabel := name
		if protoLabel == "" {
			protoLabel = kind.String()
		}
		st := &flow.Stream{
			ID:            uuid.New().String(),
			ConnID:        connID,
			Protocol:      protoLabel,
			State:         "error",
			BlockedBy:     "enabled_protocols",
			FailureReason: "protocol_not_enabled",
			Timestamp:     time.Now(),
			ConnInfo: &flow.ConnectionInfo{
				ClientAddr: clientAddr,
			},
		}
		// Use a background-derived context so a cancelled handler ctx
		// does not abort the rejection record. Bound by a short timeout
		// so a slow / hung store does not stall the accept loop.
		recordCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := store.SaveStream(recordCtx, st); err != nil {
			if logger != nil {
				logger.Error("proxybuild: rejected-protocol stream save failed",
					"listener", listenerName,
					"conn_id", connID,
					"protocol", protoLabel,
					"error", err,
				)
			}
		}
	}
}

// buildUpstreamTLSErrorRecorder returns a connector.OnUpstreamTLSErrorFunc
// that persists a state="error" Stream when BuildConnectionStack fails
// inside the CONNECT/SOCKS5 TLS MITM path (USK-784). The most common
// trigger is upstream TLS handshake rejection (expired / self-signed /
// untrusted CA cert). nil store yields a nil callback so the connector's
// silent-drop path engages — preserving behaviour for stacks that opt
// out of recording.
//
// The recorded Stream is intentionally minimal: there is no L7 message
// for this path (the inner TLS handshake never completed, so no HTTP
// request reached the proxy), and the L4 raw bytes principle does not
// apply to bytes that never flowed. The Stream alone is enough for MCP
// query("flows", filter:{state:"error"}) to surface the event, which
// satisfies the USK-784 acceptance criterion.
//
// Protocol is set to envelope.ProtocolHTTP and Scheme to "https" because
// CONNECT/SOCKS5 + TLS MITM is the HTTPS data path; no inner-protocol
// negotiation finished, so HTTP/1.x vs HTTP/2 is undecidable here.
//
// FailureReason is set to "upstream_tls_error" — a new taxonomy entry
// because the existing layer.ErrorCode classes (refused, canceled,
// aborted, internal_error, protocol_error) all describe wire-observed
// signals on a successfully established channel; an upstream TLS
// handshake reject never produced one. The error string is preserved
// verbatim in Tags["error"] so MCP users can distinguish cert-expired
// from self-signed from CA-untrusted without parsing FailureReason.
//
// USK-791: when scope is non-nil and non-empty, the recorder consults
// flow.RecordScope.ShouldRecord with a synthetic envelope carrying the
// CONNECT/SOCKS5 authority as the only identity field. Out-of-scope
// hosts (e.g. HSTS-pinned services the browser dials on its own when
// the operator only includes httpbin.org) are dropped at slog.Debug —
// the same fail-closed semantics applied by RecordStep on the live
// path. URL-prefix / method matchers are inert at this stage because
// the inner TLS handshake never completed; hostname matchers are the
// only meaningful axis for unrecorded-protocol error paths.
func buildUpstreamTLSErrorRecorder(store flow.Writer, scope *flow.RecordScope, listenerName string, logger *slog.Logger) connector.OnUpstreamTLSErrorFunc {
	if store == nil {
		return nil
	}
	if listenerName == "" {
		listenerName = DefaultListenerName
	}
	return func(ctx context.Context, target string, buildErr error) {
		if buildErr == nil {
			return
		}

		// USK-791: skip recording for out-of-scope hosts. The synthetic
		// envelope carries only Context.TargetHost (the CONNECT/SOCKS5
		// authority) so RecordScope.ShouldRecord can evaluate hostname
		// matchers; URL-prefix / method matchers in the rule set are
		// inert at this stage and are silently ignored by the
		// matchScopeRule AND-of-non-empty-fields semantics.
		if !scope.IsEmpty() {
			scopeEnv := &envelope.Envelope{
				Context: envelope.EnvelopeContext{TargetHost: target},
			}
			if !scope.ShouldRecord(scopeEnv) {
				if logger != nil {
					logger.Debug("proxybuild: upstream TLS error out of capture_scope; skipped recording",
						"listener", listenerName,
						"target", target,
						"error", buildErr.Error(),
					)
				}
				return
			}
		}

		// Resolve the connection identity. ConnIDFromContext is populated
		// by FullListener.handleConn before it dispatches to the handler,
		// so this is non-empty in the production path.
		connID := connector.ConnIDFromContext(ctx)
		if connID == "" {
			connID = uuid.New().String()
		}
		clientAddr := connector.ClientAddrFromContext(ctx)

		errMsg := buildErr.Error()

		st := &flow.Stream{
			ID:            uuid.New().String(),
			ConnID:        connID,
			Protocol:      string(envelope.ProtocolHTTP),
			Scheme:        "https",
			State:         "error",
			FailureReason: "upstream_tls_error",
			Timestamp:     time.Now(),
			Tags: map[string]string{
				"error":  errMsg,
				"target": target,
			},
			ConnInfo: &flow.ConnectionInfo{
				ClientAddr: clientAddr,
				ServerAddr: target,
			},
		}

		// Use a background-derived context so a cancelled handler ctx
		// does not abort the audit record — matches
		// buildProtocolRejectedRecorder.
		recordCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := store.SaveStream(recordCtx, st); err != nil {
			if logger != nil {
				logger.Error("proxybuild: upstream-tls-error stream save failed",
					"listener", listenerName,
					"conn_id", connID,
					"target", target,
					"error", err,
				)
			}
		}
	}
}

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
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
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
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
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
	SSEInterceptEngine  *sserules.InterceptEngine
	SSETransformEngine  *sserules.TransformEngine

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

	// RecordHTTP2FrameMaxPerStream caps the number of frame-level
	// envelopes (WireLevel=h2-frame, H2 DATA frames recorded as a
	// per-stream sub-stack overlay under WS-over-h2 / SSE-over-h2)
	// RecordStep persists per stream (USK-889). Zero uses
	// config.MaxHTTP2FrameRecordsPerStream. Wire forwarding is
	// unaffected — the frame-record callback fires BEFORE pipe.Write
	// inside http2.runDetachDrain, and the cap suppresses only the
	// downstream RecordStep dispatch.
	RecordHTTP2FrameMaxPerStream int

	// RecordHTTP1ChunkMaxPerStream caps the number of chunk-level
	// envelopes (WireLevel=h1-chunk, HTTP/1.x Transfer-Encoding chunk
	// boundaries recorded on the SSE-over-h1-chunked streaming detach
	// path) RecordStep persists per stream (USK-895). Zero uses
	// config.MaxHTTP1ChunkRecordsPerStream. Wire forwarding is
	// unaffected — the chunk-record callback fires inside the parser's
	// dechunked-read loop BEFORE the dechunked payload is forwarded to
	// the SSE event-boundary reader, and the cap suppresses only the
	// downstream RecordStep dispatch.
	RecordHTTP1ChunkMaxPerStream int

	// RecordGRPCLPMFrameMaxPerStream caps the number of gRPC LPM
	// (Length-Prefixed Message) wire envelopes
	// (WireLevel=grpc-lpm-frame, per-LPM wire bytes captured by the grpc
	// Layer's per-LPM record callback) RecordStep persists per stream
	// (USK-896). Zero uses config.MaxGRPCLPMFrameRecordsPerStream. Wire
	// forwarding is unaffected — the LPM-record callback fires inside
	// grpcChannel.absorbData BEFORE the semantic GRPCDataMessage envelope
	// is queued, and the cap suppresses only the downstream RecordStep
	// dispatch.
	RecordGRPCLPMFrameMaxPerStream int

	// RecordGRPCWebBase64MaxPerStream caps the number of gRPC-Web
	// text-variant body wire envelopes (WireLevel=grpcweb-base64,
	// pre-decode base64 body bytes captured by the grpcweb Layer's
	// per-body record callback) RecordStep persists per stream (USK-898).
	// Zero uses config.MaxGRPCWebBase64RecordsPerStream. Wire forwarding
	// is unaffected — the base64-record callback fires inside
	// grpcweb.channel.refillFromHTTPMessage BEFORE the in-place base64
	// decode + LPM parse, and the cap suppresses only the downstream
	// RecordStep dispatch.
	RecordGRPCWebBase64MaxPerStream int

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
	upstreamTLSErrorRecorder := buildTLSStackBuildErrorRecorder(deps.FlowStore, deps.RecordScope, listenerName, logger)

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
		Name:           listenerName,
		Addr:           deps.ListenAddr,
		Logger:         logger,
		PeekTimeout:    deps.PeekTimeout,
		MaxConnections: deps.MaxConnections,
		OnCONNECT:      wrapper.wrapHandler(connectHandler),
		OnSOCKS5:       wrapper.wrapHandler(socks5Handler),
		OnHTTP1:        wrapper.wrapHandler(http1ForwardHandler),
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
	r.Register(envelope.ProtocolGRPC, grpclayer.EncodeWireBytes)
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
	// USK-889: per-stream cap for h2 frame envelopes (WS-over-h2 /
	// SSE-over-h2 detach paths). Zero falls back to the package default
	// so synthetic test stacks that omit the field still observe a
	// positive cap consistent with the gRPC / SSE pattern.
	h2FrameCap := deps.RecordHTTP2FrameMaxPerStream
	if h2FrameCap <= 0 {
		h2FrameCap = config.MaxHTTP2FrameRecordsPerStream
	}
	recordOpts = append(recordOpts, pipeline.WithHTTP2FrameMaxPerStream(h2FrameCap))
	// USK-895: per-stream cap for h1 chunk envelopes (SSE-over-h1-chunked
	// streaming detach path). Zero falls back to the package default so
	// synthetic test stacks that omit the field still observe a positive
	// cap consistent with the USK-889 pattern.
	h1ChunkCap := deps.RecordHTTP1ChunkMaxPerStream
	if h1ChunkCap <= 0 {
		h1ChunkCap = config.MaxHTTP1ChunkRecordsPerStream
	}
	recordOpts = append(recordOpts, pipeline.WithHTTP1ChunkMaxPerStream(h1ChunkCap))
	// USK-896: per-stream cap for gRPC LPM wire envelopes (grpc data
	// path). Zero falls back to the package default so synthetic test
	// stacks that omit the field still observe a positive cap consistent
	// with the USK-889 / USK-895 pattern.
	grpcLPMCap := deps.RecordGRPCLPMFrameMaxPerStream
	if grpcLPMCap <= 0 {
		grpcLPMCap = config.MaxGRPCLPMFrameRecordsPerStream
	}
	recordOpts = append(recordOpts, pipeline.WithGRPCLPMFrameMaxPerStream(grpcLPMCap))
	// USK-898: per-stream cap for gRPC-Web base64 body wire envelopes
	// (grpc-web text-variant data path). Zero falls back to the package
	// default so synthetic test stacks that omit the field still observe
	// a positive cap consistent with the USK-889 / USK-895 / USK-896 /
	// USK-897 pattern.
	grpcWebBase64Cap := deps.RecordGRPCWebBase64MaxPerStream
	if grpcWebBase64Cap <= 0 {
		grpcWebBase64Cap = config.MaxGRPCWebBase64RecordsPerStream
	}
	recordOpts = append(recordOpts, pipeline.WithGRPCWebBase64MaxPerStream(grpcWebBase64Cap))

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
		pipeline.NewInterceptStep(deps.HTTPInterceptEngine, deps.WSInterceptEngine, deps.GRPCInterceptEngine, deps.SSEInterceptEngine, deps.HoldQueue, safetyStep, logger).
			WithHoldTracker(deps.InterceptHoldTracker),
		pipeline.NewTransformStep(deps.HTTPTransformEngine, deps.WSTransformEngine, deps.GRPCTransformEngine, deps.SSETransformEngine),
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
			runHTTP1ExchangeLoop(ctx, stack, clientH1, upstreamH1, p, deps, sessOpts, target, logger)
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
// USK-934: each exchange is run through connector.DispatchH1Channel
// before entering RunStackSessionExchange. When the request's content-
// type matches application/grpc-web[-text][+proto|...], the client-side
// per-exchange Channel is wrapped with grpcweb.Wrap (RoleServer) and the
// upstream-side Channel is wrapped via connector.WrapH1UpstreamForDispatch
// (RoleClient). Envelopes emitted by these wraps carry
// Protocol=ProtocolGRPCWeb so the canonical record_step.maybeRetagProtocol
// re-tags Stream.Protocol from "http" to "grpc-web". For any non-grpc-web
// content-type the dispatch is a no-op and the exchange flows through
// unchanged.
//
// Upgrade flow (WS / SSE) is owned by RunStackSessionExchange; on detach
// the http1 Layer's spawn loop closes Channels() and the loop exits.
func runHTTP1ExchangeLoop(
	ctx context.Context,
	stack *connector.ConnectionStack,
	clientH1, upstreamH1 *http1.Layer,
	p *pipeline.Pipeline,
	deps Deps,
	sessOpts session.SessionOptions,
	target string,
	logger *slog.Logger,
) {
	grpcwebOpts := connector.GRPCWebOptionsFromBuildConfig(deps.BuildConfig)
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
				runHTTP1Exchange(ctx, stack, ch, upstreamH1, p, sessOpts, target, grpcwebOpts, logger)
			}(clientCh)
		}
	}
}

// runHTTP1Exchange runs one HTTP/1.x per-exchange Channel through the
// H1 dispatcher (content-type-based grpc-web auto-classify, USK-934) and
// then into session.RunStackSessionExchange. Extracted from
// runHTTP1ExchangeLoop for readability — the wrap + dial-closure
// composition has grown beyond the inline goroutine body it used to be.
//
// Per-exchange grpc-web record callback: when the request matches
// application/grpc-web[-text][+proto|...], the per-exchange
// session.GRPCWebBase64RecordOption installs the WireLevel=grpcweb-base64
// overlay producer on BOTH the client-side and upstream-side
// grpcweb.Wrap calls. Same closure → independent per-direction sequence
// counters → distinct (StreamID, Direction, sequence, wire_level) tuples
// per the schemaV14 UNIQUE constraint. Mirrors the H2 pattern in
// buildOnHTTP2Stack (USK-898).
func runHTTP1Exchange(
	ctx context.Context,
	stack *connector.ConnectionStack,
	clientCh layer.Channel,
	upstreamH1 *http1.Layer,
	p *pipeline.Pipeline,
	sessOpts session.SessionOptions,
	target string,
	baseGRPCWebOpts []grpcweb.Option,
	logger *slog.Logger,
) {
	// Per-exchange wire-record Option for the gRPC-Web text-variant
	// base64 wire bytes. The same closure is installed on both the
	// client-side and upstream-side grpcweb wraps; the closure runs
	// independent per-direction sequence counters and rewrites
	// env.StreamID to clientCh.StreamID() for unification (mirroring
	// the H2 wiring in buildOnHTTP2Stack).
	streamFlowCtx := envelope.EnvelopeContext{ConnID: stack.ConnID, TargetHost: target}
	grpcWebBase64Opt := session.GRPCWebBase64RecordOption(ctx, p, clientCh.StreamID(), streamFlowCtx)
	streamGRPCWebOpts := make([]grpcweb.Option, 0, len(baseGRPCWebOpts)+1)
	streamGRPCWebOpts = append(streamGRPCWebOpts, baseGRPCWebOpts...)
	streamGRPCWebOpts = append(streamGRPCWebOpts, grpcWebBase64Opt)

	dispatchedCh, err := connector.DispatchH1Channel(ctx, clientCh, grpcweb.RoleServer, streamGRPCWebOpts, logger)
	if err != nil {
		// Peer hung up before sending a request, or the client Channel
		// produced a non-HTTPMessage first envelope (programmer error
		// elsewhere). Drop the exchange; the session loop normally
		// surfaces these as state="error" but the dispatcher consumed
		// the first Next so there's no envelope to drive the record
		// path. The http1 layer cleans up its own state on Close.
		_ = clientCh.Close()
		if !errors.Is(err, context.Canceled) {
			logger.Debug("proxybuild: http1 dispatch failed",
				"target", target, "stream_id", clientCh.StreamID(), "error", err)
		}
		return
	}

	dial := func(_ context.Context, env *envelope.Envelope) (layer.Channel, error) {
		upCh := upstreamH1.OpenExchange()
		if upCh == nil {
			return nil, fmt.Errorf("proxybuild: upstream http1 layer closed before opening exchange for %s", target)
		}
		// USK-934: wrap the upstream channel with the same per-protocol
		// layer the client side chose. Without this dispatch the upstream
		// stays a bare http1 Channel and rejects GRPCStartMessage on the
		// first Send (the http1 Channel only accepts *envelope.HTTPMessage),
		// aborting the exchange before any envelope reaches the Pipeline.
		// Mirrors USK-771's H2 symmetry fix.
		var reqProto envelope.Protocol
		if env != nil {
			reqProto = env.Protocol
		}
		return connector.WrapH1UpstreamForDispatch(upCh, reqProto, streamGRPCWebOpts), nil
	}
	if err := session.RunStackSessionExchange(ctx, stack, dispatchedCh, dial, p, sessOpts); err != nil && !errors.Is(err, context.Canceled) {
		logger.Debug("proxybuild: http1 exchange ended with error", "target", target, "error", err)
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

		// USK-816 / USK-991: when the pooled upstreamH2 (or a previously
		// redialed Layer) goes stale during a long intercept hold — server
		// GOAWAY / idle FIN — per-stream dial closures transparently
		// fall back to a fresh dial. The fresh Layer is shared across all
		// subsequent streams in this CONNECT lifecycle via redialChain.current
		// + mutex-serialised dial, so concurrent streams do not each open a
		// new upstream conn. The fresh Layers are owned by this handler — all
		// chain steps are closed in the deferred cleanup below.
		//
		// USK-991: the chain is unbounded (browser-equivalent transparency:
		// no cap; the per-CONNECT lifetime is the natural bound). Prior
		// Layers are retained for the CONNECT's lifetime so in-flight
		// streams on them drain naturally up to GOAWAY's last_stream_id
		// (RFC 9113 §6.8) — close-on-CONNECT-exit, not close-on-swap.
		chain := newRedialChain()
		redialFn := func(dctx context.Context, t string, stale *http2.Layer, generation int) (*http2.Layer, error) {
			return connector.RedialUpstreamH2(dctx, t, stale, deps.BuildConfig, generation)
		}
		defer chain.closeAll()

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
					// USK-896: per-stream gRPC LPM wire-record Option. Built
					// inside the per-stream goroutine because the LPM
					// record-only Pipeline closure captures per-stream
					// scope (target → flowCtx.TargetHost; client-side
					// StreamID → session-scope identity used for the
					// upstream-side StreamID rewrite mirroring
					// session.upstreamToClient). The Option is a no-op
					// when p is nil; client-side and upstream-side share
					// the same closure so both directions of a bidi RPC's
					// LPMs are recorded under the same sequence counters
					// and the same Stream row.
					// USK-910 defense-in-depth: pre-populate ConnID alongside
					// TargetHost. The wire-record callbacks no longer use this
					// template to overwrite env.Context (the inner envelope's
					// Context populated by the producing Layer wins), but
					// keeping ConnID here preserves the parameter's documented
					// semantics for any future caller that does consult it.
					streamFlowCtx := envelope.EnvelopeContext{ConnID: stack.ConnID, TargetHost: target}
					lpmOpt := session.GRPCLPMRecordOption(ctx, p, ch.StreamID(), streamFlowCtx)
					// USK-899: per-stream native-gRPC h2 DATA frame
					// wire-record Option. Closes the wire_level=h2-frame
					// producer gap left by USK-897 — native gRPC over
					// h2 bypasses httpaggregator.Wrap, so the
					// aggregator's h2-frame callback never fires here.
					// Wiring shape mirrors the LPM Option above (single
					// closure shared across client-side + upstream-side
					// grpc.Wrap calls; per-direction atomic counters in
					// the closure keep Send / Receive in independent
					// sequence spaces; StreamID unification mirrors
					// session.upstreamToClient). With this Option,
					// native-gRPC streams record three wire_level rows
					// per direction: semantic + grpc-lpm-frame +
					// h2-frame.
					grpcH2FrameOpt := session.GRPCH2DataFrameRecordOption(ctx, p, ch.StreamID(), streamFlowCtx)
					streamGRPCOpts := make([]grpclayer.Option, 0, len(grpcOpts)+2)
					streamGRPCOpts = append(streamGRPCOpts, grpcOpts...)
					streamGRPCOpts = append(streamGRPCOpts, lpmOpt)
					streamGRPCOpts = append(streamGRPCOpts, grpcH2FrameOpt)

					// USK-897: per-stream aggregator-path h2 DATA frame
					// wire-record Option. Same wiring shape as the gRPC
					// LPM Option above (single closure shared across
					// client-side + upstream-side wraps; the closure's
					// per-direction counters keep Send / Receive in
					// independent sequence spaces; the closure rewrites
					// upstream-side env.StreamID to the client-side
					// session-scope StreamID for unification). Covers the
					// gRPC-Web and default (plain HTTP/2 + httpaggregator)
					// branches of DispatchH2StreamFull; the native-gRPC
					// branch ignores aggregatorOpts and records LPM
					// envelopes instead via streamGRPCOpts above.
					aggH2FrameOpt := session.AggregatorH2FrameRecordOption(ctx, p, ch.StreamID(), streamFlowCtx)
					streamAggOpts := []httpaggregator.WrapOption{aggH2FrameOpt}

					// USK-898: per-stream gRPC-Web base64 body wire-
					// record Option. Same wiring shape as the gRPC LPM
					// Option above — single closure shared across
					// client-side + upstream-side grpcweb wraps; the
					// closure's per-direction counters keep Send / Receive
					// in independent sequence spaces; the closure rewrites
					// upstream-side env.StreamID to the client-side
					// session-scope StreamID for unification. Fires only
					// on text variants (application/grpc-web-text[+proto])
					// — binary variants do not pass through the layer's
					// base64 decode branch and the channel does not fire
					// the callback by construction.
					grpcWebBase64Opt := session.GRPCWebBase64RecordOption(ctx, p, ch.StreamID(), streamFlowCtx)
					streamGRPCWebOpts := make([]grpcweb.Option, 0, len(grpcwebOpts)+1)
					streamGRPCWebOpts = append(streamGRPCWebOpts, grpcwebOpts...)
					streamGRPCWebOpts = append(streamGRPCWebOpts, grpcWebBase64Opt)

					aggCh, derr := connector.DispatchH2StreamFull(
						ctx, ch, httpaggregator.RoleServer,
						clientLOpts, logger, streamGRPCOpts, streamGRPCWebOpts, streamAggOpts,
					)
					if derr != nil {
						logger.Debug("proxybuild: h2 dispatch failed",
							"target", target, "stream_id", ch.StreamID(), "error", derr)
						_ = ch.Close()
						return
					}
					dial := func(dctx context.Context, env *envelope.Envelope) (layer.Channel, error) {
						upL, upCh, oerr := openUpstreamStreamWithRetry(
							dctx, target, upstreamH2, chain, redialFn, logger,
						)
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
						return connector.WrapH2UpstreamForDispatchFull(
							upCh, reqProto, lopts, streamGRPCOpts, streamGRPCWebOpts, streamAggOpts,
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

// redialFunc is the closure proxybuild hands to selectUpstreamForDial.
// generation is 1 for the first redial off the pooled upstreamH2, 2 for
// the next chain step, etc. (USK-991). Implementations stamp the fresh
// Layer's ConnID with a generation-aware suffix so per-step diagnostics
// stay readable.
type redialFunc func(ctx context.Context, target string, stale *http2.Layer, generation int) (*http2.Layer, error)

// redialChain holds the chain of fresh *http2.Layer instances produced
// by recursive GOAWAY-driven redials within a single CONNECT lifecycle
// (USK-991). The pooled upstreamH2 is the implicit chain[0] and is
// managed separately by dispatchStack (Pool.Put/Close).
//
// Invariants:
//   - mu serialises append-to-layers + current.Store. Single-writer-on-
//     append guarantees no in-flight goroutine observes a partially
//     constructed slice and that current always points to a Layer
//     already inserted into layers.
//   - current is a pointer to the most recently appended fresh Layer or
//     nil before the first redial; readers (selectUpstreamForDial) use
//     it on the fast path without acquiring mu.
//   - layers retains every fresh Layer for the CONNECT's lifetime. They
//     are all closed by closeAll() from the buildOnHTTP2Stack defer.
//     Browser-equivalent semantics: prior chain steps drain their in-
//     flight streams naturally up to GOAWAY's last_stream_id (RFC 9113
//     §6.8); the proxy does not tear them down on swap.
type redialChain struct {
	mu      sync.Mutex
	layers  []*http2.Layer
	current atomic.Pointer[http2.Layer]
}

func newRedialChain() *redialChain {
	return &redialChain{}
}

// closeAll closes every fresh Layer accumulated in the chain. Called
// from the buildOnHTTP2Stack defer at CONNECT exit. Idempotent on
// repeated calls because http2.Layer.Close() is itself idempotent (the
// USK-739/798 patterns establish this for both directions).
func (c *redialChain) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.layers {
		_ = l.Close()
	}
	// Hand back the empty slot so a CONNECT that somehow re-enters
	// (it does not today) would not double-close.
	c.layers = nil
	c.current.Store(nil)
}

// selectUpstreamForDial returns the *http2.Layer to use for OpenStream on
// this dial attempt. It walks the redial chain and re-checks the
// currently-active Layer's liveness via GoAwayClosed / IsShutdown each
// call (USK-816 for the 1st step, USK-991 for the recursive case).
// When the active Layer is stale, it fresh-dials a replacement Layer
// under chain.mu, appends to chain.layers, atomically swaps
// chain.current, and returns the fresh Layer. The same fresh Layer is
// observed by concurrent streams via chain.current.Load() so they do
// not each open a new upstream conn.
//
// Active-Layer selection rule:
//   - chain.current.Load() if non-nil (we've already redialed at least
//     once in this CONNECT)
//   - else the pooled upstreamH2
//
// Why GoAwayClosed/IsShutdown at dial-closure time: USK-796 added the same
// check at Pool.Get to evict stale entries before handing them out, but
// that check fires when the CONNECT begins. A long intercept hold can
// span server GOAWAY / idle-close mid-CONNECT — the pool already gave us
// the Layer, so the dial closure must re-check.
//
// Why we do NOT Pool.Evict the stale pooled Layer here: the surrounding
// dispatchStack flow runs `Pool.Put(poolKey, upstreamH2)` deferred at
// handler exit, and the still-running clientToUpstream goroutines on
// other concurrent streams may still hold references. Single-writer
// close ownership (CLAUDE.md Concurrency Checklist) belongs to the
// pool's selectLocked path on the next Pool.Get — it is the canonical
// stale-entry evictor (USK-796) and runs after our handler has returned.
//
// Why we hold prior chain steps until CONNECT exit (USK-991): browser-
// equivalent semantics. A GOAWAY tells the client "no new streams" but
// existing streams up to last_stream_id complete normally (RFC 9113
// §6.8). Closing prior chain steps on swap would abort their in-flight
// streams; holding them lets those streams drain and only NEW streams
// fall through to the fresh chain step. The slice is bounded in
// practice by the CONNECT's lifetime — there is no chain cap; this is
// a deliberate decision for diagnostic transparency, see USK-991.
//
// The chain.mu serialises the fresh-dial attempt so concurrent streams
// observing staleness produce one upstream conn (not N). On dial
// failure, the previous (stale) Layer is returned — OpenStream will
// then surface the underlying error to the caller, so failure
// propagates naturally (state=error / failure_reason=refused). The
// failed dial is NOT cached, so the next call retries cleanly.
func selectUpstreamForDial(
	dctx context.Context,
	target string,
	upstreamH2 *http2.Layer,
	chain *redialChain,
	dialFresh redialFunc,
	logger *slog.Logger,
) *http2.Layer {
	// Fast path: lock-free read of the active Layer. current.Load() is
	// either nil (no redial yet — use pooled) or points to a Layer that
	// was appended to chain.layers under chain.mu prior to the swap, so
	// readers observing it are guaranteed to see a valid entry.
	active := upstreamH2
	if l := chain.current.Load(); l != nil {
		active = l
	}
	if !isStaleH2(active) {
		return active
	}

	// Slow path: race to fresh-dial the next chain step. The mutex
	// serialises both the re-check and the append+swap, so concurrent
	// streams observing the same stale Layer collapse into a single
	// fresh dial — and at most one per stale step.
	chain.mu.Lock()
	defer chain.mu.Unlock()
	// Re-check under lock — another goroutine may have already swapped in
	// the next chain step while we were spinning on mu.
	active = upstreamH2
	if l := chain.current.Load(); l != nil {
		active = l
	}
	if !isStaleH2(active) {
		return active
	}

	// Generation = number of fresh Layers already appended + 1. The
	// pooled upstreamH2 is implicit chain[0] (generation 0); the first
	// fresh dial is generation 1, the second is generation 2, etc. The
	// connector helper translates generation into the ConnID suffix
	// (`/upstream-redial` for gen 1; `/upstream-redial-N` for gen >= 2).
	nextGen := len(chain.layers) + 1
	fresh, err := dialFresh(dctx, target, active, nextGen)
	if err != nil {
		logger.Warn("proxybuild: upstream h2 redial failed",
			"target", target, "generation", nextGen, "error", err)
		// Return the (stale) active Layer. The caller's OpenStream will
		// surface the underlying ErrorRefused so the session records
		// state=error / failure_reason=refused — the failure mode is
		// then visible to the operator rather than silently swallowed.
		// The failed dial is NOT appended to chain.layers, so the next
		// call retries cleanly.
		return active
	}
	chain.layers = append(chain.layers, fresh)
	chain.current.Store(fresh)
	logger.Debug("proxybuild: upstream h2 redialed after stale-conn detection",
		"target", target, "generation", nextGen)
	return fresh
}

// isStaleH2 returns true when the layer has emitted GOAWAY-close or
// been observed shutdown (USK-796 surfaces). Used by both the fast and
// slow paths of selectUpstreamForDial; the slow path re-checks under
// chain.mu so concurrent stream redials still single-flight.
func isStaleH2(l *http2.Layer) bool {
	return l.GoAwayClosed() || l.IsShutdown()
}

// openStreamFunc is the OpenStream signature, injected so the unit test
// can drive Refused-then-succeed sequences deterministically without
// staging real layer.Shutdown transitions. The production caller uses
// http2OpenStream which adapts (*http2.Layer).OpenStream verbatim.
type openStreamFunc func(ctx context.Context, l *http2.Layer) (layer.Channel, error)

// http2OpenStream is the production binding of openStreamFunc.
func http2OpenStream(ctx context.Context, l *http2.Layer) (layer.Channel, error) {
	return l.OpenStream(ctx)
}

// openUpstreamStreamWithRetry resolves the active upstream Layer via
// selectUpstreamForDial and calls OpenStream on it. When OpenStream
// returns a `*layer.StreamError{Code: ErrorRefused}` (USK-993 residual
// race: the Layer was healthy at selectUpstreamForDial time but
// transitioned to shutdown / GOAWAY before the OpenStream syscall), the
// helper retries exactly once. The retry re-calls selectUpstreamForDial,
// which detects the staleness via isStaleH2 and fresh-dials under
// chain.mu single-flight (so concurrent streams sharing the same race
// converge on a single new Layer).
//
// Retry budget:
//   - Exactly 1 retry per dial closure invocation. If the second attempt
//     also returns Refused (or any other error), the underlying error is
//     returned verbatim — session records state=error / failure_reason=
//     refused, matching the pre-fix observable. The retry budget is
//     stack-local, so it cannot accumulate across requests.
//
// Idempotency:
//   - OpenStream returns ErrorRefused before any HEADERS frame is
//     enqueued (see internal/layer/http2/layer.go:481-498: the three
//     Refused emission sites — "layer shutdown", "GOAWAY sent",
//     "GOAWAY received" — all return before sendHeadersEvent /
//     allocateAndEnqueueFirstHeaders ever runs). No stream_id is
//     allocated; no bytes hit the wire. Retry is byte-for-byte
//     equivalent to a fresh request regardless of HTTP method, so POST/
//     PUT/DELETE etc. are safe (stronger than RFC 9113 §6.8 needs).
//
// Classifier:
//   - We match by Code (layer.ErrorRefused), not by Reason string. All
//     three Refused emission sites are pre-HEADERS races with identical
//     retry-safety; Reason-string matching would be brittle.
//
// Browser parity:
//   - Without the retry, the residual race window between
//     selectUpstreamForDial and OpenStream surfaces as state=error to
//     operators even though zero wire bytes were sent — diagnostic
//     distortion (see CLAUDE.md feedback memory: MITM browser-parity
//     north star). The retry absorbs the failure transparently when a
//     fresh dial succeeds.
func openUpstreamStreamWithRetry(
	dctx context.Context,
	target string,
	upstreamH2 *http2.Layer,
	chain *redialChain,
	dialFresh redialFunc,
	logger *slog.Logger,
) (*http2.Layer, layer.Channel, error) {
	return openUpstreamStreamWithRetryFn(
		dctx, target, upstreamH2, chain, dialFresh, http2OpenStream, logger,
	)
}

// openUpstreamStreamWithRetryFn is the OpenStream-injectable form used
// by tests. Production code calls openUpstreamStreamWithRetry which
// passes http2OpenStream.
func openUpstreamStreamWithRetryFn(
	dctx context.Context,
	target string,
	upstreamH2 *http2.Layer,
	chain *redialChain,
	dialFresh redialFunc,
	openStream openStreamFunc,
	logger *slog.Logger,
) (*http2.Layer, layer.Channel, error) {
	upL := selectUpstreamForDial(dctx, target, upstreamH2, chain, dialFresh, logger)
	upCh, err := openStream(dctx, upL)
	if err == nil {
		return upL, upCh, nil
	}
	if !isRefusedStreamError(err) {
		return nil, nil, err
	}
	// Attempt 1 returned Refused. Retry exactly once. The second
	// selectUpstreamForDial sees the now-stale Layer (the very Refused
	// codes imply shutdown/GOAWAY on upL) and fresh-dials under
	// chain.mu. Concurrent streams hitting the same race converge on
	// the same fresh Layer through chain.current.
	logger.Debug("proxybuild: OpenStream refused, retrying after fresh dial",
		"target", target, "reason", refusedReason(err))
	upL2 := selectUpstreamForDial(dctx, target, upstreamH2, chain, dialFresh, logger)
	upCh2, err2 := openStream(dctx, upL2)
	if err2 != nil {
		return nil, nil, err2
	}
	return upL2, upCh2, nil
}

// isRefusedStreamError reports whether err is a *layer.StreamError whose
// Code is layer.ErrorRefused. Matches all three OpenStream Refused
// emission sites (layer shutdown / GOAWAY sent / GOAWAY received) — all
// pre-HEADERS, so all retry-safe regardless of HTTP method.
func isRefusedStreamError(err error) bool {
	var se *layer.StreamError
	if !errors.As(err, &se) {
		return false
	}
	return se.Code == layer.ErrorRefused
}

// refusedReason returns the Reason field of a refused StreamError for
// logging. Returns the error's string form if Reason is unavailable.
func refusedReason(err error) string {
	var se *layer.StreamError
	if errors.As(err, &se) {
		return se.Reason
	}
	return err.Error()
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
		opts.OnComplete = buildOnCompleteFunc(store, blocked)
		opts.OnPipelineDrop = buildPipelineDropRecorder(store, listenerName, deps.Logger, blocked)
	}
	return opts
}

// buildOnCompleteFunc returns the live data path's terminal session
// finaliser. Extracted from buildSessionOptions to keep both functions
// under the gocyclo threshold (15) — the closure body grew past the
// limit when USK-885 added the StreamReader-driven Duration projection.
//
// Behaviour:
//   - empty streamID → no-op (RunSession exited before any envelope
//     produced a StreamID; nothing to update).
//   - streamID present in `blocked` → audit recorder already finalised
//     the Stream; skip and evict the marker (CWE-400 leak guard).
//   - non-EOF non-nil err → State="error" + FailureReason from
//     session.ClassifyError + Tags["error"]=truncated err string.
//   - everything else → State="complete".
//   - USK-885: Duration = time.Since(Stream.Timestamp) when the Store
//     implements flow.StreamReader and the Stream row exists. Cross-
//     protocol fix; HTTP/1.x, WS, gRPC, SSE all benefit. A nil reader
//     or GetStream miss silently leaves Duration zero so the
//     "non-zero fields only" StreamUpdate semantics still hold.
func buildOnCompleteFunc(store flow.Writer, blocked *blockedStreamSet) func(context.Context, string, error) {
	// USK-885: optional StreamReader so OnComplete can read the Stream's
	// recorded Timestamp. The live production FlowStore is *flow.SQLiteStore
	// (satisfies flow.Store, which embeds StreamReader); test stacks that
	// only implement flow.Writer fall through the type assertion and
	// Duration stays zero. The assertion runs once at build time, not
	// per-Stream.
	streamReader, _ := store.(flow.StreamReader)
	return func(ctx context.Context, streamID string, err error) {
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
		// USK-903: ErrClientGoneAcked is a graceful terminal — the SSE
		// driver detected client TCP close mid-stream (curl --max-time
		// pattern). Project state=complete (matching the H/1.1 EPIPE
		// path symmetry) and stamp tags["terminated_by"]="client" so
		// the wire-observed cancellation is preserved as queryable
		// attribution without inflating the error count.
		clientClosed := err != nil && errors.Is(err, session.ErrClientGoneAcked)
		state := "complete"
		if err != nil && !errors.Is(err, io.EOF) && !clientClosed {
			state = "error"
		}
		update := flow.StreamUpdate{
			State:         state,
			FailureReason: session.ClassifyError(err),
			Duration:      computeStreamDuration(ctx, streamReader, streamID),
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
		// USK-903: stamp the client-cancel attribution tag. Mutually
		// exclusive with tags["error"] above (clientClosed forces
		// state="complete"), so the two cannot collide on the same Stream.
		if clientClosed {
			update.AppendTags = map[string]string{
				"terminated_by": "client",
			}
		}
		_ = store.UpdateStream(ctx, streamID, update)
	}
}

// computeStreamDuration returns time.Since(Stream.Timestamp) for the
// stream identified by streamID, or zero on any lookup failure /
// nil reader / zero Timestamp. The zero return is the documented
// "only non-zero fields are applied" sentinel for StreamUpdate.Duration
// so a miss leaves the Stream's existing Duration untouched. Single
// purpose so the call site in OnComplete stays readable (USK-885).
func computeStreamDuration(ctx context.Context, reader flow.StreamReader, streamID string) time.Duration {
	if reader == nil {
		return 0
	}
	st, err := reader.GetStream(ctx, streamID)
	if err != nil || st == nil || st.Timestamp.IsZero() {
		return 0
	}
	d := time.Since(st.Timestamp)
	if d <= 0 {
		return 0
	}
	return d
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
// envelope as a flow.Stream with State="error" and BlockedBy=<reason>. The
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
		// not abort the audit record.
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

// buildTLSStackBuildErrorRecorder returns a connector.OnUpstreamTLSErrorFunc
// that persists a state="error" Stream when BuildConnectionStack fails
// inside the CONNECT/SOCKS5 TLS MITM path (USK-784, USK-858). Two
// classes of TLS handshake failures land here:
//
//   - upstream-side: proxy → upstream TLS handshake rejection (expired /
//     self-signed / untrusted CA / hostname mismatch). Classified with
//     FailureReason="upstream_tls_error".
//   - client-side: browser → proxy MITM handshake rejection (Chromium
//     pinning, bad CA install, unknown_certificate / bad_certificate /
//     unknown_ca TLS alert). The connector wraps these with
//     connector.ErrClientTLSMITMHandshake; the recorder branches via
//     errors.Is and classifies them with FailureReason="client_tls_error"
//     (USK-858).
//
// Nil store yields a nil callback so the connector's silent-drop path
// engages — preserving behaviour for stacks that opt out of recording.
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
// negotiation finished, so HTTP/1.x vs HTTP/2 is undecidable here. This
// holds for both classification directions — the same data path produced
// both error classes.
//
// FailureReason values are recorder-specific taxonomy entries that
// complement the canonical layer.ErrorCode classes (refused, canceled,
// aborted, internal_error, protocol_error). Those describe wire-observed
// signals on a successfully established channel; a TLS handshake reject
// never produces one. The error string is preserved verbatim in
// Tags["error"] so MCP users can distinguish cert-expired from
// self-signed from CA-untrusted (or pinning-failure from
// unknown_certificate) without parsing FailureReason.
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
func buildTLSStackBuildErrorRecorder(store flow.Writer, scope *flow.RecordScope, listenerName string, logger *slog.Logger) connector.OnUpstreamTLSErrorFunc {
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
					logger.Debug("proxybuild: TLS handshake error out of capture_scope; skipped recording",
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

		// USK-858: classify client-side (browser → proxy) MITM
		// handshake failures separately from upstream-side TLS
		// failures. The connector wraps the former with
		// ErrClientTLSMITMHandshake; everything else is treated as an
		// upstream failure for backward compatibility with USK-784.
		failureReason := "upstream_tls_error"
		if errors.Is(buildErr, connector.ErrClientTLSMITMHandshake) {
			failureReason = "client_tls_error"
		}

		st := &flow.Stream{
			ID:            uuid.New().String(),
			ConnID:        connID,
			Protocol:      string(envelope.ProtocolHTTP),
			Scheme:        "https",
			State:         "error",
			FailureReason: failureReason,
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
		// does not abort the audit record.
		recordCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := store.SaveStream(recordCtx, st); err != nil {
			if logger != nil {
				logger.Error("proxybuild: tls-error stream save failed",
					"listener", listenerName,
					"conn_id", connID,
					"target", target,
					"error", err,
				)
			}
		}
	}
}

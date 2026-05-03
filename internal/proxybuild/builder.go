package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
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

	// MaxConnections overrides connector.DefaultMaxConnections. Zero =
	// default. Negative = unlimited.
	MaxConnections int

	// --- Optional connector policy ---

	// Scope is the per-target capture/pass policy applied to CONNECT and
	// SOCKS5 negotiations. nil = allow all.
	Scope *connector.TargetScope

	// RateLimiter is the per-host rate-limit policy applied to CONNECT
	// and SOCKS5 negotiations. nil = unlimited.
	RateLimiter *connector.RateLimiter

	// PassthroughList lists hosts whose TLS traffic is relayed without
	// MITM (bidirectional io.Copy). nil = no passthrough.
	PassthroughList *connector.PassthroughList

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

	// --- Optional wire encoder registry ---

	// WireEncoderRegistry is shared between PluginStepPost and RecordStep
	// to dedup re-encoding (USK-684). When nil, BuildLiveStack constructs
	// a default registry pre-populated with non-conflicting protocol
	// encoders (ws / grpc / grpc-web / sse). HTTP wire encoder selection
	// is intentionally left to the caller (HTTP/1.x and HTTP/2 both
	// register against envelope.ProtocolHTTP and are mutually exclusive
	// in a single registry; USK-690 owns the production strategy).
	WireEncoderRegistry *pipeline.WireEncoderRegistry

	// --- Optional record options ---

	// RecordMaxBodySize caps the body bytes RecordStep persists. Zero
	// uses the RecordStep default.
	RecordMaxBodySize int64

	// --- Optional manager-level state (consumed by Manager wiring) ---

	// UpstreamProxy is the initial upstream proxy URL. Stored on the
	// stack for read-back via Manager.UpstreamProxy(); not consulted by
	// the live data path until wired by USK-690.
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
	// Safety → PluginPre → Intercept → Transform → PluginPost → Record).
	// Steps with nil engines act as no-ops.
	Pipeline *pipeline.Pipeline

	// PluginV2Engine is the engine wired into the Listener and Pipeline
	// Steps. May be nil.
	PluginV2Engine *pluginv2.Engine

	// WireEncoderRegistry is shared between PluginStepPost and RecordStep
	// to dedup re-encoding (USK-684). May be nil.
	WireEncoderRegistry *pipeline.WireEncoderRegistry

	// HoldQueue receives held envelopes from InterceptStep. May be nil.
	HoldQueue *common.HoldQueue

	// BuildConfig is the per-connection stack-construction configuration
	// passed to connector.BuildConnectionStack inside the per-protocol
	// handlers.
	BuildConfig *connector.BuildConfig
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

	// Select / construct the WireEncoderRegistry. Default registers
	// non-HTTP encoders only (ws/grpc/grpc-web/sse).
	encoders := deps.WireEncoderRegistry
	if encoders == nil {
		encoders = defaultWireEncoderRegistry()
	}

	// Build the canonical Pipeline. Steps tolerate nil dependencies and
	// degrade to no-ops, so the assembly is uniform across configurations.
	p := buildPipeline(deps, encoders, logger)

	// Construct the per-protocol HandlerFunc closures.
	connectHandler := connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
		Negotiator:      connector.NewCONNECTNegotiator(logger),
		BuildCfg:        deps.BuildConfig,
		Scope:           deps.Scope,
		RateLimiter:     deps.RateLimiter,
		PassthroughList: deps.PassthroughList,
		OnStack:         buildOnStack(p, logger),
		OnHTTP2Stack:    buildOnHTTP2Stack(p, logger),
		Logger:          logger,
	})
	socks5Negotiator := connector.NewSOCKS5Negotiator(logger)
	socks5Negotiator.Scope = deps.Scope
	socks5Negotiator.RateLimiter = deps.RateLimiter
	socks5Handler := connector.NewSOCKS5Handler(connector.SOCKS5HandlerConfig{
		Negotiator:      socks5Negotiator,
		BuildCfg:        deps.BuildConfig,
		PassthroughList: deps.PassthroughList,
		OnStack:         buildOnStack(p, logger),
		OnHTTP2Stack:    buildOnHTTP2Stack(p, logger),
		Logger:          logger,
		PluginV2Engine:  deps.PluginV2Engine,
	})

	// proxybuild.Listener wraps the FullListener so it can interpose
	// connection.on_connect / on_disconnect lifecycle hooks. The wrapper
	// is constructed first so wrapHandler can capture it.
	wrapper := &Listener{
		engine: deps.PluginV2Engine,
		name:   listenerName,
		logger: logger,
	}

	flCfg := connector.FullListenerConfig{
		Name:           listenerName,
		Addr:           deps.ListenAddr,
		Logger:         logger,
		PeekTimeout:    deps.PeekTimeout,
		MaxConnections: deps.MaxConnections,
		OnCONNECT:      wrapper.wrapHandler(connectHandler),
		OnSOCKS5:       wrapper.wrapHandler(socks5Handler),
		// HTTP1, HTTP2, TCP handlers are scaffold-deferred. Live
		// production wiring of forward-proxy HTTP and raw TCP belongs
		// to USK-690; CONNECT + SOCKS5 cover the common MITM entry
		// points exercised by integration tests today.
	}
	wrapper.full = connector.NewFullListener(flCfg)

	return &Stack{
		Listener:            wrapper,
		Pipeline:            p,
		PluginV2Engine:      deps.PluginV2Engine,
		WireEncoderRegistry: encoders,
		HoldQueue:           deps.HoldQueue,
		BuildConfig:         deps.BuildConfig,
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

// defaultWireEncoderRegistry returns a registry pre-populated with
// non-conflicting protocol encoders. HTTP encoder selection is intentionally
// omitted; see Deps.WireEncoderRegistry doc for the rationale.
func defaultWireEncoderRegistry() *pipeline.WireEncoderRegistry {
	r := pipeline.NewWireEncoderRegistry()
	r.Register(envelope.ProtocolWebSocket, ws.EncodeWireBytes)
	r.Register(envelope.ProtocolGRPC, grpc.EncodeWireBytes)
	r.Register(envelope.ProtocolGRPCWeb, grpcweb.EncodeWireBytes)
	r.Register(envelope.ProtocolSSE, sse.EncodeWireBytes)
	return r
}

// buildPipeline assembles the canonical 8-step RFC-001 Pipeline. Steps
// tolerate nil engines and degrade to no-ops; no conditional skipping is
// required at assembly time.
func buildPipeline(deps Deps, encoders *pipeline.WireEncoderRegistry, logger *slog.Logger) *pipeline.Pipeline {
	recordOpts := []pipeline.Option{
		pipeline.WithWireEncoderRegistry(encoders),
	}
	if deps.RecordMaxBodySize > 0 {
		recordOpts = append(recordOpts, pipeline.WithMaxBodySize(deps.RecordMaxBodySize))
	}

	return pipeline.New(
		pipeline.NewHostScopeStep(deps.Scope),
		pipeline.NewHTTPScopeStep(deps.Scope),
		pipeline.NewSafetyStep(deps.HTTPSafetyEngine, deps.WSSafetyEngine, deps.GRPCSafetyEngine, logger),
		pipeline.NewPluginStepPre(deps.PluginV2Engine, encoders, logger),
		pipeline.NewInterceptStep(deps.HTTPInterceptEngine, deps.WSInterceptEngine, deps.GRPCInterceptEngine, deps.HoldQueue, logger),
		pipeline.NewTransformStep(deps.HTTPTransformEngine, deps.WSTransformEngine, deps.GRPCTransformEngine),
		pipeline.NewPluginStepPost(deps.PluginV2Engine, encoders, logger),
		pipeline.NewRecordStep(deps.FlowStore, logger, recordOpts...),
	)
}

// buildOnStack returns the OnStackFunc invoked for non-h2 ConnectionStack
// routes. The closure runs the canonical session loop wired to the supplied
// Pipeline. h2 routes are dispatched separately via buildOnHTTP2Stack.
//
// Pattern mirrors the proven recipe in
// internal/connector/full_listener_integration_test.go.
func buildOnStack(p *pipeline.Pipeline, logger *slog.Logger) connector.OnStackFunc {
	return func(ctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, target string) {
		defer stack.Close()
		clientChans := stack.ClientTopmost().Channels()
		clientCh, ok := <-clientChans
		if !ok {
			logger.Debug("proxybuild: client topmost yielded no channels", "target", target)
			return
		}
		dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			ch, ok := <-stack.UpstreamTopmost().Channels()
			if !ok {
				return nil, fmt.Errorf("proxybuild: upstream topmost closed before yielding a channel for %s", target)
			}
			return ch, nil
		}
		session.RunSession(ctx, clientCh, dial, p)
	}
}

// buildOnHTTP2Stack handles the h2 ALPN route. For USK-688 scaffold the
// closure is a no-op stub: HTTP/2 stream dispatch (connector.DispatchH2Stream
// fan-out per stream into Pipeline + RunSession) is wired by USK-690 because
// it depends on the WireEncoderRegistry HTTP-encoder strategy + push recorder
// installation that USK-690 owns. The h2 Layer is still returned to the pool
// by connector.dispatchStack on exit (handler-config-level guarantee), so
// returning early here only means the h2 traffic is not yet recorded.
func buildOnHTTP2Stack(_ *pipeline.Pipeline, logger *slog.Logger) connector.OnHTTP2StackFunc {
	return func(_ context.Context, _ *connector.ConnectionStack, _ *http2.Layer, _, _ *envelope.TLSSnapshot, target string) {
		logger.Debug("proxybuild: h2 OnStack invoked but data path not yet wired (USK-690)", "target", target)
	}
}

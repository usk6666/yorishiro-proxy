package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

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
	// Safety → PluginPre → Intercept → Transform → PluginPost → Record)
	// applied to non-h2 routes (OnStack callback). HTTP wire encoder is
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

	// Construct the per-protocol HandlerFunc closures.
	connectHandler := connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
		Negotiator:      connector.NewCONNECTNegotiator(logger),
		BuildCfg:        deps.BuildConfig,
		Scope:           deps.Scope,
		RateLimiter:     deps.RateLimiter,
		PassthroughList: deps.PassthroughList,
		OnStack:         buildOnStack(p, deps, logger),
		OnHTTP2Stack:    buildOnHTTP2Stack(pH2, deps, logger),
		Logger:          logger,
	})
	socks5Negotiator := connector.NewSOCKS5Negotiator(logger)
	socks5Negotiator.Scope = deps.Scope
	socks5Negotiator.RateLimiter = deps.RateLimiter
	socks5Handler := connector.NewSOCKS5Handler(connector.SOCKS5HandlerConfig{
		Negotiator:      socks5Negotiator,
		BuildCfg:        deps.BuildConfig,
		PassthroughList: deps.PassthroughList,
		OnStack:         buildOnStack(p, deps, logger),
		OnHTTP2Stack:    buildOnHTTP2Stack(pH2, deps, logger),
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
		Listener:              wrapper,
		Pipeline:              p,
		PipelineH2:            pH2,
		PluginV2Engine:        deps.PluginV2Engine,
		WireEncoderRegistry:   encodersH1,
		WireEncoderRegistryH2: encodersH2,
		HoldQueue:             deps.HoldQueue,
		BuildConfig:           deps.BuildConfig,
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
// routes (http1, bytechunk, ws-via-http1-upgrade). The closure runs the
// canonical session loop wired to the supplied Pipeline. The session
// receives SessionOptions carrying the pluginv2.Engine so post-Upgrade
// Layer constructors (runUpgradeWS) attach WithLifecycleEngine /
// WithStateReleaser. h2 routes are dispatched separately via
// buildOnHTTP2Stack.
//
// Pattern mirrors the proven recipe in
// internal/connector/full_listener_integration_test.go.
func buildOnStack(p *pipeline.Pipeline, deps Deps, logger *slog.Logger) connector.OnStackFunc {
	sessOpts := buildSessionOptions(deps)
	return func(ctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, target string) {
		defer stack.Close()
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

// buildOnHTTP2Stack handles the h2 ALPN route. Per the recipe in
// internal/layer/http2/http2_integration_test.go, it iterates the client
// HTTP/2 Layer's Channels(), dispatches each stream through
// connector.DispatchH2StreamWithOpts (so plugin lifecycle hooks reach
// grpc / grpcweb / httpaggregator wrappers), and runs session.RunSession
// per stream against the upstream Layer's OpenStream-issued Channel.
//
// The connector's dispatch path returns the h2 Layer to the HTTP/2 pool on
// exit (handler-config-level guarantee), so this closure must not Close
// upstreamH2; only the per-stream channels and the WaitGroup ordering matter.
func buildOnHTTP2Stack(p *pipeline.Pipeline, deps Deps, logger *slog.Logger) connector.OnHTTP2StackFunc {
	sessOpts := buildSessionOptions(deps)
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
					dial := func(dctx context.Context, _ *envelope.Envelope) (layer.Channel, error) {
						upCh, oerr := upstreamH2.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						return httpaggregator.Wrap(upCh, httpaggregator.RoleClient, nil, upstreamLOpts), nil
					}
					session.RunSession(ctx, aggCh, dial, p, sessOpts)
				}(clientCh)
			}
		}
	}
}

// buildSessionOptions populates the pluginv2-aware SessionOptions consumed
// by post-Upgrade Layer construction (runUpgradeWS). When deps carries no
// PluginV2Engine the returned options leave the lifecycle / releaser
// fields nil, so ws.New runs with no lifecycle wiring (matches the
// pre-USK-690 behavior).
func buildSessionOptions(deps Deps) session.SessionOptions {
	if deps.PluginV2Engine == nil {
		return session.SessionOptions{}
	}
	return session.SessionOptions{
		LifecycleEngine: deps.PluginV2Engine,
		StateReleaser:   deps.PluginV2Engine,
	}
}

package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// Transparent (REDIRECT) listener wiring (USK-1316). See
// connector.TransparentHandler for the per-connection routing.

// transparentSupported reports whether the platform REDIRECT resolver
// works here. A variable so tests can exercise the unsupported-platform
// error on Linux.
var transparentSupported = connector.TransparentSupported

// transparentEnabled validates deps.TransparentMode and reports whether
// the listener is transparent.
func transparentEnabled(deps Deps) (bool, error) {
	switch deps.TransparentMode {
	case "", config.TransparentModeNone:
		return false, nil
	case config.TransparentModeRedirect:
		if deps.OriginalDstResolver == nil && !transparentSupported() {
			return false, fmt.Errorf("proxybuild: transparent_mode %q requires Linux (getsockopt SO_ORIGINAL_DST): %w",
				deps.TransparentMode, errors.ErrUnsupported)
		}
		return true, nil
	default:
		return false, fmt.Errorf("proxybuild: unknown transparent_mode %q", deps.TransparentMode)
	}
}

// transparentModeOf is the Stack / ListenerStatus mode label.
func transparentModeOf(transparent bool) string {
	if transparent {
		return config.TransparentModeRedirect
	}
	return ""
}

// configureTransparentListener turns flCfg into a transparent listener:
// the original-destination resolver plus the transparent handler wrapped
// with the connection.on_connect / on_disconnect hooks. The plain-HTTP
// route runs the listener's non-h2 Pipeline p; the TLS MITM route
// (USK-1317) runs the CONNECT handler's session callbacks — p for HTTP/1
// and raw stacks, pH2 for h2 stacks.
func configureTransparentListener(flCfg *connector.FullListenerConfig, deps Deps, wrapper *Listener, p, pH2 *pipeline.Pipeline, headRecorder requestHeadRecorder, listenerName string, logger *slog.Logger) {
	resolver := deps.OriginalDstResolver
	if resolver == nil {
		resolver = connector.PlatformOriginalDstResolver()
	}
	handler := connector.NewTransparentHandler(connector.TransparentHandlerConfig{
		BuildCfg:    deps.BuildConfig,
		Scope:       deps.Scope,
		LiveConns:   deps.LiveConns,
		RateLimiter: deps.RateLimiter,
		NameBinder:  connector.NewNameBindingCache(deps.NameResolver, connector.NameBindingConfig{}),
		PeekTimeout: deps.TransparentPeekTimeout,
		Observer:    newTransparentRecorder(deps.FlowStore, listenerName, logger, deps.RecordScope),
		OnHTTPStack: buildOnTransparentHTTPStack(p, deps, headRecorder, listenerName, logger),
		// USK-1317: TLS MITM route. The TLS passthrough list is matched
		// against the ClientHello SNI.
		PassthroughList: deps.PassthroughList,
		OnStack:         buildOnStack(p, deps, headRecorder, logger),
		OnHTTP2Stack:    buildOnHTTP2Stack(pH2, deps, logger),
		Logger:          logger,
	})
	flCfg.OriginalDst = resolver
	flCfg.OnTransparent = wrapper.wrapHandler(handler.Handle)
	flCfg.OnCONNECT, flCfg.OnSOCKS5, flCfg.OnHTTP1 = nil, nil, nil
}

// buildOnTransparentHTTPStack runs the HTTP route's [http1 → http1] stack:
// the tcp_forward exchange loop (one upstream leg, no redial chain — a
// retired upstream closes the client), the full Pipeline per request.
func buildOnTransparentHTTPStack(p *pipeline.Pipeline, deps Deps, headRecorder requestHeadRecorder, listenerName string, logger *slog.Logger) func(context.Context, *connector.ConnectionStack, string) {
	sessOpts := buildSessionOptions(deps, listenerName)
	parent := &Stack{BuildConfig: deps.BuildConfig, requestHeadRecorder: headRecorder}
	return func(ctx context.Context, stack *connector.ConnectionStack, target string) {
		defer stack.Close()
		// Close the stack when ctx ends (revoke / shutdown) so reads
		// parked in http1.Channel.Next return.
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
		clientH1, ok := stack.ClientTopmost().(*http1.Layer)
		upstreamH1, ok2 := stack.UpstreamTopmost().(*http1.Layer)
		if !ok || !ok2 {
			logger.Debug("proxybuild: transparent http stack without http1 Layers", "target", target)
			return
		}
		runTCPForwardHTTP1ExchangeLoop(ctx, stack, clientH1, upstreamH1, parent, p, sessOpts, target, logger, nil)
	}
}

// transparentRecorder persists the transparent audit records. It reuses
// the TLS-passthrough audit shape (passthroughRecorder, USK-790): one
// Stream per passthrough connection created active at OnStart, finalised
// at OnComplete together with one metadata-only Flow (passthroughMetadata
// keys plus route, alpn_offers and original_dst). No payload byte is
// ever recorded. Refusals, dial failures and TLS MITM handshake failures
// (client_tls_error / upstream_tls_error, USK-1317) get a self-contained
// error Stream. RecordScope is honoured like the passthrough recorder
// does. MITM'd connections are recorded by the Pipeline's RecordStep.
type transparentRecorder struct {
	store        flow.Writer
	listenerName string
	logger       *slog.Logger
	scope        *flow.RecordScope

	pending sync.Map // observationKey → pendingState
}

// newTransparentRecorder returns the observer; nil store yields nil.
func newTransparentRecorder(store flow.Writer, listenerName string, logger *slog.Logger, scope *flow.RecordScope) connector.TransparentObserver {
	if store == nil {
		return nil
	}
	return &transparentRecorder{store: store, listenerName: listenerName, logger: logger, scope: scope}
}

// transparentProtocol is the Stream protocol / scheme of a route.
func transparentProtocol(route connector.TransparentRoute) (protocol, scheme string) {
	switch route {
	case connector.TransparentRouteTLS:
		return string(envelope.ProtocolTLSHandshake), "https"
	case connector.TransparentRouteLateTLS:
		return string(envelope.ProtocolTLSHandshake), "http"
	case connector.TransparentRouteHTTP:
		return string(envelope.ProtocolHTTP), "http"
	default:
		return string(envelope.ProtocolRaw), "http"
	}
}

func (r *transparentRecorder) filtered(streamID string, obs connector.PassthroughObservation) bool {
	if r.scope == nil || r.scope.IsEmpty() {
		return false
	}
	pr := passthroughRecorder{}
	return !r.scope.ShouldRecord(pr.envelopeForScope(streamID, obs))
}

// OnStart implements connector.TransparentObserver.
func (r *transparentRecorder) OnStart(ctx context.Context, obs connector.TransparentObservation) {
	streamID := uuid.New().String()
	if r.filtered(streamID, obs.PassthroughObservation) {
		return
	}
	protocol, scheme := transparentProtocol(obs.Route)
	st := &flow.Stream{
		ID:        streamID,
		ConnID:    connector.ConnIDFromContext(ctx),
		Protocol:  protocol,
		Scheme:    scheme,
		State:     "active",
		Timestamp: time.Now(),
		Origin:    flow.OriginProxy,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr:    obs.RemoteAddr,
			ServerAddr:    obs.UpstreamAddr,
			UpstreamProxy: obs.UpstreamProxy,
			TLSClientJA3:  obs.ClientJA3,
			TLSClientJA4:  obs.ClientJA4,
		},
		ListenerName: r.listenerName,
		Tags: map[string]string{
			"transparent": "passthrough",
			"route":       string(obs.Route),
			"target":      obs.OriginalDst,
			// USK-1318: kept next to "target" so every transparent
			// Stream (passthrough or MITM) shares one key.
			connector.TagOriginalDst: obs.OriginalDst,
		},
	}
	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.store.SaveStream(saveCtx, st); err != nil {
		r.logger.Error("transparent recorder: stream save failed", "stream_id", streamID, "error", err)
		return
	}
	r.pending.Store(observationKey(obs.PassthroughObservation), pendingState{streamID: streamID, started: time.Now()})
}

// OnComplete implements connector.TransparentObserver.
func (r *transparentRecorder) OnComplete(_ context.Context, obs connector.TransparentObservation) {
	raw, ok := r.pending.LoadAndDelete(observationKey(obs.PassthroughObservation))
	if !ok {
		return
	}
	state, _ := raw.(pendingState)
	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	upd := flow.StreamUpdate{State: "complete", Duration: time.Since(state.started)}
	if obs.Outcome == envelope.TLSHandshakeOutcomeFailed {
		upd.State = "error"
		upd.FailureReason = "passthrough_relay_error"
	}
	if obs.Route == connector.TransparentRouteLateTLS {
		upd.Protocol = string(envelope.ProtocolTLSHandshake)
		upd.AppendTags = map[string]string{"route": string(obs.Route)}
		upd.TLSClientJA3, upd.TLSClientJA4 = obs.ClientJA3, obs.ClientJA4
	}
	if obs.BlockedBy != "" {
		// Refused mid-relay (a late ClientHello's denied SNI): recorded
		// like a pre-dial refusal (BlockedBy / FailureReason
		// target_scope, the detail in the "reason" tag).
		upd.State = "error"
		upd.BlockedBy = obs.BlockedBy
		upd.FailureReason = connector.TransparentFailureScope
		if upd.AppendTags == nil {
			upd.AppendTags = map[string]string{}
		}
		if obs.BlockReason != "" {
			upd.AppendTags["reason"] = obs.BlockReason
		}
		if obs.SNI != "" {
			upd.AppendTags["name"] = obs.SNI
		}
	}
	if err := r.store.UpdateStream(saveCtx, state.streamID, upd); err != nil {
		r.logger.Error("transparent recorder: stream finalise failed", "stream_id", state.streamID, "error", err)
	}
	fl := &flow.Flow{
		ID:        uuid.New().String(),
		StreamID:  state.streamID,
		Direction: "send",
		Timestamp: time.Now(),
		Metadata:  transparentMetadata(obs),
	}
	if err := r.store.SaveFlow(saveCtx, fl); err != nil {
		r.logger.Error("transparent recorder: flow save failed", "stream_id", state.streamID, "error", err)
	}
}

// OnBlocked implements connector.TransparentObserver: a refused
// connection (BlockedBy target_scope or rate_limit — USK-1374: the
// denial's rate_limit_* tags merged in), a failed upstream dial, or a
// failed TLS MITM handshake (USK-1317: the SNI as "name", the error as
// "error", the client's JA3 / JA4 on ConnInfo). No upstream socket was
// handed to a Layer, so ServerAddr stays empty.
func (r *transparentRecorder) OnBlocked(ctx context.Context, b connector.TransparentBlock) {
	streamID := uuid.New().String()
	obs := connector.PassthroughObservation{RemoteAddr: b.RemoteAddr, TargetHost: hostOfAddr(b.OriginalDst)}
	if b.Route == connector.TransparentRouteTLS {
		obs.SNI = b.Name
	}
	if r.filtered(streamID, obs) {
		return
	}
	protocol, scheme := transparentProtocol(b.Route)
	tags := map[string]string{
		"via":                    "transparent",
		"route":                  string(b.Route),
		"target":                 b.OriginalDst,
		connector.TagOriginalDst: b.OriginalDst,
	}
	if b.Reason != "" {
		tags["reason"] = b.Reason
	}
	if b.Name != "" {
		tags["name"] = b.Name
	}
	if b.Error != "" {
		tags["error"] = b.Error
	}
	for k, v := range b.Tags {
		tags[k] = v
	}
	st := &flow.Stream{
		ID:            streamID,
		ConnID:        connector.ConnIDFromContext(ctx),
		Protocol:      protocol,
		Scheme:        scheme,
		State:         "error",
		FailureReason: b.FailureReason,
		BlockedBy:     b.BlockedBy,
		Timestamp:     time.Now(),
		Origin:        flow.OriginProxy,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr:   b.RemoteAddr,
			TLSClientJA3: b.ClientJA3,
			TLSClientJA4: b.ClientJA4,
		},
		ListenerName: r.listenerName,
		Tags:         tags,
	}
	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.store.SaveStream(saveCtx, st); err != nil {
		r.logger.Error("transparent recorder: audit stream save failed", "stream_id", streamID, "error", err)
	}
}

// hostOfAddr returns the host of "host:port".
func hostOfAddr(hp string) string {
	if i := strings.LastIndexByte(hp, ':'); i > 0 {
		return strings.TrimSuffix(strings.TrimPrefix(hp[:i], "["), "]")
	}
	return hp
}

// transparentMetadata is the passthrough Flow metadata plus the
// transparent fields.
func transparentMetadata(obs connector.TransparentObservation) map[string]string {
	m := passthroughMetadata(obs.PassthroughObservation)
	protocol, _ := transparentProtocol(obs.Route)
	m["protocol"] = protocol
	m["route"] = string(obs.Route)
	m["original_dst"] = obs.OriginalDst
	if len(obs.ALPN) > 0 {
		m["alpn_offers"] = strings.Join(obs.ALPN, ",")
	}
	return m
}

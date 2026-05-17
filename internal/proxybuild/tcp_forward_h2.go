package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// handleTCPForwardH2Conn is the per-accepted-connection handler for
// ForwardConfig.Protocol="http2" and "grpc" (USK-914). It dials upstream
// plain TCP, assembles an h2c ConnectionStack via
// connector.BuildConnectionStackWithTarget (HTTP2 / GRPC arm), and runs
// the per-stream dispatch loop against the assembled client + upstream
// HTTP/2 Layers.
//
// Sibling of handleTCPForwardConn (raw bytechunk path, tcp_forward.go).
// Kept in this file so the h2-specific concerns (per-stream goroutines,
// DispatchH2StreamFull wiring, gRPC content-type filter) stay isolated
// from the raw forward path's per-connection session loop.
//
// Lifecycle:
//   - Dial → BuildConnectionStackWithTarget HTTP2/GRPC arm → stack.Close
//     deferred.
//   - ctx-cancellation watcher closes the stack so per-stream goroutines
//     parked in conn.Read are unblocked when the listener shuts down.
//     Pattern mirrors handleTCPForwardConn.
//   - runTCPForwardH2Loop waits for every per-stream goroutine via a
//     sync.WaitGroup before returning.
func (m *Manager) handleTCPForwardH2Conn(
	ctx context.Context,
	parentListenerName string,
	entry *tcpForwardEntry,
	fc *config.ForwardConfig,
	clientConn net.Conn,
) {
	m.handleTCPForwardH2ConnWithOverride(ctx, parentListenerName, entry, fc, nil, clientConn)
}

// handleTCPForwardH2ConnWithOverride is the override-aware extension of
// handleTCPForwardH2Conn (USK-915). The TLS terminate handler calls this
// with a non-nil override carrying the negotiated TLS snapshot; every
// other caller passes nil.
func (m *Manager) handleTCPForwardH2ConnWithOverride(
	ctx context.Context,
	parentListenerName string,
	entry *tcpForwardEntry,
	fc *config.ForwardConfig,
	override *forwardConnOverride,
	clientConn net.Conn,
) {
	defer clientConn.Close()

	connID := connector.GenerateConnID()
	clientAddr := clientConn.RemoteAddr().String()
	connLogger := m.logger.With(
		"conn_id", connID,
		"remote_addr", clientAddr,
		"name", parentListenerName,
		"port", entry.port,
		"target", entry.target,
		"protocol", fc.Protocol,
		"via", "tcp-forward-h2",
	)

	connCtx := connector.ContextWithConnID(ctx, connID)
	connCtx = connector.ContextWithClientAddr(connCtx, clientAddr)
	connCtx = connector.ContextWithListenerName(connCtx, parentListenerName)
	connCtx = connector.ContextWithLogger(connCtx, connLogger)
	connCtx = connector.ContextWithForwardTarget(connCtx, entry.target)

	parentStack := m.Stack(parentListenerName)
	if parentStack == nil {
		connLogger.Debug("tcp forward h2 parent listener no longer running; dropping connection")
		return
	}

	// Dial upstream. USK-916: dialForwardUpstream additionally performs
	// an upstream TLS handshake when entry.fc.UpstreamTLS=true. When
	// fc.UpstreamTLS=false the dial is plain TCP (h2c). When true the
	// upstream Layer reads h2 over TLS — equivalent to the "https+h2c
	// upstream" combination on the live MITM path (the proxy speaks h2
	// over TLS on the wire; the http2.Layer is protocol-agnostic and
	// reads frames identically regardless of the underlying transport).
	upstreamConn, upstreamSnap, derr := dialForwardUpstream(connCtx, entry, override, parentStack, connLogger)
	if derr != nil {
		connLogger.Debug("tcp forward h2 upstream dial failed", "error", derr)
		// USK-916: TLS-dial failures should produce a state="error" Stream
		// so MCP query("flows", filter:{state:"error"}) surfaces them.
		if entry.fc != nil && entry.fc.UpstreamTLS {
			if rec := buildTLSStackBuildErrorRecorder(parentStack.FlowStore, nil, parentListenerName, connLogger); rec != nil {
				rec(connCtx, entry.target, derr)
			}
		}
		return
	}

	fwdProto, ok := mapH2ForwardProtocol(fc.Protocol)
	if !ok {
		_ = upstreamConn.Close()
		connLogger.Warn("tcp forward h2 dispatched with unexpected protocol", "protocol", fc.Protocol)
		return
	}

	targetParams := buildH2TargetParams(entry, override, fwdProto, upstreamSnap)
	stack, berr := connector.BuildConnectionStackWithTarget(connCtx, clientConn, upstreamConn, targetParams, parentStack.BuildConfig)
	if berr != nil {
		connLogger.Debug("tcp forward h2 stack build failed", "error", berr)
		// BuildConnectionStackWithTarget closes both conns on construction
		// failure; no additional close needed here.
		return
	}
	defer stack.Close()

	// ctx-cancellation watcher. Pattern mirrors handleTCPForwardConn.
	doneCh := make(chan struct{})
	var watcherWG sync.WaitGroup
	watcherWG.Add(1)
	go func() {
		defer watcherWG.Done()
		select {
		case <-connCtx.Done():
			_ = stack.Close()
		case <-doneCh:
		}
	}()
	defer func() {
		close(doneCh)
		watcherWG.Wait()
	}()

	isGRPCFilter := fwdProto == connector.ForwardProtocolGRPC
	runTCPForwardH2Loop(connCtx, parentStack, stack, entry.target, connLogger, isGRPCFilter)
}

// mapH2ForwardProtocol translates a ForwardConfig.Protocol value into a
// connector.ForwardProtocol selector for the h2 dispatch arm. Returns
// (selector, true) for "http2" / "grpc" and (_, false) otherwise; the
// caller is expected to log and bail on false (defensive guard — the
// listener-start switch already rejects other values before reaching
// this dispatcher).
func mapH2ForwardProtocol(protocol string) (connector.ForwardProtocol, bool) {
	switch protocol {
	case "http2":
		return connector.ForwardProtocolHTTP2, true
	case "grpc":
		return connector.ForwardProtocolGRPC, true
	default:
		return "", false
	}
}

// buildH2TargetParams assembles the TargetOverrideParams for the h2
// forward stack assembly. Stamps Scheme="https" + ClientTLSSnapshot from
// the USK-915 client-side TLS terminate override, and UpstreamTLSSnapshot
// from the USK-916 upstream TLS dial result, when present.
func buildH2TargetParams(
	entry *tcpForwardEntry,
	override *forwardConnOverride,
	fwdProto connector.ForwardProtocol,
	upstreamSnap *envelope.TLSSnapshot,
) connector.TargetOverrideParams {
	params := connector.TargetOverrideParams{
		Target:   entry.target,
		Protocol: fwdProto,
	}
	// USK-915: when TLS was terminated upstream of this handler, stamp the
	// envelope Scheme as "https" and forward the client TLS snapshot so
	// recordings and plugin payloads reflect wire reality.
	if override != nil && override.tlsTerminated {
		params.Scheme = "https"
		params.ClientTLSSnapshot = override.clientTLSSnapshot
	}
	// USK-916: when an upstream TLS handshake completed, thread the snapshot
	// into the upstream Layer's EnvelopeContext.TLS via the builder.
	if entry.fc != nil && entry.fc.UpstreamTLS && upstreamSnap != nil {
		params.UpstreamTLS = true
		params.UpstreamTLSSnapshot = upstreamSnap
	}
	return params
}

// runTCPForwardH2Loop iterates the client HTTP/2 Layer's Channels()
// (one per stream) and spawns one goroutine per stream running the
// session loop against the upstream HTTP/2 Layer via OpenStream.
//
// Modelled on buildOnHTTP2Stack (the CONNECT-routed h2 dispatcher) with
// these adjustments:
//
//   - Upstream is dialed per-conn (no h2_pool integration — forward
//     dials fresh per accepted client TCP conn by design).
//   - No redial machinery (pool staleness is a MITM-only concern).
//   - When isGRPCFilter is true, the first envelope of each stream is
//     peeked and its content-type validated; non-gRPC streams are
//     refused with RST_STREAM(REFUSED_STREAM) and a state="error" Stream
//     is recorded with Tags["forward_protocol_mismatch"]=
//     "non_grpc_under_grpc_filter".
//
// Per-stream wire-record callbacks mirror buildOnHTTP2Stack so recording
// parity is preserved (h2-frame, grpc-lpm-frame, grpc-h2-frame,
// grpc-web-base64).
func runTCPForwardH2Loop(
	ctx context.Context,
	parentStack *Stack,
	stack *connector.ConnectionStack,
	target string,
	logger *slog.Logger,
	isGRPCFilter bool,
) {
	clientL, ok := stack.ClientTopmost().(*http2.Layer)
	if !ok {
		logger.Debug("tcp forward h2: client topmost is not *http2.Layer",
			"target", target, "type", fmt.Sprintf("%T", stack.ClientTopmost()))
		return
	}
	upstreamH2, ok := stack.UpstreamTopmost().(*http2.Layer)
	if !ok {
		logger.Debug("tcp forward h2: upstream topmost is not *http2.Layer",
			"target", target, "type", fmt.Sprintf("%T", stack.UpstreamTopmost()))
		return
	}

	sessOpts := tcpForwardH2SessionOpts(parentStack, ctx, logger)
	grpcOpts := connector.GRPCOptionsFromBuildConfig(parentStack.BuildConfig)
	grpcwebOpts := connector.GRPCWebOptionsFromBuildConfig(parentStack.BuildConfig)
	clientLOpts := httpaggregator.OptionsFromLayer(clientL)
	clientLOpts.StateReleaser = parentStack.PluginV2Engine
	upstreamLOpts := httpaggregator.OptionsFromLayer(upstreamH2)
	upstreamLOpts.StateReleaser = parentStack.PluginV2Engine

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case clientCh, alive := <-clientL.Channels():
			if !alive {
				wg.Wait()
				return
			}
			wg.Add(1)
			go func(ch layer.Channel) {
				defer wg.Done()
				dispatchForwardH2Stream(
					ctx, parentStack, stack, ch, upstreamH2,
					target, logger, isGRPCFilter,
					sessOpts, clientLOpts, upstreamLOpts,
					grpcOpts, grpcwebOpts,
				)
			}(clientCh)
		}
	}
}

// dispatchForwardH2Stream runs the per-stream dispatch + session loop.
// Split from runTCPForwardH2Loop so the parent stays under the gocyclo
// threshold and the per-stream callback wiring is readable.
func dispatchForwardH2Stream(
	ctx context.Context,
	parentStack *Stack,
	stack *connector.ConnectionStack,
	ch layer.Channel,
	upstreamH2 *http2.Layer,
	target string,
	logger *slog.Logger,
	isGRPCFilter bool,
	sessOpts session.SessionOptions,
	clientLOpts httpaggregator.WrapOptions,
	upstreamLOpts httpaggregator.WrapOptions,
	grpcOpts []grpclayer.Option,
	grpcwebOpts []grpcweb.Option,
) {
	p := parentStack.PipelineH2
	streamFlowCtx := envelope.EnvelopeContext{ConnID: stack.ConnID, TargetHost: target}

	// gRPC content-type filter (Protocol="grpc" only). Must run BEFORE
	// DispatchH2StreamFull, which consumes the first envelope. The filter
	// peeks the first envelope, validates content-type, and either:
	//   - rejects non-gRPC (RST_STREAM(REFUSED_STREAM) + error Stream)
	//   - re-feeds gRPC envelopes via a small replay wrapper
	dispatchCh := ch
	if isGRPCFilter {
		filtered, ok := applyGRPCFilter(ctx, ch, parentStack, target, stack.ConnID, logger)
		if !ok {
			return
		}
		dispatchCh = filtered
	}

	// Per-stream wire-record callbacks (matches buildOnHTTP2Stack).
	lpmOpt := session.GRPCLPMRecordOption(ctx, p, ch.StreamID(), streamFlowCtx)
	grpcH2FrameOpt := session.GRPCH2DataFrameRecordOption(ctx, p, ch.StreamID(), streamFlowCtx)
	streamGRPCOpts := make([]grpclayer.Option, 0, len(grpcOpts)+2)
	streamGRPCOpts = append(streamGRPCOpts, grpcOpts...)
	streamGRPCOpts = append(streamGRPCOpts, lpmOpt, grpcH2FrameOpt)

	aggH2FrameOpt := session.AggregatorH2FrameRecordOption(ctx, p, ch.StreamID(), streamFlowCtx)
	streamAggOpts := []httpaggregator.WrapOption{aggH2FrameOpt}

	grpcWebBase64Opt := session.GRPCWebBase64RecordOption(ctx, p, ch.StreamID(), streamFlowCtx)
	streamGRPCWebOpts := make([]grpcweb.Option, 0, len(grpcwebOpts)+1)
	streamGRPCWebOpts = append(streamGRPCWebOpts, grpcwebOpts...)
	streamGRPCWebOpts = append(streamGRPCWebOpts, grpcWebBase64Opt)

	aggCh, derr := connector.DispatchH2StreamFull(
		ctx, dispatchCh, httpaggregator.RoleServer,
		clientLOpts, logger, streamGRPCOpts, streamGRPCWebOpts, streamAggOpts,
	)
	if derr != nil {
		logger.Debug("tcp forward h2 dispatch failed",
			"target", target, "stream_id", ch.StreamID(), "error", derr)
		_ = ch.Close()
		return
	}

	dial := func(dctx context.Context, env *envelope.Envelope) (layer.Channel, error) {
		upCh, oerr := upstreamH2.OpenStream(dctx)
		if oerr != nil {
			return nil, oerr
		}
		var reqProto envelope.Protocol
		if env != nil {
			reqProto = env.Protocol
		}
		return connector.WrapH2UpstreamForDispatchFull(
			upCh, reqProto, upstreamLOpts, streamGRPCOpts, streamGRPCWebOpts, streamAggOpts,
		), nil
	}

	if err := session.RunStackSessionExchange(ctx, stack, aggCh, dial, p, sessOpts); err != nil &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		logger.Debug("tcp forward h2 stream exchange ended with error",
			"target", target, "stream_id", ch.StreamID(), "error", err)
	}
}

// applyGRPCFilter implements the Protocol="grpc" content-type filter on
// the first envelope of an h2 stream. Returns (filtered-channel, true)
// when the stream is gRPC-eligible — the returned Channel replays the
// peeked first envelope so DispatchH2StreamFull's own peek succeeds.
// Returns (nil, false) when the stream is rejected (RST_STREAM emitted,
// error Stream recorded); the caller should return without further work.
//
// Reject criteria (rejected → state="error" Stream with
// Tags["forward_protocol_mismatch"]="non_grpc_under_grpc_filter"):
//   - first envelope is not an H2HeadersEvent (malformed stream)
//   - content-type is missing
//   - content-type matches grpc-web (rejected — Protocol="grpc" is a
//     crisper semantic; gRPC-Web routes via Protocol="http2"). The
//     audit Stream stamps Protocol="grpc-web" so MCP queries by Protocol
//     can find the rejection without the tag scan.
//   - content-type is not native gRPC (application/grpc[+suffix]). Audit
//     Stream stamps Protocol="grpc" (the configured forward protocol —
//     the actual content-type may not map to any known Protocol).
func applyGRPCFilter(
	ctx context.Context,
	ch layer.Channel,
	parentStack *Stack,
	target string,
	connID string,
	logger *slog.Logger,
) (layer.Channel, bool) {
	firstEnv, err := ch.Next(ctx)
	if err != nil {
		logger.Debug("tcp forward grpc filter: peek failed",
			"target", target, "stream_id", ch.StreamID(), "error", err)
		_ = ch.Close()
		return nil, false
	}
	evt, ok := firstEnv.Message.(*http2.H2HeadersEvent)
	if !ok {
		logger.Debug("tcp forward grpc filter: first envelope is not H2HeadersEvent",
			"target", target, "stream_id", ch.StreamID(), "type", fmt.Sprintf("%T", firstEnv.Message))
		recordGRPCFilterReject(ctx, parentStack, ch.StreamID(), connID, "grpc", "non_grpc_under_grpc_filter")
		rejectGRPCStream(ch)
		return nil, false
	}
	ct := connector.ExtractH2ContentType(evt)
	if grpcweb.IsGRPCWebContentType(ct) {
		logger.Debug("tcp forward grpc filter: rejected grpc-web under Protocol=grpc",
			"target", target, "stream_id", ch.StreamID(), "content_type", ct)
		// USK-914 review F-2: record the observed wire protocol on the
		// audit Stream so Protocol-filtered MCP queries surface the
		// distinction. The forward_protocol_mismatch tag stays identical
		// so the meta-class is one queryable label.
		recordGRPCFilterReject(ctx, parentStack, ch.StreamID(), connID, "grpc-web", "non_grpc_under_grpc_filter")
		rejectGRPCStream(ch)
		return nil, false
	}
	if !connector.IsGRPCContentType(ct) {
		logger.Debug("tcp forward grpc filter: rejected non-gRPC content-type",
			"target", target, "stream_id", ch.StreamID(), "content_type", ct)
		recordGRPCFilterReject(ctx, parentStack, ch.StreamID(), connID, "grpc", "non_grpc_under_grpc_filter")
		rejectGRPCStream(ch)
		return nil, false
	}
	return newReplayChannel(ch, firstEnv), true
}

// rejectGRPCStream emits RST_STREAM(REFUSED_STREAM) on the client
// channel when the underlying type supports the explicit termination
// API; falls back to a plain Close otherwise.
func rejectGRPCStream(ch layer.Channel) {
	type rstCloser interface {
		MarkTerminatedWithRST(code uint32, err error)
	}
	if rc, ok := ch.(rstCloser); ok {
		rc.MarkTerminatedWithRST(http2.ErrCodeRefusedStream,
			errors.New("tcp forward grpc filter: non-gRPC content-type rejected"))
		return
	}
	_ = ch.Close()
}

// recordGRPCFilterReject records a state="error" Stream for a stream
// rejected by the gRPC content-type filter. The Stream is tagged with
// forward_protocol_mismatch so MCP queries can surface the rejection
// without grovelling through Flow rows. observedProtocol distinguishes
// the wire-observed Protocol family (e.g. "grpc-web" when the client
// sent grpc-web under a Protocol="grpc" forward; "grpc" when the
// content-type matched none of the gRPC families).
func recordGRPCFilterReject(
	ctx context.Context,
	parentStack *Stack,
	streamID string,
	connID string,
	observedProtocol string,
	mismatchKind string,
) {
	if parentStack == nil || parentStack.FlowStore == nil || streamID == "" {
		return
	}
	if observedProtocol == "" {
		observedProtocol = "grpc"
	}
	st := &flow.Stream{
		ID:       streamID,
		ConnID:   connID,
		Protocol: observedProtocol,
		State:    "error",
	}
	_ = parentStack.FlowStore.SaveStream(ctx, st)
	_ = parentStack.FlowStore.UpdateStream(ctx, streamID, flow.StreamUpdate{
		State:         "error",
		FailureReason: "forward_protocol_mismatch",
		AppendTags: map[string]string{
			"forward_protocol_mismatch": mismatchKind,
		},
	})
}

// tcpForwardH2SessionOpts builds session.SessionOptions for an h2 TCP
// forward session. Sibling of tcpForwardSessionOpts (raw path); kept
// here so the h2 dispatch file is the single touch-point for h2-specific
// concerns.
//
// OnComplete behaviour mirrors the raw sibling — listener-shutdown
// (ctx-cancel) classifies state="complete" so a forward listener stop
// mid-stream does not flag every active stream as state="error".
//
// OnPipelineDrop wiring mirrors the raw sibling (USK-782): the parent
// Stack's PipelineH2 includes scope / safety / intercept Steps that may
// emit a BlockedBy attribution against forwarded h2 traffic. Without
// this hook, blocked envelopes would never produce an audit Stream and
// MCP queries could not surface the rejection. The `blocked` set is
// shared between OnPipelineDrop and OnComplete so the latter does not
// overwrite a `State="error"+BlockedBy=*` audit row with `State="complete"`.
func tcpForwardH2SessionOpts(parent *Stack, connCtx context.Context, logger *slog.Logger) session.SessionOptions {
	opts := session.SessionOptions{}
	if parent == nil {
		return opts
	}
	if parent.PluginV2Engine != nil {
		opts.LifecycleEngine = parent.PluginV2Engine
		opts.StateReleaser = parent.PluginV2Engine
		opts.PluginEngine = parent.PluginV2Engine
	}
	if parent.FlowStore != nil {
		store := parent.FlowStore
		blocked := newBlockedStreamSet()
		opts.OnComplete = func(ctx context.Context, streamID string, err error) {
			if streamID == "" {
				return
			}
			if blocked.contains(streamID) {
				// USK-782: skip terminal-state finalisation for streams
				// already finalised by the audit recorder. Without this
				// the normal-EOF state="complete" overwrite would clobber
				// the BlockedBy attribution. Evict for consistency with
				// the raw sibling and the live-path recorder.
				blocked.remove(streamID)
				return
			}
			state := "complete"
			if err != nil && !errors.Is(err, io.EOF) {
				if (errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)) && connCtx.Err() != nil {
					// Listener-shutdown path: keep state="complete".
				} else {
					state = "error"
				}
			}
			_ = store.UpdateStream(ctx, streamID, flow.StreamUpdate{
				State:         state,
				FailureReason: session.ClassifyError(err),
			})
		}
		// USK-782 parity: persist Pipeline-Drop audit Streams for the h2
		// forward session as well. The empty listenerName falls through
		// to DefaultListenerName inside buildPipelineDropRecorder —
		// forward listeners do not own a top-level listenerName the way
		// the live-path Deps do, so DefaultListenerName matches the raw
		// forward sibling's behaviour.
		opts.OnPipelineDrop = buildPipelineDropRecorder(store, "", logger, blocked)
	}
	return opts
}

// replayChannel wraps a layer.Channel and replays a single pre-peeked
// envelope on the first Next call. Used by the gRPC content-type filter
// path: we must peek the first envelope to inspect content-type, then
// hand the channel to DispatchH2StreamFull which itself calls Next.
//
// The wrapper is single-use: after the first Next returns the replayed
// envelope, subsequent Next/Send/Close/Closed/Err calls delegate to the
// wrapped channel verbatim.
type replayChannel struct {
	inner     layer.Channel
	first     *envelope.Envelope
	consumed  bool
	consumeMu sync.Mutex
}

func newReplayChannel(inner layer.Channel, first *envelope.Envelope) *replayChannel {
	return &replayChannel{inner: inner, first: first}
}

func (r *replayChannel) StreamID() string { return r.inner.StreamID() }

func (r *replayChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	r.consumeMu.Lock()
	if !r.consumed {
		r.consumed = true
		env := r.first
		r.first = nil
		r.consumeMu.Unlock()
		return env, nil
	}
	r.consumeMu.Unlock()
	return r.inner.Next(ctx)
}

func (r *replayChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	return r.inner.Send(ctx, env)
}

func (r *replayChannel) Close() error            { return r.inner.Close() }
func (r *replayChannel) Closed() <-chan struct{} { return r.inner.Closed() }
func (r *replayChannel) Err() error              { return r.inner.Err() }

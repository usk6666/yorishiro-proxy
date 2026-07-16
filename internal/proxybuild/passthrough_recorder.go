package proxybuild

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// passthroughRecorder is the connector.PassthroughObserver implementation
// proxybuild attaches to CONNECT and SOCKS5 handlers so every TLS
// passthrough connection produces a TLSHandshakeMessage audit flow
// (USK-790).
//
// Lifecycle:
//   - OnStart: persist a flow.Stream (state="active",
//     protocol="tls-handshake", scheme="https") so MCP query consumers
//     see in-flight passthrough connections immediately rather than
//     waiting for the relay to close. No Flow row is written here — the
//     observed surface is the same single-shot meta event recorded at
//     OnComplete and writing a partial flow up-front would either need
//     a separate FlowID (mismatch with the final record) or a re-save
//     (the SQLite store's SaveFlow is INSERT-only).
//   - OnComplete: finalise the Stream (state="complete" or "error",
//     duration) and write a single send-direction Flow carrying the SNI,
//     4-tuple, byte counters, and outcome. The Flow row is the audit
//     payload; the Stream row is the pointer that MCP query("flows")
//     paginates on.
//
// recordScope is consulted on OnStart so capture-scope filters apply
// uniformly to passthrough audit flows just like to MITM-recorded HTTP /
// WS / gRPC flows. When the scope filters out a stream, OnStart returns
// early without writing a Stream and OnComplete finds no Stream to
// finalise — both calls degrade gracefully to no-ops.
type passthroughRecorder struct {
	store        flow.Writer
	listenerName string
	logger       *slog.Logger
	scope        *flow.RecordScope

	// pending correlates OnStart-issued StreamIDs with OnComplete events
	// keyed by the observation's (LocalAddr, RemoteAddr, UpstreamAddr)
	// triple. The connector invokes OnStart and OnComplete on the same
	// goroutine per connection, but callers could in principle wrap the
	// observer; the sync.Map keeps the recorder safe under arbitrary
	// call sites.
	pending sync.Map
}

// newPassthroughRecorder returns a PassthroughObserver that persists a
// TLSHandshakeMessage audit flow per passthrough relay. nil store yields
// nil so the connector's no-observer hot path stays in place.
func newPassthroughRecorder(store flow.Writer, listenerName string, logger *slog.Logger, scope *flow.RecordScope) connector.PassthroughObserver {
	if store == nil {
		return nil
	}
	if listenerName == "" {
		listenerName = DefaultListenerName
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &passthroughRecorder{
		store:        store,
		listenerName: listenerName,
		logger:       logger,
		scope:        scope,
	}
}

// pendingState holds the per-connection state OnStart records and
// OnComplete reads.
type pendingState struct {
	streamID string
	started  time.Time
}

// observationKey builds a stable string key from the observation surface
// captured at OnStart. The combination of LocalAddr + RemoteAddr +
// UpstreamAddr is unique for a given connection because both ends'
// addresses include the OS-assigned ephemeral port (the local-side port
// is unique on the proxy and the remote-side port is unique on the
// client).
func observationKey(obs connector.PassthroughObservation) string {
	return obs.LocalAddr + "|" + obs.RemoteAddr + "|" + obs.UpstreamAddr
}

// OnStart implements connector.PassthroughObserver. It writes the
// state="active" Stream row and stamps the per-connection state into
// pending so OnComplete can locate the row to update.
func (r *passthroughRecorder) OnStart(ctx context.Context, obs connector.PassthroughObservation) {
	streamID := uuid.New().String()

	if r.scope != nil && !r.scope.IsEmpty() {
		env := r.envelopeForScope(streamID, obs)
		if !r.scope.ShouldRecord(env) {
			r.logger.DebugContext(ctx, "passthrough audit flow filtered by record scope",
				"listener", r.listenerName, "stream_id", streamID,
				"sni", obs.SNI, "upstream", obs.UpstreamAddr,
			)
			return
		}
	}

	st := &flow.Stream{
		ID:        streamID,
		ConnID:    connector.ConnIDFromContext(ctx),
		Protocol:  string(envelope.ProtocolTLSHandshake),
		Scheme:    "https",
		State:     "active",
		Timestamp: time.Now(),
		Origin:    flow.OriginProxy,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: obs.RemoteAddr,
			ServerAddr: obs.UpstreamAddr,
		},
	}

	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.store.SaveStream(saveCtx, st); err != nil {
		r.logger.Error("passthrough recorder: stream save failed",
			"listener", r.listenerName,
			"stream_id", streamID,
			"sni", obs.SNI,
			"upstream", obs.UpstreamAddr,
			"error", err,
		)
		return
	}

	r.pending.Store(observationKey(obs), pendingState{streamID: streamID, started: time.Now()})
}

// OnComplete implements connector.PassthroughObserver. It finalises the
// Stream's state and writes the meta Flow with the final byte counters
// and outcome.
func (r *passthroughRecorder) OnComplete(ctx context.Context, obs connector.PassthroughObservation) {
	key := observationKey(obs)
	rawState, ok := r.pending.LoadAndDelete(key)

	switch {
	case ok:
		state, _ := rawState.(pendingState)
		r.finalisePending(ctx, state, obs)
	case obs.UpstreamAddr == "" && obs.Outcome == envelope.TLSHandshakeOutcomeFailed:
		// Upstream dial failed before OnStart could fire. Persist a
		// self-contained state="error" Stream + Flow so the operator
		// still gets an audit trail of the failed contact attempt.
		r.recordDialFailure(ctx, obs)
	default:
		// OnStart was filtered by the record scope or never fired for
		// some other reason (defensive). Nothing to record.
	}
}

// finalisePending updates the active Stream row to its terminal state and
// writes the single audit Flow row with the final byte counters and
// outcome. Two store calls; both run under a fresh background-derived
// context so a cancelled relay context does not torpedo the audit
// record. The relay-side ctx is intentionally NOT threaded through —
// the audit write outlives the relay.
func (r *passthroughRecorder) finalisePending(_ context.Context, state pendingState, obs connector.PassthroughObservation) {
	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	streamState := "complete"
	failureReason := ""
	if obs.Outcome == envelope.TLSHandshakeOutcomeFailed {
		streamState = "error"
		failureReason = "passthrough_relay_error"
	}

	upd := flow.StreamUpdate{
		State:         streamState,
		FailureReason: failureReason,
		Duration:      time.Since(state.started),
	}
	if err := r.store.UpdateStream(saveCtx, state.streamID, upd); err != nil {
		r.logger.Error("passthrough recorder: stream finalise failed",
			"listener", r.listenerName,
			"stream_id", state.streamID,
			"error", err,
		)
	}

	fl := &flow.Flow{
		ID:        uuid.New().String(),
		StreamID:  state.streamID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now(),
		Metadata:  passthroughMetadata(obs),
	}
	if err := r.store.SaveFlow(saveCtx, fl); err != nil {
		r.logger.Error("passthrough recorder: flow save failed",
			"listener", r.listenerName,
			"stream_id", state.streamID,
			"flow_id", fl.ID,
			"error", err,
		)
	}
}

// recordDialFailure emits a state="error" Stream + Flow for an upstream
// dial failure (the OnStart hook never fires in that case) so the audit
// surface still reports the attempted connection.
func (r *passthroughRecorder) recordDialFailure(ctx context.Context, obs connector.PassthroughObservation) {
	streamID := uuid.New().String()

	if r.scope != nil && !r.scope.IsEmpty() {
		env := r.envelopeForScope(streamID, obs)
		if !r.scope.ShouldRecord(env) {
			return
		}
	}

	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	st := &flow.Stream{
		ID:            streamID,
		ConnID:        connector.ConnIDFromContext(ctx),
		Protocol:      string(envelope.ProtocolTLSHandshake),
		Scheme:        "https",
		State:         "error",
		FailureReason: "passthrough_dial_failed",
		Timestamp:     time.Now(),
		Origin:        flow.OriginProxy,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: obs.RemoteAddr,
		},
	}
	if obs.ErrorReason != "" {
		st.Tags = map[string]string{"error": obs.ErrorReason}
	}
	if err := r.store.SaveStream(saveCtx, st); err != nil {
		r.logger.Error("passthrough recorder: dial-failed stream save failed",
			"listener", r.listenerName,
			"stream_id", streamID,
			"error", err,
		)
		return
	}

	fl := &flow.Flow{
		ID:        uuid.New().String(),
		StreamID:  streamID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now(),
		Metadata:  passthroughMetadata(obs),
	}
	if err := r.store.SaveFlow(saveCtx, fl); err != nil {
		r.logger.Error("passthrough recorder: dial-failed flow save failed",
			"listener", r.listenerName,
			"stream_id", streamID,
			"flow_id", fl.ID,
			"error", err,
		)
	}
}

// envelopeForScope synthesises a minimal envelope.Envelope to drive
// flow.RecordScope evaluation. The scope filter reads HTTPMessage fields
// when present and falls back to Context.TargetHost / TLS.SNI for non-HTTP
// envelopes — TLSHandshakeMessage is in the latter category, so we
// populate Context.TargetHost from the observation's TargetHost (the
// CONNECT / SOCKS5 target hostname the client requested, plumbed by
// USK-845 — using obs.UpstreamAddr here would seed the matcher with a
// resolved IP and short-circuit the SNI fallback) and Context.TLS.SNI
// when the SNI was peeked.
func (r *passthroughRecorder) envelopeForScope(streamID string, obs connector.PassthroughObservation) *envelope.Envelope {
	env := &envelope.Envelope{
		StreamID:  streamID,
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolTLSHandshake,
		Message: &envelope.TLSHandshakeMessage{
			SNI:          obs.SNI,
			ClientJA3:    obs.ClientJA3,
			ClientJA4:    obs.ClientJA4,
			LocalAddr:    obs.LocalAddr,
			RemoteAddr:   obs.RemoteAddr,
			UpstreamAddr: obs.UpstreamAddr,
		},
		Context: envelope.EnvelopeContext{
			TargetHost: obs.TargetHost,
		},
	}
	if obs.SNI != "" || obs.ClientJA3 != "" || obs.ClientJA4 != "" {
		env.Context.TLS = &envelope.TLSSnapshot{
			SNI:               obs.SNI,
			ClientJA3:         obs.ClientJA3,
			ClientJA4:         obs.ClientJA4,
			ClientFingerprint: obs.ClientJA4,
		}
	}
	return env
}

// passthroughMetadata builds the Flow.Metadata map with the canonical
// audit fields. Snake_case keys per CLAUDE.md naming convention and
// USK-790 design note Q6.
func passthroughMetadata(obs connector.PassthroughObservation) map[string]string {
	m := map[string]string{
		"protocol": string(envelope.ProtocolTLSHandshake),
	}
	if obs.SNI != "" {
		m["sni"] = obs.SNI
	}
	if obs.ClientJA3 != "" {
		m["client_ja3"] = obs.ClientJA3
	}
	if obs.ClientJA4 != "" {
		m["client_ja4"] = obs.ClientJA4
	}
	if obs.LocalAddr != "" {
		m["local_addr"] = obs.LocalAddr
	}
	if obs.RemoteAddr != "" {
		m["remote_addr"] = obs.RemoteAddr
	}
	if obs.UpstreamAddr != "" {
		m["upstream_addr"] = obs.UpstreamAddr
	}
	m["bytes_client_to_upstream"] = strconv.FormatInt(obs.BytesClientToUpstream, 10)
	m["bytes_upstream_to_client"] = strconv.FormatInt(obs.BytesUpstreamToClient, 10)
	if obs.Outcome != "" {
		m["outcome"] = obs.Outcome
	}
	if obs.ErrorReason != "" {
		m["error"] = obs.ErrorReason
	}
	return m
}

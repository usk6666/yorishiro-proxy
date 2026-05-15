package httpaggregator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// aggregatorPhase tracks the progress of a single in-flight HTTPMessage
// reconstruction.
type aggregatorPhase uint8

const (
	// phaseIdle is between messages (or before the first one).
	phaseIdle aggregatorPhase = iota
	// phaseCollectingBody has absorbed initial HEADERS; accumulating DATA.
	phaseCollectingBody
	// phaseTerminated is the terminal state (body size exceeded, stream
	// error, etc.) — Next returns the stored terminal error.
	phaseTerminated
)

// aggregatorChannel implements layer.Channel by wrapping an event-granular
// HTTP/2 Channel and folding H2HeadersEvent / H2DataEvent / H2TrailersEvent
// into aggregated *envelope.HTTPMessage envelopes.
type aggregatorChannel struct {
	inner  layer.Channel
	role   Role
	opts   WrapOptions
	peeked *envelope.Envelope // from Wrap(..., firstHeaders)

	mu          sync.Mutex
	phase       aggregatorPhase
	inflight    *envelope.Envelope
	inflightMsg *envelope.HTTPMessage
	bodyBuf     *bodybuf.BodyBuffer
	bodyLen     int64
	termErr     error // set when phase == phaseTerminated

	// emittedFlowIDs records the FlowID of every HTTPMessage envelope this
	// aggregator emitted, so Close can release each corresponding
	// ctx.transaction_state scope. The slice is bounded by the number of
	// keep-alive messages on the underlying Channel; for HTTP/2 (one
	// stream = one exchange) it carries at most one entry per direction.
	emittedFlowIDs []string

	// connID captures EnvelopeContext.ConnID from the first emitted
	// envelope so Close can issue ReleaseTransaction with the same key
	// the engine used at NewCtx time. Empty until the first emission.
	connID string

	closeOnce sync.Once
	closed    bool
	recvDone  chan struct{}

	// tunnelled records whether a Send-side extended-CONNECT request
	// (RFC 8441: :method=CONNECT + non-empty :protocol) has been observed
	// on this stream. The flag is sticky for the lifetime of the
	// aggregator and tells absorbHeaders to short-circuit the matching
	// 2xx response HEADERS even though it does not carry END_STREAM.
	// USK-775.
	tunnelled bool

	// tunnelExchangeDone latches once the receive-side 2xx accept has
	// been emitted on a tunnelled stream. After it flips, Next() parks
	// on ctx.Done() instead of pulling further events — the post-swap
	// wire (WebSocket-over-h2 frames, etc.) is opaque to the aggregator
	// and the upgrade orchestrator (USK-765 runUpgradeWSOverH2) detaches
	// the stream from the connection-level h2 Layer; subsequent events
	// belong to the post-swap wrapper. USK-775.
	tunnelExchangeDone bool

	// USK-833: pairedRequestPath/Method/RawQuery capture the wire-observed
	// request line fields from the Send-direction HEADERS so the matching
	// Receive-direction response envelope can carry them on
	// EnvelopeContext.RequestPath/RequestMethod/RequestRawQuery for
	// direction:"both" rule matching. One aggregator wraps one HTTP/2
	// stream, which is one HTTP transaction by spec — single-writer.
	pairedRequestPath     string
	pairedRequestMethod   string
	pairedRequestRawQuery string

	// h2FrameCB is the optional synchronous per-H2DataEvent wire-record
	// callback installed via WithH2FrameRecordCallback (USK-897). When
	// non-nil, the aggregator fires it from absorbData BEFORE the DATA
	// payload is appended to the body buffer. See
	// WithH2FrameRecordCallback for the contract.
	h2FrameCB func(*envelope.Envelope)
}

// StreamID delegates to the underlying Channel.
func (a *aggregatorChannel) StreamID() string {
	return a.inner.StreamID()
}

// H2StreamID returns the underlying h2 stream id when the aggregator
// wraps an *http2.channel; returns 0 when the inner Channel does not
// expose an h2 stream id (e.g. tests using a fake Channel). Used by
// the upgrade orchestrator (USK-765) to call
// http2.Layer.DetachStream(streamID) on the right wire id without
// reaching past the aggregator's encapsulation boundary.
func (a *aggregatorChannel) H2StreamID() uint32 {
	type h2StreamIDer interface{ H2StreamID() uint32 }
	if v, ok := a.inner.(h2StreamIDer); ok {
		return v.H2StreamID()
	}
	return 0
}

// Closed returns the underlying Channel's Closed signal. Aggregator does
// not add its own Closed signal — terminal events (EOF, StreamError) are
// surfaced through Next per the Channel contract.
func (a *aggregatorChannel) Closed() <-chan struct{} {
	return a.inner.Closed()
}

// Err returns the underlying Channel's Err.
func (a *aggregatorChannel) Err() error {
	return a.inner.Err()
}

// Close closes the aggregator wrapper and cascades to the underlying Channel.
//
// Cascade rationale: Session treats the aggregator as its sole Channel handle
// (no separate reference to the inner Channel exists in Session). When Session's
// defer client.Close() fires after an abnormal termination (e.g. upstream
// MaxBodySize error), the inner channel's RST_STREAM emission (driven by
// USK-618 logic in http2.channel.Close) is what signals the peer. Not
// cascading would leak per-stream state in the inner Layer and leave the
// peer waiting on an unterminated stream.
//
// Close also fires pluginv2.ReleaseTransaction for every FlowID this
// aggregator emitted, so any ctx.transaction_state stashed against those
// scopes is GC'd. The release runs AFTER the inner Channel cascades
// closed so a USK-671 dispatch path watching the inner Closed() signal
// has already run any terminal-event hook before the dict is cleared.
func (a *aggregatorChannel) Close() error {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		// Release any in-flight BodyBuffer. Once the aggregator closes,
		// no aggregated HTTPMessage will ever be emitted for this partial
		// stream, so the single refcount on bodyBuf is orphaned here.
		if a.bodyBuf != nil {
			_ = a.bodyBuf.Release()
			a.bodyBuf = nil
		}
		flows := a.emittedFlowIDs
		connID := a.connID
		a.emittedFlowIDs = nil
		a.mu.Unlock()
		close(a.recvDone)
		_ = a.inner.Close()
		a.releaseTransactionStates(connID, flows)
	})
	return nil
}

// releaseTransactionStates fires ReleaseTransaction for every FlowID the
// aggregator emitted, using the ConnID captured at first emit. No-op
// when no releaser was configured (legacy parallel) or when the ConnID
// is empty (aggregator never emitted, or template lacked one).
func (a *aggregatorChannel) releaseTransactionStates(connID string, flowIDs []string) {
	if a.opts.StateReleaser == nil || connID == "" {
		return
	}
	for _, id := range flowIDs {
		if id == "" {
			continue
		}
		a.opts.StateReleaser.ReleaseTransaction(connID, id)
	}
}

// recordEmittedLocked stamps the emitted envelope's FlowID onto the
// release queue and captures ConnID on first call. Caller must hold a.mu.
func (a *aggregatorChannel) recordEmittedLocked(env *envelope.Envelope) {
	if env == nil {
		return
	}
	if a.connID == "" {
		a.connID = env.Context.ConnID
	}
	if env.FlowID != "" {
		a.emittedFlowIDs = append(a.emittedFlowIDs, env.FlowID)
	}
}

// Next reads events from the underlying Channel until a complete
// HTTPMessage is aggregated (or a terminal error occurs), then returns
// the aggregated envelope.
//
// USK-775: once an extended-CONNECT bootstrap exchange has been emitted
// (request HEADERS via the Send-side short-circuit, response HEADERS via
// the matching receive-side short-circuit), Next() must NOT consume any
// further events from the underlying Channel. The follow-on DATA frames
// belong to the post-swap ws.Layer (via http2.Layer.DetachStream's drain
// of the same recv queue) — pulling them into the aggregator here would
// either drop them (with no DATA-bearing END_STREAM there is no place to
// put them) or surface as a "DATA in phase 0" protocol violation. Park
// on ctx.Done() instead so the upgrade orchestrator's
// errgroup-cancellation reaches us and cleanly returns control to
// runUpgradeWSOverH2.
func (a *aggregatorChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	a.mu.Lock()
	if a.phase == phaseTerminated {
		err := a.termErr
		a.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	// Park policy on a tunnelled stream depends on the aggregator role:
	//   - RoleServer (client-side, Next=>Send/requests): once the bootstrap
	//     CONNECT request HEADERS has been emitted (a.tunnelled=true), no
	//     further request envelopes belong here — the post-swap ws.Layer
	//     drives client→upstream WS frames.
	//   - RoleClient (upstream-side, Next=>Receive/responses): the 2xx
	//     accept is the only response that flows; we can safely keep
	//     reading until that arrives, then park (tunnelExchangeDone=true).
	park := a.phase == phaseIdle && ((a.role == RoleServer && a.tunnelled) || a.tunnelExchangeDone)
	a.mu.Unlock()

	if park {
		// Park until the orchestrator cancels ctx (errgroup-driven). No
		// more aggregator-shaped envelopes are coming on this stream:
		// the post-swap wire is opaque to the http aggregator.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-a.recvDone:
			// Close was called; honour it as graceful EOF.
			return nil, io.EOF
		}
	}

	for {
		ev, err := a.nextEvent(ctx)
		if err != nil {
			return nil, err
		}
		out, done, aggErr := a.absorb(ev)
		if aggErr != nil {
			return nil, aggErr
		}
		if done {
			return out, nil
		}
	}
}

// nextEvent reads the next event envelope from the underlying Channel,
// consuming the peeked first envelope (if any) before delegating.
func (a *aggregatorChannel) nextEvent(ctx context.Context) (*envelope.Envelope, error) {
	a.mu.Lock()
	if a.peeked != nil {
		env := a.peeked
		a.peeked = nil
		a.mu.Unlock()
		return env, nil
	}
	a.mu.Unlock()

	return a.inner.Next(ctx)
}

// absorb folds one event envelope into the in-flight HTTPMessage. Returns
// (out, done, err): out is non-nil and done is true when a complete
// HTTPMessage has been aggregated; err is non-nil on terminal error (body
// size exceeded, protocol violation).
func (a *aggregatorChannel) absorb(ev *envelope.Envelope) (*envelope.Envelope, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch m := ev.Message.(type) {
	case *http2.H2HeadersEvent:
		return a.absorbHeaders(ev, m)
	case *http2.H2DataEvent:
		return a.absorbData(ev, m)
	case *http2.H2TrailersEvent:
		return a.absorbTrailers(ev, m)
	default:
		// Unknown event type — log but do not terminate. Defensive; the
		// Layer only emits the three known types.
		slog.Debug("httpaggregator: unknown event type, skipping",
			"type", fmt.Sprintf("%T", ev.Message),
			"stream_id", ev.StreamID,
		)
		return nil, false, nil
	}
}

// absorbHeaders consumes an H2HeadersEvent. If the event carries
// EndStream=true, an HTTPMessage envelope is emitted immediately (bodyless
// message). Otherwise the aggregator transitions to phaseCollectingBody.
//
// USK-721: 1xx informational responses (100 Continue, 102 Processing, 103
// Early Hints; RFC 9110 §15.2) precede the actual final response on the
// same stream and never carry a body. They are emitted immediately as
// bodyless complete messages and the aggregator stays in phaseIdle so the
// subsequent HEADERS (which may be another 1xx, or the final response) is
// absorbed as a new initial HEADERS.
func (a *aggregatorChannel) absorbHeaders(env *envelope.Envelope, evt *http2.H2HeadersEvent) (*envelope.Envelope, bool, error) {
	if a.phase == phaseCollectingBody {
		// Trailers path should not come through H2HeadersEvent — the Layer
		// emits H2TrailersEvent for HEADERS-after-DATA. Treat as protocol
		// violation.
		return nil, false, fmt.Errorf("httpaggregator: unexpected H2HeadersEvent in phaseCollectingBody (stream %s)", env.StreamID)
	}

	msg := &envelope.HTTPMessage{
		Method:          evt.Method,
		Scheme:          evt.Scheme,
		Authority:       evt.Authority,
		Path:            evt.Path,
		RawQuery:        evt.RawQuery,
		ConnectProtocol: evt.ConnectProtocol,
		// USK-788: stamp the canonical HTTP/2 wire-version. The HTTP/2 Layer
		// is constructed with WithScheme("http") only by the h2c handler
		// (internal/connector/h2c_handler.go); every other producer uses
		// WithScheme("https"). Reading evt.Scheme keeps the version source
		// co-located with the rest of the pseudo-header projection.
		HTTPVersion:  envelope.HTTPVersionFromH2Scheme(evt.Scheme),
		Status:       evt.Status,
		StatusReason: evt.StatusReason,
		Headers:      cloneKVs(evt.Headers),
		Anomalies:    cloneAnomalies(evt.Anomalies),
	}

	outCtx := env.Context
	// USK-833: stamp the paired request's path/method/query onto Receive
	// envelopes for direction:"both" rule matching. On Send, capture the
	// wire-observed fields onto the aggregator so the matching Receive
	// envelope can carry them forward. Order matters: Send-direction
	// envelopes carry their own Path/Method already in HTTPMessage, so we
	// only need to mirror them onto Context for symmetry with HTTP/1.x.
	if env.Direction == envelope.Send {
		a.pairedRequestPath = msg.Path
		a.pairedRequestMethod = msg.Method
		a.pairedRequestRawQuery = msg.RawQuery
		outCtx.RequestPath = msg.Path
		outCtx.RequestMethod = msg.Method
		outCtx.RequestRawQuery = msg.RawQuery
	} else if env.Direction == envelope.Receive {
		outCtx.RequestPath = a.pairedRequestPath
		outCtx.RequestMethod = a.pairedRequestMethod
		outCtx.RequestRawQuery = a.pairedRequestRawQuery
	}

	outEnv := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    flowIDOr(env.FlowID),
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       cloneBytes(env.Raw),
		Message:   msg,
		Context:   outCtx,
	}

	// 1xx informational: emit as complete bodyless message and stay in
	// phaseIdle so the next HEADERS is treated as a fresh initial block.
	// Direction == Receive guards request HEADERS (Status == 0 there).
	if env.Direction == envelope.Receive && isInformationalStatus(evt.Status) {
		a.recordEmittedLocked(outEnv)
		a.resetLocked()
		return outEnv, true, nil
	}

	// USK-775: extended CONNECT (RFC 8441) opens a bidirectional stream
	// that carries the negotiated protocol's frames as DATA. Neither the
	// request HEADERS nor the 2xx response HEADERS carry END_STREAM —
	// the stream stays open for the protocol frames. Without this
	// short-circuit the aggregator would park in phaseCollectingBody
	// waiting for an END_STREAM that will never arrive, blocking the
	// session-side upgrade detection (UpgradeStep + runUpgradeWSOverH2,
	// USK-765) from ever firing.
	//
	//   - Send-side: discriminator is :method=CONNECT plus a non-empty
	//     :protocol pseudo-header (parsed into evt.ConnectProtocol by
	//     USK-764). Mark the stream as tunnelled so the matching
	//     response HEADERS short-circuits too.
	//   - Receive-side: a 2xx response on a tunnelled stream is the
	//     upgrade accept. Emit immediately so UpgradeStep flips
	//     Pending=UpgradeWSOverH2 and the orchestrator detaches the
	//     stream before any DATA reaches this aggregator.
	//
	// Aggregator state is reset to phaseIdle after the emit so an
	// unforeseen post-swap event lands in a coherent state. The DATA
	// frames that follow (WS frames) are NOT consumed here — the upgrade
	// orchestrator detaches the stream from the connection-level h2
	// Layer before any DATA is read by this aggregator.
	if isExtendedConnectRequest(env, evt) {
		a.tunnelled = true
		a.recordEmittedLocked(outEnv)
		a.resetLocked()
		return outEnv, true, nil
	}
	if a.tunnelled && env.Direction == envelope.Receive && evt.Status >= 200 && evt.Status < 300 {
		a.tunnelExchangeDone = true
		a.recordEmittedLocked(outEnv)
		a.resetLocked()
		return outEnv, true, nil
	}
	// USK-888: SSE-over-h2 detection. A Receive-side 2xx HEADERS whose
	// Content-Type media type is text/event-stream opens a long-lived
	// server→client byte stream (RFC 8895). If we left the aggregator
	// in phaseCollectingBody waiting for END_STREAM the wire would
	// either park indefinitely or trip MaxBodySize after enough event
	// payload accumulated — and no SSE Envelope would ever surface to
	// the Pipeline because aggregator commits one HTTPMessage per
	// exchange. Emit the HEADERS as a complete HTTPMessage immediately
	// and mark the aggregator as tunnel-done so subsequent DATA frames
	// on this stream are NOT consumed here. The post-emit
	// runUpgradeSSEOverH2 orchestrator calls http2.Layer.DetachStream
	// against the same stream id and the DATA payloads are surfaced as
	// an opaque byte stream to sse.Wrap.
	//
	// Same shape as the extended-CONNECT short-circuit (line 398-409):
	// emit + resetLocked + tunnelExchangeDone so Next() parks on
	// ctx.Done after this single envelope flows.
	if isSSEResponseHeaders(env, evt) {
		a.tunnelExchangeDone = true
		a.recordEmittedLocked(outEnv)
		a.resetLocked()
		return outEnv, true, nil
	}

	if evt.EndStream {
		// Complete bodyless message. Reset phase so subsequent events
		// (a second request-response on the same channel) can be
		// absorbed.
		a.recordEmittedLocked(outEnv)
		a.resetLocked()
		return outEnv, true, nil
	}

	// Transition to collecting body. rawAcc accumulates the HEADERS block
	// bytes so the final envelope's Raw reflects headers + DATA bytes.
	a.inflight = outEnv
	a.inflightMsg = msg
	a.phase = phaseCollectingBody
	return nil, false, nil
}

// isInformationalStatus reports whether code is a 1xx informational status
// per RFC 9110 §15.2. Mirror of http2.isInformationalStatus, kept private
// here so the aggregator does not depend on http2 internal helpers.
func isInformationalStatus(code int) bool {
	return code >= 100 && code < 200
}

// isExtendedConnectRequest reports whether the supplied HEADERS event is a
// Send-side RFC 8441 extended CONNECT request bootstrapping a non-HTTP
// protocol (websocket today; webtransport / etc. forward-compat). The
// discriminator is :method=CONNECT plus a non-empty :protocol pseudo-
// header (parsed into evt.ConnectProtocol by USK-764). USK-775 uses this
// to short-circuit the request HEADERS so the aggregator does not park
// in phaseCollectingBody waiting for an END_STREAM that the wire will
// never deliver — the stream stays open for the negotiated protocol's
// frames.
func isExtendedConnectRequest(env *envelope.Envelope, evt *http2.H2HeadersEvent) bool {
	if env == nil || evt == nil {
		return false
	}
	if env.Direction != envelope.Send {
		return false
	}
	return evt.Method == "CONNECT" && evt.ConnectProtocol != ""
}

// isSSEResponseHeaders reports whether the supplied HEADERS event is a
// Receive-side 2xx response whose Content-Type media type is
// text/event-stream. USK-888 uses this to short-circuit the response
// HEADERS so the aggregator emits the HTTPMessage immediately and does
// NOT enter phaseCollectingBody. The post-HEADERS DATA frames on this
// stream are routed to the SSE Layer by session.runUpgradeSSEOverH2 via
// http2.Layer.DetachStream.
//
// Status is constrained to 2xx because servers occasionally use 200, 201,
// 206 etc. for streamed responses and the wire-fidelity principle
// (CLAUDE.md MITM Principle #1) says the proxy reports what the server
// sent. The Content-Type token compare is case-insensitive and strips
// parameters (`;charset=utf-8`) before comparison.
func isSSEResponseHeaders(env *envelope.Envelope, evt *http2.H2HeadersEvent) bool {
	if env == nil || evt == nil {
		return false
	}
	if env.Direction != envelope.Receive {
		return false
	}
	if evt.Status < 200 || evt.Status >= 300 {
		return false
	}
	ct := ""
	for _, kv := range evt.Headers {
		if strings.EqualFold(kv.Name, "content-type") {
			ct = kv.Value
			break
		}
	}
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	return strings.EqualFold(ct, "text/event-stream")
}

// absorbData consumes an H2DataEvent. Payload is appended to the in-flight
// BodyBuffer (lazily allocated, promoted to file at BodySpillThreshold).
// MaxBodySize enforcement happens here; exceeding the cap terminates the
// aggregator with a *layer.StreamError and RST_STREAMs the underlying
// stream.
//
// USK-897: when WithH2FrameRecordCallback is installed, fire the callback
// BEFORE the DATA payload reaches the body buffer. The callback observes
// the raw DATA frame envelope (one per H2DataEvent) so per-frame
// boundaries survive aggregator folding — closing the wire-fidelity gap
// on the aggregator path symmetrically with the USK-889 detach-path
// coverage. Ordering matters: CLAUDE.md MITM Principle 3 — wire-record
// fires first, body-buffer mutation second. The callback fires for every
// H2DataEvent (including empty END_STREAM frames) regardless of whether
// the payload length triggers the MaxBodySize gate; the wire envelope is
// always recorded.
func (a *aggregatorChannel) absorbData(env *envelope.Envelope, evt *http2.H2DataEvent) (*envelope.Envelope, bool, error) {
	if a.phase != phaseCollectingBody || a.inflight == nil {
		if len(evt.Payload) == 0 && evt.EndStream {
			// Defensive: an empty END_STREAM DATA with no prior HEADERS is
			// a protocol violation but can arrive as a peer stress test.
			// Surface as an error so the session terminates this stream.
			return nil, false, fmt.Errorf("httpaggregator: DATA without HEADERS (stream %s)", env.StreamID)
		}
		return nil, false, fmt.Errorf("httpaggregator: DATA in phase %d (stream %s)", a.phase, env.StreamID)
	}

	// USK-897: fire the per-H2DataEvent wire-record callback BEFORE any
	// body-buffer mutation. The envelope passed to the callback is a
	// fresh struct with a defensive copy of the DATA payload so the
	// callback may retain the slice across return without interfering
	// with the aggregator's own raw-bytes accumulation on inflight.Raw.
	if a.h2FrameCB != nil {
		a.h2FrameCB(buildH2FrameWireEnvelope(env, evt))
	}

	maxBody := a.effectiveMaxBody()
	if len(evt.Payload) > 0 {
		newLen := a.bodyLen + int64(len(evt.Payload))
		if maxBody > 0 && newLen > maxBody {
			// Trip the MaxBodySize gate: RST the underlying stream,
			// terminate the aggregator, surface *layer.StreamError.
			se := &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "http2: body exceeds max size",
			}
			a.terminateLocked(se)
			if rstCh, ok := a.inner.(interface {
				MarkTerminatedWithRST(code uint32, err error)
			}); ok {
				rstCh.MarkTerminatedWithRST(http2.ErrCodeInternal, se)
			}
			return nil, false, se
		}
		if err := a.appendBodyLocked(evt.Payload); err != nil {
			a.terminateLocked(err)
			return nil, false, err
		}
		a.bodyLen = newLen
	}

	// Accumulate raw bytes so the final Envelope.Raw reflects the wire
	// shape (HEADERS block + concatenated DATA payloads + trailer HEADERS
	// block). Required for RFC-001 MITM wire-fidelity (raw bytes recording
	// must include DATA payloads for analysts reconstructing the wire).
	// For 25+ MiB bodies this doubles memory briefly; Pipeline's variant
	// snapshot + RecordStep consume the Raw then release it.
	a.inflight.Raw = append(a.inflight.Raw, env.Raw...)

	if evt.EndStream {
		// Finalize body onto HTTPMessage: memory mode → msg.Body,
		// file mode → msg.BodyBuffer.
		a.finalizeBodyLocked()
		out := a.inflight
		a.recordEmittedLocked(out)
		a.resetLocked()
		return out, true, nil
	}

	return nil, false, nil
}

// absorbTrailers consumes an H2TrailersEvent. The trailers are attached to
// the in-flight HTTPMessage and the aggregated envelope is emitted
// (trailer HEADERS always carries END_STREAM per RFC 9113 §8.1).
func (a *aggregatorChannel) absorbTrailers(env *envelope.Envelope, evt *http2.H2TrailersEvent) (*envelope.Envelope, bool, error) {
	if a.phase != phaseCollectingBody || a.inflight == nil {
		return nil, false, fmt.Errorf("httpaggregator: Trailers in phase %d (stream %s)", a.phase, env.StreamID)
	}

	if len(evt.Trailers) > 0 {
		a.inflightMsg.Trailers = cloneKVs(evt.Trailers)
	}
	if len(evt.Anomalies) > 0 {
		a.inflightMsg.Anomalies = append(a.inflightMsg.Anomalies, cloneAnomalies(evt.Anomalies)...)
	}
	a.inflight.Raw = append(a.inflight.Raw, env.Raw...)
	a.finalizeBodyLocked()
	out := a.inflight
	a.recordEmittedLocked(out)
	a.resetLocked()
	return out, true, nil
}

// effectiveMaxBody returns the aggregator's MaxBodySize, falling back to
// the package default.
func (a *aggregatorChannel) effectiveMaxBody() int64 {
	if a.opts.MaxBodySize > 0 {
		return a.opts.MaxBodySize
	}
	return config.MaxBodySize
}

// effectiveSpillThreshold returns the aggregator's BodySpillThreshold,
// falling back to the package default.
func (a *aggregatorChannel) effectiveSpillThreshold() int64 {
	if a.opts.BodySpillThreshold > 0 {
		return a.opts.BodySpillThreshold
	}
	return config.DefaultBodySpillThreshold
}

// appendBodyLocked appends payload to the aggregator's BodyBuffer (lazily
// allocated, promoted to file once cumulative size exceeds the spill
// threshold). Must hold a.mu.
func (a *aggregatorChannel) appendBodyLocked(payload []byte) error {
	if a.bodyBuf == nil {
		a.bodyBuf = bodybuf.NewMemory(nil)
	}
	if _, werr := a.bodyBuf.Write(payload); werr != nil {
		if errors.Is(werr, bodybuf.ErrMaxSizeExceeded) {
			_ = a.bodyBuf.Release()
			a.bodyBuf = nil
			return &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "http2: body exceeds max size",
			}
		}
		return fmt.Errorf("httpaggregator: body write: %w", werr)
	}
	// Promote to file-backed once memory size crosses the threshold.
	if !a.bodyBuf.IsFileBacked() && a.bodyBuf.Len() > a.effectiveSpillThreshold() {
		if perr := a.bodyBuf.PromoteToFile(a.opts.BodySpillDir, config.BodySpillPrefix, a.effectiveMaxBody()); perr != nil {
			slog.Warn("httpaggregator: promote body to file failed; staying in memory",
				"stream_id", a.inflight.StreamID, "err", perr)
		}
	}
	return nil
}

// finalizeBodyLocked projects the accumulated BodyBuffer onto the
// inflight HTTPMessage per the standard contract (empty → nil, memory →
// Body, file → BodyBuffer). Must hold a.mu.
func (a *aggregatorChannel) finalizeBodyLocked() {
	msg := a.inflightMsg
	if a.bodyBuf == nil {
		msg.Body = nil
		msg.BodyBuffer = nil
		return
	}
	if a.bodyBuf.Len() == 0 {
		_ = a.bodyBuf.Release()
		a.bodyBuf = nil
		msg.Body = nil
		msg.BodyBuffer = nil
		return
	}
	if a.bodyBuf.IsFileBacked() {
		msg.Body = nil
		msg.BodyBuffer = a.bodyBuf
		a.bodyBuf = nil
		return
	}
	// Memory-backed: materialize onto msg.Body (HTTP/1.x parity for small
	// bodies — downstream Pipeline Steps use the familiar []byte shape).
	b, err := a.bodyBuf.Bytes(context.Background())
	if err != nil {
		msg.Body = nil
		msg.BodyBuffer = a.bodyBuf
		a.bodyBuf = nil
		return
	}
	_ = a.bodyBuf.Release()
	a.bodyBuf = nil
	msg.Body = b
	msg.BodyBuffer = nil
}

// resetLocked returns the aggregator to phaseIdle for the next message.
// Must hold a.mu.
func (a *aggregatorChannel) resetLocked() {
	a.phase = phaseIdle
	a.inflight = nil
	a.inflightMsg = nil
	a.bodyBuf = nil
	a.bodyLen = 0
}

// terminateLocked transitions to phaseTerminated with err as the terminal
// error. Subsequent Next calls return err.
func (a *aggregatorChannel) terminateLocked(err error) {
	a.phase = phaseTerminated
	a.termErr = err
	if a.bodyBuf != nil {
		_ = a.bodyBuf.Release()
		a.bodyBuf = nil
	}
	a.inflight = nil
	a.inflightMsg = nil
}

// flowIDOr returns id if non-empty, otherwise a fresh UUID.
func flowIDOr(id string) string {
	if id != "" {
		return id
	}
	return uuid.New().String()
}

// cloneKVs returns a deep copy of a KeyValue slice.
func cloneKVs(in []envelope.KeyValue) []envelope.KeyValue {
	if in == nil {
		return nil
	}
	out := make([]envelope.KeyValue, len(in))
	copy(out, in)
	return out
}

// cloneAnomalies returns a deep copy of an Anomaly slice.
func cloneAnomalies(in []envelope.Anomaly) []envelope.Anomaly {
	if in == nil {
		return nil
	}
	out := make([]envelope.Anomaly, len(in))
	copy(out, in)
	return out
}

// cloneBytes returns a copy of b, or nil if b is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// buildH2FrameWireEnvelope constructs the per-H2DataEvent wire-record
// envelope dispatched to the WithH2FrameRecordCallback consumer (USK-897).
//
// The returned envelope mirrors the USK-889 detach-path frame envelope
// shape so the same record-only Pipeline + WireLevel discriminator
// (flow.WireLevelH2Frame) apply to both producers:
//
//   - Protocol  = envelope.ProtocolHTTP (per the H2DataEvent provenance)
//   - StreamID  = the inner envelope's StreamID (the lower-layer view)
//   - Direction = the inner envelope's Direction (Send / Receive)
//   - Sequence  = the inner envelope's Sequence (the orchestrator
//     rewrites this to a per-direction counter scoped to
//     (sessionStreamID, WireLevel=h2-frame) before
//     dispatching to the record-only Pipeline)
//   - Raw       = a defensive copy of the DATA payload bytes (no 9-byte
//     frame header — same fidelity as the H2DataEvent
//     envelope Raw and the USK-889 detach-path envelope)
//   - Message   = nil (DATA frame wire envelopes have no L7 structured
//     view by design — the matching HTTPMessage envelope
//     queued AFTER full aggregation already provides one)
//   - Context   = the inner envelope's Context (carries ConnID /
//     TargetHost / TLS / ClientAddr; the callback expects to
//     stamp WireLevel before forwarding)
//
// The defensive copy keeps the callback contract simple — consumers may
// retain the Raw slice without coordinating with the aggregator's
// inflight.Raw accumulation (which appends to the same backing array as
// env.Raw). The cost is one allocation per DATA frame; for gRPC over
// h2 this matches USK-896's grpc LPM wire-record allocation profile.
func buildH2FrameWireEnvelope(env *envelope.Envelope, evt *http2.H2DataEvent) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  env.StreamID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       cloneBytes(evt.Payload),
		// Message intentionally nil — DATA frame wire envelopes have no
		// L7 structured view; the matching HTTPMessage envelope queued
		// AFTER full aggregation provides one. The session helper
		// stamping flow.WireLevelH2Frame on Context.WireLevel is the
		// authoritative discriminator the record path keys on.
		Context: env.Context,
	}
}

package httpaggregator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	closeOnce sync.Once
	closed    bool
	recvDone  chan struct{}
}

// StreamID delegates to the underlying Channel.
func (a *aggregatorChannel) StreamID() string {
	return a.inner.StreamID()
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
		a.mu.Unlock()
		close(a.recvDone)
		_ = a.inner.Close()
	})
	return nil
}

// Next reads events from the underlying Channel until a complete
// HTTPMessage is aggregated (or a terminal error occurs), then returns
// the aggregated envelope.
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
	a.mu.Unlock()

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
func (a *aggregatorChannel) absorbHeaders(env *envelope.Envelope, evt *http2.H2HeadersEvent) (*envelope.Envelope, bool, error) {
	if a.phase == phaseCollectingBody {
		// Trailers path should not come through H2HeadersEvent — the Layer
		// emits H2TrailersEvent for HEADERS-after-DATA. Treat as protocol
		// violation.
		return nil, false, fmt.Errorf("httpaggregator: unexpected H2HeadersEvent in phaseCollectingBody (stream %s)", env.StreamID)
	}

	msg := &envelope.HTTPMessage{
		Method:       evt.Method,
		Scheme:       evt.Scheme,
		Authority:    evt.Authority,
		Path:         evt.Path,
		RawQuery:     evt.RawQuery,
		Status:       evt.Status,
		StatusReason: evt.StatusReason,
		Headers:      cloneKVs(evt.Headers),
		Anomalies:    cloneAnomalies(evt.Anomalies),
	}

	outEnv := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    flowIDOr(env.FlowID),
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       cloneBytes(env.Raw),
		Message:   msg,
		Context:   env.Context,
	}

	if evt.EndStream {
		// Complete bodyless message. Reset phase so subsequent events
		// (a second request-response on the same channel) can be
		// absorbed.
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

// absorbData consumes an H2DataEvent. Payload is appended to the in-flight
// BodyBuffer (lazily allocated, promoted to file at BodySpillThreshold).
// MaxBodySize enforcement happens here; exceeding the cap terminates the
// aggregator with a *layer.StreamError and RST_STREAMs the underlying
// stream.
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

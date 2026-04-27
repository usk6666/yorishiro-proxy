package grpc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// lpmPrefixLen is the size of a gRPC Length-Prefixed Message header on the
// wire: 1 byte (compressed flag) + 4 bytes (big-endian length).
const lpmPrefixLen = 5

// supported grpc-encoding values (D2). Anything else triggers a
// *layer.StreamError when used on a Compressed=true LPM (Receive) or when
// requested on Send.
const (
	encodingIdentity = "identity"
	encodingGzip     = "gzip"
)

// reassemblerPhase tracks the LPM reassembler state for one direction.
type reassemblerPhase uint8

const (
	// phaseWaitingPrefix needs 5 bytes to read a new LPM prefix.
	phaseWaitingPrefix reassemblerPhase = iota
	// phaseWaitingPayload has consumed the prefix and needs WireLength
	// payload bytes before emitting a GRPCDataMessage.
	phaseWaitingPayload
)

// reassembler accumulates wire bytes from H2DataEvent payloads and emits
// one (compressed flag, wire length, payload) tuple per complete LPM. A
// separate reassembler instance is held per direction so that bidi gRPC
// streams have independent buffers.
type reassembler struct {
	phase    reassemblerPhase
	prefix   [lpmPrefixLen]byte
	prefBuf  []byte // grow-once view onto prefix; nil when phase == phaseWaitingPrefix
	payload  []byte
	wireLen  uint32
	compress bool
}

// feed appends src to the in-progress LPM. Returns one lpmFrame per
// complete LPM; multiple LPMs in one src yield multiple frames.
//
// max bounds the maximum payload size; exceeding it returns
// errMessageTooLarge (the channel maps it to a *layer.StreamError).
//
// Zero-length payloads are handled correctly: when wireLen==0 the prefix
// transition immediately emits a frame without consuming any payload
// bytes, even if src is empty afterward.
func (r *reassembler) feed(src []byte, max uint32) ([]lpmFrame, error) {
	var out []lpmFrame
	// Iterate until both the source is drained AND no zero-length payload
	// is pending emission. The progress condition (`progressed`) prevents
	// an infinite loop if the state machine ever fails to advance.
	for {
		progressed := false
		switch r.phase {
		case phaseWaitingPrefix:
			if len(src) == 0 {
				return out, nil
			}
			need := lpmPrefixLen - len(r.prefBuf)
			if len(src) < need {
				r.prefBuf = append(r.prefBuf, src...)
				return out, nil
			}
			r.prefBuf = append(r.prefBuf, src[:need]...)
			src = src[need:]
			r.compress = r.prefBuf[0] != 0
			r.wireLen = binary.BigEndian.Uint32(r.prefBuf[1:5])
			if r.wireLen > max {
				return out, errMessageTooLarge
			}
			copy(r.prefix[:], r.prefBuf)
			r.prefBuf = nil
			r.payload = make([]byte, 0, r.wireLen)
			r.phase = phaseWaitingPayload
			progressed = true
		case phaseWaitingPayload:
			need := int(r.wireLen) - len(r.payload)
			if need > 0 {
				if len(src) == 0 {
					return out, nil
				}
				take := need
				if take > len(src) {
					take = len(src)
				}
				r.payload = append(r.payload, src[:take]...)
				src = src[take:]
				if len(r.payload) < int(r.wireLen) {
					return out, nil
				}
			}
			out = append(out, lpmFrame{
				Compressed: r.compress,
				WireLength: r.wireLen,
				Payload:    r.payload,
			})
			r.payload = nil
			r.wireLen = 0
			r.compress = false
			r.phase = phaseWaitingPrefix
			progressed = true
		}
		if !progressed {
			return out, nil
		}
	}
}

// lpmFrame is one fully reassembled LPM. Payload is the compressed bytes
// (or raw bytes if Compressed=false) — decompression happens in the
// channel's emit path.
type lpmFrame struct {
	Compressed bool
	WireLength uint32
	Payload    []byte
}

// errMessageTooLarge is returned by reassembler.feed when an LPM length
// exceeds the per-Channel cap (defaults to config.MaxGRPCMessageSize but
// is overridable via WithMaxMessageSize). The channel maps it to a
// *layer.StreamError.
var errMessageTooLarge = errors.New("grpc: message too large")

// directionState holds reassembler + start-headers metadata for one
// direction of an RPC. Per-direction so bidi streams have independent
// buffers, and so the gRPC content-encoding negotiated on the request
// side is remembered when decoding response DATA frames.
type directionState struct {
	reasm        reassembler
	startEmitted bool // GRPCStartMessage has been observed/emitted
	service      string
	method       string
	encoding     string // grpc-encoding value (last-seen on this direction)
}

// pendingEnvelope is one envelope queued for emission. The channel may
// produce up to two envelopes per inner event (Start + synthetic End on
// trailers-only response, D4) so a small queue is needed.
type pendingEnvelope struct {
	env *envelope.Envelope
}

// grpcChannel implements layer.Channel by wrapping an event-granular
// HTTP/2 stream Channel and translating each event into one or more
// gRPC-typed envelopes.
type grpcChannel struct {
	inner    layer.Channel
	role     Role
	streamID string

	mu      sync.Mutex
	peeked  *envelope.Envelope // from Wrap(..., firstHeaders); cleared after first read
	queued  []pendingEnvelope  // emit-side FIFO (D4 may queue 2)
	send    directionState     // request-side (Direction=Send)
	recv    directionState     // response-side (Direction=Receive)
	nextSeq int
	termErr error // first non-nil terminal error (sticky)

	closeOnce    sync.Once
	recvDone     chan struct{}
	recvDoneOnce sync.Once

	// maxMessageSize caps the per-LPM payload size for both the
	// reassembler and the gzip decoder. Resolved once at Wrap time;
	// always positive (defaults to config.MaxGRPCMessageSize).
	maxMessageSize uint32
}

// StreamID returns the inner Channel's stream identifier (one RPC = one
// stream).
func (c *grpcChannel) StreamID() string {
	return c.streamID
}

// Closed returns a channel closed when this wrapper has entered its
// terminal state. recvDone is closed when:
//   - Next observes a terminal error from inner (or an absorb error),
//   - Close is invoked by the caller, OR
//   - the inner Channel signals Closed() (e.g., late RST_STREAM after EOF)
//     so callers parking on Closed() observe imminent termination even
//     when no Next is in flight (mirroring the contract internal/session
//     relies on via lateClientErrorWatcher).
//
// Note: Closed() may fire while Err() still returns nil. This matches the
// inner h2 channel's existing contract — RST_STREAM(NO_ERROR) closes the
// inner termDone while leaving response Headers/Data/Trailers buffered
// in the inner recv chan. The wrapper's Next continues to drain those
// buffered events on subsequent calls and sets termErr lazily when the
// inner returns its own EOF/error. Consumers reading Err() after Closed()
// (e.g., lateClientErrorWatcher) tolerate the no-error case as graceful.
func (c *grpcChannel) Closed() <-chan struct{} {
	return c.recvDone
}

// Err returns the cached terminal error, or nil while the channel is
// still active. May return nil after Closed() fires until Next observes
// the inner's EOF/error (see Closed() docs).
func (c *grpcChannel) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.termErr
}

// Close cascades to inner.Close per N6.7 cascade discipline. Idempotent
// via sync.Once.
func (c *grpcChannel) Close() error {
	c.closeOnce.Do(func() {
		_ = c.inner.Close()
		c.setTermErr(io.EOF)
		c.closeRecvDone()
	})
	return nil
}

// setTermErr caches err as the terminal error if not already set (first-
// writer-wins). Independent of recvDone, which has its own sync.Once.
func (c *grpcChannel) setTermErr(err error) {
	c.mu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.mu.Unlock()
}

// closeRecvDone closes the recvDone channel exactly once. Safe to call
// from any goroutine.
func (c *grpcChannel) closeRecvDone() {
	c.recvDoneOnce.Do(func() {
		close(c.recvDone)
	})
}

// watchInnerClose blocks until the inner Channel signals Closed() and
// closes recvDone so callers parking on the wrapper's Closed() observe
// the imminent termination.
//
// Termination split:
//   - Inner terminated with a non-graceful error (not io.EOF, e.g., a
//     RST_STREAM with a non-zero code surfaced via failStream): propagate
//     to termErr eagerly so callers reading Err() after Closed() see a
//     stable terminal state.
//   - Inner terminated gracefully (io.EOF, e.g., gracefulCloseStream after
//     RST_STREAM(NO_ERROR)): leave termErr nil. The inner h2 channel's
//     contract (RFC-001 §9.1) is that termDone closes before draining
//     the inner recv chan, so any HEADERS/DATA/TRAILERS already buffered
//     there must still surface through subsequent Next calls. Next sets
//     termErr lazily when the inner returns its own io.EOF after drain.
func (c *grpcChannel) watchInnerClose() {
	<-c.inner.Closed()
	if innerErr := c.inner.Err(); innerErr != nil && !errors.Is(innerErr, io.EOF) {
		c.setTermErr(innerErr)
	}
	c.closeRecvDone()
}

// rstInner asks the inner Channel to emit RST_STREAM(INTERNAL_ERROR) and
// mark itself terminated, mirroring the httpaggregator MaxBodySize
// pattern. The inner type may not implement the optional hook (test
// stubs); in that case we simply terminate this wrapper.
func (c *grpcChannel) rstInner(se *layer.StreamError) {
	if rstCh, ok := c.inner.(interface {
		MarkTerminatedWithRST(code uint32, err error)
	}); ok {
		rstCh.MarkTerminatedWithRST(http2.ErrCodeInternal, se)
	}
}

// Next reads the next gRPC envelope. The wrapper consumes one or more
// inner events per Next call until at least one envelope has been
// queued, then drains the queue one envelope at a time on subsequent
// calls.
//
// Ordering: queued envelopes are drained BEFORE the cached termErr is
// returned. This matters when watchInnerClose has fired between an
// absorb (which queued a result) and the next loop iteration — without
// this ordering the absorbed envelope would be silently dropped on the
// stale termErr check. Inner buffered events also continue to drain
// after Closed(): termErr is set only when the inner itself returns an
// error/EOF, not when the inner's Closed() fires.
func (c *grpcChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	for {
		c.mu.Lock()
		// Fast path: emit any envelope already queued by a prior round.
		// Drain queued FIRST so an absorbed envelope is never dropped if
		// watchInnerClose set termErr between the absorb and the next
		// loop iteration.
		if len(c.queued) > 0 {
			out := c.queued[0].env
			c.queued = c.queued[1:]
			c.mu.Unlock()
			return out, nil
		}
		if c.termErr != nil {
			err := c.termErr
			c.mu.Unlock()
			return nil, err
		}
		c.mu.Unlock()

		// Read the next inner event (consuming peeked first if any).
		ev, err := c.nextInnerEvent(ctx)
		if err != nil {
			// Cache the terminal error so subsequent Next calls return it
			// idempotently, and signal Closed() for late watchers. Do NOT
			// cascade to inner.Close; the caller owns the lifecycle (per
			// Channel contract).
			c.setTermErr(err)
			c.closeRecvDone()
			return nil, err
		}

		if absorbErr := c.absorb(ev); absorbErr != nil {
			c.setTermErr(absorbErr)
			c.closeRecvDone()
			return nil, absorbErr
		}
	}
}

// nextInnerEvent returns the next event envelope from the inner Channel,
// consuming the peeked first envelope (if any) before delegating.
func (c *grpcChannel) nextInnerEvent(ctx context.Context) (*envelope.Envelope, error) {
	c.mu.Lock()
	if c.peeked != nil {
		env := c.peeked
		c.peeked = nil
		c.mu.Unlock()
		return env, nil
	}
	c.mu.Unlock()
	return c.inner.Next(ctx)
}

// absorb folds one inner event envelope into queued gRPC envelopes.
// Returns a non-nil error on protocol violation or unsupported encoding;
// the caller terminates the channel with that error.
func (c *grpcChannel) absorb(ev *envelope.Envelope) error {
	switch m := ev.Message.(type) {
	case *http2.H2HeadersEvent:
		return c.absorbHeaders(ev, m)
	case *http2.H2DataEvent:
		return c.absorbData(ev, m)
	case *http2.H2TrailersEvent:
		return c.absorbTrailers(ev, m)
	default:
		// Defensive: HTTP/2 Layer only emits the three known types.
		// Treat anything else as a protocol violation rather than silently
		// dropping data.
		return &layer.StreamError{
			Code:   layer.ErrorProtocol,
			Reason: fmt.Sprintf("grpc: unexpected inner event type %T", ev.Message),
		}
	}
}

// absorbHeaders consumes an H2HeadersEvent. It always emits a
// GRPCStartMessage envelope. If the event is a trailers-only response
// (Direction=Receive, EndStream=true, headers carry grpc-status), it
// additionally synthesizes a GRPCEndMessage envelope per D4.
//
// A second H2HeadersEvent on a direction that already saw Start yields
// a protocol error per the issue spec.
func (c *grpcChannel) absorbHeaders(ev *envelope.Envelope, evt *http2.H2HeadersEvent) error {
	c.mu.Lock()
	dir := c.dirStateLocked(ev.Direction)

	if dir.startEmitted {
		c.mu.Unlock()
		return &layer.StreamError{
			Code:   layer.ErrorProtocol,
			Reason: "grpc: unexpected second HEADERS",
		}
	}

	startMsg, encoding := buildStartMessage(evt, ev.Direction)
	dir.service = startMsg.Service
	dir.method = startMsg.Method
	dir.encoding = encoding
	dir.startEmitted = true

	startEnv := &envelope.Envelope{
		StreamID:  ev.StreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.nextSeq,
		Direction: ev.Direction,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       cloneBytes(ev.Raw),
		Message:   startMsg,
		Context:   ev.Context,
	}
	c.nextSeq++
	c.queued = append(c.queued, pendingEnvelope{env: startEnv})

	// D4: trailers-only response. Receive-side END_STREAM HEADERS that
	// carry grpc-status are simultaneously the start AND the end of the
	// RPC's response side. Synthesize a second GRPCEndMessage envelope
	// from the same headers.
	if ev.Direction == envelope.Receive && evt.EndStream && hasGRPCStatus(evt.Headers) {
		endMsg := buildEndMessage(evt.Headers)
		endEnv := &envelope.Envelope{
			StreamID:  ev.StreamID,
			FlowID:    uuid.New().String(),
			Sequence:  c.nextSeq,
			Direction: ev.Direction,
			Protocol:  envelope.ProtocolGRPC,
			// Synthetic End: no separate wire bytes (the bytes already
			// belong to the GRPCStartMessage envelope's Raw).
			Raw:     nil,
			Message: endMsg,
			Context: ev.Context,
		}
		c.nextSeq++
		c.queued = append(c.queued, pendingEnvelope{env: endEnv})
	}

	c.mu.Unlock()

	// Path-warning: log under Warn outside the mutex to keep critical
	// section short. Service/Method=="" iff buildStartMessage failed to
	// parse; surface to operator (D1 — tolerant).
	if startMsg.Service == "" && startMsg.Method == "" && ev.Direction == envelope.Send {
		slog.Warn("grpc: malformed :path; emitting Service=\"\" Method=\"\"",
			"stream_id", ev.StreamID,
			"path", evt.Path,
		)
	}
	return nil
}

// absorbData consumes one H2DataEvent. Payload bytes feed the per-
// direction LPM reassembler; each completed LPM produces one
// GRPCDataMessage envelope.
//
// END_STREAM propagation (USK-663): the wire bit lives on the H2 DATA
// frame, not on individual LPMs, so the wrapper places it on whichever
// gRPC envelope semantically corresponds to the frame boundary:
//
//   - When the frame's payload completes one or more LPMs, the trailing
//     LPM owns the bit (the LPMs ahead of it are followed by more bytes
//     within the same payload).
//   - When the frame carries END_STREAM with empty payload — the
//     canonical gRPC-Go client pattern emitted by `Stream.CloseSend`
//     (`DATA(payload=msg)` then `DATA(payload=, END_STREAM=1)`) — the
//     wrapper synthesizes an end-marker GRPCDataMessage (Payload=nil,
//     WireLength=0, Compressed=false, EndStream=true). On Send, sendData
//     emits an empty DATA payload with END_STREAM=1, preserving the
//     client's two-frame wire shape.
//   - When END_STREAM arrives mid-LPM (reassembler still in prefix or
//     payload phase with buffered bytes), the half-LPM has no faithful
//     gRPC envelope representation; surface as
//     *layer.StreamError{ErrorProtocol}.
func (c *grpcChannel) absorbData(ev *envelope.Envelope, evt *http2.H2DataEvent) error {
	c.mu.Lock()
	dir := c.dirStateLocked(ev.Direction)
	queuedBefore := len(c.queued)
	frames, err := dir.reasm.feed(evt.Payload, c.maxMessageSize)
	if err != nil {
		c.mu.Unlock()
		if errors.Is(err, errMessageTooLarge) {
			se := &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "grpc: message too large",
			}
			c.rstInner(se)
			return se
		}
		// Defensive: feed currently only produces errMessageTooLarge.
		return fmt.Errorf("grpc: reassemble: %w", err)
	}

	for i := range frames {
		f := frames[i]
		dataEnv, derr := c.buildDataEnvelopeLocked(ev, dir, f)
		if derr != nil {
			c.mu.Unlock()
			c.rstInner(derr)
			return derr
		}
		c.queued = append(c.queued, pendingEnvelope{env: dataEnv})
	}

	if evt.EndStream {
		// Reject mid-LPM termination: the reassembler still holds a
		// partial prefix or partial payload after consuming this frame.
		if dir.reasm.phase != phaseWaitingPrefix || len(dir.reasm.prefBuf) > 0 {
			c.mu.Unlock()
			se := &layer.StreamError{
				Code:   layer.ErrorProtocol,
				Reason: "grpc: stream ended mid-LPM",
			}
			c.rstInner(se)
			return se
		}
		if added := len(c.queued) - queuedBefore; added > 0 {
			// Fused: stamp END_STREAM on the trailing LPM of this frame.
			c.queued[len(c.queued)-1].env.Message.(*envelope.GRPCDataMessage).EndStream = true
		} else {
			// Separate end-marker frame: emit a synthetic empty
			// GRPCDataMessage envelope. Roundtrips on Send as DATA(empty,
			// END_STREAM=1).
			c.queued = append(c.queued, pendingEnvelope{
				env: c.buildEndMarkerEnvelopeLocked(ev, dir),
			})
		}
	}

	c.mu.Unlock()
	return nil
}

// buildEndMarkerEnvelopeLocked synthesizes a GRPCDataMessage envelope
// representing a pure END_STREAM marker — no LPM payload, just the wire
// signal. Identified on Send by the (Payload==nil, WireLength==0,
// !Compressed, EndStream=true) shape; sendData maps it to an empty H2
// DATA payload. Must hold c.mu (the caller does).
func (c *grpcChannel) buildEndMarkerEnvelopeLocked(ev *envelope.Envelope, dir *directionState) *envelope.Envelope {
	msg := &envelope.GRPCDataMessage{
		Service:    dir.service,
		Method:     dir.method,
		Compressed: false,
		WireLength: 0,
		Payload:    nil,
		EndStream:  true,
	}
	out := &envelope.Envelope{
		StreamID:  ev.StreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.nextSeq,
		Direction: ev.Direction,
		Protocol:  envelope.ProtocolGRPC,
		// Raw is empty: the wire contributes no LPM bytes for an
		// end-marker frame. sendData detects this shape and emits an
		// empty H2 DATA payload.
		Raw:     nil,
		Message: msg,
		Context: ev.Context,
	}
	c.nextSeq++
	return out
}

// buildDataEnvelopeLocked decodes one LPM into a GRPCDataMessage envelope.
// Must hold c.mu.
func (c *grpcChannel) buildDataEnvelopeLocked(ev *envelope.Envelope, dir *directionState, f lpmFrame) (*envelope.Envelope, *layer.StreamError) {
	payload := f.Payload
	if f.Compressed && f.WireLength > 0 {
		// D2: only identity (treated as no-op) and gzip are supported.
		enc := strings.ToLower(strings.TrimSpace(dir.encoding))
		switch enc {
		case "", encodingIdentity:
			// Compressed=true with no/identity encoding: leave Payload as-
			// is; this is a wire-level oddity (compression flag without
			// negotiated encoding) but per-message-compress can occur even
			// when encoding header is absent. Surface payload verbatim.
		case encodingGzip:
			decoded, derr := gunzip(payload, c.maxMessageSize)
			if derr != nil {
				if errors.Is(derr, errMessageTooLarge) {
					// CWE-409: decompression-bomb cap exceeded. Map to
					// ErrorInternalError so the caller RSTs the stream
					// (same code path as the wire-LPM cap in
					// reassembler.feed).
					return nil, &layer.StreamError{
						Code:   layer.ErrorInternalError,
						Reason: "grpc: decompressed message too large",
					}
				}
				return nil, &layer.StreamError{
					Code:   layer.ErrorProtocol,
					Reason: "grpc: gzip decode: " + derr.Error(),
				}
			}
			payload = decoded
		default:
			return nil, &layer.StreamError{
				Code:   layer.ErrorProtocol,
				Reason: fmt.Sprintf("grpc: unsupported grpc-encoding: %s", enc),
			}
		}
	}

	// Build the wire-form Raw: 5-byte LPM prefix + compressed-payload-as-
	// observed (NOT the decoded Payload).
	rawBuf := make([]byte, lpmPrefixLen+len(f.Payload))
	if f.Compressed {
		rawBuf[0] = 1
	}
	binary.BigEndian.PutUint32(rawBuf[1:5], f.WireLength)
	copy(rawBuf[lpmPrefixLen:], f.Payload)

	msg := &envelope.GRPCDataMessage{
		Service:    dir.service,
		Method:     dir.method,
		Compressed: f.Compressed,
		WireLength: f.WireLength,
		Payload:    payload,
	}

	out := &envelope.Envelope{
		StreamID:  ev.StreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.nextSeq,
		Direction: ev.Direction,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       rawBuf,
		Message:   msg,
		Context:   ev.Context,
	}
	c.nextSeq++
	return out, nil
}

// absorbTrailers consumes one H2TrailersEvent. Always Direction=Receive
// per RFC 9113 §8.1; produces one GRPCEndMessage envelope.
func (c *grpcChannel) absorbTrailers(ev *envelope.Envelope, evt *http2.H2TrailersEvent) error {
	c.mu.Lock()
	endMsg := buildEndMessage(evt.Trailers)
	endEnv := &envelope.Envelope{
		StreamID:  ev.StreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.nextSeq,
		Direction: ev.Direction,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       cloneBytes(ev.Raw),
		Message:   endMsg,
		Context:   ev.Context,
	}
	c.nextSeq++
	c.queued = append(c.queued, pendingEnvelope{env: endEnv})
	c.mu.Unlock()
	return nil
}

// dirStateLocked returns a pointer to the directionState for d. Must hold
// c.mu (the caller does).
func (c *grpcChannel) dirStateLocked(d envelope.Direction) *directionState {
	if d == envelope.Send {
		return &c.send
	}
	return &c.recv
}

// Send re-encodes a gRPC envelope back into HTTP/2 events on the inner
// Channel. The inner Channel is responsible for HPACK encoding +
// CONTINUATION splitting + flow control.
//
// GRPCStartMessage / GRPCEndMessage envelopes always rebuild the HPACK
// header field list from struct fields; Envelope.Raw on these types is
// informational only (the wire-observed HPACK block bytes change every
// time HPACK dynamic tables differ).
//
// GRPCDataMessage envelopes prefer Envelope.Raw verbatim when non-empty
// (to round-trip exact wire bytes). Otherwise the wrapper re-encodes
// Payload using Compressed + the negotiated grpc-encoding.
func (c *grpcChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	if env == nil || env.Message == nil {
		return errors.New("grpc: Send: nil envelope or Message")
	}
	switch m := env.Message.(type) {
	case *envelope.GRPCStartMessage:
		return c.sendStart(ctx, env, m)
	case *envelope.GRPCDataMessage:
		return c.sendData(ctx, env, m)
	case *envelope.GRPCEndMessage:
		return c.sendEnd(ctx, env, m)
	default:
		return fmt.Errorf("grpc: Send: unsupported Message type %T", env.Message)
	}
}

// sendStart converts a GRPCStartMessage envelope into an H2HeadersEvent
// envelope and dispatches it on the inner Channel. The negotiated
// grpc-encoding is remembered for subsequent Send-direction LPM
// re-encoding.
func (c *grpcChannel) sendStart(ctx context.Context, env *envelope.Envelope, m *envelope.GRPCStartMessage) error {
	headers := buildStartHeaderKVs(env, m)

	// Compute :path either from Service/Method or from a fallback. Empty
	// Service+Method preserves the malformed-path round-trip case (the
	// Layer is permissive on Receive per D1; on Send we mirror the
	// caller's intent — if they cleared both, we emit "/").
	pathPseudo := buildGRPCPath(m.Service, m.Method)

	// EndStream on a Send-side Start is unusual (gRPC clients always
	// follow with at least one DATA), but if no body or trailers will
	// follow, the next Send call may be an End. We never set EndStream
	// here on Start: gRPC requires DATA + trailer HEADERS minimum.
	hdrEvt := &http2.H2HeadersEvent{
		Method:    methodOr(m, env, "POST"),
		Scheme:    schemeFromContext(env, "https"),
		Authority: authorityFromContext(env),
		Path:      pathPseudo,
		Status:    statusFor(env, m),
		Headers:   headers,
		EndStream: false,
	}

	// Cache the encoding for re-compression of subsequent LPMs in this
	// direction.
	c.mu.Lock()
	dir := c.dirStateLocked(env.Direction)
	dir.service = m.Service
	dir.method = m.Method
	dir.encoding = m.Encoding
	dir.startEmitted = true
	c.mu.Unlock()

	innerEnv := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Message:   hdrEvt,
		Context:   env.Context,
	}
	return c.inner.Send(ctx, innerEnv)
}

// sendData converts a GRPCDataMessage envelope into an H2DataEvent
// envelope. When env.Raw is populated (5-byte prefix + compressed
// payload), it is emitted verbatim. Otherwise the wrapper rebuilds the
// LPM from m.Payload + m.Compressed + the negotiated grpc-encoding.
//
// Pure end-marker envelopes (USK-663) — Payload==nil, WireLength==0,
// !Compressed, EndStream=true — emit an empty H2 DATA payload, matching
// the canonical gRPC-Go CloseSend wire shape DATA(empty, END_STREAM=1).
func (c *grpcChannel) sendData(ctx context.Context, env *envelope.Envelope, m *envelope.GRPCDataMessage) error {
	var wire []byte
	switch {
	case len(env.Raw) > 0:
		// Round-trip exact wire bytes (intercept/transform tests).
		wire = append([]byte(nil), env.Raw...)
	case m.Payload == nil && m.WireLength == 0 && !m.Compressed && m.EndStream:
		// Pure end-marker: empty DATA payload + END_STREAM=1.
		wire = nil
	default:
		c.mu.Lock()
		dir := c.dirStateLocked(env.Direction)
		enc := strings.ToLower(strings.TrimSpace(dir.encoding))
		c.mu.Unlock()

		var payload []byte
		var err error
		if m.Compressed && len(m.Payload) > 0 {
			switch enc {
			case "", encodingIdentity:
				payload = m.Payload
			case encodingGzip:
				payload, err = gzipBytes(m.Payload)
				if err != nil {
					return fmt.Errorf("grpc: gzip encode: %w", err)
				}
			default:
				return &layer.StreamError{
					Code:   layer.ErrorProtocol,
					Reason: fmt.Sprintf("grpc: unsupported grpc-encoding: %s", enc),
				}
			}
		} else {
			payload = m.Payload
		}

		wire = make([]byte, lpmPrefixLen+len(payload))
		if m.Compressed {
			wire[0] = 1
		}
		binary.BigEndian.PutUint32(wire[1:5], uint32(len(payload)))
		copy(wire[lpmPrefixLen:], payload)
	}

	dataEvt := &http2.H2DataEvent{
		Payload:   wire,
		EndStream: m.EndStream,
	}
	innerEnv := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Message:   dataEvt,
		Context:   env.Context,
	}
	return c.inner.Send(ctx, innerEnv)
}

// sendEnd converts a GRPCEndMessage envelope into an H2TrailersEvent
// envelope. The trailer fields are reconstructed from m.Status,
// m.Message, m.StatusDetails, and m.Trailers (non-status remainder).
func (c *grpcChannel) sendEnd(ctx context.Context, env *envelope.Envelope, m *envelope.GRPCEndMessage) error {
	trailers := buildEndTrailerKVs(m)
	tEvt := &http2.H2TrailersEvent{
		Trailers: trailers,
	}
	innerEnv := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Message:   tEvt,
		Context:   env.Context,
	}
	return c.inner.Send(ctx, innerEnv)
}

// buildStartMessage parses an H2HeadersEvent's Headers into a
// GRPCStartMessage. It also returns the parsed grpc-encoding so the
// caller can cache it for subsequent LPM re-encoding.
func buildStartMessage(evt *http2.H2HeadersEvent, dir envelope.Direction) (*envelope.GRPCStartMessage, string) {
	msg := &envelope.GRPCStartMessage{}
	for _, kv := range evt.Headers {
		name := strings.ToLower(kv.Name)
		switch name {
		case "content-type":
			msg.ContentType = kv.Value
			continue
		case "grpc-encoding":
			msg.Encoding = kv.Value
			continue
		case "grpc-accept-encoding":
			msg.AcceptEncoding = splitCommaTrim(kv.Value)
			continue
		case "grpc-timeout":
			msg.Timeout = parseGRPCTimeout(kv.Value)
			continue
		}
		if strings.HasPrefix(kv.Name, ":") {
			// Pseudo-headers (any case) — Layer-level concern.
			continue
		}
		msg.Metadata = append(msg.Metadata, envelope.KeyValue{
			Name:  kv.Name,
			Value: kv.Value,
		})
	}

	// Service / Method on the request side derive from :path; on the
	// response side they are mirrored from the request side by the
	// channel.absorbHeaders caller (the response carries no :path).
	if dir == envelope.Send {
		msg.Service, msg.Method = parseGRPCPath(evt.Path)
	}
	return msg, msg.Encoding
}

// buildEndMessage parses a trailer (or trailers-only header) list into a
// GRPCEndMessage. grpc-status / grpc-message / grpc-status-details-bin
// are extracted; remaining metadata is preserved on Trailers in wire
// order/case.
func buildEndMessage(kvs []envelope.KeyValue) *envelope.GRPCEndMessage {
	msg := &envelope.GRPCEndMessage{}
	for _, kv := range kvs {
		name := strings.ToLower(kv.Name)
		switch name {
		case "grpc-status":
			msg.Status = parseGRPCStatus(kv.Value)
			continue
		case "grpc-message":
			msg.Message = percentDecode(kv.Value)
			continue
		case "grpc-status-details-bin":
			msg.StatusDetails = decodeBase64URL(kv.Value)
			continue
		}
		if strings.HasPrefix(kv.Name, ":") {
			// Pseudo-headers in trailers are invalid (RFC 9113 §8.1);
			// Layer surfaces an anomaly. Skip them here.
			continue
		}
		msg.Trailers = append(msg.Trailers, envelope.KeyValue{
			Name:  kv.Name,
			Value: kv.Value,
		})
	}
	return msg
}

// hasGRPCStatus reports whether kvs contains a "grpc-status" entry
// (case-insensitive). Used to detect the trailers-only response case.
func hasGRPCStatus(kvs []envelope.KeyValue) bool {
	for _, kv := range kvs {
		if strings.EqualFold(kv.Name, "grpc-status") {
			return true
		}
	}
	return false
}

// parseGRPCPath splits ":path" into (Service, Method). Tolerant per D1:
// malformed inputs return ("", "").
//
//	"/pkg.Service/Method"          → ("pkg.Service", "Method")
//	"/pkg.subpkg.Service/Method"   → ("pkg.subpkg.Service", "Method")
//	""                             → ("", "")
//	"foo"                          → ("", "")
//	"/foo"                         → ("", "")
//	"/"                            → ("", "")
func parseGRPCPath(path string) (string, string) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", ""
	}
	rest := path[1:]
	idx := strings.LastIndex(rest, "/")
	if idx <= 0 || idx == len(rest)-1 {
		// No separator, leading separator only, or trailing separator.
		return "", ""
	}
	return rest[:idx], rest[idx+1:]
}

// buildGRPCPath is the inverse of parseGRPCPath. Empty service+method
// yields "/" so the wire form remains technically valid.
func buildGRPCPath(service, method string) string {
	if service == "" && method == "" {
		return "/"
	}
	return "/" + service + "/" + method
}

// parseGRPCStatus parses a uint32 status code; defaults to 0 (OK) on
// parse failure (gRPC compatibility — peers MAY send malformed values).
func parseGRPCStatus(v string) uint32 {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// parseGRPCTimeout parses a "grpc-timeout" value of the form <n><unit>
// where unit ∈ {H, M, S, m, u, n}. Returns 0 on parse failure.
func parseGRPCTimeout(v string) time.Duration {
	v = strings.TrimSpace(v)
	if len(v) < 2 {
		return 0
	}
	unit := v[len(v)-1]
	num, err := strconv.ParseInt(v[:len(v)-1], 10, 64)
	if err != nil || num < 0 {
		return 0
	}
	switch unit {
	case 'H':
		return time.Duration(num) * time.Hour
	case 'M':
		return time.Duration(num) * time.Minute
	case 'S':
		return time.Duration(num) * time.Second
	case 'm':
		return time.Duration(num) * time.Millisecond
	case 'u':
		return time.Duration(num) * time.Microsecond
	case 'n':
		return time.Duration(num) * time.Nanosecond
	default:
		return 0
	}
}

// formatGRPCTimeout serializes a time.Duration to "<n><unit>". Picks the
// largest unit that yields a non-fractional integer, with a fallback to
// nanoseconds for sub-microsecond values. Empty for zero/negative.
func formatGRPCTimeout(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	switch {
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "H"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "M"
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "S"
	case d%time.Millisecond == 0:
		return strconv.FormatInt(int64(d/time.Millisecond), 10) + "m"
	case d%time.Microsecond == 0:
		return strconv.FormatInt(int64(d/time.Microsecond), 10) + "u"
	default:
		return strconv.FormatInt(int64(d), 10) + "n"
	}
}

// percentDecode decodes %XX escapes in s. Invalid escapes are left
// verbatim (gRPC interop tolerance).
func percentDecode(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+2 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String()
}

// percentEncode escapes ASCII control bytes, '%', and non-ASCII for
// the grpc-message wire form. Conservative (encode anything outside
// [0x20, 0x7E] except '%').
func percentEncode(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '%' {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '%' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// unhex returns the numeric value of a single hex digit and whether it
// was a valid hex character.
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodeBase64URL decodes a base64-URL-no-padding value (gRPC HTTP/2
// binary header convention). Returns nil on decode failure (malformed
// peer; surface anomalies via Layer-level handling).
func decodeBase64URL(v string) []byte {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	out, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		// Some peers include padding even though the spec calls for none;
		// fall back to padded URL encoding before giving up.
		if alt, e2 := base64.URLEncoding.DecodeString(v); e2 == nil {
			return alt
		}
		return nil
	}
	return out
}

// encodeBase64URL encodes bytes for grpc-status-details-bin (no padding
// per RFC 7541-bin convention).
func encodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// splitCommaTrim splits s on "," and trims surrounding whitespace from
// each entry. Empty entries are preserved as empty strings. Empty input
// yields nil.
func splitCommaTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.TrimSpace(p)
	}
	return out
}

// buildStartHeaderKVs constructs the wire header list for a Send-side
// GRPCStartMessage. Conventional ordering: content-type, grpc-encoding,
// grpc-accept-encoding, grpc-timeout, then user metadata in original
// order. Pseudo-headers are emitted by BuildHeaderFieldsFromEvent on the
// inner H2 channel (they are NOT included in evt.Headers).
func buildStartHeaderKVs(env *envelope.Envelope, m *envelope.GRPCStartMessage) []envelope.KeyValue {
	const reserveExtra = 4
	out := make([]envelope.KeyValue, 0, len(m.Metadata)+reserveExtra)

	ct := m.ContentType
	if ct == "" {
		ct = "application/grpc"
	}
	out = append(out, envelope.KeyValue{Name: "content-type", Value: ct})

	if m.Encoding != "" {
		out = append(out, envelope.KeyValue{Name: "grpc-encoding", Value: m.Encoding})
	}
	if len(m.AcceptEncoding) > 0 {
		out = append(out, envelope.KeyValue{
			Name:  "grpc-accept-encoding",
			Value: strings.Join(m.AcceptEncoding, ","),
		})
	}
	if m.Timeout > 0 {
		if v := formatGRPCTimeout(m.Timeout); v != "" {
			out = append(out, envelope.KeyValue{Name: "grpc-timeout", Value: v})
		}
	}

	// "te: trailers" is conventional on gRPC requests (not strictly
	// required, but many servers reject without it). Emit only on
	// Send-direction Start, and only if the user did not already
	// supply one.
	if env.Direction == envelope.Send && !hasHeader(m.Metadata, "te") {
		out = append(out, envelope.KeyValue{Name: "te", Value: "trailers"})
	}

	out = append(out, m.Metadata...)
	return out
}

// hasHeader reports whether kvs contains a header with case-insensitive
// name match.
func hasHeader(kvs []envelope.KeyValue, name string) bool {
	for _, kv := range kvs {
		if strings.EqualFold(kv.Name, name) {
			return true
		}
	}
	return false
}

// buildEndTrailerKVs constructs the wire trailer list for a Send-side
// GRPCEndMessage. grpc-status is emitted first (peers commonly look for
// it with no scan), followed by grpc-message and grpc-status-details-bin
// when populated, then user trailers in original order.
func buildEndTrailerKVs(m *envelope.GRPCEndMessage) []envelope.KeyValue {
	out := make([]envelope.KeyValue, 0, len(m.Trailers)+3)
	out = append(out, envelope.KeyValue{
		Name:  "grpc-status",
		Value: strconv.FormatUint(uint64(m.Status), 10),
	})
	if m.Message != "" {
		out = append(out, envelope.KeyValue{
			Name:  "grpc-message",
			Value: percentEncode(m.Message),
		})
	}
	if len(m.StatusDetails) > 0 {
		out = append(out, envelope.KeyValue{
			Name:  "grpc-status-details-bin",
			Value: encodeBase64URL(m.StatusDetails),
		})
	}
	out = append(out, m.Trailers...)
	return out
}

// methodOr returns evt.Method when set, else fallback. POST is the
// canonical gRPC verb.
func methodOr(_ *envelope.GRPCStartMessage, env *envelope.Envelope, fallback string) string {
	_ = env
	return fallback
}

// schemeFromContext picks "https" when TLS metadata is present on the
// envelope context, "http" otherwise (with a final fallback). gRPC over
// plaintext is technically allowed.
func schemeFromContext(env *envelope.Envelope, fallback string) string {
	if env != nil && env.Context.TLS != nil {
		return "https"
	}
	return fallback
}

// authorityFromContext returns env.Context.TargetHost when set; empty
// otherwise. The HTTP/2 Layer's BuildHeaderFieldsFromEvent does not emit
// an empty :authority, which matches gRPC's wire reality (some servers
// reject empty :authority).
func authorityFromContext(env *envelope.Envelope) string {
	if env == nil {
		return ""
	}
	return env.Context.TargetHost
}

// statusFor returns evt.Status for a Receive-side Start envelope (HTTP
// 200 typical), else 0. The HTTP/2 Layer's encoder uses Status to choose
// between request and response pseudo-headers when env.Direction is not
// available.
func statusFor(env *envelope.Envelope, _ *envelope.GRPCStartMessage) int {
	if env != nil && env.Direction == envelope.Receive {
		return 200
	}
	return 0
}

// gunzip decompresses a gzip-encoded LPM payload. The decompressed length
// is capped at max bytes (CWE-409: decompression-bomb mitigation). If the
// decompressed stream would exceed max, gunzip returns errMessageTooLarge
// so the channel maps it to *layer.StreamError{Code: ErrorInternalError}
// and RSTs the stream. The caller passes the per-Channel cap resolved at
// Wrap time (defaulting to config.MaxGRPCMessageSize when no
// WithMaxMessageSize Option is supplied).
func gunzip(b []byte, max uint32) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	// Read up to max+1 bytes; an exact-max read is fine, max+1 means we
	// hit the cap and must reject. io.LimitReader returns io.EOF at the
	// limit even if more bytes are available in the underlying stream.
	lr := io.LimitReader(r, int64(max)+1)
	out, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if uint32(len(out)) > max {
		return nil, errMessageTooLarge
	}
	return out, nil
}

// gzipBytes compresses a payload at the default level. Pure (no shared
// state). Returns the compressed bytes.
func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// cloneBytes returns a copy of b, or nil if b is nil/empty.
func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

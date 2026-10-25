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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
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
// max bounds the maximum payload size; exceeding it returns an
// *lpmTooLargeError (errors.Is errMessageTooLarge; the channel maps it to
// a *layer.StreamError). The frames completed earlier in the same src are
// returned alongside the error so the caller can still record them
// (USK-1254).
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
				return out, r.tooLarge(src, max)
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
				Prefix:     r.prefix,
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

// tooLarge builds the error feed returns when the just-completed prefix
// declares more than max payload bytes. r.prefBuf holds the 5 observed
// prefix bytes (possibly accumulated across DATA frames) and src is the
// remainder of the current DATA frame after the prefix. The captured bytes
// are the verbatim prefix plus at most the declared length of src —
// nothing beyond the current DATA event is read (USK-1254).
func (r *reassembler) tooLarge(src []byte, max uint32) *lpmTooLargeError {
	take := len(src)
	if uint64(take) > uint64(r.wireLen) {
		take = int(r.wireLen)
	}
	raw := make([]byte, 0, len(r.prefBuf)+take)
	raw = append(raw, r.prefBuf...)
	raw = append(raw, src[:take]...)
	return &lpmTooLargeError{
		declared:   r.wireLen,
		max:        max,
		compressed: r.compress,
		raw:        raw,
	}
}

// partial reports the observed bytes of the LPM still being reassembled
// (USK-1254), as a fresh slice. In the prefix phase it is the 1-4 prefix
// bytes seen so far (prefixComplete=false); in the payload phase it is the
// verbatim 5-byte prefix plus the payload bytes received so far. ok is
// false when no LPM is in progress.
func (r *reassembler) partial() (raw []byte, prefixComplete, ok bool) {
	switch r.phase {
	case phaseWaitingPrefix:
		if len(r.prefBuf) == 0 {
			return nil, false, false
		}
		return append([]byte(nil), r.prefBuf...), false, true
	case phaseWaitingPayload:
		raw = make([]byte, 0, lpmPrefixLen+len(r.payload))
		raw = append(raw, r.prefix[:]...)
		raw = append(raw, r.payload...)
		return raw, true, true
	}
	return nil, false, false
}

// lpmFrame is one fully reassembled LPM. Payload is the compressed bytes
// (or raw bytes if Compressed=false) — decompression happens in the
// channel's emit path. Prefix is the 5-byte prefix exactly as observed on
// the wire (the flag byte is not normalized to 0/1).
type lpmFrame struct {
	Prefix     [lpmPrefixLen]byte
	Compressed bool
	WireLength uint32
	Payload    []byte
}

// wireBytes returns the LPM exactly as observed (verbatim prefix +
// payload) in a fresh slice. It is the source of every LPM's Raw — the
// semantic Data envelope and all grpc-lpm-frame record paths — so the
// flag byte is never normalized to 0/1.
func (f lpmFrame) wireBytes() []byte {
	out := make([]byte, 0, lpmPrefixLen+len(f.Payload))
	out = append(out, f.Prefix[:]...)
	return append(out, f.Payload...)
}

// lpmTooLargeError is returned by reassembler.feed when an LPM prefix
// declares a length above the per-Channel cap. It carries what was
// observed of the rejected LPM so the channel can record it as an
// AnomalyGRPCLPMTooLarge row (USK-1254). errors.Is(err,
// errMessageTooLarge) holds.
type lpmTooLargeError struct {
	declared   uint32
	max        uint32
	compressed bool
	raw        []byte // verbatim prefix + payload bytes of the same DATA frame (≤ declared)
}

func (e *lpmTooLargeError) Error() string { return errMessageTooLarge.Error() }
func (e *lpmTooLargeError) Unwrap() error { return errMessageTooLarge }

// errMessageTooLarge is returned by reassembler.feed when an LPM length
// exceeds the per-Channel cap (defaults to config.MaxGRPCMessageSize but
// is overridable via WithMaxMessageSize). The channel maps it to a
// *layer.StreamError.
var errMessageTooLarge = errors.New("grpc: message too large")

// errSendAfterEnd is returned by Send when the requested direction already
// emitted its End (END_STREAM went out). Anything after END_STREAM on the
// same h2 stream is a STREAM_CLOSED connection error (RFC 9113 §5.1) that
// would kill every RPC multiplexed on the connection, so the Channel
// refuses it (USK-1202).
var errSendAfterEnd = errors.New("grpc: send after End on this direction")

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
	contentType  string // content-type of this direction's Start (wire value)
	// endSent latches once Send emitted this direction's End (END_STREAM
	// went out). Every later Send on the direction fails with
	// errSendAfterEnd (USK-1202).
	endSent bool
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

	// sendMu serializes Send. It is held across the direction-state check
	// and the inner Send so a racing Send cannot slip a frame in between
	// (e.g. response HEADERS enqueued after a proxy-synthesized
	// Trailers-Only, or anything after END_STREAM). Never acquired while
	// holding mu, and never acquired by the Next path (USK-1202).
	//
	// A Data Send parked on the peer's flow control keeps holding sendMu
	// until the write completes, its ctx is cancelled, or the Layer shuts
	// down, so a terminator Send queues behind it. That is intentional:
	// trailers must not overtake DATA already committed to the stream.
	sendMu sync.Mutex

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

	// lifecycleEngine drives (grpc, on_end) hook dispatch (USK-683).
	// nil = no-op. fireOnEnd uses onEndOnce to guarantee the hook
	// fires at most once per Channel even when both the trailers-only
	// (D4) and the absorbTrailers paths produce End envelopes.
	lifecycleEngine *pluginv2.Engine
	onEndOnce       sync.Once

	// lpmFrameRecordCallback is the optional per-LPM wire-record hook
	// installed via WithLPMFrameRecordCallback (USK-896). When non-nil,
	// fireLPMFrameRecord invokes it from absorbData with a pre-built
	// wire envelope BEFORE the matching GRPCDataMessage envelope is
	// queued. See WithLPMFrameRecordCallback for the contract.
	lpmFrameRecordCallback func(*envelope.Envelope)

	// h2DataFrameRecordCallback is the optional per-H2-DATA-frame
	// wire-record hook installed via WithH2DataFrameRecordCallback
	// (USK-899). When non-nil, absorbData invokes it BEFORE acquiring
	// c.mu and BEFORE LPM reassembly with a pre-built wire envelope
	// carrying the DATA frame payload bytes (a defensive copy of
	// evt.Payload) and Protocol=ProtocolHTTP. The callback fires for
	// EVERY absorbed H2DataEvent — including empty END_STREAM frames
	// AND the error paths that return *layer.StreamError without
	// queuing any semantic envelope (LPM cap trip, mid-LPM EOS, gzip
	// decode failure). Analysts observe per-frame boundaries on the
	// native-gRPC path symmetrically with the USK-897 aggregator-path
	// coverage. See WithH2DataFrameRecordCallback for the contract.
	h2DataFrameRecordCallback func(*envelope.Envelope)

	// pendingResp holds the response HEADERS sendStart deferred because
	// the upstream's HEADERS frame carried END_STREAM (opaqueGRPC.
	// endStreamEnd): sendEnd writes it back as ONE HEADERS frame with
	// END_STREAM, folding in any End edit (USK-1251). A sendData in
	// between flushes it first without END_STREAM. Guarded by sendMu.
	pendingResp *pendingResponseHeaders
}

// pendingResponseHeaders is a deferred response HEADERS event (see
// grpcChannel.pendingResp) plus the End the upstream-side Layer emitted
// for the same frame, against which an End edit is detected.
type pendingResponseHeaders struct {
	env      *envelope.Envelope // inner envelope carrying the *http2.H2HeadersEvent
	baseline *envelope.GRPCEndMessage
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
	c.closeWith(c.inner.Close)
	return nil
}

// CloseWithCode is Close with the RST_STREAM error code the session wants
// the client to see: the upstream's own reset code (USK-1269) or
// REFUSED_STREAM for an upstream refusal (USK-1157). It cascades to the
// inner Channel's CloseWithCode when it has one (the HTTP/2 stream applies
// the code subject to its wire state), else to its Close. Shares Close's
// sync.Once.
func (c *grpcChannel) CloseWithCode(code uint32) error {
	c.closeWith(func() error {
		if cc, ok := c.inner.(interface{ CloseWithCode(uint32) error }); ok {
			return cc.CloseWithCode(code)
		}
		return c.inner.Close()
	})
	return nil
}

// closeWith is the single teardown path behind Close and CloseWithCode;
// closeInner cascades to the inner Channel.
func (c *grpcChannel) closeWith(closeInner func() error) {
	c.closeOnce.Do(func() {
		_ = closeInner()
		c.setTermErr(io.EOF)
		c.closeRecvDone()
	})
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

// fireOnEnd dispatches (grpc, on_end) hooks for the first emitted End
// envelope. Subsequent calls are no-ops via sync.Once. nil engine and
// nil End message are no-ops. The hook fires synchronously from the
// absorb path so it runs before the inner HTTP/2 channel terminates and
// any stream_state seeded by on_data hooks is released. Errors from
// FireLifecycle are swallowed: a misbehaving plugin must not break wire
// teardown (USK-671 fail-soft contract).
func (c *grpcChannel) fireOnEnd(env *envelope.Envelope, m *envelope.GRPCEndMessage) {
	if c.lifecycleEngine == nil || env == nil || m == nil {
		return
	}
	c.onEndOnce.Do(func() {
		payload := pluginv2.BuildGRPCEndDict(m)
		_, _ = c.lifecycleEngine.FireLifecycle(context.Background(), pluginv2.ProtoGRPC, pluginv2.EventOnEnd, env, payload)
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
// GRPCStartMessage envelope. If the event is a Receive HEADERS frame with
// END_STREAM (a trailers-only response, or one without any grpc-status),
// it additionally synthesizes a GRPCEndMessage envelope per D4.
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
	// USK-1251: the observed control-header layout rides on the Start so
	// the opposite-side Channel's sendStart can restore it.
	opaque := &opaqueGRPC{layout: newHeaderLayout(evt.Headers, startMsg)}
	dir.service = startMsg.Service
	dir.method = startMsg.Method
	dir.encoding = encoding
	dir.contentType = startMsg.ContentType
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
		Opaque:    opaque,
	}
	c.nextSeq++
	c.queued = append(c.queued, pendingEnvelope{env: startEnv})

	// D4: a Receive-side HEADERS frame with END_STREAM is simultaneously
	// the start AND the end of the RPC's response side, so a second
	// GRPCEndMessage envelope is synthesized from the same frame:
	//
	//   - trailers-only response (grpc-status present): the End is parsed
	//     from the headers.
	//   - no grpc-status at all (e.g. a load balancer's bare 503): the End
	//     is a Status=0 placeholder stamped AnomalyGRPCMissingStatus
	//     (USK-1251). Without it the client-side Send never learnt the
	//     response had ended and the client never saw END_STREAM.
	//
	// Both share the Start's Opaque, whose endStreamEnd baseline makes the
	// opposite-side Send write the response back as one END_STREAM
	// HEADERS frame (sendEnd).
	var firedEndEnv *envelope.Envelope
	var firedEndMsg *envelope.GRPCEndMessage
	if ev.Direction == envelope.Receive && evt.EndStream {
		var endMsg *envelope.GRPCEndMessage
		if hasGRPCStatus(evt.Headers) {
			endMsg = buildEndMessage(evt.Headers)
		} else {
			endMsg = &envelope.GRPCEndMessage{Anomalies: []envelope.Anomaly{{
				Type:   envelope.AnomalyGRPCMissingStatus,
				Detail: "response HEADERS carried END_STREAM without grpc-status",
			}}}
		}
		opaque.endStreamEnd = snapshotEnd(endMsg)
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
			Opaque:  opaque,
		}
		c.nextSeq++
		c.queued = append(c.queued, pendingEnvelope{env: endEnv})
		firedEndEnv = endEnv
		firedEndMsg = endMsg
	}

	c.mu.Unlock()

	// Fire (grpc, on_end) outside the mutex so a slow plugin does not
	// block the consumer's Next path. fireOnEnd is sync.Once-gated, so a
	// later End from absorbTrailers (which would not happen for a true
	// trailers-only response, but defensively) is a no-op.
	if firedEndEnv != nil {
		c.fireOnEnd(firedEndEnv, firedEndMsg)
	}

	// Path-log: emitted outside the mutex to keep the critical section
	// short. Service/Method=="" iff buildStartMessage failed to parse.
	// Debug, not Warn (USK-1075): the trigger is client-controlled and
	// fires once per stream with no dedup, so H2 multiplexing turns it
	// into a log-amplification vector on untrusted input — CLAUDE.md's
	// "client sends invalid request" Debug row. The D1 "surface to
	// operator" rationale does not need Warn: the observed :path has
	// always survived into Envelope.Raw, reaches the flow record via
	// USK-920, and since USK-1053 rides the re-emitted wire too.
	if startMsg.Service == "" && startMsg.Method == "" && ev.Direction == envelope.Send {
		slog.Debug("grpc: malformed :path; emitting Service=\"\" Method=\"\"",
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
//     *layer.StreamError{ErrorProtocol}. Its observed bytes are still
//     recorded through the LPM record callback as an
//     AnomalyGRPCLPMTruncated row (USK-1254), as are the observed bytes
//     of an LPM rejected by the message-size cap (AnomalyGRPCLPMTooLarge).
func (c *grpcChannel) absorbData(ev *envelope.Envelope, evt *http2.H2DataEvent) error {
	// USK-899 (F-1 fix): fire the per-H2-DATA-frame wire-record callback
	// BEFORE LPM reassembly and BEFORE acquiring c.mu. The h2-frame
	// envelope captures the DATA frame payload as observed on the wire,
	// so it must fire UNCONDITIONALLY — including on the LPM-cap-trip
	// path (errMessageTooLarge below), the mid-LPM END_STREAM path, and
	// the buildDataEnvelopeLocked error path. Those error paths are
	// precisely the smuggling / attack-signature scenarios the
	// wire_level=h2-frame view was designed to make observable, mirroring
	// USK-897's aggregator-path behavior (the aggregator fires the
	// callback BEFORE the MaxBodySize gate).
	//
	// The envelope construction is independent of any locked channel
	// state (it only reads ev and evt, both per-event values not shared
	// with other goroutines), so building and firing the callback outside
	// c.mu is correct and contention-free. The callback contract
	// (WithH2DataFrameRecordCallback godoc) guarantees the closure must
	// not call back into the channel, so single-goroutine fire ordering
	// holds: h2-frame → grpc-lpm-frame → semantic, per CLAUDE.md MITM
	// Principle 3 (wire-record top-down by framing layer).
	if c.h2DataFrameRecordCallback != nil {
		c.h2DataFrameRecordCallback(buildH2DataFrameWireEnvelope(ev, evt))
	}

	c.mu.Lock()
	dir := c.dirStateLocked(ev.Direction)
	queuedBefore := len(c.queued)
	frames, err := dir.reasm.feed(evt.Payload, c.maxMessageSize)
	if err != nil {
		var tooLarge *lpmTooLargeError
		if errors.As(err, &tooLarge) {
			// USK-1254 case 2: record the LPMs completed earlier in this
			// event, then the rejected LPM as an anomaly row, before the
			// (unchanged) RST + StreamError.
			wireEnvs := c.tooLargeWireEnvelopesLocked(ev, dir, evt, frames, tooLarge)
			c.mu.Unlock()
			c.fireLPMFrameRecords(wireEnvs)
			se := &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "grpc: message too large",
			}
			c.rstInner(se)
			return se
		}
		c.mu.Unlock()
		// Defensive: feed currently only produces *lpmTooLargeError.
		return fmt.Errorf("grpc: reassemble: %w", err)
	}

	// USK-896: collect per-LPM wire envelopes for the WithLPMFrameRecord
	// Callback hook. We build them inside the locked section (so the
	// channel's StreamID / direction state are observed atomically with
	// the LPM emission) but defer firing them until AFTER c.mu is
	// released — the callback eventually runs through a record-only
	// Pipeline that may write to SQLite, and we must not hold c.mu
	// across an I/O-blocking call.
	var lpmWireEnvs []*envelope.Envelope
	for i := range frames {
		f := frames[i]
		dataEnv, derr := c.buildDataEnvelopeLocked(ev, dir, f)
		if derr != nil {
			c.mu.Unlock()
			// USK-1254: the LPMs completed before the failing one in this
			// event were observed on the wire; record them before the
			// (unchanged) RST + StreamError. The failing LPM itself gets
			// no anomaly row here (deferred; see the USK-1254 design note).
			c.fireLPMFrameRecords(lpmWireEnvs)
			c.rstInner(derr)
			return derr
		}
		// Build the wire-record envelope from the same LPM bytes the
		// semantic dataEnv carries on its Raw field. Building it here
		// (vs. inside the callback) means the LPM wire view is
		// guaranteed identical to the semantic view's Raw — they
		// reference distinct slices but the byte content matches.
		if c.lpmFrameRecordCallback != nil {
			lpmWireEnvs = append(lpmWireEnvs, c.buildLPMWireEnvelopeLocked(ev, dataEnv.Raw))
		}
		c.queued = append(c.queued, pendingEnvelope{env: dataEnv})
	}

	if evt.EndStream {
		// Reject mid-LPM termination: the reassembler still holds a
		// partial prefix or partial payload after consuming this frame.
		if dir.reasm.phase != phaseWaitingPrefix || len(dir.reasm.prefBuf) > 0 {
			// USK-1254 case 3: record the truncated LPM as an anomaly row
			// after the LPMs completed earlier in this event, before the
			// (unchanged) RST + StreamError. The partial LPM itself is
			// never queued for Next.
			if c.lpmFrameRecordCallback != nil {
				if env := c.buildTruncatedLPMEnvelopeLocked(ev, dir, evt); env != nil {
					lpmWireEnvs = append(lpmWireEnvs, env)
				}
			}
			c.mu.Unlock()
			c.fireLPMFrameRecords(lpmWireEnvs)
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

	// Fire the per-LPM wire-record callback outside the mutex. The
	// callback contract (WithLPMFrameRecordCallback godoc) guarantees
	// the contract holds: the closure must not call back into the
	// channel and must own its own concurrency. CLAUDE.md MITM
	// Principle 3 — wire-record envelope fires BEFORE the semantic
	// envelope is observed by the consumer's Next, which is satisfied
	// here because Next is the same goroutine that called absorbData
	// (so the consumer cannot observe the semantic envelopes queued
	// above until absorbData returns).
	c.fireLPMFrameRecords(lpmWireEnvs)
	return nil
}

// fireLPMFrameRecords hands envs to the LPM record callback in order. Must
// be called WITHOUT c.mu held (the callback may write to SQLite). envs is
// empty whenever the callback is nil.
func (c *grpcChannel) fireLPMFrameRecords(envs []*envelope.Envelope) {
	for _, env := range envs {
		c.lpmFrameRecordCallback(env)
	}
}

// tooLargeWireEnvelopesLocked builds the LPM record envelopes for the
// LPM-cap-trip path (USK-1254 case 2): one plain row per LPM completed
// earlier in the same DATA event, then the AnomalyGRPCLPMTooLarge row for
// the rejected LPM. Returns nil when no LPM record callback is installed.
// Must hold c.mu.
func (c *grpcChannel) tooLargeWireEnvelopesLocked(ev *envelope.Envelope, dir *directionState, evt *http2.H2DataEvent, frames []lpmFrame, e *lpmTooLargeError) []*envelope.Envelope {
	if c.lpmFrameRecordCallback == nil {
		return nil
	}
	envs := make([]*envelope.Envelope, 0, len(frames)+1)
	for _, f := range frames {
		envs = append(envs, c.buildLPMWireEnvelopeLocked(ev, f.wireBytes()))
	}
	envs = append(envs, c.buildPartialLPMEnvelopeLocked(ev, dir, e.raw, e.compressed, e.declared, evt.EndStream, envelope.Anomaly{
		Type:   envelope.AnomalyGRPCLPMTooLarge,
		Detail: fmt.Sprintf("declared=%d cap=%d captured=%d", e.declared, e.max, len(e.raw)-lpmPrefixLen),
	}))
	return envs
}

// buildTruncatedLPMEnvelopeLocked builds the AnomalyGRPCLPMTruncated row
// for an LPM cut short by END_STREAM (USK-1254 case 3) from the
// reassembler's in-progress state. Returns nil when no LPM is in
// progress. Must hold c.mu.
func (c *grpcChannel) buildTruncatedLPMEnvelopeLocked(ev *envelope.Envelope, dir *directionState, evt *http2.H2DataEvent) *envelope.Envelope {
	raw, prefixComplete, ok := dir.reasm.partial()
	if !ok {
		return nil
	}
	if !prefixComplete {
		// Neither the flag nor the length is known; leave both zero (the
		// RecordStep projection omits them rather than fabricate values).
		return c.buildPartialLPMEnvelopeLocked(ev, dir, raw, false, 0, evt.EndStream, envelope.Anomaly{
			Type:   envelope.AnomalyGRPCLPMTruncated,
			Detail: fmt.Sprintf("prefix_bytes=%d", len(raw)),
		})
	}
	r := &dir.reasm
	return c.buildPartialLPMEnvelopeLocked(ev, dir, raw, r.compress, r.wireLen, evt.EndStream, envelope.Anomaly{
		Type:   envelope.AnomalyGRPCLPMTruncated,
		Detail: fmt.Sprintf("declared=%d observed=%d", r.wireLen, len(r.payload)),
	})
}

// buildPartialLPMEnvelopeLocked constructs the LPM record envelope for an
// LPM the reassembler could not complete (USK-1254). Unlike the per-LPM
// rows built by buildLPMWireEnvelopeLocked it carries a GRPCDataMessage —
// Payload nil, WireLength = the declared length, Anomalies = a — so the
// typed anomaly reaches RecordStep. raw must be a fresh slice of the
// observed bytes. The envelope is handed only to the LPM record callback
// (record-only Pipeline); it is never queued for Next and so never
// forwarded. Must hold c.mu.
func (c *grpcChannel) buildPartialLPMEnvelopeLocked(ev *envelope.Envelope, dir *directionState, raw []byte, compressed bool, declared uint32, endStream bool, a envelope.Anomaly) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  ev.StreamID,
		Direction: ev.Direction,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       raw,
		Message: &envelope.GRPCDataMessage{
			Service:    dir.service,
			Method:     dir.method,
			Compressed: compressed,
			WireLength: declared,
			EndStream:  endStream,
			Anomalies:  []envelope.Anomaly{a},
		},
		Context: ev.Context,
	}
}

// buildH2DataFrameWireEnvelope constructs the per-H2-DATA-frame wire-record
// envelope dispatched to the WithH2DataFrameRecordCallback consumer
// (USK-899). The envelope is independent of any locked channel state — it
// only reads ev (StreamID / Direction / Context) and evt (Payload), so it
// is safe to construct outside c.mu.
//
// The returned envelope mirrors the USK-889 detach-path / USK-897
// aggregator-path h2-frame envelope shape so the same record-only
// Pipeline + WireLevel discriminator (flow.WireLevelH2Frame) apply across
// all three producers:
//
//   - Protocol  = envelope.ProtocolHTTP (the wire bytes are an HTTP/2
//     DATA frame payload, not a gRPC LPM — the producer is gRPC, but the
//     wire unit is HTTP/2's)
//   - StreamID  = the inner channel's StreamID (the lower-layer view;
//     the session orchestrator rewrites this to the session-scope
//     identity before dispatching to the record-only Pipeline)
//   - Direction = the inner envelope's Direction (preserved so Send /
//     Receive symmetry is observable)
//   - Sequence  = the inner envelope's Sequence (the orchestrator
//     rewrites this to a per-direction counter scoped to
//     (sessionStreamID, WireLevel=h2-frame))
//   - Raw       = a defensive copy of the DATA frame payload bytes (no
//     9-byte frame header — matches the USK-889 / USK-897 envelope
//     shape; the header is reconstructable from EndStream + payload
//     length)
//   - Message   = nil (DATA frame wire envelopes have no L7 structured
//     view; the per-LPM wire envelope and the GRPCDataMessage envelope
//     queued AFTER reassembly provide the gRPC-side views)
//   - Context   = the inner envelope's Context (carries ConnID /
//     TargetHost / TLS / ClientAddr; the callback expects to stamp
//     flow.WireLevelH2Frame before dispatching to the record-only
//     Pipeline)
//
// The defensive copy keeps the callback contract simple — consumers may
// retain the Raw slice without coordinating with the LPM reassembler's
// payload buffer (which appends to its own backing array but in the
// general case the underlying h2 frame engine may reuse evt.Payload once
// the event is consumed). The cost is one allocation per H2 DATA event;
// the allocation profile matches USK-897's aggregator-path callback.
func buildH2DataFrameWireEnvelope(ev *envelope.Envelope, evt *http2.H2DataEvent) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  ev.StreamID,
		Sequence:  ev.Sequence,
		Direction: ev.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       cloneBytes(evt.Payload),
		// Message intentionally nil — DATA frame wire envelopes have no
		// L7 structured view. The session helper stamping
		// flow.WireLevelH2Frame on Context.WireLevel is the
		// authoritative discriminator the record path keys on.
		Context: ev.Context,
	}
}

// buildLPMWireEnvelopeLocked constructs the wire-record envelope for a
// single LPM. Called from absorbData under c.mu but the returned envelope
// is consumed AFTER c.mu is released (the callback dispatch). raw is the
// LPM wire bytes (5-byte prefix + payload, BEFORE decompression) — the
// same slice content as the matching GRPCDataMessage envelope's Raw,
// allocated independently so the callback may retain it without
// interfering with the semantic envelope.
//
// The envelope intentionally leaves Sequence at the zero value; the
// session orchestrator's record-only callback (built in
// session.GRPCLPMRecordOption) rewrites it from a per-Direction
// counter before dispatching the envelope to the record-only Pipeline.
func (c *grpcChannel) buildLPMWireEnvelopeLocked(ev *envelope.Envelope, raw []byte) *envelope.Envelope {
	// Defensive copy: the dataEnv's Raw slice is owned by the channel's
	// emission path. The callback may stash the wire envelope across
	// goroutines (e.g., on a record-only Pipeline that writes
	// asynchronously). A copy here decouples the lifetimes.
	rawCopy := make([]byte, len(raw))
	copy(rawCopy, raw)
	return &envelope.Envelope{
		StreamID:  ev.StreamID,
		Direction: ev.Direction,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       rawCopy,
		// Message intentionally nil — LPM wire envelopes have no L7
		// structured view. The session helper (GRPCLPMRecordOption)
		// dispatches through a record-only Pipeline that tolerates nil
		// Message (matching the USK-895 h1-chunk path).
		Context: ev.Context,
	}
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

	// Raw is the LPM exactly as observed: the verbatim 5-byte prefix
	// (flag byte not normalized to 0/1, USK-1256) + the compressed payload
	// as observed (NOT the decoded Payload).
	rawBuf := f.wireBytes()

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

	// Fire (grpc, on_end) outside the mutex; sync.Once gates the hook
	// to a single firing per Channel even when D4 (trailers-only) also
	// produced an End earlier.
	c.fireOnEnd(endEnv, endMsg)
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
// GRPCStartMessage / GRPCEndMessage envelopes rebuild the HPACK header
// field list from struct fields (restoring the observed control-header
// layout when the Start carries this Layer's Opaque, USK-1251);
// Envelope.Raw on these types is informational only (the wire-observed
// HPACK block bytes change every time HPACK dynamic tables differ). A
// plugin msg["raw"] on them is refused by the Pipeline before RecordStep
// (RFC-001 §9.3 D4; see RawWinsSupported in raw_wins.go); one that still
// arrives is logged and sent from its struct fields.
//
// GRPCDataMessage envelopes prefer Envelope.Raw verbatim when non-empty
// (to round-trip exact wire bytes). Otherwise the wrapper re-encodes
// Payload using Compressed + the negotiated grpc-encoding.
//
// Send calls are serialized. Once a direction's End was sent, every further
// Send on that direction fails with an error wrapping errSendAfterEnd: a
// frame after END_STREAM would be a STREAM_CLOSED connection error (RFC
// 9113 §5.1) that kills every RPC multiplexed on the connection (USK-1202).
func (c *grpcChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	if env == nil || env.Message == nil {
		return errors.New("grpc: Send: nil envelope or Message")
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	c.mu.Lock()
	ended := c.dirStateLocked(env.Direction).endSent
	c.mu.Unlock()
	if ended {
		return fmt.Errorf("grpc: Send %T: %w", env.Message, errSendAfterEnd)
	}

	warnRawWinsIgnored(ctx, env)
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
	// Send's type switch matches on the dynamic type, so a typed-nil
	// *GRPCStartMessage carried in a non-nil env.Message interface passes
	// Send's `env.Message == nil` check and lands here. Reject it up
	// front: every path below dereferences m unconditionally
	// (buildStartHeaderKVs reads m.Metadata on its first line, and
	// pathForStart reads m.Path / m.Service / m.Method), so without this
	// guard the Channel would panic on a wire path instead of returning
	// an error, and the defensive nil checks inside schemeForStart /
	// authorityForStart could never run. pathForStart relies on this
	// guard instead of carrying its own (USK-1053).
	if m == nil {
		return errors.New("grpc: Send: nil GRPCStartMessage")
	}
	// USK-1251: a Start this Layer absorbed carries the observed control
	// header layout on its Opaque; restore it. Without one (Envelope.Clone
	// — intercept modify_and_forward — or a synthetic producer such as
	// resend_grpc / fuzz_grpc / RESPOND_GRPC) the synthesized layout is
	// kept exactly as before.
	opaque := opaqueFromEnv(env)
	var headers []envelope.KeyValue
	if opaque != nil && opaque.layout != nil {
		headers = rebuildStartHeaders(m, opaque.layout)
	} else {
		headers = buildStartHeaderKVs(env, m)
	}

	// Compute :path from the derived Service/Method view, falling back to
	// the wire overlay when that view cannot represent the observed :path
	// (USK-1053). The query component rides along on RawQuery and is
	// rejoined by the HTTP/2 Layer's appendRequestPseudoHeaders — do not
	// join it here, or parseGRPCPath would later read it as part of the
	// method name. See pathForStart for the precedence rule.
	pathPseudo := pathForStart(m)

	// EndStream on a Send-side Start is unusual (gRPC clients always
	// follow with at least one DATA), but if no body or trailers will
	// follow, the next Send call may be an End. We never set EndStream
	// here on Start: gRPC requires DATA + trailer HEADERS minimum.
	hdrEvt := &http2.H2HeadersEvent{
		Method:    methodOr(m, env, "POST"),
		Scheme:    schemeForStart(env, m, "https"),
		Authority: authorityForStart(m),
		Path:      pathPseudo,
		RawQuery:  m.RawQuery,
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
	dir.contentType = m.ContentType
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
	if env.Direction == envelope.Receive && opaque != nil && opaque.endStreamEnd != nil {
		// The upstream's HEADERS frame carried END_STREAM: hold it so
		// sendEnd can write the response back as that one frame
		// (USK-1251). If a Step drops the Receive End (intercept drop,
		// plugin), the held HEADERS is never sent: session teardown
		// closes this Channel, which discards it, and the client sees
		// RST_STREAM with no response HEADERS. Only an operator action
		// reaches this, and nothing leaks (pendingResp dies with c).
		c.pendingResp = &pendingResponseHeaders{env: innerEnv, baseline: opaque.endStreamEnd}
		return nil
	}
	return c.inner.Send(ctx, innerEnv)
}

// flushPendingResponseHeaders sends a deferred response HEADERS frame
// without END_STREAM. Used when something other than the End follows the
// deferred Start (e.g. a plugin injected a Data envelope), so the frame
// order on the wire stays HEADERS, DATA, ... Caller holds c.sendMu.
func (c *grpcChannel) flushPendingResponseHeaders(ctx context.Context) error {
	p := c.pendingResp
	if p == nil {
		return nil
	}
	c.pendingResp = nil
	return c.inner.Send(ctx, p.env)
}

// sendEndStreamResponse writes the End of a response whose upstream
// HEADERS frame carried END_STREAM (pending holds the deferred HEADERS).
//
//   - Default: ONE HEADERS frame with END_STREAM carrying the Start's
//     header list, with any End status edit (detected against the End as
//     the upstream-side Layer emitted it) written into the grpc-status /
//     grpc-message / grpc-status-details-bin entries in place. An
//     untouched response is relayed with its observed header list.
//   - The End's trailer metadata was edited: that cannot be written in
//     place, so the response falls back to HEADERS (no END_STREAM) plus a
//     TRAILERS frame rebuilt from the End — the pre-USK-1251 shape, in
//     which the edit reaches the wire.
//
// Caller holds c.sendMu; the direction's endSent latch is set before the
// inner Send.
func (c *grpcChannel) sendEndStreamResponse(ctx context.Context, env *envelope.Envelope, m *envelope.GRPCEndMessage, pending *pendingResponseHeaders) error {
	c.mu.Lock()
	c.recv.endSent = true
	c.mu.Unlock()

	hdr := pending.env.Message.(*http2.H2HeadersEvent)
	if endTrailersEdited(m, pending.baseline) {
		if err := c.inner.Send(ctx, pending.env); err != nil {
			return err
		}
		trailers := buildEndTrailerKVs(m)
		if hasPlaceholderStatus(m) {
			// The upstream sent no grpc-status and the End's status was
			// not edited: write only the edited trailers rather than a
			// made-up grpc-status: 0.
			trailers = slices.Clone(m.Trailers)
		}
		return c.inner.Send(ctx, &envelope.Envelope{
			StreamID:  env.StreamID,
			FlowID:    env.FlowID,
			Sequence:  env.Sequence,
			Direction: env.Direction,
			Protocol:  envelope.ProtocolHTTP,
			Message:   &http2.H2TrailersEvent{Trailers: trailers},
			Context:   env.Context,
		})
	}
	hdr.Headers = withEndStatusInHeaders(hdr.Headers, m, pending.baseline)
	hdr.EndStream = true
	return c.inner.Send(ctx, pending.env)
}

// sendPlaceholderEnd writes a Receive-direction AnomalyGRPCMissingStatus
// End (status fields untouched) whose response HEADERS was not deferred.
// It never fabricates a grpc-status the upstream did not send (USK-1251):
//
//   - The response HEADERS already went out (the Start was Clone()d, or a
//     Data flushed it): an untouched End ends the stream with an empty
//     DATA frame; an End whose Trailers were edited ends it with a
//     TRAILERS frame carrying exactly those trailers.
//   - No response HEADERS went out (a Step dropped the Receive Start):
//     the only frame left would be a proxy-built Trailers-Only, which
//     needs a fabricated :status and grpc-status and would turn e.g. a
//     load balancer's 503 into a successful RPC. Send fails with a
//     StreamError instead, so the session resets the client stream.
//
// Caller holds c.sendMu. The endSent latch is set before the inner Send.
func (c *grpcChannel) sendPlaceholderEnd(ctx context.Context, env *envelope.Envelope, m *envelope.GRPCEndMessage) error {
	c.mu.Lock()
	started := c.recv.startEmitted
	c.recv.endSent = true
	c.mu.Unlock()
	if !started {
		return &layer.StreamError{
			Code:   layer.ErrorInternalError,
			Reason: "grpc: response without grpc-status has no response HEADERS to end",
		}
	}
	var msg envelope.Message = &http2.H2DataEvent{EndStream: true}
	if len(m.Trailers) > 0 {
		msg = &http2.H2TrailersEvent{Trailers: slices.Clone(m.Trailers)}
	}
	return c.inner.Send(ctx, &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Context:   env.Context,
	})
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
	if env.Direction == envelope.Receive {
		if err := c.flushPendingResponseHeaders(ctx); err != nil {
			return err
		}
	}
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

// sendEnd converts a GRPCEndMessage envelope into the HTTP/2 event that ends
// its direction. The status fields are reconstructed from m.Status,
// m.Message, m.StatusDetails, and m.Trailers (non-status remainder).
//
// Normally that is an H2TrailersEvent. A Receive-direction End with no
// response Start sent before it — a proxy-synthesized reply such as a
// SafetyFilter / intercept-drop terminator or a plugin RESPOND_GRPC — is
// instead rendered as a gRPC "Trailers-Only" response (PROTOCOL-HTTP2.md):
// ONE HEADERS frame carrying :status 200, content-type, and the status
// fields, with END_STREAM. A bare trailers block there would be a HEADERS
// frame without :status, which RFC 9113 §8.3.2 makes malformed (USK-1202).
// The content-type mirrors the request's when one was observed.
//
// Two relayed shapes take precedence (USK-1251): when sendStart deferred
// the response HEADERS because the upstream's frame carried END_STREAM,
// sendEndStreamResponse writes it back as that one frame; and an
// AnomalyGRPCMissingStatus placeholder End otherwise goes through
// sendPlaceholderEnd, which never fabricates a grpc-status.
//
// Caller (Send) holds c.sendMu. The direction's endSent latch is set before
// the inner Send so a failed write is not retried with more frames.
func (c *grpcChannel) sendEnd(ctx context.Context, env *envelope.Envelope, m *envelope.GRPCEndMessage) error {
	if env.Direction == envelope.Receive {
		if p := c.pendingResp; p != nil {
			c.pendingResp = nil
			return c.sendEndStreamResponse(ctx, env, m, p)
		}
		if hasPlaceholderStatus(m) {
			return c.sendPlaceholderEnd(ctx, env, m)
		}
	}
	statusKVs := buildEndTrailerKVs(m)

	c.mu.Lock()
	dir := c.dirStateLocked(env.Direction)
	trailersOnly := env.Direction == envelope.Receive && !dir.startEmitted
	contentType := c.send.contentType
	dir.endSent = true
	if trailersOnly {
		dir.startEmitted = true
	}
	c.mu.Unlock()

	var msg envelope.Message
	if trailersOnly {
		if contentType == "" {
			contentType = "application/grpc"
		}
		headers := make([]envelope.KeyValue, 0, len(statusKVs)+1)
		headers = append(headers, envelope.KeyValue{Name: "content-type", Value: contentType})
		for _, kv := range statusKVs {
			// Mirror the trailers path, which drops pseudo-headers: the
			// Layer emits :status itself.
			if strings.HasPrefix(kv.Name, ":") {
				continue
			}
			headers = append(headers, kv)
		}
		msg = &http2.H2HeadersEvent{
			Status:    statusFor(env, nil),
			Headers:   headers,
			EndStream: true,
		}
	} else {
		msg = &http2.H2TrailersEvent{Trailers: statusKVs}
	}
	innerEnv := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
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
	//
	// USK-920: also surface the request-side pseudo-headers (:authority /
	// :scheme / :path) as derived L7 fields so RecordStep can project
	// Flow.URL the same way it does for HTTPMessage. Response-side
	// HEADERS frames only carry :status (no authority/scheme/path), so we
	// leave the fields zero in that case.
	if dir == envelope.Receive {
		// USK-1251: the response :status, relayed by the opposite-side
		// sendStart (statusFor) and recorded as Flow.StatusCode. 0 when
		// the HTTP/2 Layer could not parse it. HTTPStatusReason stays
		// empty: HTTP/2 has no reason phrase on the wire.
		msg.HTTPStatus = evt.Status
	}
	if dir == envelope.Send {
		msg.Authority = evt.Authority
		msg.Scheme = evt.Scheme
		msg.Path = evt.Path
		msg.RawQuery = evt.RawQuery
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
// GRPCStartMessage that carries no observed layout (no opaqueGRPC: a
// synthetic producer, or an Envelope.Clone). Conventional ordering:
// content-type (defaulting to application/grpc), grpc-encoding,
// grpc-accept-encoding, grpc-timeout, te: trailers on requests, then user
// metadata in original order. A Start this Layer absorbed goes through
// rebuildStartHeaders instead, which restores the observed layout and
// synthesizes none of these defaults (USK-1251). Pseudo-headers are
// emitted by BuildHeaderFieldsFromEvent on the inner H2 channel (they are
// NOT included in evt.Headers).
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

// methodOr returns fallback unconditionally; the message and envelope
// arguments are ignored. gRPC's HTTP/2 mapping fixes the request verb at
// POST, and neither GRPCStartMessage nor Envelope carries a :method field
// to prefer over the caller's literal. The parameters are retained so the
// call site in sendStart reads uniformly with schemeForStart /
// authorityForStart / statusFor.
func methodOr(_ *envelope.GRPCStartMessage, env *envelope.Envelope, fallback string) string {
	_ = env
	return fallback
}

// schemeForStart resolves the :scheme pseudo-header for a Send-side Start.
//
// USK-1051: the wire-observed value on the L7 overlay
// (GRPCStartMessage.Scheme, projected by absorbHeaders per USK-920) wins,
// so an h2c RPC observed as ":scheme: http" is forwarded as "http" rather
// than being silently rewritten to "https" (MITM Principle #1 — do not
// normalize what the wire did not normalize).
//
// Synthetic producers (resend_grpc / fuzz_grpc / reflection discover) that
// leave Scheme empty fall back to the envelope's TLS metadata, then to the
// caller-supplied literal. Unlike :authority, deriving :scheme is correct
// rather than a fabrication: RFC 9113 §8.3.1 requires exactly one
// non-empty value on every request, and the HTTP/2 Layer's
// appendRequestPseudoHeaders already defaults an empty scheme to "https".
func schemeForStart(env *envelope.Envelope, m *envelope.GRPCStartMessage, fallback string) string {
	if m != nil && m.Scheme != "" {
		return m.Scheme
	}
	if env != nil && env.Context.TLS != nil {
		return "https"
	}
	return fallback
}

// authorityForStart resolves the :authority pseudo-header for a Send-side
// Start from the L7 overlay only (GRPCStartMessage.Authority, projected by
// absorbHeaders per USK-920).
//
// USK-1051: there is deliberately NO Envelope.Context.TargetHost fallback.
// RFC 9113 §8.3.1 requires an intermediary forwarding a request over
// HTTP/2 to construct :authority from the authority information in the
// control data of the *original request*, and forbids generating one when
// the original request carried none. The CONNECT target is not that
// control data — substituting it rewrites a value the wire actually
// carried, and would let the proxy repair a client that omitted
// :authority (succeeding through the proxy while failing direct), which is
// exactly the diagnostic distortion this tool must not introduce.
//
// A client that legitimately sends only "host:" still works:
// buildStartMessage keeps non-pseudo headers in Metadata, so "host"
// reaches the upstream verbatim and gRPC's A41 host→:authority rename
// applies there.
//
// The HTTP/2 Layer's appendRequestPseudoHeaders omits the field entirely
// when this returns "", preserving the client's omission on the wire.
func authorityForStart(m *envelope.GRPCStartMessage) string {
	if m == nil {
		return ""
	}
	return m.Authority
}

// pathForStart resolves the :path pseudo-header for a Send-side Start.
//
// Service / Method are the derived L7 view; Path is the wire overlay
// (USK-920). The derived view wins whenever the observed :path was
// parseable into it — that is what keeps the intercept / plugin
// service+method override working exactly as it did before USK-1053.
// When parseGRPCPath could not represent the observed :path (no inner
// slash, leading "//" with a single remaining segment, trailing "/", no
// leading "/"), rebuilding would normalize it to "/" — destroying a
// malformed path the wire actually carried — so the overlay wins
// instead (MITM Principle #1 / RFC-001 §3 "L7 parsing is an overlay").
//
// An empty Path falls through to the rebuild, so synthetic producers
// (resend_grpc / fuzz_grpc) that never populate it keep their pre-USK-1053
// behaviour exactly; this is what stops the rule from regressing them the
// way a naive "Path always wins" rule would (the USK-1051 defect class).
//
// Unlike authorityForStart / schemeForStart there is deliberately no nil
// guard: sendStart is the sole call site and rejects a typed-nil message
// before reaching here, so a guard would be dead defence (USK-1051
// review F-2).
//
// The rule itself lives in envelope.GRPCStartWirePath, shared with the
// gRPC-Web Layer and the TargetScope request check (USK-1236), so the
// path the policy judges is the path written here.
func pathForStart(m *envelope.GRPCStartMessage) string {
	return envelope.GRPCStartWirePath(m)
}

// statusFor returns the :status for a Receive-side Start envelope, else 0.
// The upstream's observed status (GRPCStartMessage.HTTPStatus, projected
// by buildStartMessage) is relayed as is — an Envoy / load balancer 503 in
// front of a gRPC service must reach the client as 503, not 200
// (USK-1251). A Start without one (synthetic producers, a nil message such
// as sendEnd's proxy-synthesized Trailers-Only, or a live :status the
// HTTP/2 Layer could not parse) gets 200, the status gRPC's HTTP/2 mapping
// prescribes. The HTTP/2 Layer's encoder uses Status to choose between
// request and response pseudo-headers when env.Direction is not available.
func statusFor(env *envelope.Envelope, m *envelope.GRPCStartMessage) int {
	if env == nil || env.Direction != envelope.Receive {
		return 0
	}
	if m != nil && m.HTTPStatus > 0 {
		return m.HTTPStatus
	}
	return 200
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

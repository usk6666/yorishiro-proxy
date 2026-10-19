package grpcweb

import (
	"bytes"
	"compress/gzip"
	"context"
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

	"github.com/usk6666/yorishiro-proxy/internal/encoding/grpclpm"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// opaqueGRPCWeb is per-RPC layer-internal state attached to every
// envelope emitted by refillFromHTTPMessage. It carries the wire-format
// signal (binary vs base64) and the negotiated grpc-encoding so the
// package-level WireEncoder can re-render modified envelopes back to wire
// form without per-stream lookup tables. Pipeline Steps must not type-
// assert on Opaque (RFC §3.1) — only the same-package WireEncoder may
// inspect it.
type opaqueGRPCWeb struct {
	wireBase64 bool
	encoding   string
}

// channel is the layer.Channel returned by Wrap. It maintains a small
// emission queue (Receive: one HTTPMessage produces 1+N+1 envelopes) and a
// Send-side assembly buffer (the caller pushes 1+N+1 events that we
// concatenate into a single outbound HTTPMessage).
type channel struct {
	inner layer.Channel
	role  Role

	mu sync.Mutex

	// emitQueue holds envelopes ready to be returned by Next, fed by
	// pumpFromInner whenever the queue is empty.
	emitQueue []*envelope.Envelope

	// nextSeq is the per-channel monotonic Sequence counter for emitted
	// envelopes (reset to 0 at construction).
	nextSeq int

	// terminated becomes true once the inner Channel returned io.EOF or a
	// terminal error and emitQueue has been drained.
	terminated  bool
	terminalErr error

	// recvDone is closed by terminate() when the channel reaches terminal
	// state (either inner termination propagated or layer-internal failure).
	// terminalErr is populated before recvDone fires, satisfying the Channel
	// contract invariant ("populate Err before closing Closed").
	termOnce sync.Once
	recvDone chan struct{}

	// Send-side accumulator (for the direction we are responsible for
	// assembling and forwarding via inner.Send).
	sendStart    *envelope.GRPCStartMessage
	sendDataBuf  bytes.Buffer // concatenated wire LPM bytes (post-encode/passthrough)
	sendCtxEnv   *envelope.Envelope
	sendStreamID string

	// sendPassthrough holds the wire-form body carried on a Start's
	// Envelope.Raw (the emitAnomalyStart shape: a body that failed to
	// parse). When non-nil, sendEndLocked forwards it verbatim instead of
	// re-assembling a body from LPM frames (USK-1203).
	sendPassthrough []byte

	closeOnce sync.Once

	// maxMessageSize caps the per-LPM length on the wire and the
	// gunzip-decoded length. Resolved once at Wrap time via the Option
	// list; always positive (defaults to config.MaxGRPCMessageSize).
	maxMessageSize uint32

	// lifecycleEngine drives (grpc-web, on_end) hook dispatch (USK-683).
	// fireOnEnd uses onEndOnce so the hook fires once per Channel even
	// when the parser's natural-trailer and missing-trailer-anomaly
	// paths both produce End envelopes.
	lifecycleEngine *pluginv2.Engine
	onEndOnce       sync.Once

	// encodedFormRecordCallback is the optional per-body wire-record
	// hook installed via WithEncodedFormRecordCallback (USK-898). When
	// non-nil, refillFromHTTPMessage invokes it on the text-variant
	// (isBase64=true) branch with the on-wire base64 body bytes BEFORE
	// the layer base64-decodes + parses LPM frames. See
	// WithEncodedFormRecordCallback for the contract.
	encodedFormRecordCallback func(*envelope.Envelope)
}

// newChannel constructs the wrapper.
func newChannel(inner layer.Channel, role Role, o options) *channel {
	return &channel{
		inner:                     inner,
		role:                      role,
		recvDone:                  make(chan struct{}),
		maxMessageSize:            o.maxMessageSize,
		lifecycleEngine:           o.lifecycleEngine,
		encodedFormRecordCallback: o.encodedFormRecordCallback,
	}
}

// maybeFireEncodedFormRecord is the entrypoint to fireEncodedFormRecord
// that hides the isBase64 + nil-callback + empty-body gating from
// refillFromHTTPMessage so that function stays under the gocyclo
// threshold. The negative-test contract (binary variants do NOT fire
// the callback) remains enforced by code structure — the isBase64
// check lives here, inside the channel method, not in the caller.
func (c *channel) maybeFireEncodedFormRecord(src *envelope.Envelope, dir envelope.Direction, body []byte, isBase64 bool) {
	if !isBase64 || c.encodedFormRecordCallback == nil || len(body) == 0 {
		return
	}
	c.fireEncodedFormRecord(src, dir, body)
}

// fireEncodedFormRecord dispatches the per-body wire-record envelope
// for a text-variant (base64-encoded) gRPC-Web body. Builds the envelope
// from the inbound src envelope's identity and a defensive copy of the
// on-wire base64 body bytes, then invokes the callback synchronously.
//
// The callback contract (WithEncodedFormRecordCallback) requires that
// the wire bytes are observable BEFORE the in-place base64-decode runs.
// Callers (refillFromHTTPMessage) must invoke this method before
// DecodeBodyWithMaxMessageSize.
//
// Defensive copy: the body slice passed in is owned by the channel's
// materializeBody path. The callback may retain the wire envelope
// across goroutines (a record-only Pipeline may write to SQLite
// asynchronously), so we hand it an independent copy. This mirrors the
// USK-896 grpc LPM record callback's defensive-copy contract.
//
// Message intentionally nil — base64 wire envelopes have no L7
// structured view by design (the GRPCStart / GRPCData / GRPCEnd
// envelopes queued by refillFromHTTPMessage carry the decoded view).
// The session helper (GRPCWebBase64RecordOption) dispatches through a
// record-only Pipeline that tolerates nil Message (matching the
// USK-895 h1-chunk and USK-896 grpc-lpm-frame paths).
//
// The envelope intentionally leaves Sequence at the zero value; the
// session orchestrator's record-only callback (built in
// session.GRPCWebBase64RecordOption) rewrites it from a per-Direction
// counter before dispatching the envelope to the record-only Pipeline.
func (c *channel) fireEncodedFormRecord(src *envelope.Envelope, dir envelope.Direction, body []byte) {
	rawCopy := make([]byte, len(body))
	copy(rawCopy, body)
	wireEnv := &envelope.Envelope{
		StreamID:  src.StreamID,
		Direction: dir,
		Protocol:  envelope.ProtocolGRPCWeb,
		Raw:       rawCopy,
		// Message intentionally nil — see godoc.
		Context: src.Context,
	}
	c.encodedFormRecordCallback(wireEnv)
}

// fireOnEnd dispatches (grpc-web, on_end) hooks for the first emitted
// End envelope. Subsequent calls are no-ops via sync.Once. nil engine
// and nil End message are no-ops. Errors from FireLifecycle are
// swallowed (USK-671 fail-soft: a misbehaving plugin must not break
// wire teardown).
func (c *channel) fireOnEnd(env *envelope.Envelope, m *envelope.GRPCEndMessage) {
	if c.lifecycleEngine == nil || env == nil || m == nil {
		return
	}
	c.onEndOnce.Do(func() {
		payload := pluginv2.BuildGRPCEndDict(m)
		_, _ = c.lifecycleEngine.FireLifecycle(context.Background(), pluginv2.ProtoGRPCWeb, pluginv2.EventOnEnd, env, payload)
	})
}

// terminate marks the channel terminated, caches err, and fires recvDone.
// Caller MUST NOT hold c.mu. Idempotent.
func (c *channel) terminate(err error) {
	c.termOnce.Do(func() {
		c.mu.Lock()
		c.terminated = true
		c.terminalErr = err
		c.mu.Unlock()
		close(c.recvDone)
	})
}

// StreamID delegates to the inner Channel.
func (c *channel) StreamID() string {
	return c.inner.StreamID()
}

// Closed returns the layer's own terminal signal. Fires when terminate()
// is called (either from a Next-side terminal error propagated from inner,
// a layer-internal protocol/parse failure, or an explicit Close).
func (c *channel) Closed() <-chan struct{} {
	return c.recvDone
}

// Err returns the stored terminal error if any, otherwise delegates to inner.
// The Channel contract requires Err to be populated before Closed fires;
// terminate() preserves that ordering.
func (c *channel) Err() error {
	c.mu.Lock()
	if c.terminated {
		err := c.terminalErr
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	return c.inner.Err()
}

// Close cascades to inner.Close exactly once and fires the layer's own
// terminal signal so observers parked on Closed() unblock.
func (c *channel) Close() error {
	c.closeWith(c.inner.Close)
	return nil
}

// CloseRefused is Close for a stream the far side of the proxy refused
// without processing it (USK-1157). It cascades to the inner Channel's
// CloseRefused when it has one (an aggregator over an HTTP/2 stream, which
// picks RST_STREAM(REFUSED_STREAM) vs CANCEL from wire state), else to its
// Close. Shares Close's sync.Once.
func (c *channel) CloseRefused() error {
	c.closeWith(func() error {
		if rc, ok := c.inner.(interface{ CloseRefused() error }); ok {
			return rc.CloseRefused()
		}
		return c.inner.Close()
	})
	return nil
}

// closeWith is the single teardown path behind Close and CloseRefused;
// closeInner cascades to the inner Channel.
func (c *channel) closeWith(closeInner func() error) {
	c.closeOnce.Do(func() {
		// Set a terminal error if none has been recorded yet; an explicit
		// Close represents normal teardown so we use io.EOF.
		c.terminate(io.EOF)
		_ = closeInner()
	})
}

// Next returns the next gRPC-Web envelope. When the emission queue is
// empty, it pulls one HTTPMessage from inner and splits it into Start/Data*/
// End envelopes.
func (c *channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	for {
		c.mu.Lock()
		if c.terminated && len(c.emitQueue) == 0 {
			err := c.terminalErr
			c.mu.Unlock()
			return nil, err
		}
		if len(c.emitQueue) > 0 {
			env := c.emitQueue[0]
			c.emitQueue = c.emitQueue[1:]
			c.mu.Unlock()
			return env, nil
		}
		c.mu.Unlock()

		// Queue empty; pull next HTTPMessage from inner and refill.
		env, err := c.inner.Next(ctx)
		if err != nil {
			c.terminate(err)
			return nil, err
		}

		httpMsg, ok := env.Message.(*envelope.HTTPMessage)
		if !ok {
			se := &layer.StreamError{
				Code:   layer.ErrorProtocol,
				Reason: fmt.Sprintf("grpcweb: inner produced non-HTTPMessage (got %T)", env.Message),
			}
			c.terminate(se)
			return nil, se
		}

		if err := c.refillFromHTTPMessage(ctx, env, httpMsg); err != nil {
			c.terminate(err)
			return nil, err
		}
	}
}

// refillFromHTTPMessage splits one inbound HTTPMessage into a sequence of
// gRPC-Web envelopes pushed onto emitQueue. Direction matches the inbound
// HTTPMessage's Direction. Always emits at least one GRPCStartMessage.
func (c *channel) refillFromHTTPMessage(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage) error {
	dir := env.Direction

	// Materialize body bytes. http1 fully buffers Body; httpaggregator may
	// produce either Body or BodyBuffer. Empty body is valid (request
	// trailers-only or response trailers-only).
	bodyBytes, err := materializeBody(ctx, msg)
	if err != nil {
		return &layer.StreamError{
			Code:   layer.ErrorInternalError,
			Reason: "grpcweb: materialize body: " + err.Error(),
		}
	}

	// Detect base64 encoding from response or request content-type. Response
	// content-type wins for Receive-side; request content-type for Send-side
	// (when this Layer is RoleServer reading a request, msg is the request).
	contentType := headerGet(msg.Headers, "content-type")
	isBase64 := IsBase64Encoded(contentType)

	// USK-898: per-body wire-record callback. Fired BEFORE the in-place
	// base64 decode + LPM parse so the wire snapshot is preserved even
	// when the decode fails (ErrMalformedBase64). Fired ONLY on the
	// text-variant branch — binary variants (application/grpc-web[+proto])
	// skip this entire block by design.
	c.maybeFireEncodedFormRecord(env, dir, bodyBytes, isBase64)

	// Extract gRPC-specific metadata fields.
	encoding := strings.TrimSpace(headerGet(msg.Headers, "grpc-encoding"))
	acceptEnc := splitCSV(headerGet(msg.Headers, "grpc-accept-encoding"))
	timeout := parseGRPCTimeout(headerGet(msg.Headers, "grpc-timeout"))

	// opaque carries the wire-format signal (binary vs base64) and the
	// negotiated grpc-encoding so the package-level WireEncoder can re-render
	// modified envelopes back to wire form. Pipeline Steps must not type-
	// assert on Opaque (RFC §3.1) — only the same-package WireEncoder does.
	opaque := &opaqueGRPCWeb{wireBase64: isBase64, encoding: encoding}

	// Service/Method derivation. On the request side (Direction=Send for
	// RoleServer Next, Direction=Send for assembled outbound) the path is
	// authoritative. On the response side (Direction=Receive) the path is
	// not present on the response HTTPMessage; service/method are denormalized
	// downstream (we leave empty here unless a path happens to be set, which
	// the aggregator does not).
	service, method := "", ""
	if msg.Path != "" {
		s, m, ok := parseServiceMethod(msg.Path)
		if !ok {
			// Debug, not Warn (USK-1075): sibling of the gRPC Layer's
			// log. Client-controlled and fired once per stream with no
			// dedup, so it is a log-amplification vector on untrusted
			// input — CLAUDE.md's "client sends invalid request" Debug row.
			slog.Debug("grpcweb: malformed :path; emitting empty service/method",
				"path", msg.Path,
				"stream_id", env.StreamID,
			)
		} else {
			service, method = s, m
		}
	}

	// Build GRPCStartMessage with stripped Metadata.
	start := &envelope.GRPCStartMessage{
		Service:        service,
		Method:         method,
		Metadata:       stripStartHeaders(msg.Headers),
		Timeout:        timeout,
		ContentType:    contentType,
		Encoding:       encoding,
		AcceptEncoding: acceptEnc,
	}
	applyRequestOverlay(start, msg, dir)
	// Before DecodeBody: the malformed-body passthrough Start
	// (emitAnomalyStart) must carry the status too.
	applyResponseOverlay(start, msg, dir)

	// Decode body LPMs. Returns ParseResult with DataFrames + optional
	// TrailerFrame. Empty body → empty result, no error. The cap is the
	// per-Channel value resolved from WithMaxMessageSize.
	parsed, parseErr := DecodeBodyWithMaxMessageSize(bodyBytes, isBase64, c.maxMessageSize)
	if parseErr != nil {
		// Recoverable wire-format failures classify as envelope.Anomaly
		// values: emit a Start envelope carrying the malformed body bytes
		// verbatim on Envelope.Raw plus a sentinel End that flushes them
		// to the opposite side (USK-1203), then latch terminal EOF
		// so the session OnComplete sees a clean termination and the
		// Stream is recorded with the diagnostic preserved. Unrecoverable
		// failures (security caps such as the per-LPM size limit) fall
		// through to *layer.StreamError as before.
		if anomalyType, ok := classifyParseError(parseErr); ok {
			c.emitAnomalyStart(env, dir, start, bodyBytes, anomalyType, parseErr.Error(), opaque)
			return nil
		}
		return &layer.StreamError{
			Code:   layer.ErrorInternalError,
			Reason: "grpcweb: parse body: " + parseErr.Error(),
		}
	}

	// On the wire, frames are concatenated in the body; for Raw on each
	// emitted GRPCDataMessage / GRPCEndMessage we want the exact wire bytes
	// for that single frame, in the same encoding form (binary or base64).
	// For base64 we re-encode each frame's bytes individually so the
	// downstream "Raw" reflects the per-event slice in base64 form (per
	// USK-641 spec).
	//
	// For binary wire we slice the raw bodyBytes per offset to preserve byte
	// identity. For base64 wire we reconstruct from the (decoded) frame
	// payload + flags + length, then base64-encode that single LPM.

	// Pre-compute per-frame raw byte slices.
	frameRawBytes, trailerRawBytes := perFrameRaw(bodyBytes, isBase64, parsed)

	// Always emit one Start envelope first.
	c.mu.Lock()
	c.emitQueue = append(c.emitQueue, c.buildEnvelope(env, dir, start, nil, opaque))

	// Emit one Data envelope per data frame.
	for i, fr := range parsed.DataFrames {
		// Decompress payload for inspection convenience (if compressed).
		payload, derr := maybeDecompress(fr.Payload, fr.Compressed, encoding, c.maxMessageSize)
		if derr != nil {
			c.mu.Unlock()
			return derr
		}
		data := &envelope.GRPCDataMessage{
			Service:    service,
			Method:     method,
			Compressed: fr.Compressed,
			WireLength: uint32(len(fr.Payload)),
			Payload:    payload,
		}
		var raw []byte
		if i < len(frameRawBytes) {
			raw = frameRawBytes[i]
		}
		c.emitQueue = append(c.emitQueue, c.buildEnvelopeRaw(env, dir, data, raw, opaque))
	}

	// Emit one End envelope.
	//
	// Receive direction: an embedded trailer LPM is required to terminate
	// the response. If present, build the End from its parsed trailers; if
	// absent (and at least one data frame was emitted, so we know the body
	// is non-empty), synthesize a placeholder End with Status=0, Raw=nil,
	// and AnomalyMissingGRPCWebTrailer stamped — this surfaces silent
	// truncation as a recorded anomaly instead of an empty event tail.
	//
	// Send direction: gRPC-Web request bodies must NOT carry an embedded
	// trailer. If one is observed, emit the End anyway (so the analyst
	// can inspect what was sent) and stamp
	// AnomalyUnexpectedGRPCWebRequestTrailer; its Raw makes the upstream-
	// side Send forward the frame verbatim (USK-1203). If absent (the spec-conformant
	// case), synthesize a Status=0 End with Raw=nil so the upstream-side
	// RoleClient.Send observes the D6 flush sentinel via Pipeline → upstream
	// dispatch and the assembled HTTPMessage actually reaches the upstream
	// wire. Without this synthesis, well-formed gRPC-Web requests hang at
	// the upstream Send buffer (USK-780).
	var firedEndEnv *envelope.Envelope
	var firedEndMsg *envelope.GRPCEndMessage
	if parsed.TrailerFrame != nil {
		end := buildEndFromTrailers(parsed.Trailers)
		if dir == envelope.Send {
			end.Anomalies = append(end.Anomalies, envelope.Anomaly{
				Type:   envelope.AnomalyUnexpectedGRPCWebRequestTrailer,
				Detail: "gRPC-Web request body carried an embedded trailer LPM frame",
			})
		}
		endEnv := c.buildEnvelopeRaw(env, dir, end, trailerRawBytes, opaque)
		c.emitQueue = append(c.emitQueue, endEnv)
		firedEndEnv = endEnv
		firedEndMsg = end
	} else if dir == envelope.Receive && len(parsed.DataFrames) > 0 {
		end := &envelope.GRPCEndMessage{
			Anomalies: []envelope.Anomaly{{
				Type:   envelope.AnomalyMissingGRPCWebTrailer,
				Detail: "gRPC-Web response body had data frames but no terminating trailer LPM",
			}},
		}
		endEnv := c.buildEnvelope(env, dir, end, nil, opaque)
		c.emitQueue = append(c.emitQueue, endEnv)
		firedEndEnv = endEnv
		firedEndMsg = end
	} else if dir == envelope.Send {
		// Spec-conformant gRPC-Web request: no embedded trailer LPM. Emit
		// a clean Status=0 End so it flows through the Pipeline and reaches
		// the upstream-side RoleClient.Send as the D6 flush sentinel.
		end := &envelope.GRPCEndMessage{}
		endEnv := c.buildEnvelope(env, dir, end, nil, opaque)
		c.emitQueue = append(c.emitQueue, endEnv)
		// Intentionally do not fire (grpc-web, on_end) for the request side:
		// the lifecycle hook represents an RPC's terminal status (grpc-status),
		// which has no analog on the request half. Leaving firedEndEnv nil
		// preserves observe-only semantics for response terminations.
	}
	c.mu.Unlock()

	// Fire (grpc-web, on_end) outside the mutex so a slow plugin does not
	// block the consumer's Next path. fireOnEnd is sync.Once-gated. Only
	// Receive-direction terminations populate firedEndEnv; Send-direction
	// synthetic Ends deliberately leave it nil.
	if firedEndEnv != nil {
		c.fireOnEnd(firedEndEnv, firedEndMsg)
	}
	return nil
}

// applyRequestOverlay projects the request-side pseudo-headers
// (:authority / :scheme / :path, plus the query split off :path) from the
// inbound HTTPMessage onto the
// derived L7 overlay of the GRPCStartMessage, mirroring the USK-920
// projection that internal/layer/grpc.buildStartMessage performs for
// native gRPC.
//
// USK-1057: without this, the fields stay zero for gRPC-Web and the
// Send-side buildHTTPMessage has nothing to read, so an H2 upstream leg
// emits a request with :authority omitted entirely and :scheme silently
// defaulted to "https" by the HTTP/2 encoder — the USK-1051 defect class
// reproduced one Layer over.
//
// Guarded on dir because response-side HTTPMessages legitimately carry
// none of these: http2's buildHeadersEvent only projects the request
// pseudo-headers when direction == Send, and http1's parseRequestURI runs
// on requests only. Projecting unconditionally would be a no-op today but
// would silently fabricate a request authority onto a response overlay the
// moment any producer changed.
//
// Works for both inner transports: on HTTP/2 msg.Authority originates from
// the client's :authority pseudo-header; on HTTP/1.x it originates from
// the Host header. Only the overlay changes — Envelope.Raw is untouched
// and the HTTP/1.x send path never reads HTTPMessage.Authority (it
// re-emits the preserved Host header out of Metadata), so no HTTP/1.x wire
// byte moves.
func applyRequestOverlay(start *envelope.GRPCStartMessage, msg *envelope.HTTPMessage, dir envelope.Direction) {
	if dir != envelope.Send {
		return
	}
	start.Authority = msg.Authority
	start.Scheme = msg.Scheme
	start.Path = msg.Path
	// USK-1110: the query component has its home on the Start (USK-1053),
	// so it reaches the upstream, Flow.URL, and the Input SafetyFilter's
	// url / query targets.
	start.RawQuery = msg.RawQuery
}

// applyResponseOverlay projects the response status (HTTP/1.x status line
// or HTTP/2 :status, plus the HTTP/1.x reason phrase) from the inbound
// HTTPMessage onto GRPCStartMessage.HTTPStatus / HTTPStatusReason, the
// response-side sibling of applyRequestOverlay (USK-1219).
//
// Without it the status had nowhere to live once the HTTPMessage was split
// into gRPC-Web events, and the opposite-side Send wrote every response as
// 200 OK — an upstream 503 reached the client as a success.
//
// Guarded on dir for the same reason as applyRequestOverlay: a request
// HTTPMessage carries no status, and projecting unconditionally would
// fabricate one onto a request overlay the moment a producer changed.
// Only the overlay changes; Envelope.Raw is untouched.
func applyResponseOverlay(start *envelope.GRPCStartMessage, msg *envelope.HTTPMessage, dir envelope.Direction) {
	if dir != envelope.Receive {
		return
	}
	start.HTTPStatus = msg.Status
	start.HTTPStatusReason = msg.StatusReason
}

// classifyParseError maps a DecodeBody error to a recoverable Anomaly type.
// Returns ("", false) when the error is a security cap or otherwise
// unrecoverable; the caller surfaces those as *layer.StreamError. The
// classification uses errors.Is against the sentinels exported from
// frame.go and trailer.go so the channel never string-matches.
func classifyParseError(err error) (envelope.AnomalyType, bool) {
	switch {
	case errors.Is(err, ErrMalformedBase64):
		return envelope.AnomalyMalformedGRPCWebBase64, true
	case errors.Is(err, ErrMalformedTrailer):
		return envelope.AnomalyMalformedGRPCWebTrailer, true
	case errors.Is(err, ErrMalformedLPM):
		return envelope.AnomalyMalformedGRPCWebLPM, true
	default:
		return "", false
	}
}

// emitAnomalyStart pushes a GRPCStartMessage envelope onto emitQueue
// carrying the parser's diagnostic state (Anomalies populated) and the full
// inbound body in Envelope.Raw, followed by a sentinel End (Raw nil, no
// trailer fields) stamped with the same anomaly type, then latches the
// channel into a clean terminal-EOF state.
// Next() drains the queue first (the existing Next loop returns queued
// envelopes before observing terminalErr) so RecordStep sees the Anomaly
// envelope before the session OnComplete sees io.EOF and finalizes the
// Stream cleanly.
//
// USK-1203: the sentinel End is what makes the opposite-side Send flush
// the body to the wire (the D6 convention — sendStartLocked only buffers).
// Without it a malformed body was recorded but never forwarded, in either
// direction, and the peer waited for bytes that never came. sendStartLocked
// treats the Start's non-empty Raw as a passthrough body, so the observed
// bytes reach the next hop verbatim (MITM principles 1 and 5). The sentinel
// does not fire (grpc-web, on_end): no trailer was parsed, so there is no
// RPC status to report.
//
// The sentinel End carries the Start's anomaly type so its recorded flow
// reads as "body failed to parse, no trailer observed" rather than a clean
// grpc_status=0 the peer never sent (USK-1203 review F-2). Both directions
// are stamped alike: on Receive a clean End would be a fabricated RPC
// outcome, and on Send it terminates a request that was never parsed, which
// the clean USK-780 flush sentinel does not convey. shouldEmbedTrailer never
// encodes a trailer frame for such an End.
func (c *channel) emitAnomalyStart(
	src *envelope.Envelope,
	dir envelope.Direction,
	start *envelope.GRPCStartMessage,
	bodyBytes []byte,
	anomalyType envelope.AnomalyType,
	detail string,
	opaque any,
) {
	start.Anomalies = append(start.Anomalies, envelope.Anomaly{
		Type:   anomalyType,
		Detail: detail,
	})

	c.mu.Lock()
	c.emitQueue = append(c.emitQueue,
		c.buildEnvelopeRaw(src, dir, start, bodyBytes, opaque),
		c.buildEnvelope(src, dir, &envelope.GRPCEndMessage{
			Anomalies: []envelope.Anomaly{{
				Type:   anomalyType,
				Detail: "flush sentinel: body failed to parse; no trailer observed",
			}},
		}, nil, opaque),
	)
	c.mu.Unlock()

	// Latch clean termination via the existing helper. terminate()
	// preserves emitQueue intact, so Next() drains the Anomaly envelope
	// first and only then observes io.EOF on the next call.
	c.terminate(io.EOF)
}

// buildEnvelope constructs an emitted Envelope. opaque attaches the per-RPC
// wire-format / grpc-encoding hints so the package-level WireEncoder can re-
// render a modified Envelope back to wire form. Pipeline Steps must not
// type-assert on Envelope.Opaque.
func (c *channel) buildEnvelope(src *envelope.Envelope, dir envelope.Direction, msg envelope.Message, raw []byte, opaque any) *envelope.Envelope {
	seq := c.nextSeq
	c.nextSeq++
	return &envelope.Envelope{
		StreamID:  src.StreamID,
		FlowID:    uuid.New().String(),
		Sequence:  seq,
		Direction: dir,
		Protocol:  envelope.ProtocolGRPCWeb,
		Raw:       raw,
		Message:   msg,
		Context:   src.Context,
		Opaque:    opaque,
	}
}

// buildEnvelopeRaw is buildEnvelope with an explicit raw byte slice.
func (c *channel) buildEnvelopeRaw(src *envelope.Envelope, dir envelope.Direction, msg envelope.Message, raw []byte, opaque any) *envelope.Envelope {
	return c.buildEnvelope(src, dir, msg, raw, opaque)
}

// Send accepts a gRPC-Web envelope. The caller must push GRPCStartMessage
// first, then zero or more GRPCDataMessage, terminated by a
// GRPCEndMessage. See the package doc for the D6 Send-side flush convention.
func (c *channel) Send(ctx context.Context, env *envelope.Envelope) error {
	if env == nil || env.Message == nil {
		return errors.New("grpcweb: Send envelope or Message is nil")
	}

	switch m := env.Message.(type) {
	case *envelope.GRPCStartMessage:
		return c.sendStartLocked(env, m)
	case *envelope.GRPCDataMessage:
		return c.sendDataLocked(env, m)
	case *envelope.GRPCEndMessage:
		return c.sendEndLocked(ctx, env, m)
	default:
		return fmt.Errorf("grpcweb: unsupported Send Message type %T", env.Message)
	}
}

// sendStartLocked records the Start metadata for assembly. Resets any prior
// in-flight assembly buffer (defensive).
//
// A non-empty env.Raw is kept as a passthrough body (USK-1203) only when
// the Start carries a malformed-body anomaly (AnomalyMalformedGRPCWeb*):
// that is the emitAnomalyStart shape, whose Raw is the full observed body
// in wire form (base64 text for -text content-types), which sendEndLocked
// forwards verbatim. Raw on any other Start (e.g. a (grpc-web, on_start)
// plugin assigning msg["raw"]) is ignored, as it was before USK-1203 — it
// never becomes a prefix of a re-assembled body (review F-3).
func (c *channel) sendStartLocked(env *envelope.Envelope, m *envelope.GRPCStartMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendStart = m
	c.sendCtxEnv = env
	c.sendStreamID = env.StreamID
	c.sendDataBuf.Reset()
	c.sendPassthrough = nil
	if hasMalformedBodyAnomaly(m.Anomalies) && len(env.Raw) > 0 {
		c.sendPassthrough = append([]byte(nil), env.Raw...)
	}
	return nil
}

// sendDataLocked appends one LPM frame to the assembly buffer. If
// env.Raw is non-nil, it is appended verbatim (Send-side fast path for
// malformed bytes / re-injected wire-form). Otherwise the LPM prefix is
// computed from m.Payload + m.Compressed and the payload is (re-)compressed
// per the negotiated grpc-encoding when m.Compressed=true.
func (c *channel) sendDataLocked(env *envelope.Envelope, m *envelope.GRPCDataMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendStart == nil {
		return errors.New("grpcweb: GRPCDataMessage before GRPCStartMessage on Send")
	}

	// Fast path: raw bytes provided — append to the assembly buffer.
	// Assembly buffer holds binary LPM frames; the final base64 wrap at
	// sendEndLocked is the only base64 encode applied. For -text wire
	// formats, refillFromHTTPMessage emits Raw in base64-encoded form per
	// USK-641, so we must base64-decode here before writing the binary
	// LPM into the buffer or the final wrap would produce a double-encode.
	if len(env.Raw) > 0 {
		raw := env.Raw
		if IsBase64Encoded(c.sendStart.ContentType) {
			decoded, err := decodeBase64(raw)
			if err != nil {
				return &layer.StreamError{
					Code:   layer.ErrorInternalError,
					Reason: "grpcweb: sendDataLocked decode base64 Raw: " + err.Error(),
				}
			}
			raw = decoded
		}
		c.sendDataBuf.Write(raw)
		return nil
	}

	// Re-encode from structured fields.
	wirePayload := m.Payload
	if m.Compressed {
		enc := strings.TrimSpace(c.sendStart.Encoding)
		compressed, err := compressPayload(wirePayload, enc)
		if err != nil {
			return err
		}
		wirePayload = compressed
	}
	frame := EncodeFrame(false, m.Compressed, wirePayload)
	c.sendDataBuf.Write(frame)
	return nil
}

// sendEndLocked finalizes the assembly and hands one HTTPMessage to
// inner.Send. Whether an embedded trailer LPM frame is appended is decided
// by shouldEmbedTrailer. When the Start carried a passthrough body
// (sendStartLocked), that body is forwarded verbatim — it is already in
// wire form, so it is neither re-assembled nor base64-wrapped again.
func (c *channel) sendEndLocked(ctx context.Context, env *envelope.Envelope, m *envelope.GRPCEndMessage) error {
	c.mu.Lock()
	if c.sendStart == nil {
		c.mu.Unlock()
		return errors.New("grpcweb: GRPCEndMessage before GRPCStartMessage on Send")
	}
	start := c.sendStart
	srcEnv := c.sendCtxEnv
	streamID := c.sendStreamID
	passthrough := c.sendPassthrough
	dir := env.Direction
	dataBytes := append([]byte(nil), c.sendDataBuf.Bytes()...)
	// Reset assembly state immediately to allow pipelined RPCs.
	c.sendStart = nil
	c.sendCtxEnv = nil
	c.sendPassthrough = nil
	c.sendDataBuf.Reset()
	c.mu.Unlock()

	isBase64 := IsBase64Encoded(start.ContentType)

	if shouldEmbedTrailer(dir, env, m, passthrough != nil) {
		trailer, err := trailerFrameBytes(env, m, isBase64)
		if err != nil {
			return err
		}
		dataBytes = append(dataBytes, trailer...)
	}

	// The assembly buffer holds binary LPM frames; apply the -text base64
	// wrap exactly once. A passthrough body is already wire form, so only
	// frames assembled after it (none on the live path) are wrapped.
	var body []byte
	switch {
	case passthrough != nil:
		body = passthrough
		if len(dataBytes) > 0 {
			if isBase64 {
				dataBytes = EncodeBase64Body(dataBytes)
			}
			body = append(body, dataBytes...)
		}
	case isBase64:
		body = EncodeBase64Body(dataBytes)
	default:
		body = dataBytes
	}

	// Reconstruct HTTPMessage.
	httpMsg := buildHTTPMessage(start, body, dir, srcEnv)

	out := &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.New().String(),
		Sequence:  env.Sequence,
		Direction: dir,
		Protocol:  envelope.ProtocolHTTP,
		Message:   httpMsg,
	}
	if srcEnv != nil {
		out.Context = srcEnv.Context
	}

	return c.inner.Send(ctx, out)
}

// shouldEmbedTrailer decides whether sendEndLocked appends an embedded
// trailer LPM frame to the body. The rule forwards what the wire carried
// and never fabricates a trailer the peer did not send (MITM principle 1):
//
//   - End.Raw non-empty: an observed trailer frame — forward it in either
//     direction. On the request side this is the
//     AnomalyUnexpectedGRPCWebRequestTrailer case: the frame is recorded as
//     an anomaly AND relayed, rather than silently stripped (USK-1203).
//   - Passthrough body: the observed body is already complete; the End is
//     only the flush sentinel, so nothing is added.
//   - End stamped with a malformed-body anomaly: the emitAnomalyStart
//     sentinel, standing for "no trailer observed". Nothing is added even
//     if the passthrough body was lost before this Send.
//   - Receive: a response End re-encoded from its fields (a plugin or
//     intercept may have synthesized or rewritten it) — except when it is
//     the AnomalyMissingGRPCWebTrailer placeholder, which stands for a
//     trailer the upstream never sent.
//   - Send: only an End flagged AnomalyUnexpectedGRPCWebRequestTrailer whose
//     Raw was dropped (e.g. by a mutation) is re-encoded from its fields;
//     the clean synthetic End (USK-780 flush sentinel) adds nothing.
func shouldEmbedTrailer(dir envelope.Direction, env *envelope.Envelope, m *envelope.GRPCEndMessage, passthrough bool) bool {
	switch {
	case len(env.Raw) > 0:
		return true
	case passthrough, hasMalformedBodyAnomaly(m.Anomalies):
		return false
	case dir == envelope.Receive:
		return !hasAnomaly(m.Anomalies, envelope.AnomalyMissingGRPCWebTrailer)
	default:
		return hasAnomaly(m.Anomalies, envelope.AnomalyUnexpectedGRPCWebRequestTrailer)
	}
}

// hasMalformedBodyAnomaly reports whether anomalies contains a
// malformed-body anomaly (envelope.IsMalformedGRPCWebBodyAnomaly).
func hasMalformedBodyAnomaly(anomalies []envelope.Anomaly) bool {
	_, ok := envelope.MalformedGRPCWebBodyAnomaly(anomalies)
	return ok
}

// hasAnomaly reports whether anomalies contains an entry of type t.
func hasAnomaly(anomalies []envelope.Anomaly, t envelope.AnomalyType) bool {
	for _, a := range anomalies {
		if a.Type == t {
			return true
		}
	}
	return false
}

// trailerFrameBytes returns the binary trailer LPM frame to append to the
// assembly buffer. env.Raw, when present, is used verbatim; for -text wire
// formats Raw is base64-encoded (USK-641), so it is decoded once here to keep
// the buffer binary — the final wrap in sendEndLocked is the only base64
// encode applied. Otherwise the frame is encoded from m's fields.
func trailerFrameBytes(env *envelope.Envelope, m *envelope.GRPCEndMessage, isBase64 bool) ([]byte, error) {
	if len(env.Raw) == 0 {
		return EncodeFrame(true, false, encodeTrailerPayload(m)), nil
	}
	if !isBase64 {
		return env.Raw, nil
	}
	decoded, err := decodeBase64(env.Raw)
	if err != nil {
		return nil, &layer.StreamError{
			Code:   layer.ErrorInternalError,
			Reason: "grpcweb: sendEndLocked decode base64 Raw: " + err.Error(),
		}
	}
	return decoded, nil
}

// --- helpers ---

// materializeBody returns the body bytes for an HTTPMessage. http1 produces
// Body []byte; httpaggregator may produce BodyBuffer for large bodies. Empty
// body returns nil with no error.
func materializeBody(ctx context.Context, msg *envelope.HTTPMessage) ([]byte, error) {
	if msg.Body != nil {
		return msg.Body, nil
	}
	if msg.BodyBuffer != nil {
		b, err := msg.BodyBuffer.Bytes(ctx)
		if err != nil {
			return nil, fmt.Errorf("bodybuffer.Bytes: %w", err)
		}
		return b, nil
	}
	return nil, nil
}

// headerGet returns the first matching value for name (case-insensitive),
// or "" if absent.
func headerGet(kvs []envelope.KeyValue, name string) string {
	for _, kv := range kvs {
		if strings.EqualFold(kv.Name, name) {
			return kv.Value
		}
	}
	return ""
}

// splitCSV splits a comma-separated value, trimming surrounding whitespace
// and dropping empty entries. Used for grpc-accept-encoding.
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseGRPCTimeout parses a grpc-timeout header value of the form
// "<digits><unit>" where unit is one of H, M, S, m, u, n. Returns 0 on
// missing or malformed values (defensive — gRPC clients sometimes omit it).
func parseGRPCTimeout(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if len(v) < 2 {
		return 0
	}
	unit := v[len(v)-1]
	digits := v[:len(v)-1]
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	switch unit {
	case 'H':
		return time.Duration(n) * time.Hour
	case 'M':
		return time.Duration(n) * time.Minute
	case 'S':
		return time.Duration(n) * time.Second
	case 'm':
		return time.Duration(n) * time.Millisecond
	case 'u':
		return time.Duration(n) * time.Microsecond
	case 'n':
		return time.Duration(n) * time.Nanosecond
	default:
		return 0
	}
}

// stripStartHeaders returns a copy of headers with pseudo-headers and
// gRPC-specific control headers removed (D7 strip set). Order and casing of
// retained entries are preserved.
func stripStartHeaders(headers []envelope.KeyValue) []envelope.KeyValue {
	if len(headers) == 0 {
		return nil
	}
	out := make([]envelope.KeyValue, 0, len(headers))
	for _, kv := range headers {
		if isStartStripName(kv.Name) {
			continue
		}
		out = append(out, kv)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// isStartStripName reports whether a header name belongs to the D7 strip set
// for GRPCStartMessage.Metadata.
func isStartStripName(name string) bool {
	if name == "" {
		return false
	}
	if name[0] == ':' {
		return true // pseudo-header (defensive)
	}
	switch strings.ToLower(name) {
	case "content-type", "grpc-encoding", "grpc-accept-encoding", "grpc-timeout":
		return true
	}
	return false
}

// stripEndTrailerNames is the D7 strip set for GRPCEndMessage.Trailers.
func isEndStripName(name string) bool {
	switch strings.ToLower(name) {
	case "grpc-status", "grpc-message", "grpc-status-details-bin":
		return true
	}
	return false
}

// buildEndFromTrailers parses a flat trailer map into a GRPCEndMessage with
// status/message/status-details-bin extracted and remaining entries left
// in Trailers. Trailer order from the parsed map cannot be preserved (map
// iteration is unordered), so wire fidelity for trailer ordering is a
// known limitation; ParseTrailers returns map[string]string. Future work
// could promote ParseTrailers to []KeyValue if order proves load-bearing.
func buildEndFromTrailers(trailers map[string]string) *envelope.GRPCEndMessage {
	end := &envelope.GRPCEndMessage{}
	if trailers == nil {
		return end
	}
	for k, v := range trailers {
		switch strings.ToLower(k) {
		case "grpc-status":
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
			if err == nil {
				end.Status = uint32(n)
			}
		case "grpc-message":
			end.Message = v
		case "grpc-status-details-bin":
			end.StatusDetails = []byte(v)
		default:
			end.Trailers = append(end.Trailers, envelope.KeyValue{Name: k, Value: v})
		}
	}
	return end
}

// perFrameRaw computes per-frame Raw byte slices from the original body
// bytes. For binary wire we slice the source body offset-by-offset. For
// base64 wire we re-encode each frame's bytes individually (the spec keeps
// Raw in base64 form for -text content-types).
//
// Returns frameRawBytes (one entry per parsed.DataFrames item, in the same
// order) and trailerRawBytes (or nil when no TrailerFrame).
func perFrameRaw(body []byte, isBase64 bool, parsed *ParseResult) ([][]byte, []byte) {
	if parsed == nil {
		return nil, nil
	}

	// We need to walk the (decoded) body and slice in the order frames were
	// parsed. parsed.DataFrames are in wire order; if a TrailerFrame exists
	// it is positioned anywhere — readAllFrames already classifies each
	// frame in pass order. We replicate that classification while emitting
	// per-frame slices.
	var decoded []byte
	if isBase64 {
		// We decoded once inside DecodeBody; re-decode once here to get the
		// binary stream we will slice over. Failure to decode is impossible
		// at this point (DecodeBody already succeeded).
		dec, err := decodeBase64(body)
		if err != nil {
			// Defensive: should not happen.
			return nil, nil
		}
		decoded = dec
	} else {
		decoded = body
	}

	dataIdx := 0
	var frameRaws [][]byte
	if len(parsed.DataFrames) > 0 {
		frameRaws = make([][]byte, 0, len(parsed.DataFrames))
	}
	var trailerRaw []byte

	off := 0
	for off < len(decoded) {
		if len(decoded)-off < frameHeaderSize {
			break
		}
		flags := decoded[off]
		length := binary.BigEndian.Uint32(decoded[off+1 : off+5])
		end := off + frameHeaderSize + int(length)
		if end > len(decoded) {
			break
		}
		isTrailer := flags&trailerFlagBit != 0
		slice := append([]byte(nil), decoded[off:end]...)
		if isBase64 {
			slice = []byte(base64StdEncode(slice))
		}
		if isTrailer {
			trailerRaw = slice
		} else {
			if dataIdx < len(parsed.DataFrames) {
				frameRaws = append(frameRaws, slice)
				dataIdx++
			}
		}
		off = end
	}

	return frameRaws, trailerRaw
}

// base64StdEncode wraps EncodeBase64Body for clarity.
func base64StdEncode(b []byte) string {
	return string(EncodeBase64Body(b))
}

// maybeDecompress decompresses payload according to encoding when
// compressed=true. encoding is the negotiated grpc-encoding header value
// ("identity", "gzip", or empty). identity / empty / compressed=false are
// no-ops. Other encodings produce a *layer.StreamError per design D7-adj.
//
// maxMessageSize bounds the decompressed length (CWE-409 defense against
// gzip bombs). The caller threads the per-Channel cap resolved at Wrap
// time (defaulting to config.MaxGRPCMessageSize when no
// WithMaxMessageSize Option is supplied).
//
// The algorithm set and bound live in grpclpm.Decompress, shared with the
// gRPC Input SafetyEngine's scan of malformed-body passthroughs (USK-1203).
// "Compressed" flag with encoding=identity is technically an RFC violation;
// it is treated as passthrough rather than failing.
func maybeDecompress(payload []byte, compressed bool, encoding string, maxMessageSize uint32) ([]byte, error) {
	if !compressed {
		return payload, nil
	}
	out, err := grpclpm.Decompress(payload, encoding, maxMessageSize)
	if err != nil {
		return nil, &layer.StreamError{
			Code:   layer.ErrorInternalError,
			Reason: "grpcweb: " + err.Error(),
		}
	}
	return out, nil
}

// compressPayload compresses payload using encoding. identity / empty are
// passthrough. Unsupported encodings produce a *layer.StreamError.
func compressPayload(payload []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return payload, nil
	case "gzip":
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(payload); err != nil {
			_ = gw.Close()
			return nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "grpcweb: gzip write: " + err.Error(),
			}
		}
		if err := gw.Close(); err != nil {
			return nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "grpcweb: gzip close: " + err.Error(),
			}
		}
		return buf.Bytes(), nil
	default:
		return nil, &layer.StreamError{
			Code:   layer.ErrorInternalError,
			Reason: "grpcweb: unsupported grpc-encoding: " + encoding,
		}
	}
}

// encodeTrailerPayload serializes the GRPCEndMessage status/message/details
// + remaining trailers into the embedded trailer frame text format
// ("name: value\r\n" lines).
func encodeTrailerPayload(end *envelope.GRPCEndMessage) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "grpc-status: %d\r\n", end.Status)
	if end.Message != "" {
		fmt.Fprintf(&buf, "grpc-message: %s\r\n", end.Message)
	}
	if len(end.StatusDetails) > 0 {
		fmt.Fprintf(&buf, "grpc-status-details-bin: %s\r\n", string(end.StatusDetails))
	}
	for _, kv := range end.Trailers {
		if isEndStripName(kv.Name) {
			continue
		}
		fmt.Fprintf(&buf, "%s: %s\r\n", kv.Name, kv.Value)
	}
	return buf.Bytes()
}

// buildHTTPMessage reconstructs an outbound HTTPMessage for inner.Send. The
// request side (Send-side from the caller's perspective) sets Method=POST,
// resolves Path with pathForStart, carries RawQuery, and carries the
// wire-observed :authority / :scheme forward from the Start message's
// derived L7 overlay (USK-1057). The response side takes Status /
// StatusReason from the Start's HTTPStatus / HTTPStatusReason overlay
// (USK-1219).
//
// The framing headers carried over from the observed message are reconciled
// with the re-assembled body (reconcileBodyFraming, USK-1203) — this is the
// seam where the body is rebuilt, so it is the seam that owns keeping the
// two consistent.
func buildHTTPMessage(
	start *envelope.GRPCStartMessage,
	body []byte,
	dir envelope.Direction,
	srcEnv *envelope.Envelope,
) *envelope.HTTPMessage {
	msg := &envelope.HTTPMessage{
		Body:    body,
		Headers: reconcileBodyFraming(rebuildStartHeaders(start), len(body)),
	}

	switch dir {
	case envelope.Send:
		// Request side: assemble path + method.
		msg.Method = "POST"
		// USK-1069 / USK-1110: the observed :path wins when the derived
		// Service/Method view cannot represent it (pathForStart), and the
		// query string rides along on RawQuery — the inner HTTP Layer
		// rejoins it (http1 sendRequestSynthetic, http2
		// appendRequestPseudoHeaders). Joining here would make a later
		// parseServiceMethod read the query as part of the method name.
		msg.Path = pathForStart(start)
		msg.RawQuery = start.RawQuery
		// USK-1057: :authority and :scheme come from the derived L7 overlay
		// only — the fields refillFromHTTPMessage projects from the
		// wire-observed request (applyRequestOverlay). There is deliberately
		// NO Envelope.Context.TargetHost fallback: RFC 9113 §8.3.1 requires
		// an intermediary forwarding a request over HTTP/2 to construct
		// :authority from the authority information in the control data of
		// the *original request*, and forbids generating one when the
		// original request carried none. The CONNECT target is not that
		// control data, and substituting it would let the proxy repair a
		// client that omitted :authority — succeeding through the proxy
		// while failing direct. Mirrors internal/layer/grpc.authorityForStart.
		//
		// The HTTP/2 encoder omits :authority entirely when this is empty
		// (appendRequestPseudoHeaders), so a client's own omission survives
		// onto the upstream wire. A client that sends only "host:" still
		// works: stripStartHeaders keeps non-pseudo headers in Metadata, so
		// "host" reaches the upstream verbatim.
		//
		// No TLS-derived :scheme fallback either (unlike grpc's
		// schemeForStart): every live producer of a gRPC-Web Start reaches
		// here through applyRequestOverlay, http2 already defaults an empty
		// :scheme, and the HTTP/1.x send path ignores the field — a fallback
		// would be unreachable code.
		msg.Authority = start.Authority
		msg.Scheme = start.Scheme
	case envelope.Receive:
		// Response side: the status observed on the upstream response,
		// carried on the Start overlay (applyResponseOverlay, USK-1219).
		// An empty reason phrase stays empty — an HTTP/2 upstream has none,
		// and the HTTP/1.x synthetic send path fills it from statusText.
		msg.Status = start.HTTPStatus
		msg.StatusReason = start.HTTPStatusReason
		if msg.Status == 0 {
			// Zero-value path for synthetic / test producers that build a
			// Receive Start without an HTTP status (the same shape as
			// pathForStart's empty-Path fall-through). Every live Start
			// comes through applyResponseOverlay, and an HTTP Layer never
			// yields status 0 for a parsed response. Without this an
			// HTTP/1.x client would see "0 Unknown" and an HTTP/2 client
			// :status 0.
			msg.Status = 200
			msg.StatusReason = "OK"
		}
	}
	return msg
}

// rebuildStartHeaders re-injects content-type / grpc-encoding /
// grpc-accept-encoding / grpc-timeout (when set on Start) and appends the
// preserved Metadata in original order.
func rebuildStartHeaders(start *envelope.GRPCStartMessage) []envelope.KeyValue {
	out := make([]envelope.KeyValue, 0, len(start.Metadata)+4)
	if start.ContentType != "" {
		out = append(out, envelope.KeyValue{Name: "content-type", Value: start.ContentType})
	}
	if start.Encoding != "" {
		out = append(out, envelope.KeyValue{Name: "grpc-encoding", Value: start.Encoding})
	}
	if len(start.AcceptEncoding) > 0 {
		out = append(out, envelope.KeyValue{Name: "grpc-accept-encoding", Value: strings.Join(start.AcceptEncoding, ",")})
	}
	if start.Timeout > 0 {
		out = append(out, envelope.KeyValue{Name: "grpc-timeout", Value: formatGRPCTimeout(start.Timeout)})
	}
	out = append(out, start.Metadata...)
	return out
}

// reconcileBodyFraming makes the framing headers carried over from the
// observed message agree with the re-assembled body of bodyLen bytes
// (USK-1203). The body the grpcweb Layer hands to inner.Send is rebuilt from
// LPM frames, so its length changes whenever a Transform / intercept /
// plugin resized a message, and it is always a de-chunked byte string.
// Copying the observed Content-Length / Transfer-Encoding forward unchanged
// therefore produced (a) a stale Content-Length that truncated the body and
// left its tail on a keep-alive connection (desync), and (b) for a chunked
// request, Transfer-Encoding: chunked over an un-chunked body plus the
// Content-Length the HTTP/1.x synthetic send path stamps — the CL+TE
// request-smuggling shape.
//
// Rules, mirroring the http1 opaque path's applyTEToCLRewrite (USK-769):
//
//   - Transfer-Encoding present: every entry is dropped and the body is
//     framed by Content-Length instead. This is a documented divergence
//     from the wire: the chunk boundaries the peer used are not reproduced
//     on the next hop (the de-chunked body is all the Layer has).
//   - Content-Length present: when no entry already equals bodyLen, every
//     entry's value is rewritten in place — name casing and position are
//     kept. When one already matches, the entries are left byte-identical
//     (an unchanged length never moves a header, and a duplicate-CL probe
//     whose first value matches the body survives intact).
//   - Content-Length absent: stays absent (unless Transfer-Encoding was
//     dropped, in which case one is appended). On HTTP/1.x the synthetic
//     send path stamps one; on HTTP/2 END_STREAM frames the body.
//
// Known edge (USK-1203 review S-2; documented, deliberately not changed):
// the "an entry already matches" test is per-entry. If the peer sent
// duplicate conflicting Content-Length values and a Transform / intercept /
// plugin resizes the body to exactly one of the non-first values, every
// entry is left as-is — so the conflicting set the next hop sees no longer
// describes the framing the peer used (which entry the next hop honours
// decides where it thinks the body ends). The entries are not deduplicated
// or collapsed to one: that would normalize what the wire did not normalize
// (MITM principle 1), and with an unchanged body this pass-through is the
// faithful forwarding of a duplicate-CL probe, matching the http1 opaque
// path.
//
// The returned slice is a fresh copy; headers is not mutated.
func reconcileBodyFraming(headers []envelope.KeyValue, bodyLen int) []envelope.KeyValue {
	if len(headers) == 0 {
		return headers
	}
	want := strconv.Itoa(bodyLen)
	out := make([]envelope.KeyValue, 0, len(headers)+1)
	var clIdx []int
	clMatches, droppedTE := false, false
	for _, kv := range headers {
		switch {
		case strings.EqualFold(kv.Name, "transfer-encoding"):
			droppedTE = true
			continue
		case strings.EqualFold(kv.Name, "content-length"):
			if strings.TrimSpace(kv.Value) == want {
				clMatches = true
			}
			clIdx = append(clIdx, len(out))
		}
		out = append(out, kv)
	}
	switch {
	case len(clIdx) == 0 && droppedTE:
		out = append(out, envelope.KeyValue{Name: "Content-Length", Value: want})
	case len(clIdx) > 0 && !clMatches:
		for _, i := range clIdx {
			out[i].Value = want
		}
	}
	return out
}

// formatGRPCTimeout returns a grpc-timeout-formatted string. The simplest
// safe choice is milliseconds with the 'm' unit for any positive duration.
func formatGRPCTimeout(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	ms := d.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	return strconv.FormatInt(ms, 10) + "m"
}

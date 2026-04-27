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

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
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

	closeOnce sync.Once

	// maxMessageSize caps the per-LPM length on the wire and the
	// gunzip-decoded length. Resolved once at Wrap time via the Option
	// list; always positive (defaults to config.MaxGRPCMessageSize).
	maxMessageSize uint32
}

// newChannel constructs the wrapper.
func newChannel(inner layer.Channel, role Role, o options) *channel {
	return &channel{
		inner:          inner,
		role:           role,
		recvDone:       make(chan struct{}),
		maxMessageSize: o.maxMessageSize,
	}
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
	c.closeOnce.Do(func() {
		// Set a terminal error if none has been recorded yet; an explicit
		// Close represents normal teardown so we use io.EOF.
		c.terminate(io.EOF)
		_ = c.inner.Close()
	})
	return nil
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
			slog.Warn("grpcweb: malformed :path; emitting empty service/method",
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

	// Decode body LPMs. Returns ParseResult with DataFrames + optional
	// TrailerFrame. Empty body → empty result, no error. The cap is the
	// per-Channel value resolved from WithMaxMessageSize.
	parsed, parseErr := DecodeBodyWithMaxMessageSize(bodyBytes, isBase64, c.maxMessageSize)
	if parseErr != nil {
		// Recoverable wire-format failures classify as envelope.Anomaly
		// values: emit a single Start envelope carrying the malformed
		// body bytes verbatim on Envelope.Raw, then latch terminal EOF
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
	defer c.mu.Unlock()
	c.emitQueue = append(c.emitQueue, c.buildEnvelope(env, dir, start, nil, opaque))

	// Emit one Data envelope per data frame.
	for i, fr := range parsed.DataFrames {
		// Decompress payload for inspection convenience (if compressed).
		payload, derr := maybeDecompress(fr.Payload, fr.Compressed, encoding, c.maxMessageSize)
		if derr != nil {
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
	// AnomalyUnexpectedGRPCWebRequestTrailer.
	if parsed.TrailerFrame != nil {
		end := buildEndFromTrailers(parsed.Trailers)
		if dir == envelope.Send {
			end.Anomalies = append(end.Anomalies, envelope.Anomaly{
				Type:   envelope.AnomalyUnexpectedGRPCWebRequestTrailer,
				Detail: "gRPC-Web request body carried an embedded trailer LPM frame",
			})
		}
		c.emitQueue = append(c.emitQueue, c.buildEnvelopeRaw(env, dir, end, trailerRawBytes, opaque))
	} else if dir == envelope.Receive && len(parsed.DataFrames) > 0 {
		end := &envelope.GRPCEndMessage{
			Anomalies: []envelope.Anomaly{{
				Type:   envelope.AnomalyMissingGRPCWebTrailer,
				Detail: "gRPC-Web response body had data frames but no terminating trailer LPM",
			}},
		}
		c.emitQueue = append(c.emitQueue, c.buildEnvelope(env, dir, end, nil, opaque))
	}

	return nil
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

// emitAnomalyStart pushes a single GRPCStartMessage envelope onto emitQueue
// carrying the parser's diagnostic state (Anomalies populated) and the full
// inbound body in Envelope.Raw, then latches the channel into a clean
// terminal-EOF state. Next() drains the queue first (the existing Next loop
// returns queued envelopes before observing terminalErr) so RecordStep sees
// the Anomaly envelope before the session OnComplete sees io.EOF and
// finalizes the Stream cleanly.
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
	c.emitQueue = append(c.emitQueue, c.buildEnvelopeRaw(src, dir, start, bodyBytes, opaque))
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
func (c *channel) sendStartLocked(env *envelope.Envelope, m *envelope.GRPCStartMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendStart = m
	c.sendCtxEnv = env
	c.sendStreamID = env.StreamID
	c.sendDataBuf.Reset()
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

	// Fast path: raw bytes provided — write verbatim. We treat Raw on Data
	// envelopes as the wire-form 5-byte prefix + payload (binary). For
	// base64-wire output the assembler base64-encodes the full body once at
	// the end, so Raw at this stage stays binary either way.
	if len(env.Raw) > 0 {
		c.sendDataBuf.Write(env.Raw)
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

// sendEndLocked finalizes the assembly. For Send-side (request) flush
// direction this writes no embedded trailer (gRPC-Web requests have none —
// the Layer-internal sentinel only triggers HTTPMessage.Send). For Receive-
// side (response from RoleServer) direction this encodes the embedded
// trailer LPM frame at the end of the body.
func (c *channel) sendEndLocked(ctx context.Context, env *envelope.Envelope, m *envelope.GRPCEndMessage) error {
	c.mu.Lock()
	if c.sendStart == nil {
		c.mu.Unlock()
		return errors.New("grpcweb: GRPCEndMessage before GRPCStartMessage on Send")
	}
	start := c.sendStart
	srcEnv := c.sendCtxEnv
	streamID := c.sendStreamID
	dir := env.Direction
	dataBytes := append([]byte(nil), c.sendDataBuf.Bytes()...)
	// Reset assembly state immediately to allow pipelined RPCs.
	c.sendStart = nil
	c.sendCtxEnv = nil
	c.sendDataBuf.Reset()
	c.mu.Unlock()

	// Determine whether to embed the trailer frame.
	embedTrailer := dir == envelope.Receive

	if embedTrailer {
		trailerPayload := encodeTrailerPayload(m)
		if len(env.Raw) > 0 {
			// Fast path: caller provided raw trailer bytes (binary
			// LPM-prefixed form expected per RFC §3.2.3 Raw definition).
			dataBytes = append(dataBytes, env.Raw...)
		} else {
			dataBytes = append(dataBytes, EncodeFrame(true, false, trailerPayload)...)
		}
	}

	// Apply base64 encoding if the original Start ContentType indicated -text.
	body := dataBytes
	isBase64 := IsBase64Encoded(start.ContentType)
	if isBase64 {
		body = EncodeBase64Body(dataBytes)
	}

	// Reconstruct HTTPMessage.
	httpMsg := buildHTTPMessage(start, m, body, dir, srcEnv, embedTrailer)

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
func maybeDecompress(payload []byte, compressed bool, encoding string, maxMessageSize uint32) ([]byte, error) {
	if !compressed {
		return payload, nil
	}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		// "Compressed" flag set but encoding=identity is technically an RFC
		// violation; treat as passthrough rather than failing.
		return payload, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "grpcweb: gzip new reader: " + err.Error(),
			}
		}
		defer zr.Close()
		// Bound decompressed length to maxMessageSize to defend against
		// gzip-bomb DoS. Read at most cap+1 so we can detect overflow.
		cap := int64(maxMessageSize)
		out, err := io.ReadAll(io.LimitReader(zr, cap+1))
		if err != nil {
			return nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "grpcweb: gzip read: " + err.Error(),
			}
		}
		if int64(len(out)) > cap {
			return nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: fmt.Sprintf("grpcweb: gzip decompressed size exceeds cap %d", cap),
			}
		}
		return out, nil
	default:
		return nil, &layer.StreamError{
			Code:   layer.ErrorInternalError,
			Reason: "grpcweb: unsupported grpc-encoding: " + encoding,
		}
	}
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
// request side (Send-side from the caller's perspective) sets Method=POST
// and Path=/Service/Method per gRPC-Web convention. The response side keeps
// Status/StatusReason from the original Receive-side context envelope when
// available.
func buildHTTPMessage(
	start *envelope.GRPCStartMessage,
	end *envelope.GRPCEndMessage,
	body []byte,
	dir envelope.Direction,
	srcEnv *envelope.Envelope,
	embedTrailer bool,
) *envelope.HTTPMessage {
	msg := &envelope.HTTPMessage{
		Body:    body,
		Headers: rebuildStartHeaders(start),
	}

	switch dir {
	case envelope.Send:
		// Request side: assemble path + method.
		msg.Method = "POST"
		if start.Service != "" || start.Method != "" {
			msg.Path = "/" + start.Service + "/" + start.Method
		}
		// Caller-provided Authority/Scheme on srcEnv.Context is opaque to
		// HTTPMessage; leave Authority/Scheme empty unless srcEnv carries
		// useful values via its Message (when re-issuing a captured request).
		if srcEnv != nil {
			if hm, ok := srcEnv.Message.(*envelope.HTTPMessage); ok {
				msg.Authority = hm.Authority
				msg.Scheme = hm.Scheme
				if hm.RawQuery != "" {
					msg.RawQuery = hm.RawQuery
				}
			}
		}
	case envelope.Receive:
		// Response side: status from srcEnv if available; otherwise default
		// to 200.
		msg.Status = 200
		msg.StatusReason = "OK"
		if srcEnv != nil {
			if hm, ok := srcEnv.Message.(*envelope.HTTPMessage); ok {
				if hm.Status != 0 {
					msg.Status = hm.Status
				}
				if hm.StatusReason != "" {
					msg.StatusReason = hm.StatusReason
				}
			}
		}
	}
	_ = embedTrailer // kept in signature for parity / future use
	_ = end
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

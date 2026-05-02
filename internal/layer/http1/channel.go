package http1

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// opaqueHTTP1 holds Layer-specific data stored in Envelope.Opaque.
// Pipeline Steps must not type-assert on this.
type opaqueHTTP1 struct {
	rawReq         *parser.RawRequest
	rawResp        *parser.RawResponse
	origKV         []envelope.KeyValue // header snapshot at Next() time
	origBody       []byte              // body snapshot at Next() time (nil for buffer-backed)
	origBodyBuffer *bodybuf.BodyBuffer // buffer-backed body snapshot (nil for memory-backed)
}

// bodyOpts are the per-channel body assembly options, threaded through
// http1.New via WithBodySpillDir / WithBodySpillThreshold / WithMaxBodySize.
type bodyOpts struct {
	spillDir       string
	spillThreshold int64
	maxBody        int64
}

// channel implements layer.Channel for HTTP/1.x.
type channel struct {
	reader    *bufio.Reader // created by Layer
	writer    io.Writer
	streamID  string
	direction envelope.Direction
	scheme    string
	ctxTmpl   envelope.EnvelopeContext
	bodyOpts  bodyOpts

	// streamingDetect, when non-nil and direction == Receive, decides
	// whether to bypass body draining for a parsed response. See
	// [WithStreamingResponseDetect] / [Layer.DetachStreamingBody].
	streamingDetect StreamingResponsePredicate

	// streamingBody holds the pending response body io.Reader after the
	// predicate matched. Layer.DetachStreamingBody claims it.
	streamingBody io.Reader

	// Per-request state.
	currentStreamID string // changes per request-response pair
	sequence        int    // 0=request, 1=response within a pair
	connClosed      bool   // set when Connection: close or HTTP/1.0

	// stateReleaser, when non-nil, is invoked once per emitted FlowID
	// when the Channel reaches its terminal state. RFC §9.3 D6 / Q26
	// maps the HTTP transaction scope to (ConnID, FlowID).
	stateReleaser pluginv2.StateReleaser

	// emittedFlowIDs accumulates the FlowID of every envelope this
	// Channel emitted via Next. Drained by releaseTransactionStates at
	// markTerminated time. Append-only, guarded by termMu (which already
	// guards termErr — both are touched on the terminal path).
	emittedFlowIDs []string

	// Terminal-state tracking. Populated before termDone closes.
	termMu   sync.Mutex
	termErr  error
	termOnce sync.Once
	termDone chan struct{}
}

// StreamID returns the connection-level identifier for this channel.
func (c *channel) StreamID() string { return c.streamID }

// Next reads the next HTTP message from the wire and returns it as an Envelope.
//
// For direction=Send, it parses HTTP requests.
// For direction=Receive, it parses HTTP responses.
//
// Returns io.EOF when the connection should close (Connection: close was set
// on the previous message, or HTTP/1.0 without keep-alive).
func (c *channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	if c.connClosed {
		c.markTerminated(io.EOF)
		return nil, io.EOF
	}

	switch c.direction {
	case envelope.Send:
		return c.nextRequest(ctx)
	case envelope.Receive:
		return c.nextResponse(ctx)
	default:
		err := fmt.Errorf("http1: unknown direction %d", c.direction)
		c.markTerminated(err)
		return nil, err
	}
}

// Send writes an Envelope to the wire.
//
// For direction=Send (server-facing), it serializes responses.
// For direction=Receive (upstream-facing), it serializes requests.
//
// Two paths:
//   - Opaque-based: raw-first patching with OWS preservation (normal flow)
//   - Opaque-less: synthetic serialization fallback (for Resend in N5)
func (c *channel) Send(ctx context.Context, env *envelope.Envelope) error {
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return fmt.Errorf("http1: Send requires *HTTPMessage, got %T", env.Message)
	}

	switch c.direction {
	case envelope.Send:
		// Server-facing layer: Next parses requests, Send writes responses.
		return c.sendResponse(msg, env)
	case envelope.Receive:
		// Upstream-facing layer: Next parses responses, Send writes requests.
		return c.sendRequest(msg, env)
	default:
		return fmt.Errorf("http1: unknown direction %d", c.direction)
	}
}

// Close is a no-op. The connection is owned by the Layer, not the Channel.
func (c *channel) Close() error { return nil }

// Closed returns a channel closed when this Channel has reached its terminal
// state. See layer.Channel for the contract.
func (c *channel) Closed() <-chan struct{} { return c.termDone }

// Err returns the terminal error. See layer.Channel for the contract.
func (c *channel) Err() error {
	c.termMu.Lock()
	defer c.termMu.Unlock()
	return c.termErr
}

// markTerminated stores err (first-writer-wins) and closes termDone exactly
// once. Callers must guarantee err is non-nil.
//
// On the first call we also fire the configured pluginv2 state release for
// every FlowID this Channel emitted via Next. The release is sequenced
// AFTER close(termDone) so a USK-671 dispatch path observing the close
// can run any terminal-event hook before the backing transaction_state
// dict is cleared (matches the http2 / ws ordering contract).
func (c *channel) markTerminated(err error) {
	c.termMu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.termMu.Unlock()
	c.termOnce.Do(func() {
		close(c.termDone)
		c.releaseTransactionStates()
	})
}

// recordEmittedFlowID appends flowID to the set of envelopes the Channel
// has produced via Next. Empty FlowIDs are ignored (defensive — every
// successful Next path mints a uuid, but a future refactor that produces
// envelopes without FlowID must not leak an empty-string release).
func (c *channel) recordEmittedFlowID(flowID string) {
	if flowID == "" {
		return
	}
	c.termMu.Lock()
	c.emittedFlowIDs = append(c.emittedFlowIDs, flowID)
	c.termMu.Unlock()
}

// releaseTransactionStates fires the configured pluginv2.StateReleaser for
// every FlowID this Channel emitted. No-op when no releaser was configured
// (legacy parallel path / plain unit tests) or when the Layer's
// EnvelopeContext has no ConnID (the scope key would be incomplete).
//
// Snapshot under termMu, release outside (mirrors httpaggregator.Channel
// pattern) so a downstream Engine can fan out without holding our mutex.
func (c *channel) releaseTransactionStates() {
	if c.stateReleaser == nil {
		return
	}
	if c.ctxTmpl.ConnID == "" {
		return
	}
	c.termMu.Lock()
	if len(c.emittedFlowIDs) == 0 {
		c.termMu.Unlock()
		return
	}
	snapshot := make([]string, len(c.emittedFlowIDs))
	copy(snapshot, c.emittedFlowIDs)
	c.termMu.Unlock()

	connID := c.ctxTmpl.ConnID
	for _, flowID := range snapshot {
		c.stateReleaser.ReleaseTransaction(connID, flowID)
	}
}

// --- Next() implementation ---

func (c *channel) nextRequest(_ context.Context) (env *envelope.Envelope, retErr error) {
	rawReq, err := parser.ParseRequest(c.reader)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			c.markTerminated(io.EOF)
			return nil, io.EOF
		}
		wrapped := fmt.Errorf("http1: parse request: %w", err)
		c.markTerminated(wrapped)
		return nil, wrapped
	}

	// Generate new StreamID for each request-response pair.
	c.currentStreamID = uuid.New().String()
	c.sequence = 0

	// Parse RequestURI into structured fields.
	path, rawQuery, authority := parseRequestURI(rawReq.RequestURI, rawReq.Headers)

	// Read body. Small bodies are buffered in memory; large bodies spill to a
	// file-backed BodyBuffer. MaxBodySize is enforced as an absolute cap.
	bb, body, err := readBodyWithThreshold(rawReq.Body,
		c.bodyOpts.spillDir, c.bodyOpts.spillThreshold, c.bodyOpts.maxBody)
	if err != nil {
		wrapped := fmt.Errorf("http1: read request body: %w", err)
		c.markTerminated(wrapped)
		return nil, wrapped
	}
	// Release the partial buffer on any subsequent error. On success, bb is
	// owned by the envelope/opaque (single refcount = 1) and released later
	// by the session OnComplete backstop (USK-634).
	defer func() {
		if retErr != nil && bb != nil {
			_ = bb.Release()
		}
	}()

	// Convert anomalies.
	anomalies := convertAnomalies(rawReq.Anomalies)

	// Project chunked trailers. The body reader has been fully drained by
	// readBodyWithThreshold, so trailers are available synchronously.
	trailers, trailerAnomalies := extractTrailers(rawReq.Body)
	anomalies = append(anomalies, trailerAnomalies...)

	// Build HTTPMessage. At most one of Body/BodyBuffer is non-nil.
	msg := &envelope.HTTPMessage{
		Method:     rawReq.Method,
		Scheme:     c.scheme,
		Authority:  authority,
		Path:       path,
		RawQuery:   rawQuery,
		Headers:    rawHeadersToKV(rawReq.Headers),
		Trailers:   trailers,
		Body:       body,
		BodyBuffer: bb,
		Anomalies:  anomalies,
	}

	// Build Envelope.
	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()

	env = &envelope.Envelope{
		StreamID:  c.currentStreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawReq.RawBytes,
		Message:   msg,
		Context:   envCtx,
		Opaque: &opaqueHTTP1{
			rawReq:         rawReq,
			origKV:         cloneKV(msg.Headers),
			origBody:       cloneBytes(body),
			origBodyBuffer: bb,
		},
	}

	// Set connection close semantics.
	c.connClosed = rawReq.Close

	c.recordEmittedFlowID(env.FlowID)
	return env, nil
}

func (c *channel) nextResponse(_ context.Context) (env *envelope.Envelope, retErr error) {
	rawResp, err := parser.ParseResponse(c.reader)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			c.markTerminated(io.EOF)
			return nil, io.EOF
		}
		wrapped := fmt.Errorf("http1: parse response: %w", err)
		c.markTerminated(wrapped)
		return nil, wrapped
	}

	// Streaming-body bypass (USK-655): when the configured predicate matches
	// (e.g. text/event-stream), emit the response Envelope with empty body
	// and stash the still-open body reader on the channel for the swap
	// orchestrator to claim via Layer.DetachStreamingBody. Draining a
	// streaming body would block forever (no Content-Length, no end), so
	// this path is the only safe one for SSE-like responses.
	if c.streamingDetect != nil && c.streamingDetect(rawResp) {
		return c.buildStreamingResponseEnvelope(rawResp), nil
	}

	// Read body. Small bodies are buffered in memory; large bodies spill to a
	// file-backed BodyBuffer. MaxBodySize is enforced as an absolute cap.
	bb, body, err := readBodyWithThreshold(rawResp.Body,
		c.bodyOpts.spillDir, c.bodyOpts.spillThreshold, c.bodyOpts.maxBody)
	if err != nil {
		wrapped := fmt.Errorf("http1: read response body: %w", err)
		c.markTerminated(wrapped)
		return nil, wrapped
	}
	defer func() {
		if retErr != nil && bb != nil {
			_ = bb.Release()
		}
	}()

	// Extract status reason from the full status string.
	statusReason := extractStatusReason(rawResp.Status)

	// Convert anomalies.
	anomalies := convertAnomalies(rawResp.Anomalies)

	// Project chunked trailers. The body reader has been fully drained by
	// readBodyWithThreshold, so trailers are available synchronously.
	trailers, trailerAnomalies := extractTrailers(rawResp.Body)
	anomalies = append(anomalies, trailerAnomalies...)

	// Build HTTPMessage. At most one of Body/BodyBuffer is non-nil.
	msg := &envelope.HTTPMessage{
		Status:       rawResp.StatusCode,
		StatusReason: statusReason,
		Headers:      rawHeadersToKV(rawResp.Headers),
		Trailers:     trailers,
		Body:         body,
		BodyBuffer:   bb,
		Anomalies:    anomalies,
	}

	// Build Envelope.
	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()

	env = &envelope.Envelope{
		StreamID:  c.currentStreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence + 1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawResp.RawBytes,
		Message:   msg,
		Context:   envCtx,
		Opaque: &opaqueHTTP1{
			rawResp:        rawResp,
			origKV:         cloneKV(msg.Headers),
			origBody:       cloneBytes(body),
			origBodyBuffer: bb,
		},
	}

	c.recordEmittedFlowID(env.FlowID)
	return env, nil
}

// buildStreamingResponseEnvelope assembles the response Envelope for the
// streaming-body bypass path. The body is NOT drained; the post-headers
// byte stream on c.reader is stashed on c.streamingBody for
// [Layer.DetachStreamingBody]. msg.Body and msg.BodyBuffer are nil so
// RecordStep records a header-only flow.
//
// We use c.reader directly (rather than rawResp.Body) because the parser's
// resolveResponseBody returns io.LimitReader(r,0) for an HTTP/1.1 response
// with no Content-Length and no chunked Transfer-Encoding — strictly
// correct per RFC 7230 §3.3.3 but wrong for SSE, which intentionally
// violates that rule with an open-ended event stream. Chunked-TE SSE is
// rare in practice (browsers do not require it) and not supported by the
// bypass path; if encountered, the SSE parser will surface a StreamError
// on the unexpected chunk markers.
//
// No Anomaly is attached for the bypass itself: the wire shape is
// well-formed; we are deliberately deferring body materialization.
func (c *channel) buildStreamingResponseEnvelope(rawResp *parser.RawResponse) *envelope.Envelope {
	statusReason := extractStatusReason(rawResp.Status)
	anomalies := convertAnomalies(rawResp.Anomalies)

	msg := &envelope.HTTPMessage{
		Status:       rawResp.StatusCode,
		StatusReason: statusReason,
		Headers:      rawHeadersToKV(rawResp.Headers),
		Anomalies:    anomalies,
	}

	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()

	c.streamingBody = c.reader

	env := &envelope.Envelope{
		StreamID:  c.currentStreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence + 1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawResp.RawBytes,
		Message:   msg,
		Context:   envCtx,
		Opaque: &opaqueHTTP1{
			rawResp: rawResp,
			origKV:  cloneKV(msg.Headers),
		},
	}
	c.recordEmittedFlowID(env.FlowID)
	return env
}

// --- Send() implementation ---

func (c *channel) sendRequest(msg *envelope.HTTPMessage, env *envelope.Envelope) error {
	opaque, _ := env.Opaque.(*opaqueHTTP1)

	// Path 1: Opaque-based (normal flow, raw-first patching).
	if opaque != nil && opaque.rawReq != nil {
		return c.sendRequestOpaque(msg, opaque)
	}

	// Path 2: Synthetic fallback (no Opaque).
	return c.sendRequestSynthetic(msg)
}

func (c *channel) sendResponse(msg *envelope.HTTPMessage, env *envelope.Envelope) error {
	opaque, _ := env.Opaque.(*opaqueHTTP1)

	// Path 1: Opaque-based (normal flow, raw-first patching).
	if opaque != nil && opaque.rawResp != nil {
		return c.sendResponseOpaque(msg, opaque)
	}

	// Path 2: Synthetic fallback (no Opaque).
	return c.sendResponseSynthetic(msg)
}

// --- Send Path 1: Opaque-based ---

func (c *channel) sendRequestOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) error {
	rawReq := opaque.rawReq
	headersChanged := !kvEqual(msg.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(msg, opaque)

	// Zero-copy fast path: nothing changed.
	if !headersChanged && !bodyChanged && len(rawReq.RawBytes) > 0 {
		if _, err := c.writer.Write(rawReq.RawBytes); err != nil {
			return fmt.Errorf("http1: send request raw: %w", err)
		}
		return c.writeBody(msg)
	}

	// Apply header patches.
	if headersChanged {
		rawReq.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawReq.Headers)
	}

	// Update body headers if the body changed. Three sub-cases:
	//   - msg.Body != nil                   → re-stamp CL from len(msg.Body).
	//   - msg.BodyBuffer != nil             → re-stamp CL from BodyBuffer.Len().
	//   - both nil                          → body was cleared; stamp CL=0.
	if bodyChanged {
		rawReq.Headers.Del("Transfer-Encoding")
		switch {
		case msg.Body != nil:
			rawReq.Headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			rawReq.Headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		default:
			rawReq.Headers.Set("Content-Length", "0")
		}
	}

	// Serialize and write.
	headerBytes := serializeRequestHeader(rawReq)
	if _, err := c.writer.Write(headerBytes); err != nil {
		return fmt.Errorf("http1: send request: %w", err)
	}
	return c.writeBody(msg)
}

func (c *channel) sendResponseOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) error {
	rawResp := opaque.rawResp
	headersChanged := !kvEqual(msg.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(msg, opaque)

	// Zero-copy fast path: nothing changed.
	if !headersChanged && !bodyChanged && len(rawResp.RawBytes) > 0 {
		if _, err := c.writer.Write(rawResp.RawBytes); err != nil {
			return fmt.Errorf("http1: send response raw: %w", err)
		}
		return c.writeBody(msg)
	}

	// Apply header patches.
	if headersChanged {
		rawResp.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawResp.Headers)
	}

	// Update body headers if the body changed. See sendRequestOpaque for
	// the three sub-cases.
	if bodyChanged {
		rawResp.Headers.Del("Transfer-Encoding")
		switch {
		case msg.Body != nil:
			rawResp.Headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			rawResp.Headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		default:
			rawResp.Headers.Set("Content-Length", "0")
		}
	}

	// Serialize and write.
	headerBytes := serializeResponseHeader(rawResp)
	if _, err := c.writer.Write(headerBytes); err != nil {
		return fmt.Errorf("http1: send response: %w", err)
	}
	return c.writeBody(msg)
}

// --- Send Path 2: Synthetic (no Opaque) ---

func (c *channel) sendRequestSynthetic(msg *envelope.HTTPMessage) error {
	var buf bytes.Buffer

	// Build request-line.
	requestURI := msg.Path
	if msg.RawQuery != "" {
		requestURI += "?" + msg.RawQuery
	}
	if requestURI == "" {
		requestURI = "/"
	}
	if err := serializeRequestLine(&buf, msg.Method, requestURI, "HTTP/1.1"); err != nil {
		return fmt.Errorf("http1: send synthetic request line: %w", err)
	}

	// Build headers from KeyValue (no OWS preservation — no raw source).
	headers := kvToRawHeaders(msg.Headers)

	// Set Content-Length if body present and header not already set.
	if headers.Get("Content-Length") == "" {
		switch {
		case msg.Body != nil:
			headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		}
	}

	if err := serializeHeaders(&buf, headers); err != nil {
		return fmt.Errorf("http1: send synthetic request headers: %w", err)
	}

	if _, err := c.writer.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("http1: send synthetic request: %w", err)
	}

	return c.writeBody(msg)
}

func (c *channel) sendResponseSynthetic(msg *envelope.HTTPMessage) error {
	var buf bytes.Buffer

	// Build status-line.
	status := fmt.Sprintf("%d %s", msg.Status, msg.StatusReason)
	if msg.StatusReason == "" {
		text := statusText(msg.Status)
		if text == "" {
			text = "Unknown"
		}
		status = fmt.Sprintf("%d %s", msg.Status, text)
	}
	if err := serializeStatusLine(&buf, "HTTP/1.1", status, msg.Status); err != nil {
		return fmt.Errorf("http1: send synthetic status line: %w", err)
	}

	// Build headers from KeyValue.
	headers := kvToRawHeaders(msg.Headers)

	// Set Content-Length if body present and header not already set.
	if headers.Get("Content-Length") == "" {
		switch {
		case msg.Body != nil:
			headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		}
	}

	if err := serializeHeaders(&buf, headers); err != nil {
		return fmt.Errorf("http1: send synthetic response headers: %w", err)
	}

	if _, err := c.writer.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("http1: send synthetic response: %w", err)
	}

	return c.writeBody(msg)
}

// --- Helpers ---

// writeBody writes the body portion of a message to the wire.
// Reads from msg.Body, msg.BodyBuffer, or writes nothing if both are nil.
func (c *channel) writeBody(msg *envelope.HTTPMessage) error {
	if msg.Body != nil {
		if _, err := c.writer.Write(msg.Body); err != nil {
			return fmt.Errorf("http1: write body: %w", err)
		}
		return nil
	}
	if msg.BodyBuffer != nil {
		r, err := msg.BodyBuffer.Reader()
		if err != nil {
			return fmt.Errorf("http1: open body buffer: %w", err)
		}
		defer r.Close()
		if _, err := io.Copy(c.writer, r); err != nil {
			return fmt.Errorf("http1: write body buffer: %w", err)
		}
	}
	return nil
}

// readBodyWithThreshold drains r into either an in-memory []byte (when the
// total size fits within spillThreshold) or a file-backed BodyBuffer (when
// it exceeds the threshold). Enforces maxBody as an absolute cap; exceeding
// it returns a *layer.StreamError{Code: ErrorInternalError}.
//
// Returns: at most one of (bb, body) is non-nil. Both nil means r was nil
// (no body present). On any error, partial resources are released so the
// caller gets a nil bb.
func readBodyWithThreshold(r io.Reader, spillDir string, spillThreshold, maxBody int64) (bb *bodybuf.BodyBuffer, body []byte, retErr error) {
	if r == nil {
		return nil, nil, nil
	}
	// Defensive: caps must be sane even if the layer forgot to set defaults.
	if spillThreshold <= 0 {
		spillThreshold = config.DefaultBodySpillThreshold
	}
	if maxBody <= 0 {
		maxBody = config.MaxBodySize
	}

	// Phase 1: read up to spillThreshold+1 into a scratch buffer to detect
	// overflow. If EOF arrives before the scratch fills, the whole body fits
	// in memory.
	scratch := make([]byte, spillThreshold+1)
	n, readErr := io.ReadFull(r, scratch)

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		if n == 0 {
			return nil, []byte{}, nil
		}
		out := make([]byte, n)
		copy(out, scratch[:n])
		return nil, out, nil
	}
	if readErr != nil {
		return nil, nil, fmt.Errorf("http1: read body: %w", readErr)
	}

	// Phase 2: overflow → switch to file-backed BodyBuffer. At this point
	// n == spillThreshold+1 bytes were consumed into scratch.
	bb, err := bodybuf.NewFile(spillDir, config.BodySpillPrefix, maxBody)
	if err != nil {
		return nil, nil, fmt.Errorf("http1: create body file: %w", err)
	}
	defer func() {
		if retErr != nil && bb != nil {
			_ = bb.Release()
			bb = nil
		}
	}()

	if _, werr := bb.Write(scratch[:n]); werr != nil {
		if errors.Is(werr, bodybuf.ErrMaxSizeExceeded) {
			return nil, nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "http1: body exceeds max size",
			}
		}
		return nil, nil, fmt.Errorf("http1: write body: %w", werr)
	}

	// Stream the remainder directly into the file-backed buffer.
	if _, cerr := io.Copy(bb, r); cerr != nil {
		if errors.Is(cerr, bodybuf.ErrMaxSizeExceeded) {
			return nil, nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "http1: body exceeds max size",
			}
		}
		return nil, nil, fmt.Errorf("http1: read body: %w", cerr)
	}

	return bb, nil, nil
}

// parseRequestURI extracts path, rawQuery, and authority from a RequestURI.
func parseRequestURI(requestURI string, headers parser.RawHeaders) (path, rawQuery, authority string) {
	authority = headers.Get("Host")

	if requestURI == "*" {
		return "*", "", authority
	}

	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		// Best-effort: use as-is.
		return requestURI, "", authority
	}

	path = u.Path
	rawQuery = u.RawQuery

	// For absolute-form URIs, extract authority from URI if Host header is absent.
	if u.Host != "" && authority == "" {
		authority = u.Host
	}

	return path, rawQuery, authority
}

// extractStatusReason extracts the reason phrase from a status string like "200 OK".
func extractStatusReason(status string) string {
	// status is "StatusCode ReasonPhrase" (e.g., "200 OK", "404 Not Found").
	if idx := strings.IndexByte(status, ' '); idx >= 0 {
		return status[idx+1:]
	}
	return ""
}

// rawHeadersToKV converts parser.RawHeaders to []envelope.KeyValue.
func rawHeadersToKV(raw parser.RawHeaders) []envelope.KeyValue {
	kv := make([]envelope.KeyValue, len(raw))
	for i, h := range raw {
		kv[i] = envelope.KeyValue{Name: h.Name, Value: h.Value}
	}
	return kv
}

// kvToRawHeaders converts []envelope.KeyValue to parser.RawHeaders (no RawValue).
func kvToRawHeaders(kv []envelope.KeyValue) parser.RawHeaders {
	raw := make(parser.RawHeaders, len(kv))
	for i, h := range kv {
		raw[i] = parser.RawHeader{Name: h.Name, Value: h.Value}
	}
	return raw
}

// cloneKV returns a deep copy of []envelope.KeyValue.
func cloneKV(kv []envelope.KeyValue) []envelope.KeyValue {
	if kv == nil {
		return nil
	}
	out := make([]envelope.KeyValue, len(kv))
	copy(out, kv)
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

// kvEqual checks if two []envelope.KeyValue slices are identical.
func kvEqual(a, b []envelope.KeyValue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

// isBodyChanged checks whether the message body was modified from the original.
// Priority: BodyBuffer pointer identity (Transform can't create a fresh
// BodyBuffer; Pipeline mutations materialize into msg.Body), then fall back
// to byte compare.
func isBodyChanged(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) bool {
	// If the BodyBuffer pointer changed, the body changed. This catches both
	// (a) Pipeline replaced a buffered body with a fresh BodyBuffer, and
	// (b) Pipeline dropped the buffered body (msg.BodyBuffer=nil, origBodyBuffer!=nil).
	if msg.BodyBuffer != opaque.origBodyBuffer {
		// Exception: if Pipeline materialized the original buffer into msg.Body
		// and left BodyBuffer nil, that's still a change only if the bytes differ.
		// But we don't have the original bytes in memory when origBodyBuffer was
		// set, so we must treat this as changed. Either way, CL needs restamping.
		return true
	}
	// BodyBuffer unchanged (both nil OR same pointer).
	// If BodyBuffer is still the original, msg.Body is expected to be nil.
	// A non-nil msg.Body alongside the same origBodyBuffer would mean the
	// Pipeline both kept the buffer AND set Body — treat as changed and let
	// the msg.Body path win in the write code.
	if opaque.origBodyBuffer != nil {
		if msg.Body != nil {
			return true
		}
		// Buffer-backed and unchanged.
		return false
	}
	// Memory-backed path.
	if msg.Body == nil && opaque.origBody == nil {
		return false
	}
	if opaque.origBody == nil {
		// Pipeline set Body where there was nothing before.
		return true
	}
	if msg.Body == nil {
		// Pipeline cleared the body.
		return true
	}
	return !bytes.Equal(msg.Body, opaque.origBody)
}

// convertAnomalies converts parser anomalies to envelope anomalies.
func convertAnomalies(parserAnomalies []parser.Anomaly) []envelope.Anomaly {
	if len(parserAnomalies) == 0 {
		return nil
	}
	anomalies := make([]envelope.Anomaly, len(parserAnomalies))
	for i, a := range parserAnomalies {
		anomalies[i] = envelope.Anomaly{
			Type:   envelope.AnomalyType(a.Type),
			Detail: a.Detail,
		}
	}
	return anomalies
}

// extractTrailers projects chunked trailers from the parser body onto the
// outgoing HTTPMessage. After USK-631 the HTTP/1.x layer always fully drains
// the body into either in-memory bytes or a file-backed BodyBuffer, so
// trailers are always available synchronously on the TrailerProvider. The
// passthrough-mode path that emitted AnomalyTrailersInPassthrough is gone.
//
// parserBody that is not a TrailerProvider (e.g., Content-Length framing,
// no-body) yields no trailers and no anomaly.
func extractTrailers(parserBody io.Reader) ([]envelope.KeyValue, []envelope.Anomaly) {
	tp, ok := parserBody.(parser.TrailerProvider)
	if !ok {
		return nil, nil
	}
	var trailers []envelope.KeyValue
	if raw := tp.Trailers(); len(raw) > 0 {
		trailers = rawHeadersToKV(raw)
	}
	anomalies := convertAnomalies(tp.TrailerAnomalies())
	return trailers, anomalies
}

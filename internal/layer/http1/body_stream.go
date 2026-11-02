package http1

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// USK-1409: HTTP/1.x response body streaming (RFC-001 §3.2.1 "HTTP body
// streaming").
//
// For a final response the body-mode predicate (WithResponseBodyMode)
// chose to stream, the receive loop emits the Envelope right after the
// header section with HTTPMessage.BodyStream set, and waits until that
// body ended before parsing anything else from the conn. The body is read
// by the goroutine that forwards the response — the session goroutine,
// inside the client Channel's Send — directly from the parser's body
// reader. The parser's raw tap (parser.RawTapSetter) reports every wire
// byte of the body as it is read; an HTTP/1.x client Channel writes those
// bytes to its client verbatim, so chunk sizes, extensions and trailers
// reach the client exactly as the upstream sent them, and RecordStep
// observes them for the record.

// streamCopyBufSize is the read / write unit of a streamed body.
const streamCopyBufSize = 32 << 10

// streamedResponse is a response the receive loop emits with a streamed
// body.
type streamedResponse struct {
	env *envelope.Envelope
	src *h1BodySource
}

// maybeStreamResponse applies the body-mode decision to a parsed final
// response. It returns streamed != nil when the body is streamed. For a
// layer.BodyBufferUpTo decision whose body turned out to fit, prefix holds
// the whole body already read; the caller then assembles the buffered
// envelope from it.
func (c *channel) maybeStreamResponse(rawResp *parser.RawResponse) (prefix []byte, streamed *streamedResponse, err error) {
	mode := c.responseBodyMode(rawResp)
	switch mode.Kind {
	case layer.BodyStream:
		return nil, c.streamResponse(rawResp, nil), nil
	case layer.BodyBufferUpTo:
		if n, ok := declaredContentLength(rawResp); ok && n > mode.Limit {
			return nil, c.streamResponse(rawResp, nil), nil
		}
		probe, fits, perr := c.probeBody(rawResp, mode.Limit)
		if perr != nil {
			return nil, nil, perr
		}
		if fits {
			return probe, nil, nil
		}
		if s := c.streamResponse(rawResp, probe); s != nil {
			return nil, s, nil
		}
		// The probe's raw capture was cut: the wire bytes already read
		// cannot be forwarded verbatim, so keep buffering (the pre-USK-1409
		// path, bounded by max_body_size).
		return probe, nil, nil
	default:
		return nil, nil, nil
	}
}

// responseBodyMode returns the body mode for rawResp. The predicate is not
// consulted — the body is buffered — when none is configured and for
// responses whose body is empty by framing or protocol, or which belong to
// gRPC-Web (whose Layer reassembles the whole body, USK-1409 R13).
func (c *channel) responseBodyMode(rawResp *parser.RawResponse) layer.BodyMode {
	if c.bodyMode == nil || c.direction != envelope.Receive {
		return layer.Buffer()
	}
	code := rawResp.StatusCode
	if code < 200 || code == 204 || code == 304 {
		return layer.Buffer()
	}
	switch strings.ToUpper(c.pairedRequestMethod()) {
	case "HEAD", "CONNECT":
		return layer.Buffer()
	}
	if !responseHasFramedBody(rawResp) {
		return layer.Buffer()
	}
	if isGRPCWebMediaType(rawResp.Headers.Get("Content-Type")) {
		return layer.Buffer()
	}
	if p := c.requestContentType.Load(); p != nil && isGRPCWebMediaType(*p) {
		return layer.Buffer()
	}
	if _, ok := rawResp.Body.(parser.RawTapSetter); !ok {
		return layer.Buffer()
	}
	env, msg := c.responseHeadEnvelope(rawResp)
	return c.bodyMode(env, msg)
}

// responseHasFramedBody reports whether the response can carry body bytes:
// chunked (HTTP/1.1+), a positive Content-Length, or an EOF-delimited body
// (HTTP/1.0 or Connection: close without Content-Length). An HTTP/1.1
// response with none of these has no body (parser resolveResponseBody).
func responseHasFramedBody(rawResp *parser.RawResponse) bool {
	if rawResp.Proto != "HTTP/1.0" && parser.IsChunked(rawResp.Headers) {
		return true
	}
	if rawResp.Headers.Get("Content-Length") != "" {
		n, ok := declaredContentLength(rawResp)
		return ok && n > 0
	}
	return rawResp.Proto == "HTTP/1.0" || responseConnectionClose(rawResp)
}

// declaredContentLength returns the response's Content-Length when it is
// the body framing (not chunked) and parses.
func declaredContentLength(rawResp *parser.RawResponse) (int64, bool) {
	if rawResp.Proto != "HTTP/1.0" && parser.IsChunked(rawResp.Headers) {
		return 0, false
	}
	cl := rawResp.Headers.Get("Content-Length")
	if cl == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// isGRPCWebMediaType reports whether ct names a gRPC-Web media type.
func isGRPCWebMediaType(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/grpc-web")
}

// headerKVValue returns the first value of name (case-insensitive).
func headerKVValue(headers []envelope.KeyValue, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// responseHeadEnvelope builds the header-only response Message and the
// Envelope the predicate sees: the Channel's context template, which
// carries the paired request's method / path / authority (USK-1409 R2), so
// the predicate's rule matchers see what the Pipeline Steps will see.
func (c *channel) responseHeadEnvelope(rawResp *parser.RawResponse) (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{
		Status:       rawResp.StatusCode,
		StatusReason: extractStatusReason(rawResp.Status),
		HTTPVersion:  envelope.HTTPVersionFromProto(rawResp.Proto),
		Headers:      rawHeadersToKV(rawResp.Headers),
		Anomalies:    convertAnomalies(rawResp.Anomalies),
	}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Context:   c.ctxTmpl,
	}
	return env, msg
}

// probeBody reads up to limit+1 semantic body bytes (USK-1409 R14). fits
// reports that the body ended within limit; the bytes read are returned
// either way. Raw-body spill is configured first, as for a buffered body,
// so the wire bytes of the probed prefix are captured whatever its size.
func (c *channel) probeBody(rawResp *parser.RawResponse, limit int64) (probe []byte, fits bool, err error) {
	configureRawBodySpill(rawResp.Body, c.bodyOpts)
	if limit < 0 {
		limit = 0
	}
	buf := make([]byte, limit+1)
	n, rerr := io.ReadFull(rawResp.Body, buf)
	switch {
	case rerr == nil:
		return buf[:n], false, nil
	case errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF):
		return buf[:n], true, nil
	default:
		releaseOrphanRawBodyBuffer(rawResp.Body)
		return nil, false, fmt.Errorf("http1: read response body: %w", rerr)
	}
}

// streamResponse builds the streamed-body Envelope for rawResp. semPrefix
// holds body bytes a probe already read (nil when none); their wire bytes
// are still in the parser's raw capture and are forwarded first. Returns
// nil when that capture was cut (the prefix cannot be forwarded verbatim).
func (c *channel) streamResponse(rawResp *parser.RawResponse, semPrefix []byte) *streamedResponse {
	src := &h1BodySource{
		ch:   c,
		body: rawResp.Body,
		done: make(chan struct{}),
	}
	if semPrefix != nil {
		rp, ok := rawResp.Body.(parser.RawBodyProvider)
		if !ok || rp.RawBodyTruncated() {
			return nil
		}
		src.semPrefix = semPrefix
		src.rawPrefix = rp.RawBody()
		src.rawPrefixBuf = rp.RawBodyBuffer()
	}
	bs := envelope.NewBodyStream(src)
	src.bs = bs
	rawResp.Body.(parser.RawTapSetter).SetRawTap(src.onRaw)

	env, msg := c.responseHeadEnvelope(rawResp)
	msg.BodyStream = bs
	env.Context.ReceivedAt = time.Now()

	emitSeq, _ := c.advanceResponseSequence(rawResp.StatusCode)
	if c.currentStreamID == "" {
		c.currentStreamID = uuid.New().String()
	}
	opaque := &opaqueHTTP1{
		rawResp: rawResp,
		origKV:  cloneKV(msg.Headers),
	}
	opaque.snapshotStatusLine(msg)

	env.StreamID = c.currentStreamID
	env.FlowID = uuid.New().String()
	env.Sequence = emitSeq
	// Raw is the header section only, like the SSE bypass: the body's wire
	// bytes are observed through the BodyStream as they are forwarded.
	env.Raw = rawResp.RawBytes
	env.Opaque = opaque

	c.bodyStream.Store(bs)
	c.recordEmittedFlowID(env.FlowID)
	return &streamedResponse{env: env, src: src}
}

// Raw-prefix ownership states for h1BodySource.prefixState.
const (
	prefixPending int32 = iota
	prefixFlushing
	prefixReleased
)

// h1BodySource is the HTTP/1.x producer of a streamed response body
// (envelope.BodyStreamSource). Read runs on the consumer's goroutine and is
// the only reader of the parent Layer's bufio.Reader until done is closed;
// the receive loop waits on done.
type h1BodySource struct {
	ch   *channel
	body io.Reader // parser body reader (raw tap installed)
	bs   *envelope.BodyStream

	// semPrefix / rawPrefix / rawPrefixBuf: a BufferUpTo probe's bytes,
	// replayed first (semantic via Read, raw via onRaw on the first Read).
	semPrefix    []byte
	rawPrefix    []byte
	rawPrefixBuf *bodybuf.BodyBuffer
	prefixState  atomic.Int32

	// fwd, when set by an HTTP/1.x client Channel, receives the raw body
	// bytes; fwdErr latches its first write error. Reading goroutine only.
	fwd    *bufio.Writer
	fwdErr error

	done chan struct{}
}

// Read implements envelope.BodyStreamSource.
func (s *h1BodySource) Read(p []byte) (int, error) {
	if s.prefixState.CompareAndSwap(prefixPending, prefixFlushing) {
		s.flushRawPrefix()
		s.prefixState.Store(prefixReleased)
	}
	if len(s.semPrefix) > 0 {
		n := copy(p, s.semPrefix)
		s.semPrefix = s.semPrefix[n:]
		return n, nil
	}
	return s.body.Read(p)
}

// onRaw is the parser raw tap: forward the wire bytes, then report them to
// the BodyStream observers.
func (s *h1BodySource) onRaw(p []byte) {
	if s.fwd != nil && s.fwdErr == nil {
		if _, err := s.fwd.Write(p); err != nil {
			s.fwdErr = err
		}
	}
	s.bs.EmitRaw(p)
}

// flushRawPrefix forwards / reports the probe's raw bytes and releases the
// spilled copy. Called once, from the first Read.
func (s *h1BodySource) flushRawPrefix() {
	if len(s.rawPrefix) > 0 {
		s.onRaw(s.rawPrefix)
		s.rawPrefix = nil
	}
	if s.rawPrefixBuf == nil {
		return
	}
	defer func() {
		_ = s.rawPrefixBuf.Release()
		s.rawPrefixBuf = nil
	}()
	r, err := s.rawPrefixBuf.Reader()
	if err != nil {
		s.fwdErr = fmt.Errorf("http1: open probed raw body: %w", err)
		return
	}
	defer r.Close()
	buf := make([]byte, streamCopyBufSize)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			s.onRaw(buf[:n])
		}
		if rerr != nil {
			return
		}
	}
}

// forwardTo makes the raw tap write the body's wire bytes to w. Must be
// called on the reading goroutine before the first Read.
func (s *h1BodySource) forwardTo(w *bufio.Writer) { s.fwd = w }

// flushForward flushes the forwarded bytes, returning the first forward
// write error.
func (s *h1BodySource) flushForward() error {
	if s.fwdErr != nil {
		return s.fwdErr
	}
	if s.fwd == nil {
		return nil
	}
	if err := s.fwd.Flush(); err != nil {
		s.fwdErr = err
	}
	return s.fwdErr
}

// Finish implements envelope.BodyStreamSource. On the reading goroutine
// (cause from Read) it collects trailers / anomalies and, for an abnormal
// end, stores the exchange's terminal error before Read returns — so the
// consumer's next Next on the upstream Channel reports it (USK-1409 R8) —
// and marks the Layer dead. For a body closed unread (cause
// ErrBodyStreamClosed, possibly concurrent with a Read) it touches no
// reader state: it marks the Layer dead and arms an immediate read
// deadline so an in-flight read returns. done is closed last, releasing
// the receive loop.
func (s *h1BodySource) Finish(cause error) envelope.BodyResult {
	defer close(s.done)
	if s.prefixState.CompareAndSwap(prefixPending, prefixReleased) && s.rawPrefixBuf != nil {
		_ = s.rawPrefixBuf.Release()
	}
	l := s.ch.layer
	var res envelope.BodyResult
	if errors.Is(cause, envelope.ErrBodyStreamClosed) {
		res.Err = cause
		l.markDead("streamed response body closed before its end", cause)
		_ = l.conn.SetReadDeadline(time.Now())
		return res
	}
	res.Trailers, res.Anomalies = extractTrailers(s.body)
	if a, ok := bodyTruncationAnomaly(s.body); ok {
		res.Anomalies = append(res.Anomalies, a)
		res.Truncated = true
		se := &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: "http1: upstream closed the connection mid-body",
		}
		res.Err = se
		s.ch.postFinalErr.Store(se)
		l.markDead("upstream closed mid-body", se)
		return res
	}
	if !errors.Is(cause, io.EOF) {
		se := &layer.StreamError{
			Code:   layer.ErrorProtocol,
			Reason: fmt.Sprintf("http1: read response body: %v", cause),
		}
		res.Err = se
		s.ch.postFinalErr.Store(se)
		l.markDead("streamed response body read failed", cause)
	}
	return res
}

// sendResponseStreamed writes a response whose body is a BodyStream
// (USK-1409). The Channel owns the stream from here: it is closed on every
// exit. The head is written and flushed first, then the body is read and
// the upstream's body wire bytes are written to the client as they arrive
// (raw forwarding through the parser tap; never re-chunked). An upstream
// cut ends the body, not the Send: the bytes received are written, the
// exchange is marked incomplete so the client connection closes, and the
// upstream Channel's next Next reports the abort. A client write error is
// returned.
func (c *channel) sendResponseStreamed(msg *envelope.HTTPMessage, env *envelope.Envelope) error {
	bs := msg.BodyStream
	defer bs.Close()
	if env.RawWins() {
		if err := c.sendRawWins(env.Raw, "response"); err != nil {
			return err
		}
		c.noteResponseWritten(msg, true)
		return nil
	}
	src, ok := bs.Source().(*h1BodySource)
	opaque, _ := env.Opaque.(*opaqueHTTP1)
	if !ok || opaque == nil || opaque.rawResp == nil {
		// USK-1409 D4: only an HTTP/1.x upstream produces BodyStream today.
		return errors.New("http1: send response: body stream was not produced by an HTTP/1.x upstream")
	}
	head, d := opaqueResponseHead(msg, opaque)
	bw := bufio.NewWriterSize(c.layer.conn, streamCopyBufSize)
	if _, err := bw.Write(head); err != nil {
		return fmt.Errorf("http1: send response: %w", err)
	}
	if err := bw.Flush(); err != nil {
		what := "send response"
		if d.zeroCopy {
			what = "send response raw"
		}
		return fmt.Errorf("http1: %s: %w", what, err)
	}
	src.forwardTo(bw)
	buf := make([]byte, streamCopyBufSize)
	for {
		_, rerr := bs.Read(buf)
		if ferr := src.flushForward(); ferr != nil {
			return fmt.Errorf("http1: send response body: %w", ferr)
		}
		if rerr == nil {
			continue
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if res, _ := bs.Result(); res.Truncated {
			c.responseIncomplete.Store(true)
			c.finalResponseSent.Store(true)
			return nil
		}
		return fmt.Errorf("http1: send response body: %w", rerr)
	}
	c.noteResponseWritten(msg, false)
	return nil
}

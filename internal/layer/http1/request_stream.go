package http1

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// USK-1414: HTTP/1.x request body streaming (RFC-001 §3.2.1 "HTTP body
// streaming"), the request-direction twin of the USK-1409 response path.
//
// For a request the body-mode predicate (WithRequestBodyMode) chose to
// stream, the client-facing Layer emits the Envelope right after the header
// section with HTTPMessage.BodyStream set. The body is read by the
// upstream-facing HTTP/1.x Channel's Send — the session goroutine — directly
// from the client Layer's parser body reader; the parser's raw tap reports
// every wire byte of the body as it is read and Send writes those bytes to
// the upstream verbatim (chunk sizes, extensions and trailers as the client
// sent them, never re-chunked).
//
// The client Layer parses the next request only after that body ended
// cleanly. Any other end — closed unread (Pipeline Respond / Drop, a dial
// failure), the client closing mid-body, a framing error — ends the
// connection, so bytes of an unfinished body are never parsed as a request.

// requestBodyMode returns the body mode for rawReq. The predicate is not
// consulted — the body is buffered — when none is configured, for a request
// whose head frames no body bytes (parser.RequestFraming: neither chunked
// nor Content-Length > 0; an invalid Content-Length frames an empty body),
// and for gRPC-Web, whose Layer reassembles the whole body. env and msg are
// the head-only Envelope and Message the request is emitted with.
func (c *channel) requestBodyMode(rawReq *parser.RawRequest, env *envelope.Envelope, msg *envelope.HTTPMessage) layer.BodyMode {
	if c.bodyMode == nil || c.direction != envelope.Send {
		return layer.Buffer()
	}
	if !parser.RequestFraming(rawReq.Headers, rawReq.Proto).HasBody() {
		return layer.Buffer()
	}
	if isGRPCWebMediaType(rawReq.Headers.Get("Content-Type")) {
		return layer.Buffer()
	}
	if _, ok := rawReq.Body.(parser.RawTapSetter); !ok {
		return layer.Buffer()
	}
	return c.bodyMode(env, msg)
}

// requestHeadEnvelope builds the request Message without a body and the
// Envelope it is emitted with: the identity, the Channel's context template
// (stamped with the request line by the caller) and the absolute-form
// authority. ReceivedAt is the header-arrival time. The body-mode predicate
// sees exactly these values, and the emitted Envelope is this one.
func (c *channel) requestHeadEnvelope(rawReq *parser.RawRequest, streamID, path, rawQuery, authority string) (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{
		Method:      rawReq.Method,
		Scheme:      c.scheme,
		Authority:   authority,
		Path:        path,
		RawQuery:    rawQuery,
		HTTPVersion: envelope.HTTPVersionFromProto(rawReq.Proto),
		Headers:     rawHeadersToKV(rawReq.Headers),
		Anomalies:   convertAnomalies(rawReq.Anomalies),
	}
	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()
	// USK-1274: the absolute-form authority, for the scope check only.
	// Set on this request envelope's copy, not on ctxTmpl, so the paired
	// Receive envelopes do not carry it.
	envCtx.AbsoluteFormAuthority = absoluteFormAuthority(rawReq.RequestURI)
	env := &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Context:   envCtx,
	}
	return env, msg
}

// newRequestOpaque returns the Opaque of a request parsed from rawReq into
// msg; body / bb are the buffered body (both nil for a streamed body).
func (c *channel) newRequestOpaque(rawReq *parser.RawRequest, msg *envelope.HTTPMessage, body []byte, bb *bodybuf.BodyBuffer) *opaqueHTTP1 {
	opaque := &opaqueHTTP1{
		rawReq:         rawReq,
		origKV:         cloneKV(msg.Headers),
		origBody:       cloneBytes(body),
		origBodyBuffer: bb,
	}
	opaque.snapshotRequestLine(msg)
	opaque.setForwardOriginForm(c.layer.opts.forwardOriginForm)
	return opaque
}

// streamRequest completes the head-only request Envelope for a body
// streamed through src. Envelope.Raw is the header section only; the body's
// wire bytes are observed through the BodyStream while they are forwarded.
func (c *channel) streamRequest(rawReq *parser.RawRequest, env *envelope.Envelope, msg *envelope.HTTPMessage, src *h1BodySource) {
	msg.BodyStream = src.bs
	env.Raw = rawReq.RawBytes
	env.Opaque = c.newRequestOpaque(rawReq, msg, nil, nil)
}

// finishRequest is Finish for a request body (the producer is a
// client-facing Channel). A clean end leaves the connection usable for the
// next request. Any other end marks the request body incomplete, which ends
// the connection once the exchange is over (Layer.requestBodyEnded): a
// body closed unread (possibly concurrent with a Read; no reader state is
// touched) also arms an immediate read deadline so an in-flight read
// returns; a client that closed mid-body yields AnomalyTruncatedBody and an
// aborted error; a framing or read error a protocol error.
func (s *h1BodySource) finishRequest(cause error) envelope.BodyResult {
	c := s.ch
	var res envelope.BodyResult
	if errors.Is(cause, envelope.ErrBodyStreamClosed) {
		res.Err = cause
		c.requestBodyIncomplete.Store(true)
		_ = c.layer.conn.SetReadDeadline(time.Now())
		return res
	}
	res.Trailers, res.Anomalies = extractTrailers(s.body)
	if a, ok := bodyTruncationAnomaly(s.body); ok {
		res.Anomalies = append(res.Anomalies, a)
		res.Truncated = true
		res.Err = &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: "http1: client closed the connection mid-body",
		}
		c.requestBodyIncomplete.Store(true)
		return res
	}
	if !errors.Is(cause, io.EOF) {
		res.Err = &layer.StreamError{
			Code:   layer.ErrorProtocol,
			Reason: fmt.Sprintf("http1: read request body: %v", cause),
		}
		c.requestBodyIncomplete.Store(true)
	}
	return res
}

// requestBodyEnded reports, once ch's exchange is over (termDone), whether
// the connection may carry another request (USK-1414 R8). Without a
// streamed request body it is true. Otherwise the body is closed — nobody
// reads it any more; a body that already ended is unaffected — and, after
// it ended, true only for a clean end. An unfinished body ends the
// connection: its remaining bytes are never parsed as a request. When a
// final response was written (a Pipeline Respond), the write side is
// half-closed and the rest of the client's upload is read and discarded,
// bounded, so closing does not reset the connection before the client read
// the response.
func (l *Layer) requestBodyEnded(ch *channel) bool {
	if ch.direction != envelope.Send {
		return true
	}
	bs := ch.bodyStream.Load()
	if bs == nil {
		return true
	}
	_ = bs.Close()
	select {
	case <-bs.Done():
	case <-l.closed:
		return false
	}
	if !ch.requestBodyIncomplete.Load() {
		return true
	}
	slog.Debug("http1: request body did not end cleanly; ending client connection",
		"stream_id", l.streamID,
		"final_response_sent", ch.finalResponseSent.Load())
	if ch.finalResponseSent.Load() {
		l.writeMu.Lock()
		l.halfCloseAndLinger()
		l.writeMu.Unlock()
	}
	return false
}

// halfCloseAndLinger half-closes the write side (FIN / close_notify) and
// reads and discards what the client still sends, bounded by
// rejectLingerTimeout and rejectLingerMaxBytes, so that closing the
// connection afterwards sends FIN rather than RST — an RST can make the
// client discard a response it has not read yet. Caller holds writeMu.
func (l *Layer) halfCloseAndLinger() {
	if cw, ok := l.conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	_ = l.conn.SetReadDeadline(time.Now().Add(rejectLingerTimeout))
	_, _ = io.CopyN(io.Discard, l.conn, rejectLingerMaxBytes)
}

// sendRequestStreamed writes a request whose body is a BodyStream produced
// by a client-facing HTTP/1.x Channel (USK-1414). The head is written and
// flushed first, then the body is read and the client's body wire bytes are
// written upstream as they arrive (raw forwarding through the parser tap;
// never re-chunked).
//
// Ownership: a failure writing the head leaves the stream untouched — no
// body byte was read — so a stale-connection replay on a fresh upstream
// sends the same one-shot body (R11). From the first body read on, Send owns
// the stream and closes it on every exit; a write failure then is a
// body-stage error, never replay-safe. ctx cancellation closes the stream,
// which unblocks a read waiting on an idle client.
//
// A client that closed mid-body (U1) ends the body, not the Send: the bytes
// received were written, the upstream's write side is half-closed so it
// sees the same end of the request, and the response keeps flowing. The
// upstream connection carries no further exchange.
func (c *channel) sendRequestStreamed(ctx context.Context, msg *envelope.HTTPMessage, env *envelope.Envelope, opaque *opaqueHTTP1) error {
	bs := msg.BodyStream
	src, ok := bs.Source().(*h1BodySource)
	if !ok || opaque == nil || opaque.rawReq == nil {
		_ = bs.Close()
		return errors.New("http1: send request: body stream was not produced by an HTTP/1.x client")
	}
	head, d := opaqueRequestHead(msg, opaque)
	bw := bufio.NewWriterSize(c.layer.conn, streamCopyBufSize)
	_, err := bw.Write(head)
	if err == nil {
		err = bw.Flush()
	}
	if err != nil {
		what := "send request"
		if d.zeroCopy {
			what = "send request raw"
		}
		return fmt.Errorf("http1: %s: %w", what, wrapStaleErr(err, msg, opaque, "header"))
	}

	defer bs.Close()
	stop := context.AfterFunc(ctx, func() { _ = bs.Close() })
	defer stop()
	src.forwardTo(bw)
	buf := make([]byte, streamCopyBufSize)
	for {
		_, rerr := bs.Read(buf)
		if ferr := src.flushForward(); ferr != nil {
			return wrapSendBodyStaleErr(fmt.Errorf("http1: send request body: %w", ferr), msg, opaque)
		}
		if rerr == nil {
			continue
		}
		if errors.Is(rerr, io.EOF) {
			return nil
		}
		if res, _ := bs.Result(); res.Truncated {
			c.layer.markDead("client closed mid-body; upstream write side closed", res.Err)
			if cw, ok := c.layer.conn.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			return nil
		}
		return fmt.Errorf("http1: send request body: %w", rerr)
	}
}

package httpaggregator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-1401: HTTP/2 body streaming (RFC-001 §3.2.1 "HTTP body streaming").
//
// When the body-mode predicate (WrapOptions.BodyMode) chooses to stream a
// message, the aggregator emits the HTTPMessage right after its HEADERS,
// with HTTPMessage.BodyStream set, instead of folding every DATA event into
// one message. The body is read by the goroutine that forwards the message
// — the session goroutine, inside the peer aggregator's Send — and each
// Read pulls the next event from the underlying h2 stream Channel itself:
//
//   - a DATA event fires the h2-frame overlay callback, is reported as raw
//     body bytes (EmitRaw), is forwarded as one DATA event (one DATA frame,
//     never coalesced) by a consuming aggregator, and its payload is the
//     semantic body;
//   - a trailers event is reported as raw bytes (its HPACK block), forwarded
//     as trailers and ends the body;
//   - a terminal error from the stream (RST_STREAM, a connection drop before
//     END_STREAM) ends the body truncated; the consumer forwarded what
//     arrived and sends no END_STREAM, and the producing aggregator's next
//     Next reports the error so the session resets the peer with the same
//     code.
//
// The aggregator never reads the stream concurrently with the source: until
// the body ended, its Next does not call the inner Next (see settleStream).

// streamReadBufSize is the Read buffer a consuming Send uses for a streamed
// body. A DATA payload larger than it is returned over several Reads; it is
// forwarded once, whole, on the first.
const streamReadBufSize = 32 << 10

// h2BodySource is the envelope.BodyStreamSource of a streamed HTTP/2 body.
//
// Read runs on the consumer's goroutine and is the only caller of the
// stream Channel's Next while the body is open. Finish may run concurrently
// with Read when the body is closed before its end (envelope.BodyStream
// contract): it then only cancels the read context and releases the probed
// prefix, both safe from any goroutine.
type h2BodySource struct {
	inner  layer.Channel
	ctx    context.Context
	cancel context.CancelFunc
	bs     *envelope.BodyStream
	// cb is the h2-frame overlay callback (WithH2FrameRecordCallback);
	// headCtx is the head's Context, which carries the request fields the
	// overlay envelopes need (USK-1199).
	cb      func(*envelope.Envelope)
	headCtx envelope.EnvelopeContext

	// started latches on the first Read: a consumer owns the body.
	started atomic.Bool

	// The BufferUpTo probe's DATA events (USK-1401 R21): the payloads in
	// prefixBuf at the event lengths prefixLens, replayed first (their
	// overlay rows already fired), then pendingEv — the event that took the
	// probe over its limit — then the live stream. prefixMu serialises the
	// replay with a concurrent Finish.
	prefixMu       sync.Mutex
	prefixBuf      *bodybuf.BodyBuffer
	prefixR        io.ReadCloser
	prefixLens     []int
	prefixIdx      int
	prefixReleased bool
	pendingEv      *envelope.Envelope

	// Reading-goroutine state.
	pending   []byte // semantic bytes of the last DATA not yet returned
	ended     bool
	endErr    error
	truncated bool
	trailers  []envelope.KeyValue
	anomalies []envelope.Anomaly

	// fwd, set by a consuming aggregator before the first Read, forwards
	// each event; fwdErr latches its first error.
	fwd    func(envelope.Message) error
	fwdErr error
}

// Read implements envelope.BodyStreamSource.
func (s *h2BodySource) Read(p []byte) (int, error) {
	s.started.Store(true)
	for {
		if len(s.pending) > 0 {
			n := copy(p, s.pending)
			s.pending = s.pending[n:]
			if len(s.pending) == 0 && s.ended {
				return n, s.endErr
			}
			return n, nil
		}
		if s.ended {
			return 0, s.endErr
		}
		ev, overlay, err := s.nextEvent()
		if err != nil {
			s.fail(err)
			continue
		}
		s.handle(ev, overlay)
	}
}

// nextEvent returns the next body event: the probed prefix, then the event
// that ended the probe, then the live stream. overlay reports whether the
// h2-frame overlay callback still has to fire for it.
func (s *h2BodySource) nextEvent() (*envelope.Envelope, bool, error) {
	if ev, ok, err := s.nextPrefixEvent(); ok || err != nil {
		return ev, false, err
	}
	if ev := s.pendingEv; ev != nil {
		s.pendingEv = nil
		return ev, true, nil
	}
	ev, err := s.inner.Next(s.ctx)
	return ev, true, err
}

// nextPrefixEvent returns the next probed DATA event, ok=false once the
// prefix is exhausted (it is then released).
func (s *h2BodySource) nextPrefixEvent() (*envelope.Envelope, bool, error) {
	s.prefixMu.Lock()
	defer s.prefixMu.Unlock()
	if s.prefixReleased {
		if s.prefixIdx < len(s.prefixLens) {
			return nil, false, envelope.ErrBodyStreamClosed
		}
		return nil, false, nil
	}
	if s.prefixIdx >= len(s.prefixLens) {
		s.releasePrefixLocked()
		return nil, false, nil
	}
	n := s.prefixLens[s.prefixIdx]
	s.prefixIdx++
	payload := []byte{}
	if n > 0 {
		if s.prefixR == nil {
			if s.prefixBuf == nil {
				return nil, false, errors.New("httpaggregator: probed body missing")
			}
			r, err := s.prefixBuf.Reader()
			if err != nil {
				return nil, false, fmt.Errorf("httpaggregator: open probed body: %w", err)
			}
			s.prefixR = r
		}
		payload = make([]byte, n)
		if _, err := io.ReadFull(s.prefixR, payload); err != nil {
			return nil, false, fmt.Errorf("httpaggregator: read probed body: %w", err)
		}
	}
	return &envelope.Envelope{Message: &http2.H2DataEvent{Payload: payload}}, true, nil
}

// releasePrefix closes and releases the probed prefix. Safe from any
// goroutine; idempotent.
func (s *h2BodySource) releasePrefix() {
	s.prefixMu.Lock()
	defer s.prefixMu.Unlock()
	s.releasePrefixLocked()
}

func (s *h2BodySource) releasePrefixLocked() {
	if s.prefixReleased {
		return
	}
	s.prefixReleased = true
	if s.prefixR != nil {
		_ = s.prefixR.Close()
		s.prefixR = nil
	}
	if s.prefixBuf != nil {
		_ = s.prefixBuf.Release()
		s.prefixBuf = nil
	}
}

// handle applies one stream event to the body.
func (s *h2BodySource) handle(ev *envelope.Envelope, overlay bool) {
	switch m := ev.Message.(type) {
	case *http2.H2DataEvent:
		if overlay && s.cb != nil {
			s.cb(buildH2FrameWireEnvelope(ev, m, &s.headCtx))
		}
		s.bs.EmitRaw(m.Payload)
		s.forward(&http2.H2DataEvent{Payload: m.Payload, EndStream: m.EndStream})
		s.pending = m.Payload
		if m.EndStream {
			s.ended, s.endErr = true, io.EOF
		}
	case *http2.H2TrailersEvent:
		s.bs.EmitRaw(ev.Raw)
		s.trailers = cloneKVs(m.Trailers)
		s.anomalies = append(s.anomalies, cloneAnomalies(m.Anomalies)...)
		s.forward(&http2.H2TrailersEvent{Trailers: cloneKVs(m.Trailers)})
		s.ended, s.endErr = true, io.EOF
	case *http2.H2HeadersEvent:
		// The Layer reports HEADERS after DATA as trailers; another
		// HEADERS here is a protocol violation (Principle 5: an error,
		// never a panic).
		s.fail(fmt.Errorf("httpaggregator: unexpected HEADERS in a streamed body (stream %s)", ev.StreamID))
	}
}

// forward hands m to the consuming aggregator, if any.
func (s *h2BodySource) forward(m envelope.Message) {
	if s.fwd == nil || s.fwdErr != nil {
		return
	}
	if err := s.fwd(m); err != nil {
		s.fwdErr = err
	}
}

// forwardTo makes every later event go to fwd. Must be called on the
// reading goroutine before the first Read.
func (s *h2BodySource) forwardTo(fwd func(envelope.Message) error) { s.fwd = fwd }

// forwardErr returns the first forward error. Reading goroutine only.
func (s *h2BodySource) forwardErr() error { return s.fwdErr }

// fail ends the body with the read error err. A producer-side end before
// END_STREAM — a stream reset (the peer's *layer.StreamError, wire code
// kept), the stream or connection closing (io.EOF) or a protocol violation
// — is a truncation (AnomalyTruncatedBody). Cancellation of the read
// context is not: it is the consumer's (or the session's) own end.
func (s *h2BodySource) fail(err error) {
	s.ended = true
	var se *layer.StreamError
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, envelope.ErrBodyStreamClosed):
		s.endErr = err
		return
	case errors.As(err, &se):
		s.endErr = err
		s.addTruncation(fmt.Sprintf("stream reset before END_STREAM (%s)", se.Error()))
	case errors.Is(err, io.EOF):
		s.endErr = &layer.StreamError{Code: layer.ErrorAborted, Reason: "http2: stream closed before END_STREAM"}
		s.addTruncation("stream closed before END_STREAM")
	default:
		s.endErr = &layer.StreamError{Code: layer.ErrorProtocol, Reason: err.Error()}
		s.addTruncation(err.Error())
	}
}

func (s *h2BodySource) addTruncation(detail string) {
	s.truncated = true
	s.anomalies = append(s.anomalies, envelope.Anomaly{Type: envelope.AnomalyTruncatedBody, Detail: detail})
}

// Finish implements envelope.BodyStreamSource. It cancels the read context
// (an in-flight inner Next returns) and releases the probed prefix. For a
// body closed before its end it touches no reading-goroutine state. Finish
// does nothing on the wire: resetting the stream stays with the Channel's
// Close / CloseWithCode.
func (s *h2BodySource) Finish(cause error) envelope.BodyResult {
	s.cancel()
	s.releasePrefix()
	if errors.Is(cause, envelope.ErrBodyStreamClosed) {
		return envelope.BodyResult{Err: cause}
	}
	res := envelope.BodyResult{Trailers: s.trailers, Anomalies: s.anomalies}
	if errors.Is(cause, io.EOF) {
		return res
	}
	res.Err = cause
	res.Truncated = s.truncated
	return res
}

// declaredContentLength returns the content-length of headers when there is
// exactly one that parses.
func declaredContentLength(headers []envelope.KeyValue) (int64, bool) {
	var v string
	found := false
	for _, kv := range headers {
		if strings.EqualFold(kv.Name, "content-length") {
			if found {
				return 0, false
			}
			v, found = kv.Value, true
		}
	}
	if !found {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

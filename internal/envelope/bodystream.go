package envelope

import (
	"errors"
	"io"
)

// ErrBodyStreamClosed is the cause a [BodyStreamSource] receives from
// [BodyStream.Close] when the body is ended before it was read to the end,
// and the error Read returns afterwards.
var ErrBodyStreamClosed = errors.New("envelope: body stream closed before its end")

// BodyResult describes how a streamed body ended. It is delivered exactly
// once to every [BodyStream.OnComplete] callback.
type BodyResult struct {
	// Trailers are the trailer fields that followed the body (chunked
	// trailers on HTTP/1.x), in wire order.
	Trailers []KeyValue
	// Anomalies are protocol anomalies observed while reading the body
	// (for example AnomalyTruncatedBody or trailer anomalies).
	Anomalies []Anomaly
	// SemanticBytes counts the body bytes Read returned (de-chunked).
	SemanticBytes int64
	// RawBytes counts the wire bytes the producer observed for the body
	// (chunk framing, extensions and trailers included).
	RawBytes int64
	// Truncated reports that the peer closed before the body's framed end.
	Truncated bool
	// Err is nil when the body ended cleanly. Otherwise it is the reason the
	// body ended early (a truncation, a framing error, or
	// ErrBodyStreamClosed for a body closed before its end).
	Err error
}

// BodyStreamSource is the producer side of a [BodyStream]. Read yields the
// semantic (de-chunked) body bytes; the producer reports the wire bytes it
// consumes through [BodyStream.EmitRaw].
type BodyStreamSource interface {
	// Read reads semantic body bytes. It returns io.EOF at the body's end.
	Read(p []byte) (int, error)
	// Finish ends the body and returns its result. cause is the error Read
	// returned (io.EOF on a normal end) or ErrBodyStreamClosed when the
	// stream was closed first. Finish is called exactly once. When cause is
	// ErrBodyStreamClosed it may run concurrently with an in-flight Read
	// and must not touch state that Read mutates.
	Finish(cause error) BodyResult
}

// BodyStream is a one-shot streamed message body (RFC-001 §3.2.1). The
// Layer that produced the Envelope owns the source; a consumer that
// forwards the message reads the body through Read and Closes it when done.
//
// Observers registered with Observe see every semantic chunk Read returns
// and every raw wire chunk the producer reports, on the reading goroutine,
// in order. Completion callbacks registered with OnComplete run exactly
// once, after the body ended (normally, with an error, or by Close), on
// the goroutine that ended it. A callback registered after completion runs
// immediately on the registering goroutine.
//
// Observers and callbacks must not block and must not call back into the
// BodyStream.
type BodyStream struct {
	src BodyStreamSource

	done chan struct{}
}

// NewBodyStream returns a BodyStream reading from src.
func NewBodyStream(src BodyStreamSource) *BodyStream {
	return &BodyStream{src: src, done: make(chan struct{})}
}

// Source returns the producer.
func (s *BodyStream) Source() BodyStreamSource { return s.src }

// Read is not implemented yet (USK-1409 scaffolding).
func (s *BodyStream) Read(p []byte) (int, error) { return 0, io.EOF }

// EmitRaw is not implemented yet (USK-1409 scaffolding).
func (s *BodyStream) EmitRaw(p []byte) {}

// Observe is not implemented yet (USK-1409 scaffolding).
func (s *BodyStream) Observe(onSemantic, onRaw func([]byte)) {}

// OnComplete is not implemented yet (USK-1409 scaffolding).
func (s *BodyStream) OnComplete(fn func(BodyResult)) {}

// Close is not implemented yet (USK-1409 scaffolding).
func (s *BodyStream) Close() error { return nil }

// Done is closed once the body ended.
func (s *BodyStream) Done() <-chan struct{} { return s.done }

// Result is not implemented yet (USK-1409 scaffolding).
func (s *BodyStream) Result() (BodyResult, bool) { return BodyResult{}, false }

package envelope

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
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
// Observers and callbacks must not call back into the BodyStream or its
// producer. They run inline on the goroutine that reads or ends the body,
// so their time is added to the transfer: observers should be cheap, and a
// completion callback may do bounded synchronous work — RecordStep's callback saves
// the Flow rows to the store, which for a chunked HTTP/1.x body happens
// before the terminal chunk is flushed to the client.
type BodyStream struct {
	src BodyStreamSource

	mu        sync.Mutex
	semObs    []func([]byte)
	rawObs    []func([]byte)
	onDone    []func(BodyResult)
	completed bool
	result    BodyResult

	semBytes atomic.Int64
	rawBytes atomic.Int64

	finishOnce sync.Once
	done       chan struct{}
}

// NewBodyStream returns a BodyStream reading from src.
func NewBodyStream(src BodyStreamSource) *BodyStream {
	return &BodyStream{src: src, done: make(chan struct{})}
}

// Source returns the producer. A consumer of the same protocol may use it
// to reach a producer-specific capability (HTTP/1.x raw forwarding).
func (s *BodyStream) Source() BodyStreamSource { return s.src }

// Read reads semantic body bytes. After the body ended it returns io.EOF
// for a clean end and the BodyResult error otherwise.
func (s *BodyStream) Read(p []byte) (int, error) {
	select {
	case <-s.done:
		return 0, s.endErr()
	default:
	}
	n, err := s.src.Read(p)
	if n > 0 {
		s.semBytes.Add(int64(n))
		s.emit(p[:n], false)
	}
	if err != nil {
		s.finish(err)
		return n, s.endErr()
	}
	return n, nil
}

// EmitRaw reports wire bytes the producer consumed for this body. Called by
// the producer only, on the reading goroutine. p is delivered to the raw
// observers and must not be retained by them.
func (s *BodyStream) EmitRaw(p []byte) {
	if len(p) == 0 {
		return
	}
	s.rawBytes.Add(int64(len(p)))
	s.emit(p, true)
}

func (s *BodyStream) emit(p []byte, raw bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return
	}
	obs := s.semObs
	if raw {
		obs = s.rawObs
	}
	for _, fn := range obs {
		fn(p)
	}
}

// Observe registers observers for the semantic and raw body bytes. Either
// may be nil. Bytes read before the call are not replayed; register before
// the body is read.
func (s *BodyStream) Observe(onSemantic, onRaw func([]byte)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return
	}
	if onSemantic != nil {
		s.semObs = append(s.semObs, onSemantic)
	}
	if onRaw != nil {
		s.rawObs = append(s.rawObs, onRaw)
	}
}

// OnComplete registers fn to run once the body ended. When the body has
// already ended, fn runs immediately.
func (s *BodyStream) OnComplete(fn func(BodyResult)) {
	if fn == nil {
		return
	}
	s.mu.Lock()
	if s.completed {
		res := s.result
		s.mu.Unlock()
		fn(res)
		return
	}
	s.onDone = append(s.onDone, fn)
	s.mu.Unlock()
}

// Close ends the body. Closing a body that was not read to its end reports
// ErrBodyStreamClosed to the producer. Idempotent; always returns nil.
func (s *BodyStream) Close() error {
	s.finish(ErrBodyStreamClosed)
	return nil
}

// Done is closed once the body ended.
func (s *BodyStream) Done() <-chan struct{} { return s.done }

// Result returns the BodyResult and true once the body ended.
func (s *BodyStream) Result() (BodyResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.result, s.completed
}

func (s *BodyStream) endErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.result.Err != nil {
		return s.result.Err
	}
	return io.EOF
}

// finish runs the producer's Finish and the completion callbacks exactly
// once.
func (s *BodyStream) finish(cause error) {
	s.finishOnce.Do(func() {
		res := s.src.Finish(cause)
		res.SemanticBytes = s.semBytes.Load()
		res.RawBytes = s.rawBytes.Load()
		s.mu.Lock()
		s.result = res
		s.completed = true
		cbs := s.onDone
		s.onDone, s.semObs, s.rawObs = nil, nil, nil
		s.mu.Unlock()
		close(s.done)
		for _, fn := range cbs {
			fn(res)
		}
	})
}

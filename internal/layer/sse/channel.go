package sse

import (
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// sseChannel implements layer.Channel as a Receive-only adapter. The first
// Next call returns a pre-shaped clone of the upstream HTTP response
// envelope (Protocol overridden to ProtocolSSE); subsequent Next calls
// drive an SSEParser over a body io.Reader and emit one
// envelope.SSEMessage per parsed event.
type sseChannel struct {
	inner    layer.Channel
	body     io.Reader
	firstEnv *envelope.Envelope // pre-shaped first envelope (Protocol=ProtocolSSE)
	streamID string
	maxEvent int

	mu        sync.Mutex
	parser    *SSEParser
	firstSent bool
	nextSeq   int

	termOnce sync.Once
	termErr  error
	recvDone chan struct{}

	closeOnce sync.Once
}

// StreamID delegates to the inner Channel's StreamID. SSE shares the
// underlying HTTP/1.x connection's stream identity.
func (s *sseChannel) StreamID() string {
	return s.streamID
}

// Closed returns the SSE Channel's own terminal signal. The wrapper owns
// its lifecycle (body EOF / parse error / explicit Close) independently
// of the inner Channel.
func (s *sseChannel) Closed() <-chan struct{} {
	return s.recvDone
}

// Err returns the cached terminal error. Returns nil before Closed has
// fired; io.EOF on normal stream termination; a non-EOF error (typically
// *layer.StreamError) on abnormal termination.
func (s *sseChannel) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.termErr
}

// Next returns the next envelope from the SSE stream. The first call
// returns the pre-shaped first envelope (the response Envelope with
// Protocol=ProtocolSSE). Subsequent calls drive the parser and return
// one envelope.SSEMessage envelope per parsed event. Returns io.EOF on
// graceful termination, *layer.StreamError on parse failure or
// MaxEventSize overflow.
func (s *sseChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	s.mu.Lock()
	if s.termErr != nil {
		err := s.termErr
		s.mu.Unlock()
		return nil, err
	}
	if !s.firstSent {
		s.firstSent = true
		out := s.firstEnv
		s.mu.Unlock()
		return out, nil
	}
	if s.parser == nil {
		s.parser = NewSSEParser(s.body, s.maxEvent)
	}
	s.mu.Unlock()

	// Honor caller cancellation between events. The parser itself blocks
	// on body reads; we cannot interrupt it without closing the body.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ev, err := s.parser.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			s.terminate(io.EOF)
			return nil, io.EOF
		}
		se := &layer.StreamError{
			Code:   layer.ErrorInternalError,
			Reason: "sse: " + err.Error(),
		}
		s.terminate(se)
		return nil, se
	}

	s.mu.Lock()
	seq := s.nextSeq
	s.nextSeq++
	streamID := s.firstEnv.StreamID
	flowCtx := s.firstEnv.Context
	s.mu.Unlock()

	msg := &envelope.SSEMessage{
		Event:     ev.EventType,
		Data:      ev.Data,
		ID:        ev.ID,
		Retry:     parseRetry(ev.Retry),
		Anomalies: ev.Anomalies,
	}

	out := &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.New().String(),
		Sequence:  seq,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolSSE,
		Raw:       ev.RawBytes, // already a fresh copy from parser.copyBytes
		Message:   msg,
		Context:   flowCtx,
	}
	return out, nil
}

// Send always fails: SSE is half-duplex (server → client). The error is
// the sentinel ErrSendUnsupported, matchable with errors.Is.
func (s *sseChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	return ErrSendUnsupported
}

// Close releases the wrapper. Cascades:
//  1. Close body if it is an io.Closer.
//  2. Close the inner Channel (per RFC-001 N6.7 cascade discipline).
//  3. Cache io.EOF as termErr (if not already terminated) and close
//     recvDone so observers unblock.
//
// Idempotent via sync.Once.
func (s *sseChannel) Close() error {
	s.closeOnce.Do(func() {
		if c, ok := s.body.(io.Closer); ok {
			_ = c.Close()
		}
		_ = s.inner.Close()
		s.terminate(io.EOF)
	})
	return nil
}

// terminate caches err as the terminal error (first call wins) and
// closes recvDone. Safe to call multiple times.
func (s *sseChannel) terminate(err error) {
	s.termOnce.Do(func() {
		s.mu.Lock()
		s.termErr = err
		s.mu.Unlock()
		close(s.recvDone)
	})
}

// parseRetry converts the SSE "retry:" string field into a time.Duration.
// Per RFC 8895 the value is in milliseconds. Empty / non-numeric values
// yield zero (the caller is expected to interpret zero as "unset").
func parseRetry(s string) time.Duration {
	if s == "" {
		return 0
	}
	ms, err := strconv.Atoi(s)
	if err != nil || ms < 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
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

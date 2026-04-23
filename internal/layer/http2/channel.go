package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// perStreamEventChanCap is the per-stream event channel capacity. Bounded
// memory: at most cap events queued per stream while the aggregator is
// draining. The bound exists to cap memory during transient aggregator
// stalls — WINDOW_UPDATE fires at frame-arrival (not at Send consumption),
// so a full event channel does NOT stall connection-level flow control.
const perStreamEventChanCap = 32

// channel implements layer.Channel for one HTTP/2 stream, using the
// event-granular envelope shape (H2HeadersEvent / H2DataEvent /
// H2TrailersEvent). Aggregation into HTTPMessage is the responsibility of
// an upper-layer wrapper (see internal/layer/httpaggregator) or a
// per-protocol adapter (e.g., GRPCLayer).
type channel struct {
	layer    *Layer
	streamID string // UUID-based identifier returned by StreamID()
	h2Stream uint32 // HTTP/2 stream identifier
	isPush   bool

	// originStreamID is set on push channels (isPush=true) to the UUID
	// StreamID of the channel that carried the PUSH_PROMISE.
	originStreamID string

	recv          chan *envelope.Envelope
	errCh         chan *layer.StreamError
	closeRecvOnce sync.Once
	closeSendOnce sync.Once

	mu         sync.Mutex
	sequence   int
	headersHas bool // true after first request HEADERS sent (client side)
	closed     bool

	// sentEndStream / recvEndStream drive Close's RST-or-not decision
	// (USK-618). sentEndStream is set when a Send path emits END_STREAM on
	// the wire (final DATA, trailer HEADERS, or a lone EndStream=true
	// HEADERS event). recvEndStream is set when the reader observes the
	// natural end of the receive half.
	sentEndStream bool
	recvEndStream bool

	// Terminal-state tracking.
	termMu   sync.Mutex
	termErr  error
	termOnce sync.Once
	termDone chan struct{}
}

// newChannel constructs a channel bound to layer for h2 stream id.
func newChannel(l *Layer, h2Stream uint32, isPush bool) *channel {
	return &channel{
		layer:    l,
		streamID: uuid.New().String(),
		h2Stream: h2Stream,
		isPush:   isPush,
		recv:     make(chan *envelope.Envelope, perStreamEventChanCap),
		errCh:    make(chan *layer.StreamError, 1),
		termDone: make(chan struct{}),
	}
}

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
// once.
func (c *channel) markTerminated(err error) {
	c.termMu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.termMu.Unlock()
	c.termOnce.Do(func() { close(c.termDone) })
}

// markRecvEnded records that the reader has observed the natural end of the
// receive half.
func (c *channel) markRecvEnded() {
	c.mu.Lock()
	c.recvEndStream = true
	c.mu.Unlock()
}

// nextSequence returns the next sequence number, atomically.
func (c *channel) nextSequence() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.sequence
	c.sequence++
	return n
}

// StreamID returns the channel's stable identifier (a UUID, not the h2
// stream id).
func (c *channel) StreamID() string { return c.streamID }

// H2StreamID returns the underlying HTTP/2 stream id. Used by tests and by
// the aggregator's Send path when it needs to reference the wire-level
// stream id (e.g., for RST_STREAM on MaxBodySize enforcement).
func (c *channel) H2StreamID() uint32 { return c.h2Stream }

// MarkTerminatedWithRST emits RST_STREAM with the given wire error code and
// marks the channel terminated locally. Intended for the aggregator's
// MaxBodySize enforcement path, where the aggregator needs to reset the
// underlying stream without closing the whole channel surface itself.
// err becomes the channel's terminal Err.
func (c *channel) MarkTerminatedWithRST(code uint32, err error) {
	c.layer.enqueueWrite(writeRequest{rst: &writeRST{streamID: c.h2Stream, code: code}})
	if err == nil {
		err = errors.New("http2: aggregator-initiated RST")
	}
	c.markTerminated(err)
	c.layer.closeChannelRecv(c)
}

// Next returns the next event envelope on this channel.
//
// Returns io.EOF on normal close, *layer.StreamError on stream error,
// ctx.Err() on cancellation.
func (c *channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	select {
	case env, ok := <-c.recv:
		if !ok {
			// Drain a pending error if any.
			select {
			case se := <-c.errCh:
				return nil, se
			default:
			}
			return nil, io.EOF
		}
		return env, nil
	case se := <-c.errCh:
		return nil, se
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.layer.shutdown:
		return nil, io.EOF
	}
}

// Send writes the given event envelope onto this stream. The Message must
// be one of *H2HeadersEvent / *H2DataEvent / *H2TrailersEvent; other Message
// types yield an error.
//
// For push channels, only RST_STREAM is permitted (the channel models a
// server-initiated stream we did not request); Send always returns an error
// on push channels.
func (c *channel) Send(ctx context.Context, env *envelope.Envelope) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("http2: send on closed channel")
	}
	c.mu.Unlock()

	if c.isPush {
		return errors.New("http2: send on push channel rejected — only RST_STREAM is valid")
	}

	switch m := env.Message.(type) {
	case *H2HeadersEvent:
		return c.sendHeadersEvent(ctx, env, m)
	case *H2DataEvent:
		return c.sendDataEvent(ctx, m)
	case *H2TrailersEvent:
		return c.sendTrailersEvent(ctx, m)
	default:
		return fmt.Errorf("http2: Send requires *H2HeadersEvent / *H2DataEvent / *H2TrailersEvent, got %T", env.Message)
	}
}

// sendHeadersEvent encodes the event's pseudo-headers + headers into HPACK
// and writes HEADERS (+ CONTINUATION*) frames. When evt.EndStream is true,
// END_STREAM is placed on the last frame.
func (c *channel) sendHeadersEvent(ctx context.Context, env *envelope.Envelope, evt *H2HeadersEvent) error {
	fields := BuildHeaderFieldsFromEvent(env, evt)
	done := make(chan error, 1)
	c.layer.enqueueWrite(writeRequest{headers: &writeHeaders{
		streamID:  c.h2Stream,
		fields:    fields,
		endStream: evt.EndStream,
		done:      done,
	}})
	if err := waitDone(ctx, done, c.layer.shutdown); err != nil {
		return err
	}
	c.mu.Lock()
	c.headersHas = true
	if evt.EndStream {
		c.sentEndStream = true
	}
	c.mu.Unlock()
	return nil
}

// sendDataEvent writes a DATA frame (or splits the payload into multiple
// DATA frames per MAX_FRAME_SIZE), respecting flow control. When
// evt.EndStream is true, END_STREAM is placed on the final DATA frame.
func (c *channel) sendDataEvent(ctx context.Context, evt *H2DataEvent) error {
	done := make(chan error, 1)
	c.layer.enqueueWrite(writeRequest{dataEvent: &writeDataEvent{
		streamID:  c.h2Stream,
		payload:   evt.Payload,
		endStream: evt.EndStream,
		done:      done,
	}})
	if err := waitDone(ctx, done, c.layer.shutdown); err != nil {
		return err
	}
	if evt.EndStream {
		c.mu.Lock()
		c.sentEndStream = true
		c.mu.Unlock()
	}
	return nil
}

// sendTrailersEvent encodes the trailer fields into HPACK and writes a
// trailer HEADERS frame with END_STREAM per RFC 9113 §8.1.
func (c *channel) sendTrailersEvent(ctx context.Context, evt *H2TrailersEvent) error {
	// Convert KeyValues → hpack fields. Anomalies for pseudo-header-in-
	// trailers are surfaced by the aggregator via evt.Anomalies at decode
	// time; on Send, we drop pseudo-headers to avoid emitting an invalid
	// wire form (matches the Receive path's handling).
	fields := make([]hpack.HeaderField, 0, len(evt.Trailers))
	for _, kv := range evt.Trailers {
		if strings.HasPrefix(kv.Name, ":") {
			// Drop pseudo-headers silently — invalid in trailers per
			// RFC 9113 §8.1. Aggregator is expected to flag them.
			continue
		}
		fields = append(fields, hpack.HeaderField{
			Name:  strings.ToLower(kv.Name),
			Value: kv.Value,
		})
	}
	done := make(chan error, 1)
	c.layer.enqueueWrite(writeRequest{headers: &writeHeaders{
		streamID:  c.h2Stream,
		fields:    fields,
		endStream: true, // trailers always END_STREAM
		done:      done,
	}})
	if err := waitDone(ctx, done, c.layer.shutdown); err != nil {
		return err
	}
	c.mu.Lock()
	c.sentEndStream = true
	c.mu.Unlock()
	return nil
}

// Close tears down the receive side and, for abnormal terminations, emits
// RST_STREAM(CANCEL). Idempotent.
func (c *channel) Close() error {
	c.closeSendOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		sentEnd := c.sentEndStream
		recvEnd := c.recvEndStream
		c.mu.Unlock()

		if c.isPush || !sentEnd || !recvEnd {
			c.layer.enqueueWrite(writeRequest{rst: &writeRST{
				streamID: c.h2Stream,
				code:     ErrCodeCancel,
			}})
		}
		c.layer.closeChannelRecv(c)
		c.markTerminated(io.EOF)
	})
	return nil
}

// BuildHeaderFieldsFromEvent constructs the HPACK header field list for an
// H2HeadersEvent, generating request or response pseudo-headers based on
// envelope.Direction.
//
// Header-name case is lowercased on the wire per RFC 9113 §8.2.1.
// MITM-fidelity caveat: this normalizes case on the Send path. A preserve-
// case hook would require extending KeyValue with a marker; for now the
// Receive path flags uppercase-name anomalies on the observation side.
func BuildHeaderFieldsFromEvent(env *envelope.Envelope, evt *H2HeadersEvent) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(evt.Headers)+5)

	isResponse := env != nil && env.Direction == envelope.Receive
	if !isResponse {
		// If no Direction on env, heuristic fallback: Status != 0 ⇒ response.
		isResponse = env == nil && evt.Status != 0
	}

	if isResponse {
		status := itoa3(evt.Status)
		if evt.Status == 0 {
			status = "200"
		}
		out = append(out, hpack.HeaderField{Name: ":status", Value: status})
	} else {
		method := evt.Method
		if method == "" {
			method = "GET"
		}
		out = append(out, hpack.HeaderField{Name: ":method", Value: method})
		scheme := evt.Scheme
		if scheme == "" {
			scheme = "https"
		}
		out = append(out, hpack.HeaderField{Name: ":scheme", Value: scheme})
		if evt.Authority != "" {
			out = append(out, hpack.HeaderField{Name: ":authority", Value: evt.Authority})
		}
		path := evt.Path
		if path == "" {
			path = "/"
		}
		if evt.RawQuery != "" {
			path = path + "?" + evt.RawQuery
		}
		out = append(out, hpack.HeaderField{Name: ":path", Value: path})
	}

	for _, kv := range evt.Headers {
		out = append(out, hpack.HeaderField{
			Name:  strings.ToLower(kv.Name),
			Value: kv.Value,
		})
	}
	return out
}

// itoa3 formats a status code without allocating for well-known 3-digit
// codes; falls back to fmt.Sprintf for edge cases.
func itoa3(n int) string {
	if n >= 100 && n <= 999 {
		b := [3]byte{
			byte('0' + n/100),
			byte('0' + (n/10)%10),
			byte('0' + n%10),
		}
		return string(b[:])
	}
	return fmt.Sprintf("%d", n)
}

// waitDone blocks until the writer signals done, or ctx/shutdown fires.
func waitDone(ctx context.Context, done chan error, shutdown chan struct{}) error {
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-shutdown:
		return errWriterClosed
	}
}

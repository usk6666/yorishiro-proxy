package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// channel implements layer.Channel for one HTTP/2 stream.
//
// recv is bounded (size 1) so the assembler applies natural backpressure.
// errCh is bounded (size 1) so a single stream-level error can be delivered.
// Closing recv is gated by closeRecvOnce — the reader and Close both racey-
// close it.
type channel struct {
	layer    *Layer
	streamID string // UUID-based identifier returned by StreamID()
	h2Stream uint32 // HTTP/2 stream identifier
	isPush   bool

	recv          chan *envelope.Envelope
	errCh         chan *layer.StreamError
	closeRecvOnce sync.Once
	closeSendOnce sync.Once

	mu         sync.Mutex
	sequence   int
	headersHas bool // true after first request HEADERS sent (client side)
	closed     bool
}

// newChannel constructs a channel bound to layer for h2 stream id.
func newChannel(l *Layer, h2Stream uint32, isPush bool) *channel {
	return &channel{
		layer:    l,
		streamID: uuid.New().String(),
		h2Stream: h2Stream,
		isPush:   isPush,
		recv:     make(chan *envelope.Envelope, 1),
		errCh:    make(chan *layer.StreamError, 1),
	}
}

// nextSequence returns the next sequence number, atomically.
func (c *channel) nextSequence() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.sequence
	c.sequence++
	return n
}

// StreamID returns the channel's stable identifier (a UUID, not the h2 stream id).
func (c *channel) StreamID() string { return c.streamID }

// Next returns the next envelope on this channel.
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

// Send writes the envelope as one logical message on this stream.
//
// For push channels, only RST_STREAM is permitted (the channel models a
// server-initiated stream we did not request).
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

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return fmt.Errorf("http2: Send requires *HTTPMessage, got %T", env.Message)
	}

	// Opaque-based zero-copy path.
	if op, ok := env.Opaque.(*opaqueHTTP2); ok && op != nil && op.streamID == c.h2Stream {
		if !headersChanged(msg, op) && !bodyChanged(msg, op) && len(op.frames) > 0 {
			done := make(chan error, 1)
			c.layer.enqueueWrite(writeRequest{opaque: &writeOpaque{
				streamID: c.h2Stream,
				frames:   op.frames,
				done:     done,
			}})
			return waitDone(ctx, done, c.layer.shutdown)
		}
	}

	// Synthetic path.
	headers := buildHeaderFields(env, msg)

	done := make(chan error, 1)
	c.layer.enqueueWrite(writeRequest{message: &writeMessage{
		streamID:   c.h2Stream,
		headers:    headers,
		body:       msg.Body,
		bodyReader: msg.BodyStream,
		endStream:  true,
		done:       done,
	}})
	if err := waitDone(ctx, done, c.layer.shutdown); err != nil {
		return err
	}
	c.mu.Lock()
	c.headersHas = true
	c.mu.Unlock()
	return nil
}

// Close emits a RST_STREAM(CANCEL) once and tears down the receive side.
// Idempotent.
func (c *channel) Close() error {
	c.closeSendOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		// Best-effort RST_STREAM. We do not wait for the result.
		c.layer.enqueueWrite(writeRequest{rst: &writeRST{
			streamID: c.h2Stream,
			code:     ErrCodeCancel,
		}})
		c.layer.closeChannelRecv(c)
	})
	return nil
}

// opaqueHTTP2 holds Layer-internal state for raw-first patching.
type opaqueHTTP2 struct {
	streamID    uint32 // HTTP/2 stream ID
	frames      [][]byte
	origHeaders []hpack.HeaderField
	origBody    []byte
	bodyReader  io.Reader
	isPush      bool
}

// headersChanged reports whether the message's headers differ from the
// original (pre-Pipeline) ones.
func headersChanged(msg *envelope.HTTPMessage, op *opaqueHTTP2) bool {
	if op == nil || op.origHeaders == nil {
		return true
	}
	current := buildHeaderFields(nil, msg)
	if len(current) != len(op.origHeaders) {
		return true
	}
	for i := range current {
		if current[i].Name != op.origHeaders[i].Name || current[i].Value != op.origHeaders[i].Value {
			return true
		}
	}
	return false
}

func bodyChanged(msg *envelope.HTTPMessage, op *opaqueHTTP2) bool {
	if msg.Body == nil && op.bodyReader != nil {
		// Passthrough body still attached and unchanged.
		return false
	}
	if msg.Body == nil && op.origBody == nil && op.bodyReader == nil {
		return false
	}
	if op.origBody == nil {
		return true
	}
	if len(msg.Body) != len(op.origBody) {
		return true
	}
	for i, b := range msg.Body {
		if b != op.origBody[i] {
			return true
		}
	}
	return false
}

// buildHeaderFields constructs the HPACK header field list for a message,
// generating the appropriate pseudo-headers from the envelope/HTTPMessage.
func buildHeaderFields(env *envelope.Envelope, msg *envelope.HTTPMessage) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(msg.Headers)+5)

	if msg.Status != 0 || isResponse(env, msg) {
		// Response.
		status := strconv.Itoa(msg.Status)
		if msg.Status == 0 {
			status = "200"
		}
		out = append(out, hpack.HeaderField{Name: ":status", Value: status})
	} else {
		// Request.
		method := msg.Method
		if method == "" {
			method = "GET"
		}
		out = append(out, hpack.HeaderField{Name: ":method", Value: method})
		scheme := msg.Scheme
		if scheme == "" {
			scheme = "https"
		}
		out = append(out, hpack.HeaderField{Name: ":scheme", Value: scheme})
		if msg.Authority != "" {
			out = append(out, hpack.HeaderField{Name: ":authority", Value: msg.Authority})
		}
		path := msg.Path
		if path == "" {
			path = "/"
		}
		if msg.RawQuery != "" {
			path = path + "?" + msg.RawQuery
		}
		out = append(out, hpack.HeaderField{Name: ":path", Value: path})
	}

	for _, kv := range msg.Headers {
		// Lowercase for HPACK transport per RFC 9113 §8.2.1, but only if the
		// caller hasn't already lowercased it (no normalization beyond what
		// HPACK requires).
		name := strings.ToLower(kv.Name)
		out = append(out, hpack.HeaderField{Name: name, Value: kv.Value})
	}
	return out
}

// isResponse infers whether msg is a response (vs request) when env is nil
// or env.Direction is unset.
func isResponse(env *envelope.Envelope, msg *envelope.HTTPMessage) bool {
	if env != nil {
		return env.Direction == envelope.Receive
	}
	return msg.Status != 0
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

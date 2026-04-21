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

	// Terminal-state tracking. Populated before termDone closes so any
	// observer of Closed sees a stable Err value.
	//
	// markTerminated is deliberately NOT invoked on normal END_STREAM
	// (assembler asmDone path). A peer may still deliver a late RST_STREAM
	// on a stream it half-closed, and firing Closed on asmDone would
	// latch io.EOF as the terminal error and prevent the subsequent
	// StreamError from becoming visible through Err.
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
		recv:     make(chan *envelope.Envelope, 1),
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
// once. Callers must guarantee err is non-nil; io.EOF is used for normal
// termination.
func (c *channel) markTerminated(err error) {
	c.termMu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.termMu.Unlock()
	c.termOnce.Do(func() { close(c.termDone) })
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

	// Opaque-based zero-copy path. Restricted to same-Layer sends:
	// cross-Layer forwarding cannot use raw frames because HPACK dynamic-
	// table indices are per-connection and MAX_FRAME_SIZE / flow-control
	// state differ. Cross-Layer sends fall through to the synthetic path,
	// which re-encodes headers and flow-controls DATA via writeStreamingBody.
	if op, ok := env.Opaque.(*opaqueHTTP2); ok && op != nil && op.layer == c.layer && op.streamID == c.h2Stream {
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
	trailers := buildTrailerFields(msg.Trailers)

	done := make(chan error, 1)
	c.layer.enqueueWrite(writeRequest{message: &writeMessage{
		streamID:   c.h2Stream,
		headers:    headers,
		body:       msg.Body,
		bodyReader: msg.BodyStream,
		trailers:   trailers,
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
		// Local cancellation is "normal" from the watcher's perspective:
		// we initiated it and do not want the session's late-error path
		// to cascade the close back onto the peer.
		c.markTerminated(io.EOF)
	})
	return nil
}

// opaqueHTTP2 holds Layer-internal state for raw-first patching.
//
// The opaque zero-copy fast path in channel.Send is valid only when the
// receiving Channel belongs to the same Layer that produced the snapshot:
// HPACK dynamic-table indices embedded in op.frames are meaningful only
// within the encoder/decoder pair of one connection. Cross-Layer forwarding
// (e.g., upstream → client in a MITM proxy) must re-encode through the
// destination Layer's HPACK context. The layer field records the owning
// Layer for this identity check.
type opaqueHTTP2 struct {
	layer       *Layer // owning Layer; gates the zero-copy fast path to same-Layer sends
	streamID    uint32 // HTTP/2 stream ID (scoped to layer)
	frames      [][]byte
	origHeaders []hpack.HeaderField
	origBody    []byte
	bodyReader  io.Reader
	isPush      bool
}

// headersChanged reports whether the message's headers differ from the
// original (pre-Pipeline) ones.
//
// We must NOT compare positionally because buildHeaderFields generates the
// pseudo-header list in a fixed canonical order (:method, :scheme,
// :authority, :path / :status), while op.origHeaders preserves the wire
// order the peer used. A positional mismatch on a non-canonical-order peer
// would falsely claim "headers changed", forcing every Send through the
// HPACK re-encode path and defeating the opaque zero-copy fast path.
//
// Instead, separately compare the pseudo-header values (set semantics) and
// the regular header sequence (which IS order-sensitive on the wire).
func headersChanged(msg *envelope.HTTPMessage, op *opaqueHTTP2) bool {
	if op == nil || op.origHeaders == nil {
		return true
	}
	origPseudo, origRegular := splitOrigHeaders(op.origHeaders)
	if pseudoChanged(msg, origPseudo) {
		return true
	}
	return regularHeadersChanged(msg.Headers, origRegular)
}

// splitOrigHeaders separates a wire-order header list into a pseudo-header
// value map (first-occurrence-wins) and the regular-header sequence.
func splitOrigHeaders(orig []hpack.HeaderField) (map[string]string, []hpack.HeaderField) {
	pseudo := map[string]string{}
	regular := make([]hpack.HeaderField, 0, len(orig))
	for _, hf := range orig {
		if strings.HasPrefix(hf.Name, ":") {
			if _, ok := pseudo[hf.Name]; !ok {
				pseudo[hf.Name] = hf.Value
			}
			continue
		}
		regular = append(regular, hf)
	}
	return pseudo, regular
}

// pseudoChanged reports whether msg's request/response pseudo-headers differ
// from origPseudo. Direction is inferred from whether origPseudo carries a
// :status (response) or msg.Status is set.
func pseudoChanged(msg *envelope.HTTPMessage, origPseudo map[string]string) bool {
	if msg.Status != 0 || origPseudo[":status"] != "" {
		return pseudoStatus(msg) != origPseudo[":status"]
	}
	if msg.Method != origPseudo[":method"] {
		return true
	}
	if msg.Scheme != origPseudo[":scheme"] {
		return true
	}
	if msg.Authority != origPseudo[":authority"] {
		return true
	}
	return reconstructPath(msg) != origPseudo[":path"]
}

// regularHeadersChanged reports whether the wire-order regular header
// sequence differs (including duplicates and order). Names are compared
// case-insensitively because the wire form is lowercase per RFC 9113 §8.2.1.
func regularHeadersChanged(msgHeaders []envelope.KeyValue, origRegular []hpack.HeaderField) bool {
	if len(msgHeaders) != len(origRegular) {
		return true
	}
	for i, kv := range msgHeaders {
		if strings.ToLower(kv.Name) != origRegular[i].Name {
			return true
		}
		if kv.Value != origRegular[i].Value {
			return true
		}
	}
	return false
}

// pseudoStatus returns the :status pseudo-header value buildHeaderFields
// would emit for msg. Mirrors the response branch in buildHeaderFields.
func pseudoStatus(msg *envelope.HTTPMessage) string {
	if msg.Status == 0 {
		return "200"
	}
	return strconv.Itoa(msg.Status)
}

// reconstructPath returns the :path pseudo-header value buildHeaderFields
// would emit for msg. Mirrors the request branch in buildHeaderFields.
func reconstructPath(msg *envelope.HTTPMessage) string {
	path := msg.Path
	if path == "" {
		path = "/"
	}
	if msg.RawQuery != "" {
		path = path + "?" + msg.RawQuery
	}
	return path
}

func bodyChanged(msg *envelope.HTTPMessage, op *opaqueHTTP2) bool {
	if msg.Body == nil && op.bodyReader != nil {
		// Passthrough mode: op.frames snapshot was taken at the threshold
		// handoff and contains only the pre-handoff portion of the body
		// (no END_STREAM). The remainder streams through op.bodyReader
		// (the pipe attached to msg.BodyStream). Treating this as
		// "unchanged" and taking the opaque fast path would emit only the
		// captured frames and never drain the pipe, stalling the reader
		// goroutine and truncating the body on the wire. Force the
		// synthetic path so writeStreamingBody drains bodyReader with
		// flow control (USK-617).
		return true
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
		// Per RFC 9113 §8.2.1, header names in HTTP/2 MUST be lowercase on
		// the wire; uppercase names cause peers to treat the message as
		// malformed (and likely RST_STREAM with PROTOCOL_ERROR).
		//
		// MITM-fidelity caveat: this means the Send path normalizes case,
		// while the Receive path (assembler.go) preserves wire case and
		// flags H2UppercaseHeaderName as an anomaly. Operators wishing to
		// pentest a server's behavior on uppercase header names cannot
		// currently emit them through this path; they must use the opaque
		// zero-copy path with hand-crafted frames or extend this layer to
		// honor an explicit "preserve case" flag on KeyValue.
		name := strings.ToLower(kv.Name)
		out = append(out, hpack.HeaderField{Name: name, Value: kv.Value})
	}
	return out
}

// buildTrailerFields converts HTTPMessage.Trailers to lowercase hpack.HeaderField
// entries for the trailer HEADERS frame. Returns nil when there are no trailers
// so the writer's hasTrailers check stays false and no frame is emitted.
//
// HTTP/2 trailers must not contain pseudo-headers (RFC 9113 §8.1); any such
// entries are dropped defensively. Wire case is normalized to lowercase per
// the same rule as initial headers (documented limitation in buildHeaderFields).
func buildTrailerFields(trailers []envelope.KeyValue) []hpack.HeaderField {
	if len(trailers) == 0 {
		return nil
	}
	out := make([]hpack.HeaderField, 0, len(trailers))
	for _, kv := range trailers {
		if strings.HasPrefix(kv.Name, ":") {
			continue
		}
		out = append(out, hpack.HeaderField{
			Name:  strings.ToLower(kv.Name),
			Value: kv.Value,
		})
	}
	if len(out) == 0 {
		return nil
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

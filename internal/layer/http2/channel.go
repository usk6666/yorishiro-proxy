package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"

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
	// h2Stream is the HTTP/2 stream identifier.
	//
	// For client-initiated channels (created via Layer.OpenStream) the
	// id is allocated lazily, on the first sendHeadersEvent, under l.mu
	// — this guarantees id order matches enqueue order on the writer
	// queue, satisfying RFC 9113 §5.1.1 wire-order without the chained
	// HEADERS-order gate that USK-739 introduced (USK-740). Until the
	// first Send, h2Stream reads as 0; Close() and MarkTerminatedWithRST
	// guard h2Stream == 0 to avoid emitting RST_STREAM on a stream the
	// peer has never seen (RFC 9113 §5.4.2 forbids RST on idle streams).
	//
	// For peer-initiated channels (server-role: client HEADERS arrives)
	// the id is set at construction time from the frame and never
	// mutates.
	//
	// Stored as atomic.Uint32 so the id-allocating Send path and any
	// concurrent reader (tests, aggregator inspection paths) cannot race.
	h2Stream atomic.Uint32

	recv chan *envelope.Envelope
	// recvMu serializes close(recv) against sends from the reader goroutine.
	// The reader (deliverEnvelope) holds it for the duration of a send-select;
	// closeChannelRecv acquires it before closing. Close() sequences
	// markTerminated → closeChannelRecv so a reader blocked in the send-select
	// unblocks via the termDone case and releases recvMu before close runs.
	recvMu        sync.Mutex
	errCh         chan *layer.StreamError
	closeRecvOnce sync.Once
	closeSendOnce sync.Once

	// recvClosed is set atomically by closeChannelRecv before closing
	// ch.recv. deliverEnvelope reads it under recvMu (USK-721) to skip
	// the send-select when recv has been closed by an assembler-driven
	// terminal — for example, when an upstream that violated the protocol
	// keeps writing DATA after END_STREAM. Distinct from termDone so a
	// later RST_STREAM (failStream) can still install its own terminal
	// error via markTerminated without being shadowed by an io.EOF stamp.
	recvClosed atomic.Bool

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

	// detached is set to true exactly once when DetachStream(streamID)
	// transitions this channel into per-stream byte mode (RFC-001 §3.3.2).
	// Read by tests via detachActive(); writes happen under l.mu inside
	// the DetachStream constructor.
	detached atomic.Bool
	// detachWriter is the producer side of the io.Pipe that DetachStream
	// returns as the reader. Set under l.mu inside DetachStream;
	// written-to by the runDetachDrain goroutine; closed by
	// closeDetached. nil before detach.
	detachWriter *io.PipeWriter
	// detachPipeReader is the consumer-side handle. Stored on the channel
	// for symmetry; the actual reader returned to the caller wraps this
	// in a detachReader so future telemetry can hook in without changing
	// the io.Pipe surface.
	detachPipeReader *io.PipeReader
	// detachDrainDone fires when runDetachDrain exits.
	detachDrainDone chan struct{}
	// detachCloseOnce guards closeDetached against re-entry.
	detachCloseOnce sync.Once
}

// newChannel constructs a channel bound to layer for h2 stream id.
//
// Pass h2Stream=0 for client-initiated channels (the id is allocated
// lazily on the first sendHeadersEvent — see h2Stream's docstring).
// For peer-initiated channels, pass the wire id from the inbound frame.
func newChannel(l *Layer, h2Stream uint32) *channel {
	c := &channel{
		layer:    l,
		streamID: uuid.New().String(),
		recv:     make(chan *envelope.Envelope, perStreamEventChanCap),
		errCh:    make(chan *layer.StreamError, 1),
		termDone: make(chan struct{}),
	}
	c.h2Stream.Store(h2Stream)
	return c
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
//
// On the first call we also fire the Layer's plugin state release so any
// ctx.stream_state held against this channel's StreamID is GC'd. The call
// is intentionally placed AFTER close(termDone) so a USK-671 dispatch path
// observing termDone has already run any terminal-event hook (e.g.
// grpc.on_end) before the backing dict is cleared.
func (c *channel) markTerminated(err error) {
	c.termMu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.termMu.Unlock()
	c.termOnce.Do(func() {
		close(c.termDone)
		c.layer.releaseStreamState(c.streamID)
	})
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
//
// Returns 0 for client-initiated channels that have not yet sent HEADERS
// (the id is allocated lazily on the first sendHeadersEvent, USK-740).
func (c *channel) H2StreamID() uint32 { return c.h2Stream.Load() }

// MarkTerminatedWithRST emits RST_STREAM with the given wire error code and
// marks the channel terminated locally. Intended for the aggregator's
// MaxBodySize enforcement path, where the aggregator needs to reset the
// underlying stream without closing the whole channel surface itself.
// err becomes the channel's terminal Err.
//
// USK-740 guard: when h2Stream == 0 the peer has never been told this
// stream exists (lazy allocation: the id is reserved on the first
// sendHeadersEvent). Emitting RST_STREAM on an idle stream is a
// connection-level error per RFC 9113 §5.4.2, so we skip the wire emit
// and only run the local-teardown half. In practice the aggregator only
// reaches this entry point after HEADERS has been observed (post-Send
// receive paths), but the guard is defensive — any future caller that
// races allocation against teardown is covered.
//
// Note: this intentionally does NOT close ch.recv. Closing from this
// external goroutine would race with the reader goroutine's in-flight
// ch.recv <- env send. We rely on markTerminated closing termDone, which
// deliverEnvelope's select observes to short-circuit subsequent sends
// before they would land on a closed channel. (USK-721: there is NO
// process-wide recover() — an earlier comment claimed a "defer-recover
// protects" mechanism that does not actually exist; the safety here is
// purely the termDone gate. The matching ch.recvClosed atomic also
// short-circuits the assembler-terminal close path, which closes recv
// without closing termDone.) Any ch.recv close happens later when the
// caller eventually invokes channel.Close (bilateral close or session
// teardown).
func (c *channel) MarkTerminatedWithRST(code uint32, err error) {
	if id := c.h2Stream.Load(); id != 0 {
		c.layer.enqueueWrite(writeRequest{rst: &writeRST{streamID: id, code: code}})
	}
	if err == nil {
		err = errors.New("http2: aggregator-initiated RST")
	}
	// Push onto errCh so any current Next blocked in select picks it up.
	// Non-blocking: if errCh is full a prior error is preserved (first-
	// writer-wins semantics match markTerminated).
	if se, ok := err.(*layer.StreamError); ok {
		select {
		case c.errCh <- se:
		default:
		}
	}
	c.markTerminated(err)
}

// Next returns the next event envelope on this channel.
//
// Returns io.EOF on normal close, *layer.StreamError on stream error,
// ctx.Err() on cancellation.
//
// Drain priority: already-buffered envelopes on c.recv take precedence over
// c.errCh. The reader goroutine populates both independently — when the peer
// sends HEADERS, DATA(END_STREAM), and a trailing RST_STREAM in quick
// succession (e.g., x/net/http2 server emits RST after a handler returns
// without draining the request body), the multi-way select would otherwise
// pick the StreamError before the consumer drains the response envelopes
// already sitting in recv. That race surfaces as a phantom upstream error on
// a stream whose response actually arrived intact, which then cascades into
// a spurious RST_STREAM(CANCEL) toward the original client because the
// session never gets to deliver the response.
func (c *channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	// Fast path: drain any envelope already sitting in recv before consulting
	// errCh. This is non-blocking — if recv is empty we fall through to the
	// multi-way select below.
	select {
	case env, ok := <-c.recv:
		if ok {
			return env, nil
		}
		// recv is closed; drain a pending error if any, otherwise EOF.
		select {
		case se := <-c.errCh:
			return nil, se
		default:
		}
		return nil, io.EOF
	default:
	}
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
func (c *channel) Send(ctx context.Context, env *envelope.Envelope) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("http2: send on closed channel")
	}
	c.mu.Unlock()

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
//
// For client-initiated channels (h2Stream == 0 on entry), the first call
// allocates the wire-level stream id under l.mu atomically with the
// state-machine Transition, the channels-map registration, and the
// writer-queue enqueue — this guarantees id order matches enqueue order
// on the writer queue (RFC 9113 §5.1.1 wire-order), without the chained
// HEADERS-order gate that USK-739 introduced. Subsequent HEADERS frames
// (trailer HEADERS, retry on the same channel) reuse the already-allocated
// id. Server-role channels arrive here with h2Stream pre-populated from
// the inbound frame and skip allocation.
func (c *channel) sendHeadersEvent(ctx context.Context, env *envelope.Envelope, evt *H2HeadersEvent) error {
	fields := BuildHeaderFieldsFromEvent(env, evt)
	done := make(chan error, 1)

	if err := c.allocateAndEnqueueFirstHeaders(ctx, fields, evt.EndStream, done); err != nil {
		return err
	}

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

// allocateAndEnqueueFirstHeaders performs the lazy id-allocation +
// state-machine Transition + channels-map registration + writer-queue
// enqueue sequence atomically under l.mu when this is the first HEADERS
// frame on a client-initiated channel. For subsequent HEADERS or for
// channels constructed with a pre-assigned id (server-role), it just
// enqueues using the already-stored id.
//
// Holding l.mu across the four steps is what makes the refactor work:
// because the writer queue is FIFO, any other goroutine racing through
// this same critical section serialises behind us — its allocation gets
// the next id, its enqueue lands strictly after ours. ID order matches
// wire order by construction; the explicit headers-order gate is no
// longer needed (USK-740).
func (c *channel) allocateAndEnqueueFirstHeaders(ctx context.Context, fields []hpack.HeaderField, endStream bool, done chan error) error {
	// Fast path: id is already populated (peer-initiated channel, or this
	// is a follow-up HEADERS on a client-initiated channel). No allocation
	// required; just enqueue with the existing id.
	if id := c.h2Stream.Load(); id != 0 {
		c.layer.enqueueWrite(writeRequest{headers: &writeHeaders{
			streamID:  id,
			fields:    fields,
			endStream: endStream,
			done:      done,
		}})
		return nil
	}

	// Lazy-allocation path: client-initiated, no id yet. Acquire l.mu and
	// (under it) re-check the shutdown flag, allocate the next odd id,
	// transition the stream-state machine, register the channel, then
	// enqueue. enqueueWrite must be called inside the lock so a concurrent
	// caller that wins the next allocation cannot enqueue ahead of us.
	l := c.layer
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return errWriterClosed
	}

	id := l.nextClientStreamID
	l.nextClientStreamID += 2
	c.h2Stream.Store(id)

	_ = l.conn.Streams().Transition(id, EventSendHeaders)
	l.channels[id] = c
	l.assemblers[id] = newEventAssembler(id, c)

	// Inline the writer-queue enqueue rather than calling enqueueWrite so
	// the send happens under l.mu. The shutdown branch returns
	// errWriterClosed to the caller; we already checked l.closed above,
	// but a concurrent Close may close shutdown between the check and the
	// send — handle that case explicitly.
	req := writeRequest{headers: &writeHeaders{
		streamID:  id,
		fields:    fields,
		endStream: endStream,
		done:      done,
	}}
	// USK-812: try the buffered send in a non-blocking probe so a concurrent
	// close(shutdown) or ctx cancellation does not pseudo-randomly reject a
	// request the queue had room for. The writerLoop's drain branch processes
	// queued requests after shutdown, so a request enqueued just before
	// shutdown still reaches the wire. Mirrors the prefer-queue fix in
	// Layer.enqueueWrite. l.mu must be held across the probe — see the
	// allocateAndEnqueueFirstHeaders docstring.
	select {
	case l.writerQueue <- req:
		l.mu.Unlock()
		return nil
	default:
	}
	select {
	case l.writerQueue <- req:
		l.mu.Unlock()
		return nil
	case <-l.shutdown:
		l.mu.Unlock()
		failWriteRequest(req, errWriterClosed)
		return errWriterClosed
	case <-ctx.Done():
		l.mu.Unlock()
		failWriteRequest(req, ctx.Err())
		return ctx.Err()
	}
}

// sendDataEvent writes a DATA frame (or splits the payload into multiple
// DATA frames per MAX_FRAME_SIZE), respecting flow control. When
// evt.EndStream is true, END_STREAM is placed on the final DATA frame.
//
// Requires that a HEADERS frame has already been sent on this channel
// (h2Stream != 0). DATA before HEADERS is a protocol violation; the
// nominal call sites (aggregator's request-body path, gRPC frame writer)
// always invoke Send(HEADERS) first, but we reject defensively here so a
// misuse surfaces as a clean error rather than emitting DATA on stream 0.
func (c *channel) sendDataEvent(ctx context.Context, evt *H2DataEvent) error {
	id := c.h2Stream.Load()
	if id == 0 {
		return errors.New("http2: DATA before HEADERS — channel has no allocated stream id")
	}
	done := make(chan error, 1)
	c.layer.enqueueWrite(writeRequest{dataEvent: &writeDataEvent{
		streamID:  id,
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
//
// Requires h2Stream != 0; trailers without a preceding HEADERS frame is
// a protocol violation. See sendDataEvent's docstring for the same
// rationale.
func (c *channel) sendTrailersEvent(ctx context.Context, evt *H2TrailersEvent) error {
	id := c.h2Stream.Load()
	if id == 0 {
		return errors.New("http2: TRAILERS before HEADERS — channel has no allocated stream id")
	}
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
		streamID:  id,
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
//
// USK-740 guard: when h2Stream == 0 we have not yet told the peer this
// stream exists (lazy id allocation: OpenStream is a pure constructor;
// the wire id is reserved on the first sendHeadersEvent). Emitting
// RST_STREAM on an idle stream is a connection-level error per RFC 9113
// §5.4.2, so we skip the wire emit on the close-before-send path. The
// local teardown half (markTerminated, closeChannelRecv) still runs.
func (c *channel) Close() error {
	c.closeSendOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		sentEnd := c.sentEndStream
		recvEnd := c.recvEndStream
		c.mu.Unlock()

		// Only emit RST_STREAM if the peer has been told this stream
		// exists (h2Stream != 0) AND the close is abnormal (one side
		// still open). The h2Stream guard makes the close-before-send
		// path spec-compliant; the abnormal-close guard preserves the
		// USK-618 bilateral-close contract.
		if id := c.h2Stream.Load(); id != 0 && (!sentEnd || !recvEnd) {
			c.layer.enqueueWrite(writeRequest{rst: &writeRST{
				streamID: id,
				code:     ErrCodeCancel,
			}})
		}
		// Order matters: markTerminated FIRST so a reader currently blocked
		// in deliverEnvelope's send-select unblocks via the termDone case
		// before we acquire recvMu to close ch.recv. Reversing this risks a
		// deadlock when the consumer has stopped draining and the reader is
		// stuck mid-send holding recvMu.
		c.markTerminated(io.EOF)
		c.layer.closeChannelRecv(c)
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
		// RFC 8441 §4: extended CONNECT carries :protocol on the request.
		// Emit it only when the event actually populates the field — this
		// keeps classic CONNECT (Method=CONNECT, ConnectProtocol="")
		// wire-compatible with HTTP/2 Layer's pre-USK-764 output.
		if evt.Method == "CONNECT" && evt.ConnectProtocol != "" {
			out = append(out, hpack.HeaderField{Name: ":protocol", Value: evt.ConnectProtocol})
		}
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
//
// USK-812: when shutdown fires before the writer has called deliverDone, we
// must NOT immediately surface errWriterClosed because the writerLoop's
// drain branch (`case <-l.shutdown:` inside writerLoop) processes any
// already-queued requests on its way out. The write can still complete
// successfully on the wire after shutdown closes; the consumer side just
// needs to wait for the writer's authoritative result.
//
// Concrete failure mode this fixes — the
// TestE2E_LiveGRPCWeb_DispatchDeliversEnvelope/binary_proto flake:
//
//  1. client.Send(response HEADERS) — enqueued + processed; deliverDone(nil).
//  2. client.Send(response DATA, END_STREAM) — enqueued; writer goroutine
//     hasn't picked it up yet OR is mid-write.
//  3. The test client receives HEADERS via the writer's earlier flush,
//     eventually closes — kernel TCP RST/FIN propagates to the proxy's
//     frameReader → handleReadError(io.EOF) → close(l.shutdown).
//  4. Original code: waitDone for step 2's done picks `<-shutdown`,
//     returns errWriterClosed. But the writer's drain branch was about to
//     (or did) process the queued DATA write successfully — the bytes
//     reached the test client (cli.Do returned matching bytes) yet the
//     session recorded the Stream as state=error.
//
// The fix: after `<-shutdown` fires, block on `<-done` so the writer's
// eventual deliverDone — whether success or a real wire error — is the
// authoritative result. The drain branch in writerLoop guarantees done
// WILL fire for any already-queued request; if the request was never
// queued (lost in the enqueueWrite race), failWriteRequest already wrote
// errWriterClosed onto done before close(shutdown), so the unconditional
// receive returns immediately with that value. Either way the writer is
// the sole producer to done, so no goroutine leak is possible.
//
// ctx.Done branch keeps the original "return ctx.Err() promptly" semantics
// — caller-driven cancellation should not block waiting for the writer.
// We do peek at done first so a write that completed concurrently with ctx
// cancel still reports its actual result instead of being shadowed by the
// pseudo-random select.
//
// This is the H2 close-vs-write twin of the HTTP/1.x USK-798 fix
// (responseReadyMu mutex+atomic+sync.Once), simpler because the writer
// goroutine itself owns the done channel and is the sole writer to it.
func waitDone(ctx context.Context, done chan error, shutdown chan struct{}) error {
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// The write may have completed concurrently with ctx cancellation.
		// Prefer the writer's authoritative result over the cancellation
		// signal so a successful wire write is not reported as ctx.Err().
		select {
		case err := <-done:
			return err
		default:
		}
		return ctx.Err()
	case <-shutdown:
		// close(shutdown) racing a pending write must not surface as
		// errWriterClosed when the writer's drain loop will still process
		// the request. Block on done — failWriteRequest writes
		// errWriterClosed to done in the "request was never queued" path,
		// and the writer's drain loop writes the wire result in the
		// "request was queued" path. Either way done will fire, returning
		// the authoritative result.
		return <-done
	}
}

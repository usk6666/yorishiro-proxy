// detach.go implements per-stream byte detachment for HTTP/2 streams that
// have transitioned to a tunnelled wire format — currently only RFC 8441
// extended CONNECT → WebSocket-over-h2 (USK-765 / RFC-001 §3.3.2).
//
// DetachStream(streamID) peels framing for ONE stream off the connection-
// level h2 Layer: subsequent inbound DATA frames on that stream surface
// as opaque bytes on the returned reader; outbound writes are framed as
// DATA on the same stream id via the existing writer queue. Sibling
// streams continue to be processed by the standard event-granular path
// (RFC-001 §3.4.1 multiplex-isolation MUST).

package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// DetachStream tears down per-frame H2DataEvent assembly for one stream and
// returns a (reader, writer, closer) triple bound to the bytes flowing on
// that stream id. The connection-level h2 Layer (HPACK state, connection-
// level flow control, sibling streams) is untouched.
//
// Reader semantics:
//   - DATA frame payloads arrive in arrival order on the returned reader.
//   - Bytes that arrived between the trigger envelope (the 2xx response to
//     the extended CONNECT) and the DetachStream call are surfaced first
//     (the per-stream channel's recv buffer is drained on entry).
//   - END_STREAM surfaces as io.EOF on the reader after any preceding bytes.
//   - A stream-level error (RST_STREAM, GOAWAY-failed stream, etc.) surfaces
//     as a wrapped *layer.StreamError on the reader.
//
// Writer semantics:
//   - Each Write call enqueues exactly one DATA frame request on the
//     connection's writer queue. Multi-frame fragmentation is performed
//     by the writer goroutine (handleWriteDataEvent) per peer
//     MAX_FRAME_SIZE — the caller writes opaque bytes in arbitrary chunk
//     sizes and the wire layer takes care of frame boundaries.
//   - Writes block on flow control just like the existing event-granular
//     Send path.
//   - Closing the writer emits an END_STREAM-on-empty-DATA frame, signalling
//     the local half-close of the per-stream byte tunnel.
//
// Closer semantics:
//   - The returned closer terminates the per-stream framing and (when
//     neither half has been END_STREAM'd locally) emits RST_STREAM(NO_ERROR).
//     The underlying h2 connection survives.
//
// Distinct from http1.Layer.DetachStream(): the http2 variant takes a
// stream id and returns io.ReadCloser / io.WriteCloser triple wrapped in a
// closer func because the underlying connection survives detachment and
// the per-stream framing layer needs its own Close hook.
//
// Used by session.runUpgradeWSOverH2 in conjunction with ws.New(...,
// ws.WithH2Mode(true)) to swap a single stream into WebSocket framing
// under RFC 8441 extended CONNECT.
//
// Variadic DetachOption values configure optional behavior; today the
// only supported option is WithFrameRecordCallback (USK-889). Passing no
// options preserves the pre-USK-889 contract verbatim.
func (l *Layer) DetachStream(streamID uint32, opts ...DetachOption) (io.ReadCloser, io.WriteCloser, func() error, error) {
	if streamID == 0 {
		return nil, nil, nil, fmt.Errorf("http2: DetachStream requires non-zero streamID")
	}

	cfg := &detachConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, nil, nil, errors.New("http2: DetachStream on closed layer")
	}
	ch, ok := l.channels[streamID]
	if !ok || ch == nil {
		l.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("http2: DetachStream: stream %d not registered", streamID)
	}
	if ch.detached.Load() {
		l.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("http2: DetachStream: stream %d already detached", streamID)
	}
	pr, pw := io.Pipe()
	ch.detachWriter = pw
	ch.detachPipeReader = pr
	ch.detachFrameRecordCB = cfg.frameRecordCB
	ch.detached.Store(true)
	l.mu.Unlock()

	// Drain any envelopes already queued on ch.recv into the pipe writer
	// BEFORE returning the reader to the caller. RFC-001 §3.3.2 BodyBuffer
	// drain MUST: bytes that arrived between the trigger 2xx and this call
	// MUST be surfaced on the returned reader in arrival order.
	//
	// The drain runs in a goroutine because writing into the pipe blocks
	// until the consumer reads. Goroutine termination is bounded by:
	//   - ch.recv close (producer-side signal that no more events arrive)
	//   - ch.termDone close (channel terminated; pipe writer should close)
	//   - pipe writer close (caller closed reader; CloseWithError unblocks
	//     us on the next Write attempt)
	drainDone := make(chan struct{})
	ch.detachDrainDone = drainDone
	go ch.runDetachDrain(drainDone)

	r := &detachReader{
		channel: ch,
		pipe:    pr,
	}
	w := &detachWriter{
		channel:  ch,
		layer:    l,
		streamID: streamID,
	}
	closer := func() error {
		return ch.closeDetached()
	}
	return r, w, closer, nil
}

// runDetachDrain forwards inbound DATA event payloads from ch.recv into
// ch.detachWriter, and forwards any non-EOF terminal error via
// CloseWithError. Returns when ch.recv closes (reader-side EOF), termDone
// fires (terminal state), or the pipe writer is closed by the consumer
// (CloseWithError surfaces back on the next Write attempt).
//
// Drain order is the same as the assembler emit order, so any DATA bytes
// that the channel already buffered between the 2xx and the DetachStream
// call (RFC-001 §3.3.2 BodyBuffer drain MUST) are preserved verbatim.
func (c *channel) runDetachDrain(done chan struct{}) {
	defer close(done)
	pw := c.detachWriter
	if pw == nil {
		return
	}
	for {
		// Prefer recv (data) over termDone (terminal). The reader goroutine
		// closes recv on graceful end-of-stream and on protocol-violation
		// teardown; the multi-way select below then observes the closed
		// recv and exits via the "ok=false" branch.
		select {
		case env, ok := <-c.recv:
			if !ok {
				c.closeDetachPipeForTerminal(pw)
				return
			}
			if !c.forwardDetachEnvelope(pw, env) {
				return
			}
		case <-c.termDone:
			c.closeDetachPipeForTerminal(pw)
			return
		}
	}
}

// closeDetachPipeForTerminal closes the detach pipe writer with the
// channel's terminal error (CloseWithError for non-EOF, plain Close
// otherwise). Used by both the recv-closed and termDone branches of
// runDetachDrain.
func (c *channel) closeDetachPipeForTerminal(pw *io.PipeWriter) {
	if err := c.Err(); err != nil && !errors.Is(err, io.EOF) {
		_ = pw.CloseWithError(err)
		return
	}
	_ = pw.Close()
}

// forwardDetachEnvelope writes the DATA payload (if any) from env to pw
// and returns false when the drain loop should exit (terminal envelope
// or pipe-writer error). Returns true to continue draining.
//
// USK-889: when detachFrameRecordCB is non-nil, the callback fires
// synchronously BEFORE pipe.Write. The wire observation precedes the
// delivery of the bytes to the consumer Layer (RFC-001 §3.1 / CLAUDE.md
// MITM Principle #3 — raw bytes recording reflects on-wire reality, not
// post-delivery state). The callback contract documented on the channel
// field requires non-blocking behavior; runDetachDrain is single-
// consumer for ch.recv and any block here stalls the per-stream byte
// stream for sibling-frame delivery.
func (c *channel) forwardDetachEnvelope(pw *io.PipeWriter, env *envelope.Envelope) bool {
	if env == nil {
		return true
	}
	// In detach mode we only care about DATA payloads. HEADERS /
	// trailers events that race past the detach handshake are dropped —
	// the per-stream wire is now opaque to the h2 framing layer by
	// contract.
	data, isData := env.Message.(*H2DataEvent)
	if !isData {
		return true
	}
	// USK-889: invoke the frame-record callback (if installed) before
	// the pipe.Write delivery so the recorder snapshot reflects the
	// wire observation, not the post-delivery state. Defensive panic
	// guard is intentionally omitted — the callback is set by trusted
	// orchestrator code in the same process, and we want any panic to
	// surface to the operator rather than be silently swallowed.
	if cb := c.detachFrameRecordCB; cb != nil {
		cb(env)
	}
	if len(data.Payload) > 0 {
		if _, werr := pw.Write(data.Payload); werr != nil {
			// Consumer closed the pipe reader; producer is done.
			return false
		}
	}
	if data.EndStream {
		_ = pw.Close()
		return false
	}
	return true
}

// closeDetached terminates the per-stream framing. Idempotent: subsequent
// calls are no-ops. Closes the pipe writer (which surfaces io.EOF to the
// consumer reader) and runs the standard channel close path (which emits
// RST_STREAM(NO_ERROR) when neither half has been END_STREAM'd locally).
func (c *channel) closeDetached() error {
	c.detachCloseOnce.Do(func() {
		// Close the pipe writer first so any in-flight Write from the
		// producer goroutine returns and the drainer exits cleanly.
		if c.detachWriter != nil {
			_ = c.detachWriter.Close()
		}
		// Run the standard channel close path so the layer maps clean up,
		// state-machine transitions fire, and (when needed) RST_STREAM
		// goes on the wire. Idempotent via channel.closeSendOnce.
		_ = c.Close()
	})
	return nil
}

// detachReader implements io.ReadCloser over a per-stream byte reader
// returned by DetachStream. Reads block until the next DATA payload bytes
// arrive, an error fires, or io.EOF is signalled.
type detachReader struct {
	channel *channel
	pipe    *io.PipeReader
}

// Read forwards to the underlying pipe.
func (r *detachReader) Read(p []byte) (int, error) {
	return r.pipe.Read(p)
}

// Close closes the pipe reader, unblocking any concurrent Write in the
// drainer goroutine. The Layer continues running for sibling streams.
func (r *detachReader) Close() error {
	return r.pipe.Close()
}

// detachWriter implements io.WriteCloser by enqueueing DATA frames on the
// connection-level writer queue scoped to a single stream id.
type detachWriter struct {
	channel  *channel
	layer    *Layer
	streamID uint32

	mu     sync.Mutex
	closed bool
}

// Write enqueues one DATA frame request with payload p on the stream id
// captured at DetachStream time. Multi-frame fragmentation per peer
// MAX_FRAME_SIZE is performed by the writer goroutine.
//
// A nil / zero-length p is a no-op (returns 0, nil) — matching io.Writer
// semantics. Use Close to emit a terminal END_STREAM signal.
func (w *detachWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return 0, errors.New("http2: detachWriter: write after close")
	}
	w.mu.Unlock()

	// Defensive copy: the writer goroutine may hold p past Write return.
	buf := make([]byte, len(p))
	copy(buf, p)

	done := make(chan error, 1)
	w.layer.enqueueWrite(writeRequest{dataEvent: &writeDataEvent{
		streamID:  w.streamID,
		payload:   buf,
		endStream: false,
		done:      done,
	}})
	if err := waitDone(context.Background(), done, w.layer.shutdown); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close emits a single empty DATA frame with END_STREAM=1, signalling the
// local half-close of the per-stream byte tunnel. Idempotent.
func (w *detachWriter) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()

	done := make(chan error, 1)
	w.layer.enqueueWrite(writeRequest{dataEvent: &writeDataEvent{
		streamID:  w.streamID,
		payload:   nil,
		endStream: true,
		done:      done,
	}})
	if err := waitDone(context.Background(), done, w.layer.shutdown); err != nil {
		return err
	}
	w.channel.mu.Lock()
	w.channel.sentEndStream = true
	w.channel.mu.Unlock()
	// Best-effort state-machine transition; ignore error (the connection
	// may already be torn down by the time the local half-close lands).
	_ = w.layer.conn.Streams().Transition(w.streamID, EventSendEndStream)
	return nil
}

// detachActive reports whether the channel has been transitioned to detach
// mode. Test-only / diagnostic helper exposing the atomic flag.
func (c *channel) detachActive() bool {
	return c.detached.Load()
}

// drainDoneChan exposes the drainer-completion channel for tests that want
// to confirm the detach drainer has exited (e.g. before asserting on
// pipe-reader EOF). nil when the channel is not detached.
func (c *channel) drainDoneChan() <-chan struct{} {
	return c.detachDrainDone
}

// detachConfig collects values supplied to DetachStream via the variadic
// DetachOption mechanism. Defined as a struct (not a parameter struct
// passed by value) so future fields can be added without breaking
// existing callers, mirroring the precedent set by USK-802's RecordStep
// Option pattern.
type detachConfig struct {
	// frameRecordCB is the optional synchronous callback that fires
	// inside runDetachDrain for every H2DataEvent envelope produced on
	// the detached stream. nil when no caller installed the option.
	frameRecordCB func(*envelope.Envelope)
}

// DetachOption configures DetachStream. The variadic-option shape lets
// future per-call configuration land without breaking existing callers
// (USK-781 callers pass no options; USK-889 introduces
// WithFrameRecordCallback as the first option). Mirrors the USK-802
// pipeline.Option precedent so the API style stays uniform across the
// codebase.
type DetachOption func(*detachConfig)

// WithFrameRecordCallback installs a synchronous frame-record callback
// invoked inside runDetachDrain for every H2DataEvent envelope drained
// from the detached stream's channel (USK-889).
//
// Timing: the callback fires BEFORE the payload is written to the
// detach pipe. This ordering reflects the MITM contract — the
// recorder's snapshot must mirror on-wire observation, not the
// post-delivery state the consumer Layer sees. Without this ordering a
// late consumer error could cause runDetachDrain to exit before the
// recorder ever sees the frame.
//
// Contract:
//   - cb MUST NOT block. runDetachDrain is single-consumer for the
//     channel's recv queue; any block here stalls subsequent DATA
//     frames on the same stream. If the orchestrator's recording path
//     needs to perform IO that may block (DB write under contention,
//     network call), it must dispatch its own goroutine inside cb.
//   - cb receives the envelope in its drained form (Envelope.Raw
//     contains the DATA frame payload; Message is *H2DataEvent;
//     Protocol is envelope.ProtocolHTTP — NOT a new ProtocolHTTP2
//     value, by design). The callback may read but must not mutate
//     the envelope; mutating fields is undefined.
//   - The envelope's identity (StreamID / FlowID / Sequence /
//     Direction) is the connection-level h2 channel's view of the
//     stream. The session.runUpgrade* orchestrators that install this
//     callback typically rewrite these fields to the post-swap
//     session-scope StreamID + a separate per-direction sequence
//     counter scoped to (sessionStreamID, WireLevel=h2-frame) before
//     dispatching to the record-only Pipeline.
//
// Passing a nil cb is equivalent to not supplying the option at all:
// the Option is a no-op on the underlying config and the detached
// stream behaves identically to the pre-USK-889 contract.
func WithFrameRecordCallback(cb func(*envelope.Envelope)) DetachOption {
	return func(c *detachConfig) {
		c.frameRecordCB = cb
	}
}

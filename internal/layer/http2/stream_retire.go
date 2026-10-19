package http2

import (
	"errors"
	"fmt"
)

// Stream retirement (USK-1144 / USK-1176).
//
// A stream that is closed in the RFC 9113 §5.1 sense — END_STREAM sent and
// received, or RST_STREAM sent or received — leaves the Layer's bookkeeping
// so that it neither counts against SETTINGS_MAX_CONCURRENT_STREAMS (nor the
// upstream pool's per-connection capacity, which reads ActiveStreamCount)
// nor holds memory for the rest of the connection's lifetime.
//
// The bookkeeping is owned by different goroutines, so retirement is split:
//
//   - StreamMap entry: removed by whichever goroutine's transition closed the
//     stream — the reader (END_STREAM / RST_STREAM received) or the writer
//     (END_STREAM / RST_STREAM written). After removal StreamMap.IsClosed
//     reports the id as closed (ids are never reused, §5.1.1), which is how
//     late frames on it are recognised.
//   - l.assemblers entry: removed under l.mu by cleanupRetired. The reader
//     runs it for streams it closed; streams the writer closed are handed
//     over via l.retired, drained by the reader before every frame and by
//     closeStream. An assembler retired in the middle of a header block
//     stays reachable through l.pendingAsm, so the HPACK decoder still sees
//     every fragment of the block.
//   - l.channels entry and sched.reset entry: removed only once the stream
//     is closed on the wire AND the consumer has closed the Channel
//     (closeStream), whichever happens second. A Channel the consumer still
//     holds stays registered so failStream / broadcastShutdown still reach
//     it. Its Sends after the stream closed fail in the writer (absent
//     stream) unless a recorded reset decides their result.
//
// The writer never takes l.mu here: allocateAndEnqueueFirstHeaders holds
// l.mu while it blocks on a full writer queue, so the writer waiting on
// l.mu would deadlock. A stream the writer closes after its Channel was
// closed (RST_STREAM(CANCEL) from closeStream) is therefore cleaned up on
// the next frame read or the next Channel close on the connection.

// errStreamClosed is delivered to a HEADERS / DATA write for a stream that is
// already closed and has no recorded reset result.
var errStreamClosed = errors.New("http2: write on closed stream")

// headerDiscard accumulates a header block that is decoded only to keep the
// HPACK dynamic table in sync (RFC 9113 §4.3) and then dropped.
type headerDiscard struct {
	streamID uint32
	buf      []byte
	frames   int
}

// retireOnSend applies a send-side closing event (END_STREAM or RST_STREAM
// written) to an existing stream and, when that closed it, removes it from
// StreamMap and hands the id to the reader for the rest of the cleanup.
// Writer goroutine only. A stream with no entry (refused before it was
// registered, or already retired) is left alone.
func (l *Layer) retireOnSend(streamID uint32, event StreamEvent) {
	closed, _ := l.conn.Streams().TransitionExisting(streamID, event)
	if !closed {
		return
	}
	l.conn.Streams().Remove(streamID)
	l.retireMu.Lock()
	l.retired = append(l.retired, streamID)
	l.retirePending.Store(true)
	l.retireMu.Unlock()
}

// retireOnRecv applies a receive-side END_STREAM to an existing stream and
// retires it when that closed it. Reader goroutine only.
func (l *Layer) retireOnRecv(streamID uint32, event StreamEvent) {
	closed, _ := l.conn.Streams().TransitionExisting(streamID, event)
	if !closed {
		return
	}
	l.conn.Streams().Remove(streamID)
	l.cleanupRetired(streamID)
}

// retireAfterRecvRST retires a stream that HandleRSTStream closed. Reader
// goroutine only.
func (l *Layer) retireAfterRecvRST(streamID uint32) {
	if l.conn.Streams().RemoveIfClosed(streamID) {
		l.cleanupRetired(streamID)
	}
}

// cleanupRetired removes the assembler of a retired stream, and its Channel
// when the consumer has already closed it. Idempotent. Must not be called
// with l.mu held, and never from the writer goroutine.
func (l *Layer) cleanupRetired(streamID uint32) {
	l.mu.Lock()
	delete(l.assemblers, streamID)
	ch := l.channels[streamID]
	release := ch != nil && ch.closedLocal.Load()
	if release {
		delete(l.channels, streamID)
	}
	l.mu.Unlock()
	if release {
		l.forgetStreamWrites(streamID)
	}
}

// drainRetired runs cleanupRetired for every stream the writer retired since
// the last call. Called by the reader before each frame and by closeStream;
// same constraints as cleanupRetired.
func (l *Layer) drainRetired() {
	if !l.retirePending.Load() {
		return
	}
	l.retireMu.Lock()
	ids := l.retired
	l.retired = nil
	l.retirePending.Store(false)
	l.retireMu.Unlock()
	for _, id := range ids {
		l.cleanupRetired(id)
	}
}

// releaseClosedChannel is closeStream's half of the l.channels hand-off:
// called after c is terminated and marked closedLocal, it removes c if its
// stream is already closed on the wire; otherwise the cleanupRetired that
// runs once the stream closes does. It also drains streams the writer
// retired, so their cleanup does not wait for the next frame read. Never
// called with l.mu held.
func (l *Layer) releaseClosedChannel(c *channel) {
	l.drainRetired()
	if id := c.h2Stream.Load(); id != 0 && l.conn.Streams().IsClosed(id) {
		l.cleanupRetired(id)
	}
}

// discardHeaderFragment feeds one HEADERS / CONTINUATION fragment of a block
// that is not delivered anywhere into the HPACK decoder, so the dynamic table
// stays in sync with the peer's encoder. The same size and CONTINUATION
// limits as eventAssembler apply. Reader goroutine only.
func (l *Layer) discardHeaderFragment(streamID uint32, fragment []byte, endHeaders bool) error {
	if l.discard == nil || l.discard.streamID != streamID {
		l.discard = &headerDiscard{streamID: streamID}
	}
	d := l.discard
	if len(d.buf)+len(fragment) > maxHeaderFragmentBytes {
		l.discard = nil
		return &ConnError{
			Code:   ErrCodeCompression,
			Reason: fmt.Sprintf("header block fragment exceeds %d bytes (stream %d)", maxHeaderFragmentBytes, streamID),
		}
	}
	d.buf = append(d.buf, fragment...)
	if !endHeaders {
		d.frames++
		if d.frames > maxContinuationFrames {
			l.discard = nil
			return &ConnError{
				Code:   ErrCodeEnhanceYourCalm,
				Reason: fmt.Sprintf("too many CONTINUATION frames (>%d) for stream %d", maxContinuationFrames, streamID),
			}
		}
		l.pendingHeaderStream = streamID
		l.pendingAsm = nil
		return nil
	}
	l.pendingHeaderStream = 0
	l.discard = nil
	if _, err := l.decoder.Decode(d.buf); err != nil {
		return &ConnError{
			Code:   ErrCodeCompression,
			Reason: fmt.Sprintf("decode discarded header block (stream %d): %v", streamID, err),
		}
	}
	return nil
}

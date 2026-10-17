package http2

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// ErrWriterClosed is returned to pending Send calls when the writer goroutine
// is shutting down before their write request was processed.
//
// Exported (USK-903) so cross-package classifiers can distinguish a
// connection-level writer shutdown from genuine wire errors. The session
// layer uses errors.Is(err, http2.ErrWriterClosed) to recognise client-side
// HTTP/2 teardown as a graceful client-gone signal in SSE-over-h2 — without
// this, curl --max-time-style client cancellation surfaced as state=error
// instead of state=complete (asymmetric with HTTP/1.1).
var ErrWriterClosed = errors.New("http2: writer closed")

// writeRequest is the union type sent on the writer queue. Exactly one of
// the typed pointer fields is non-nil for any request. Event-granular
// writes (USK-637) are expressed via writeHeaders + writeDataEvent; the
// previous writeMessage-shaped "whole request in one queued item" path is
// gone.
type writeRequest struct {
	headers      *writeHeaders
	dataEvent    *writeDataEvent
	rst          *writeRST
	windowUpdate *writeWindowUpdate
	pingAck      *writePingAck
	settings     *writeSettings
	settingsAck  *writeSettingsAck
	goAway       *writeGoAway
}

// writeHeaders encodes and writes a HEADERS block (+ CONTINUATION* as
// needed). endStream places END_STREAM on the HEADERS frame that opens the
// block — never on a CONTINUATION frame (RFC 9113 §6.2, §6.10). Used for
// both initial HEADERS and trailer HEADERS.
type writeHeaders struct {
	streamID  uint32
	fields    []hpack.HeaderField
	endStream bool
	done      chan error
}

// writeDataEvent writes a single H2DataEvent's payload as one-or-more DATA
// frames (splitting at MAX_FRAME_SIZE), respecting stream and connection
// flow control windows. endStream places END_STREAM on the final frame.
//
// A nil payload combined with endStream=true emits a single empty
// END_STREAM DATA frame — this is how the aggregator signals "no body,
// no trailers" when initial HEADERS did not carry END_STREAM.
type writeDataEvent struct {
	streamID  uint32
	payload   []byte
	endStream bool
	done      chan error

	// off is how much of payload has been written. Writer goroutine only;
	// non-zero while the request is parked part-way (USK-1166).
	off int
	// abandoned is set by the sending goroutine when its ctx expired before
	// the write finished; the writer then drops the unwritten remainder at
	// the next frame boundary instead of writing it later (USK-1166).
	abandoned atomic.Bool
}

// writeRST emits a RST_STREAM frame.
type writeRST struct {
	streamID uint32
	code     uint32
	done     chan error
}

// writeWindowUpdate emits a WINDOW_UPDATE frame.
type writeWindowUpdate struct {
	streamID        uint32
	increment       uint32
	skipLocalUpdate bool
	done            chan error
}

// writePingAck emits a PING frame with the ACK flag set.
type writePingAck struct {
	data [8]byte
	done chan error
}

// writeSettings emits a non-ACK SETTINGS frame.
type writeSettings struct {
	params []frame.Setting
	done   chan error
}

// writeSettingsAck emits a SETTINGS ACK frame.
type writeSettingsAck struct {
	done chan error
}

// writeGoAway emits a GOAWAY frame.
type writeGoAway struct {
	lastStreamID uint32
	code         uint32
	debug        []byte
	done         chan error
}

// writerLoop is the body of the single writer goroutine. It serializes all
// frame writes for the connection.
//
// Exit invariant: every queued writeRequest's done chan is signaled exactly
// once before close(l.writerDone) fires. The shutdown drain branch handles
// requests queued before shutdown; the deferred fail-drain catches requests
// enqueued in the brief race window between the drain branch sampling
// `default` and writerLoop returning. The companion check in enqueueWrite
// (`<-l.writerDone` short-circuit) covers requests that arrive after
// writerDone closes. Together these prevent the orphaned-request hang
// observed in the SSE-over-h2 sibling teardown path: detachWriter.Close
// enqueues an empty END_STREAM DATA from a deferred call AFTER the client
// h2 layer's reader saw EOF and broadcastShutdown ran, and waitDone's
// `<-shutdown` fall-through (`return <-done`) requires done to fire.
//
// USK-1166: the writer never blocks on flow control. DATA that does not fit
// the peer's windows is parked per stream (see writeSched) and resumed when
// windowUpdated fires; the same signal carries stream resets recorded by the
// reader. Writes still parked at exit are failed with ErrWriterClosed by
// failParkedWrites, so the exit invariant above covers them too.
func (l *Layer) writerLoop() {
	defer close(l.writerDone)
	defer l.failDrainQueuedWrites()
	defer l.failParkedWrites(ErrWriterClosed)

	for {
		select {
		case <-l.shutdown:
			// Best-effort drain of already-queued requests.
			for {
				select {
				case req := <-l.writerQueue:
					l.dispatchWrite(req)
				default:
					return
				}
			}
		case req := <-l.writerQueue:
			l.dispatchWrite(req)
		case <-l.windowUpdated:
			l.applyPendingResets()
			l.serviceParked()
		}
	}
}

// failDrainQueuedWrites empties any remaining writeRequests on the queue
// and signals ErrWriterClosed on each one's done channel. Runs as a defer
// in writerLoop after the shutdown-drain branch returns, catching requests
// enqueued between the drain's `default` sample and writerLoop's actual
// exit. The race window without this drain is small but real and produces
// the deterministic "waitDone hang" failure mode.
func (l *Layer) failDrainQueuedWrites() {
	for {
		select {
		case req := <-l.writerQueue:
			failWriteRequest(req, ErrWriterClosed)
		default:
			return
		}
	}
}

func (l *Layer) dispatchWrite(req writeRequest) {
	// Resets observed by the reader must apply before any later-dequeued
	// write for the same stream is considered.
	l.applyPendingResets()
	switch {
	case req.headers != nil:
		l.scheduleStreamWrite(req.headers.streamID, req)
	case req.dataEvent != nil:
		l.scheduleStreamWrite(req.dataEvent.streamID, req)
	case req.rst != nil:
		l.handleWriteRST(req.rst)
	case req.windowUpdate != nil:
		l.handleWriteWindowUpdate(req.windowUpdate)
	case req.pingAck != nil:
		l.handleWritePingAck(req.pingAck)
	case req.settings != nil:
		l.handleWriteSettings(req.settings)
	case req.settingsAck != nil:
		l.handleWriteSettingsAck(req.settingsAck)
	case req.goAway != nil:
		l.handleWriteGoAway(req.goAway)
	}
}

func (l *Layer) handleWriteRST(req *writeRST) {
	// RFC 9113 §5.1 / §6.9: once RST_STREAM is sent no DATA or HEADERS may
	// follow on the stream; drop anything parked for it before the RST goes
	// out (USK-1166).
	l.purgeStream(req.streamID, localResetError(req.code))
	err := l.frameWriter.WriteRSTStream(req.streamID, req.code)
	deliverDone(req.done, err)
}

func (l *Layer) handleWriteWindowUpdate(req *writeWindowUpdate) {
	err := l.frameWriter.WriteWindowUpdate(req.streamID, req.increment)
	if err == nil && !req.skipLocalUpdate {
		if req.streamID == 0 {
			_ = l.conn.IncrementRecvWindow(req.increment)
		} else {
			_ = l.conn.Streams().IncrementRecvWindow(req.streamID, req.increment)
		}
	}
	deliverDone(req.done, err)
}

func (l *Layer) handleWritePingAck(req *writePingAck) {
	err := l.frameWriter.WritePing(true, req.data)
	deliverDone(req.done, err)
}

func (l *Layer) handleWriteSettings(req *writeSettings) {
	err := l.frameWriter.WriteSettings(req.params)
	deliverDone(req.done, err)
}

func (l *Layer) handleWriteSettingsAck(req *writeSettingsAck) {
	err := l.frameWriter.WriteSettingsAck()
	deliverDone(req.done, err)
}

func (l *Layer) handleWriteGoAway(req *writeGoAway) {
	err := l.frameWriter.WriteGoAway(req.lastStreamID, req.code, req.debug)
	if err == nil {
		l.conn.MarkGoAwaySent(req.lastStreamID)
	}
	deliverDone(req.done, err)
}

// handleWriteHeaders encodes the given header field list via the Layer's
// HPACK encoder and writes HEADERS (+ CONTINUATION*) respecting the peer's
// MAX_FRAME_SIZE. endStream places END_STREAM on the HEADERS frame (the
// first frame of the block), as RFC 9113 §6.2 requires; CONTINUATION frames
// cannot carry it.
func (l *Layer) handleWriteHeaders(req *writeHeaders) {
	peer := l.conn.PeerSettings()
	if peer.MaxHeaderListSize > 0 {
		if err := checkHeaderListSize(req.fields, peer.MaxHeaderListSize); err != nil {
			deliverDone(req.done, err)
			return
		}
	}
	if l.encoderTableSize != peer.HeaderTableSize {
		l.encoder.SetMaxTableSize(peer.HeaderTableSize)
		l.encoderTableSize = peer.HeaderTableSize
	}
	if peer.MaxFrameSize >= frame.DefaultMaxFrameSize && peer.MaxFrameSize <= frame.MaxAllowedFrameSize {
		_ = l.frameWriter.SetMaxFrameSize(peer.MaxFrameSize)
	}
	maxFrameSize := l.frameWriter.MaxFrameSize()

	encoded := l.encoder.Encode(req.fields)
	err := l.writeHeaderBlock(req.streamID, encoded, req.endStream, maxFrameSize)
	deliverDone(req.done, err)
}

// writeDataProgress writes as much of req as the stream and connection send
// windows allow, splitting at MAX_FRAME_SIZE; END_STREAM goes on the final
// frame, and a nil payload with endStream=true is a single empty END_STREAM
// DATA frame. It never waits for window (USK-1166): it reports false when
// the windows are exhausted with payload left over, leaving req.off at the
// resume point, and true once req is finished and its done signalled.
func (l *Layer) writeDataProgress(req *writeDataEvent) bool {
	if len(req.payload) == 0 {
		var err error
		if req.endStream {
			err = l.frameWriter.WriteData(req.streamID, true, nil)
		}
		deliverDone(req.done, err)
		return true
	}

	maxFrameSize := int(l.frameWriter.MaxFrameSize())
	if maxFrameSize == 0 {
		maxFrameSize = int(frame.DefaultMaxFrameSize)
	}
	for req.off < len(req.payload) {
		if req.abandoned.Load() {
			deliverDone(req.done, errWriteAbandoned)
			return true
		}
		n, err := l.reserveWindow(req.streamID, len(req.payload)-req.off, maxFrameSize)
		if err != nil {
			deliverDone(req.done, err)
			return true
		}
		if n == 0 {
			return false
		}
		chunk := req.payload[req.off : req.off+n]
		req.off += n
		endStream := req.endStream && req.off == len(req.payload)
		if err := l.frameWriter.WriteData(req.streamID, endStream, chunk); err != nil {
			deliverDone(req.done, err)
			return true
		}
	}
	deliverDone(req.done, nil)
	return true
}

// checkHeaderListSize returns an error when the cumulative Size() of fields
// exceeds limit. Used to enforce the peer's SETTINGS_MAX_HEADER_LIST_SIZE.
func checkHeaderListSize(fields []hpack.HeaderField, limit uint32) error {
	var total uint32
	for _, hf := range fields {
		total += hf.Size()
		if total > limit {
			return fmt.Errorf("http2: encoded header list size %d exceeds peer max %d", total, limit)
		}
	}
	return nil
}

// writeHeaderBlock splits encoded header block fragment across HEADERS +
// CONTINUATION frames according to maxFrameSize.
func (l *Layer) writeHeaderBlock(streamID uint32, encoded []byte, endStream bool, maxFrameSize uint32) error {
	if maxFrameSize == 0 {
		maxFrameSize = frame.DefaultMaxFrameSize
	}

	if uint32(len(encoded)) <= maxFrameSize {
		return l.frameWriter.WriteHeaders(streamID, endStream, true, encoded)
	}

	first := encoded[:maxFrameSize]
	rest := encoded[maxFrameSize:]
	if err := l.frameWriter.WriteHeaders(streamID, endStream, false, first); err != nil {
		return err
	}
	for len(rest) > int(maxFrameSize) {
		chunk := rest[:maxFrameSize]
		if err := l.frameWriter.WriteContinuation(streamID, false, chunk); err != nil {
			return err
		}
		rest = rest[maxFrameSize:]
	}
	return l.frameWriter.WriteContinuation(streamID, true, rest)
}

// reserveWindow consumes and returns min{stream send window, conn send
// window, requested, maxFrameSize} bytes from both windows, or 0 when either
// window is exhausted. It never blocks (USK-1166).
func (l *Layer) reserveWindow(streamID uint32, requested, maxFrameSize int) (int, error) {
	streamWin, ok := l.conn.Streams().GetSendWindow(streamID)
	if !ok {
		return 0, fmt.Errorf("http2: stream %d does not exist for window check", streamID)
	}
	avail := requested
	if int(streamWin) < avail {
		avail = int(streamWin)
	}
	if connWin := int(l.conn.SendWindow()); connWin < avail {
		avail = connWin
	}
	if maxFrameSize > 0 && maxFrameSize < avail {
		avail = maxFrameSize
	}
	if avail <= 0 {
		return 0, nil
	}
	if err := l.conn.Streams().ConsumeSendWindow(streamID, int32(avail)); err != nil {
		return 0, err
	}
	if err := l.conn.ConsumeSendWindow(int32(avail)); err != nil {
		_ = l.conn.Streams().IncrementSendWindow(streamID, uint32(avail))
		return 0, err
	}
	return avail, nil
}

// deliverDone sends err on done if non-nil.
func deliverDone(done chan error, err error) {
	if done == nil {
		return
	}
	select {
	case done <- err:
	default:
	}
}

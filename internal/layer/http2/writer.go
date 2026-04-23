package http2

import (
	"errors"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// errWriterClosed is returned to pending Send calls when the writer goroutine
// is shutting down before their write request was processed.
var errWriterClosed = errors.New("http2: writer closed")

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
// needed). endStream places END_STREAM on the final frame of the block.
// Used for both initial HEADERS and trailer HEADERS.
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
func (l *Layer) writerLoop() {
	defer close(l.writerDone)

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
		}
	}
}

func (l *Layer) dispatchWrite(req writeRequest) {
	switch {
	case req.headers != nil:
		l.handleWriteHeaders(req.headers)
	case req.dataEvent != nil:
		l.handleWriteDataEvent(req.dataEvent)
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
// MAX_FRAME_SIZE. endStream places END_STREAM on the final frame.
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

// handleWriteDataEvent writes req.payload as one or more DATA frames,
// splitting at MAX_FRAME_SIZE and respecting flow control. When
// req.endStream is true, END_STREAM is placed on the final frame. A nil
// payload combined with endStream=true produces a single empty DATA frame.
func (l *Layer) handleWriteDataEvent(req *writeDataEvent) {
	maxFrameSize := int(l.frameWriter.MaxFrameSize())
	if maxFrameSize == 0 {
		maxFrameSize = int(frame.DefaultMaxFrameSize)
	}

	body := req.payload
	if len(body) == 0 {
		// Empty payload.
		if req.endStream {
			err := l.frameWriter.WriteData(req.streamID, true, nil)
			deliverDone(req.done, err)
			return
		}
		// Empty payload, no END_STREAM: no-op.
		deliverDone(req.done, nil)
		return
	}

	for len(body) > 0 {
		n, err := l.waitForWindow(req.streamID, len(body), maxFrameSize)
		if err != nil {
			deliverDone(req.done, err)
			return
		}
		chunk := body[:n]
		body = body[n:]
		endStream := req.endStream && len(body) == 0
		if err := l.frameWriter.WriteData(req.streamID, endStream, chunk); err != nil {
			deliverDone(req.done, err)
			return
		}
	}
	deliverDone(req.done, nil)
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

// waitForWindow blocks until the smaller of {stream send window, conn send
// window, requested, maxFrameSize} is positive, then consumes that many bytes
// from both windows and returns the consumed amount.
func (l *Layer) waitForWindow(streamID uint32, requested, maxFrameSize int) (int, error) {
	for {
		select {
		case <-l.shutdown:
			return 0, errWriterClosed
		default:
		}

		streamWin, ok := l.conn.Streams().GetSendWindow(streamID)
		if !ok {
			return 0, fmt.Errorf("http2: stream %d does not exist for window check", streamID)
		}
		connWin := l.conn.SendWindow()

		avail := requested
		if int(streamWin) < avail {
			avail = int(streamWin)
		}
		if int(connWin) < avail {
			avail = int(connWin)
		}
		if maxFrameSize > 0 && maxFrameSize < avail {
			avail = maxFrameSize
		}
		if avail > 0 {
			if err := l.conn.Streams().ConsumeSendWindow(streamID, int32(avail)); err != nil {
				return 0, err
			}
			if err := l.conn.ConsumeSendWindow(int32(avail)); err != nil {
				_ = l.conn.Streams().IncrementSendWindow(streamID, uint32(avail))
				return 0, err
			}
			return avail, nil
		}

		select {
		case <-l.windowUpdated:
		case <-l.shutdown:
			return 0, errWriterClosed
		}
	}
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

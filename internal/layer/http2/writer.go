package http2

import (
	"errors"
	"fmt"
	"io"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// errWriterClosed is returned to pending Send calls when the writer goroutine
// is shutting down before their write request was processed.
var errWriterClosed = errors.New("http2: writer closed")

// writeRequest is the union type sent on the writer queue. Exactly one of
// the typed pointer fields is non-nil for any request.
type writeRequest struct {
	opaque       *writeOpaque
	message      *writeMessage
	rst          *writeRST
	windowUpdate *writeWindowUpdate
	pingAck      *writePingAck
	settings     *writeSettings
	settingsAck  *writeSettingsAck
	goAway       *writeGoAway
}

// writeOpaque writes pre-formed frame bytes for a stream zero-copy.
// Frames must already include the 9-byte HTTP/2 header.
type writeOpaque struct {
	streamID uint32
	frames   [][]byte
	endHook  func() // optional: called after successful write while holding writer lock
	done     chan error
}

// writeMessage encodes a request or response: HEADERS (+ CONTINUATION*) plus
// flow-controlled DATA and optional trailer HEADERS. Headers, body, and
// trailers are owned by the writer goroutine after this request is queued.
//
// When trailers is non-empty, END_STREAM is placed on the trailer HEADERS
// frame rather than the final DATA frame per RFC 9113 §8.1.
type writeMessage struct {
	streamID   uint32
	headers    []hpack.HeaderField
	body       []byte
	bodyReader io.Reader
	trailers   []hpack.HeaderField
	endStream  bool
	endHook    func() // optional: called after successful write
	done       chan error
}

// writeRST emits a RST_STREAM frame.
type writeRST struct {
	streamID uint32
	code     uint32
	done     chan error
}

// writeWindowUpdate emits a WINDOW_UPDATE frame.
type writeWindowUpdate struct {
	streamID  uint32
	increment uint32
	// skipLocalUpdate suppresses the post-write IncrementRecvWindow call.
	// Used when the caller has already bumped the local accounting (e.g.,
	// during Layer initialization).
	skipLocalUpdate bool
	done            chan error // optional; may be nil
}

// writePingAck emits a PING frame with the ACK flag set.
type writePingAck struct {
	data [8]byte
	done chan error // optional; may be nil
}

// writeSettings emits a non-ACK SETTINGS frame.
type writeSettings struct {
	params []frame.Setting
	done   chan error
}

// writeSettingsAck emits a SETTINGS ACK frame.
type writeSettingsAck struct {
	done chan error // optional
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
// Shutdown model (USK-614): the writer is the sole owner of writerQueue
// lifecycle — it never closes the channel, and neither does anyone else.
// When <-shutdown fires, the writer performs a non-blocking drain of any
// remaining requests and exits. This is safe because every sender
// (enqueueWrite) selects on <-shutdown as well, so once shutdown is closed
// no new requests reach writerQueue — the drain observes exactly the set
// of requests that were enqueued before shutdown became visible.
//
// The writer also needs access to the per-stream send window (held in conn)
// and a way to wait for WINDOW_UPDATE; that wait happens on l.windowUpdated.
func (l *Layer) writerLoop() {
	defer close(l.writerDone)

	for {
		select {
		case <-l.shutdown:
			// Best-effort drain of already-queued requests. After
			// shutdown, no new senders can succeed on writerQueue
			// (they select on <-shutdown), so a non-blocking drain
			// reaches a quiescent state.
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
	case req.opaque != nil:
		l.handleWriteOpaque(req.opaque)
	case req.message != nil:
		l.handleWriteMessage(req.message)
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

func (l *Layer) handleWriteOpaque(req *writeOpaque) {
	for _, b := range req.frames {
		if err := l.frameWriter.WriteRawBytes(b); err != nil {
			deliverDone(req.done, err)
			return
		}
	}
	if req.endHook != nil {
		req.endHook()
	}
	deliverDone(req.done, nil)
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

// handleWriteMessage encodes headers+body+trailers and writes them, respecting
// peer's MaxHeaderListSize, MaxFrameSize, and stream/connection send windows.
//
// Frame ordering (RFC 9113 §8.1):
//   - HEADERS (END_STREAM iff no body and no trailers)
//   - DATA*   (END_STREAM on the last frame iff no trailers)
//   - HEADERS (trailers; END_STREAM always set when trailers are present)
func (l *Layer) handleWriteMessage(req *writeMessage) {
	peer := l.conn.PeerSettings()
	if err := l.preparePeerWriteSettings(peer, req.headers, req.trailers); err != nil {
		deliverDone(req.done, err)
		return
	}
	maxFrameSize := l.frameWriter.MaxFrameSize()

	hasBody := len(req.body) > 0 || req.bodyReader != nil
	hasTrailers := len(req.trailers) > 0
	// END_STREAM goes on the last frame emitted — trailers if any, else the
	// last DATA, else the initial HEADERS.
	headersEndStream := req.endStream && !hasBody && !hasTrailers

	encoded := l.encoder.Encode(req.headers)
	if err := l.writeHeaderBlock(req.streamID, encoded, headersEndStream, maxFrameSize); err != nil {
		deliverDone(req.done, err)
		return
	}

	if hasBody {
		if err := l.writeBodyForMessage(req, hasTrailers); err != nil {
			deliverDone(req.done, err)
			return
		}
	}

	if hasTrailers {
		trailerBlock := l.encoder.Encode(req.trailers)
		if err := l.writeHeaderBlock(req.streamID, trailerBlock, req.endStream, maxFrameSize); err != nil {
			deliverDone(req.done, err)
			return
		}
	}

	if req.endHook != nil {
		req.endHook()
	}
	deliverDone(req.done, nil)
}

// preparePeerWriteSettings validates header/trailer sizes against the peer's
// SETTINGS_MAX_HEADER_LIST_SIZE and updates the encoder/frame writer state for
// the peer's HEADER_TABLE_SIZE and MAX_FRAME_SIZE.
func (l *Layer) preparePeerWriteSettings(peer Settings, headers, trailers []hpack.HeaderField) error {
	if peer.MaxHeaderListSize > 0 {
		if err := checkHeaderListSize(headers, peer.MaxHeaderListSize); err != nil {
			return err
		}
		if err := checkHeaderListSize(trailers, peer.MaxHeaderListSize); err != nil {
			return err
		}
	}
	if l.encoderTableSize != peer.HeaderTableSize {
		l.encoder.SetMaxTableSize(peer.HeaderTableSize)
		l.encoderTableSize = peer.HeaderTableSize
	}
	if peer.MaxFrameSize >= frame.DefaultMaxFrameSize && peer.MaxFrameSize <= frame.MaxAllowedFrameSize {
		_ = l.frameWriter.SetMaxFrameSize(peer.MaxFrameSize)
	}
	return nil
}

// writeBodyForMessage writes the body portion of req. When hasTrailers is true,
// END_STREAM is suppressed on the body's final DATA frame so the trailer
// HEADERS frame can carry it instead (RFC 9113 §8.1).
//
// Invariant: bodyReq is a shallow copy of *req. bodyReq.done shares the
// underlying channel with req.done, so this helper MUST NOT call deliverDone
// on bodyReq.done — only the top-level handleWriteMessage signals completion.
// Returning the error up to the caller preserves the single-signaller
// invariant; adding a deliverDone here would fire req.done prematurely and
// leak the caller goroutine awaiting the real completion signal.
func (l *Layer) writeBodyForMessage(req *writeMessage, hasTrailers bool) error {
	bodyReq := *req
	if hasTrailers {
		bodyReq.endStream = false
	}
	return l.writeMessageBody(&bodyReq)
}

// checkHeaderListSize returns an error when the cumulative Size() of fields
// exceeds limit. Used to enforce the peer's SETTINGS_MAX_HEADER_LIST_SIZE for
// both the initial header block and the trailer block (RFC 9113 §6.5.2).
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
// CONTINUATION frames according to maxFrameSize, then writes them.
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

// writeMessageBody writes DATA frames for the body, respecting flow control
// and MAX_FRAME_SIZE. Blocks on l.windowUpdated when a window is exhausted.
func (l *Layer) writeMessageBody(req *writeMessage) error {
	maxFrameSize := int(l.frameWriter.MaxFrameSize())
	if maxFrameSize == 0 {
		maxFrameSize = int(frame.DefaultMaxFrameSize)
	}
	if req.body != nil {
		return l.writeBufferedBody(req, maxFrameSize)
	}
	return l.writeStreamingBody(req, maxFrameSize)
}

// writeBufferedBody serializes a fully-buffered body in maxFrameSize chunks.
func (l *Layer) writeBufferedBody(req *writeMessage, maxFrameSize int) error {
	body := req.body
	for len(body) > 0 {
		n, err := l.waitForWindow(req.streamID, len(body), maxFrameSize)
		if err != nil {
			return err
		}
		chunk := body[:n]
		body = body[n:]
		endStream := req.endStream && len(body) == 0
		if err := l.frameWriter.WriteData(req.streamID, endStream, chunk); err != nil {
			return err
		}
	}
	if req.endStream && len(req.body) == 0 {
		if err := l.frameWriter.WriteData(req.streamID, true, nil); err != nil {
			return err
		}
	}
	return nil
}

// writeStreamingBody serializes a streaming body until EOF in maxFrameSize chunks.
func (l *Layer) writeStreamingBody(req *writeMessage, maxFrameSize int) error {
	buf := make([]byte, maxFrameSize)
	for {
		n, readErr := io.ReadFull(req.bodyReader, buf)
		eof := readErr == io.EOF || readErr == io.ErrUnexpectedEOF
		if !eof && readErr != nil {
			return fmt.Errorf("http2: read body stream: %w", readErr)
		}
		if err := l.writeStreamingChunk(req, buf, n, eof, maxFrameSize); err != nil {
			return err
		}
		if eof {
			return nil
		}
	}
}

// writeStreamingChunk writes one slice of streaming body bytes, respecting
// flow control. n=0 with eof+endStream emits a single empty END_STREAM DATA.
func (l *Layer) writeStreamingChunk(req *writeMessage, buf []byte, n int, eof bool, maxFrameSize int) error {
	if n == 0 {
		if eof && req.endStream {
			return l.frameWriter.WriteData(req.streamID, true, nil)
		}
		return nil
	}
	toWrite := n
	off := 0
	for toWrite > 0 {
		avail, err := l.waitForWindow(req.streamID, toWrite, maxFrameSize)
		if err != nil {
			return err
		}
		chunk := buf[off : off+avail]
		off += avail
		toWrite -= avail
		endStream := req.endStream && eof && toWrite == 0
		if err := l.frameWriter.WriteData(req.streamID, endStream, chunk); err != nil {
			return err
		}
	}
	return nil
}

// waitForWindow blocks until the smaller of {stream send window, conn send
// window, requested, maxFrameSize} is positive, then consumes that many bytes
// from both windows and returns the consumed amount.
//
// Slow-peer / shutdown invariant: <-l.shutdown is the ONLY escape when a peer
// withholds WINDOW_UPDATE. Per-request context is intentionally not observed
// here — request-level deadlines do not apply to body streaming, because the
// writer goroutine is owned by the Layer's lifecycle, not by any individual
// request. A malicious or slow peer that never emits WINDOW_UPDATE parks the
// writer in the select below until Layer.Close cascades shutdown. This is
// acceptable because the Layer's close path bounds total waiting time; it is
// the operator's responsibility to tear down the Layer on abuse.
func (l *Layer) waitForWindow(streamID uint32, requested, maxFrameSize int) (int, error) {
	for {
		// Check shutdown first.
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
				// Restore stream window on conn-level failure.
				_ = l.conn.Streams().IncrementSendWindow(streamID, uint32(avail))
				return 0, err
			}
			return avail, nil
		}

		// Block until WINDOW_UPDATE arrives or shutdown.
		select {
		case <-l.windowUpdated:
		case <-l.shutdown:
			return 0, errWriterClosed
		}
	}
}

// deliverDone sends err on done if non-nil. Done channels are buffered (cap 1)
// so this never blocks.
func deliverDone(done chan error, err error) {
	if done == nil {
		return
	}
	select {
	case done <- err:
	default:
	}
}

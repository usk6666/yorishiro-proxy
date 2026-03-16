package http2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// clientMagic is the HTTP/2 connection preface that clients must send.
// Per RFC 9113 Section 3.4.
const clientMagic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// streamRequest holds the accumulated state for building an HTTP/2 request
// from received frames. Accessed only by the main read loop (single-goroutine).
type streamRequest struct {
	// headerFragments accumulates the header block across HEADERS + CONTINUATION frames.
	headerFragments []byte
	// endStream indicates whether END_STREAM was set on the HEADERS frame.
	headersEndStream bool
	// bodyBuf accumulates DATA frame payloads.
	bodyBuf bytes.Buffer
	// rawFrames stores raw bytes of all received frames for L4 recording.
	rawFrames [][]byte
}

// clientConn manages the lifecycle of a single HTTP/2 client connection
// using the custom frame engine. It replaces http2.Server.ServeConn().
type clientConn struct {
	conn   net.Conn
	ctx    context.Context
	cancel context.CancelFunc
	logger *slog.Logger

	h2conn  *Conn
	reader  *frame.Reader
	writer  *frame.Writer
	writeMu sync.Mutex // protects writer for concurrent response writes

	decoder *hpack.Decoder
	encoder *hpack.Encoder

	// pendingStreams maps stream ID -> in-progress request being assembled.
	// Accessed only from the main read loop goroutine.
	pendingStreams map[uint32]*streamRequest

	// headerStreamID tracks the stream ID currently receiving a header block
	// (HEADERS followed by CONTINUATION). Zero means no header block in progress.
	// Per RFC 9113 Section 6.2, only one header block can be in progress at a time.
	headerStreamID uint32

	// active tracks in-flight handler goroutines.
	active atomic.Int64
	mu     sync.Mutex
	cond   *sync.Cond

	// decodedHeaders stores decoded HPACK headers for streams that have received
	// HEADERS but not yet END_STREAM (waiting for DATA frames).
	// Accessed only from the main read loop goroutine.
	decodedHeaders map[uint32][]hpack.HeaderField

	// streamHandler is called for each completed request.
	streamHandler func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request)
}

// newClientConn creates a new clientConn from a raw net.Conn.
func newClientConn(
	ctx context.Context,
	conn net.Conn,
	logger *slog.Logger,
	handler func(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request),
) *clientConn {
	ctx, cancel := context.WithCancel(ctx)
	cc := &clientConn{
		conn:           conn,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		h2conn:         NewConn(),
		reader:         frame.NewReader(conn),
		writer:         frame.NewWriter(conn),
		decoder:        hpack.NewDecoder(defaultHeaderTableSize),
		encoder:        hpack.NewEncoder(defaultHeaderTableSize, true),
		pendingStreams: make(map[uint32]*streamRequest),
		streamHandler:  handler,
	}
	cc.cond = sync.NewCond(&cc.mu)
	return cc
}

// serve runs the HTTP/2 server-side connection handling.
// It reads the client preface, exchanges SETTINGS, and then enters the
// main frame read loop. It blocks until the connection is closed or an error
// occurs, then waits for all in-flight handlers to finish.
func (cc *clientConn) serve() error {
	if err := cc.readClientPreface(); err != nil {
		return fmt.Errorf("client preface: %w", err)
	}

	if err := cc.sendServerPreface(); err != nil {
		return fmt.Errorf("server preface: %w", err)
	}

	// Read the client's initial SETTINGS (non-ACK).
	if err := cc.readClientSettings(); err != nil {
		return fmt.Errorf("client settings: %w", err)
	}

	if err := cc.runFrameLoop(); err != nil {
		cc.logger.Debug("frame loop ended", "error", err)
	}

	// Wait for all in-flight handlers to complete.
	cc.mu.Lock()
	for cc.active.Load() > 0 {
		cc.cond.Wait()
	}
	cc.mu.Unlock()

	return nil
}

// readClientPreface reads and validates the HTTP/2 connection preface.
func (cc *clientConn) readClientPreface() error {
	buf := make([]byte, len(clientMagic))
	if _, err := io.ReadFull(cc.conn, buf); err != nil {
		return fmt.Errorf("read connection preface: %w", err)
	}
	if string(buf) != clientMagic {
		return fmt.Errorf("invalid connection preface")
	}
	return nil
}

// sendServerPreface sends the server's SETTINGS frame as the connection preface.
func (cc *clientConn) sendServerPreface() error {
	localSettings := cc.h2conn.LocalSettings()
	settings := []frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: localSettings.MaxConcurrentStreams},
		{ID: frame.SettingInitialWindowSize, Value: localSettings.InitialWindowSize},
		{ID: frame.SettingMaxFrameSize, Value: localSettings.MaxFrameSize},
	}
	cc.writeMu.Lock()
	defer cc.writeMu.Unlock()
	return cc.writer.WriteSettings(settings)
}

// readClientSettings reads the client's initial SETTINGS frame (non-ACK).
func (cc *clientConn) readClientSettings() error {
	f, err := cc.reader.ReadFrame()
	if err != nil {
		return fmt.Errorf("read initial SETTINGS: %w", err)
	}
	if f.Header.Type != frame.TypeSettings || f.Header.Flags.Has(frame.FlagAck) {
		return fmt.Errorf("expected SETTINGS frame, got %s (flags=0x%02x)", f.Header.Type, f.Header.Flags)
	}
	if _, err := cc.h2conn.HandleSettings(f); err != nil {
		return fmt.Errorf("apply client settings: %w", err)
	}
	// Peer's MAX_FRAME_SIZE is the maximum frame size the peer can receive,
	// so it limits what we can send (Writer). Our own MAX_FRAME_SIZE (local
	// settings) limits what we accept (Reader), and defaults to 16384.
	peerSettings := cc.h2conn.PeerSettings()
	if peerSettings.MaxFrameSize > frame.DefaultMaxFrameSize {
		if err := cc.writer.SetMaxFrameSize(peerSettings.MaxFrameSize); err != nil {
			cc.logger.Warn("failed to set writer max frame size", "error", err)
		}
	}
	// Send SETTINGS ACK.
	cc.writeMu.Lock()
	defer cc.writeMu.Unlock()
	return cc.writer.WriteSettingsAck()
}

// runFrameLoop is the main frame processing loop.
func (cc *clientConn) runFrameLoop() error {
	for {
		select {
		case <-cc.ctx.Done():
			return cc.ctx.Err()
		default:
		}

		f, err := cc.reader.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			if isConnectionClosed(err) {
				return nil
			}
			return fmt.Errorf("read frame: %w", err)
		}

		if err := cc.processFrame(f); err != nil {
			var connErr *ConnError
			if errors.As(err, &connErr) {
				cc.sendGoAway(connErr.Code, connErr.Reason)
				return err
			}
			var streamErr *StreamError
			if errors.As(err, &streamErr) {
				cc.sendRSTStream(streamErr.StreamID, streamErr.Code)
				continue
			}
			return err
		}
	}
}

// processFrame dispatches a single frame to the appropriate handler.
func (cc *clientConn) processFrame(f *frame.Frame) error {
	// If we are in the middle of a header block, only CONTINUATION on the
	// same stream is allowed. Per RFC 9113 Section 6.2.
	if cc.headerStreamID != 0 && f.Header.Type != frame.TypeContinuation {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("expected CONTINUATION for stream %d, got %s", cc.headerStreamID, f.Header.Type),
		}
	}

	switch f.Header.Type {
	case frame.TypeSettings:
		return cc.handleSettingsFrame(f)
	case frame.TypeHeaders:
		return cc.handleHeadersFrame(f)
	case frame.TypeContinuation:
		return cc.handleContinuationFrame(f)
	case frame.TypeData:
		return cc.handleDataFrame(f)
	case frame.TypePing:
		return cc.handlePingFrame(f)
	case frame.TypeGoAway:
		return cc.handleGoAwayFrame(f)
	case frame.TypeWindowUpdate:
		return cc.handleWindowUpdateFrame(f)
	case frame.TypeRSTStream:
		return cc.handleRSTStreamFrame(f)
	case frame.TypePriority:
		// PRIORITY frames are advisory; ignore them per RFC 9113 Section 6.3.
		return nil
	default:
		// Unknown frame types MUST be ignored per RFC 9113 Section 4.1.
		return nil
	}
}

// handleSettingsFrame processes a SETTINGS frame.
func (cc *clientConn) handleSettingsFrame(f *frame.Frame) error {
	_, err := cc.h2conn.HandleSettings(f)
	if err != nil {
		return err
	}
	// If it was a SETTINGS ACK, no response needed.
	if f.Header.Flags.Has(frame.FlagAck) {
		return nil
	}
	// Send SETTINGS ACK.
	cc.writeMu.Lock()
	defer cc.writeMu.Unlock()
	return cc.writer.WriteSettingsAck()
}

// handleHeadersFrame processes a HEADERS frame, beginning or completing a
// header block for a new stream.
func (cc *clientConn) handleHeadersFrame(f *frame.Frame) error {
	streamID := f.Header.StreamID
	if streamID == 0 {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: "HEADERS frame with stream ID 0",
		}
	}
	// Client-initiated streams must be odd per RFC 9113 Section 5.1.1.
	if streamID%2 == 0 {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("client stream ID %d is even", streamID),
		}
	}

	// Validate stream ID ordering: client streams must be ascending.
	lastPeer := cc.h2conn.Streams().LastPeerStreamID()
	if streamID <= lastPeer {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("stream ID %d not greater than previous %d", streamID, lastPeer),
		}
	}
	cc.h2conn.Streams().SetLastPeerStreamID(streamID)

	// Check concurrent stream limit.
	peerSettings := cc.h2conn.LocalSettings()
	if uint32(cc.h2conn.Streams().ActiveCount()) >= peerSettings.MaxConcurrentStreams {
		return &StreamError{
			StreamID: streamID,
			Code:     ErrCodeRefusedStream,
			Reason:   "max concurrent streams exceeded",
		}
	}

	// Transition stream state: idle -> open.
	if err := cc.h2conn.Streams().Transition(streamID, EventRecvHeaders); err != nil {
		return err
	}

	fragment, err := f.HeaderBlockFragment()
	if err != nil {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("HEADERS fragment: %v", err),
		}
	}

	sr := &streamRequest{
		headersEndStream: f.Header.Flags.Has(frame.FlagEndStream),
		rawFrames:        [][]byte{f.RawBytes},
	}
	sr.headerFragments = append(sr.headerFragments, fragment...)
	cc.pendingStreams[streamID] = sr

	if f.Header.Flags.Has(frame.FlagEndHeaders) {
		return cc.completeHeaders(streamID)
	}
	// More CONTINUATION frames expected.
	cc.headerStreamID = streamID
	return nil
}

// handleContinuationFrame processes a CONTINUATION frame, appending to the
// current header block.
func (cc *clientConn) handleContinuationFrame(f *frame.Frame) error {
	if cc.headerStreamID == 0 {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: "unexpected CONTINUATION frame",
		}
	}
	if f.Header.StreamID != cc.headerStreamID {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("CONTINUATION for stream %d, expected %d", f.Header.StreamID, cc.headerStreamID),
		}
	}

	sr := cc.pendingStreams[cc.headerStreamID]
	if sr == nil {
		// Stream was reset during header block assembly.
		cc.headerStreamID = 0
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("CONTINUATION for reset stream %d", cc.headerStreamID),
		}
	}
	fragment, err := f.ContinuationFragment()
	if err != nil {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("CONTINUATION fragment: %v", err),
		}
	}
	sr.headerFragments = append(sr.headerFragments, fragment...)
	sr.rawFrames = append(sr.rawFrames, f.RawBytes)

	if f.Header.Flags.Has(frame.FlagEndHeaders) {
		cc.headerStreamID = 0
		return cc.completeHeaders(f.Header.StreamID)
	}
	return nil
}

// completeHeaders decodes the accumulated header block and, if the request
// is complete (END_STREAM was set on HEADERS), dispatches it.
func (cc *clientConn) completeHeaders(streamID uint32) error {
	sr := cc.pendingStreams[streamID]
	headers, err := cc.decoder.Decode(sr.headerFragments)
	if err != nil {
		return &ConnError{
			Code:   ErrCodeCompression,
			Reason: fmt.Sprintf("HPACK decode: %v", err),
		}
	}
	sr.headerFragments = nil // free memory

	// Store decoded headers back into streamRequest for later use.
	// We will build the http.Request when the stream is complete.
	// For now, we just need to check if we can dispatch immediately.
	if sr.headersEndStream {
		// Transition: open -> half-closed (remote) — client is done sending.
		if err := cc.h2conn.Streams().Transition(streamID, EventRecvEndStream); err != nil {
			return err
		}
		return cc.dispatchStream(streamID, headers, nil)
	}
	// Store headers for when we get DATA frames and eventually END_STREAM.
	// We store a temporary marker so we know headers are decoded.
	sr.headerFragments = nil // already decoded
	// We need to keep the decoded headers somewhere — re-encode to HPACK is wasteful.
	// Instead, store them as a serialized form in the streamRequest.
	cc.storeDecodedHeaders(streamID, headers)
	return nil
}

// storeDecodedHeaders stores decoded HPACK headers on the clientConn for
// later retrieval when the stream completes via DATA + END_STREAM.
func (cc *clientConn) storeDecodedHeaders(streamID uint32, headers []hpack.HeaderField) {
	if cc.decodedHeaders == nil {
		cc.decodedHeaders = make(map[uint32][]hpack.HeaderField)
	}
	cc.decodedHeaders[streamID] = headers
}

// handleDataFrame processes a DATA frame, accumulating the body and updating
// flow control.
func (cc *clientConn) handleDataFrame(f *frame.Frame) error {
	streamID := f.Header.StreamID
	if streamID == 0 {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: "DATA frame with stream ID 0",
		}
	}

	sr := cc.pendingStreams[streamID]
	if sr == nil {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("DATA frame for unknown stream %d", streamID),
		}
	}

	data, err := f.DataPayload()
	if err != nil {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("DATA payload: %v", err),
		}
	}

	// Flow control: consume receive window.
	payloadLen := int32(f.Header.Length)
	if payloadLen > 0 {
		if err := cc.h2conn.ConsumeRecvWindow(payloadLen); err != nil {
			return err
		}
		if err := cc.h2conn.Streams().ConsumeRecvWindow(streamID, payloadLen); err != nil {
			return err
		}
		// Send WINDOW_UPDATE to replenish connection and stream windows.
		cc.writeMu.Lock()
		if wErr := cc.writer.WriteWindowUpdate(0, uint32(payloadLen)); wErr != nil {
			cc.writeMu.Unlock()
			return fmt.Errorf("write connection WINDOW_UPDATE: %w", wErr)
		}
		if wErr := cc.writer.WriteWindowUpdate(streamID, uint32(payloadLen)); wErr != nil {
			cc.writeMu.Unlock()
			return fmt.Errorf("write stream WINDOW_UPDATE: %w", wErr)
		}
		cc.writeMu.Unlock()
		// Replenish local tracking.
		if err := cc.h2conn.IncrementRecvWindow(uint32(payloadLen)); err != nil {
			return err
		}
		if err := cc.h2conn.Streams().IncrementRecvWindow(streamID, uint32(payloadLen)); err != nil {
			return err
		}
	}

	sr.bodyBuf.Write(data)
	sr.rawFrames = append(sr.rawFrames, f.RawBytes)

	if f.Header.Flags.Has(frame.FlagEndStream) {
		// Transition: open -> half-closed (remote).
		if err := cc.h2conn.Streams().Transition(streamID, EventRecvEndStream); err != nil {
			return err
		}
		headers := cc.decodedHeaders[streamID]
		delete(cc.decodedHeaders, streamID)
		return cc.dispatchStream(streamID, headers, sr.bodyBuf.Bytes())
	}
	return nil
}

// handlePingFrame processes a PING frame.
func (cc *clientConn) handlePingFrame(f *frame.Frame) error {
	needsAck, data, err := cc.h2conn.HandlePing(f)
	if err != nil {
		return err
	}
	if needsAck {
		cc.writeMu.Lock()
		defer cc.writeMu.Unlock()
		return cc.writer.WritePing(true, data)
	}
	return nil
}

// handleGoAwayFrame processes a GOAWAY frame from the client.
func (cc *clientConn) handleGoAwayFrame(f *frame.Frame) error {
	lastStreamID, errCode, _, err := cc.h2conn.HandleGoAway(f)
	if err != nil {
		return err
	}
	cc.logger.Debug("received GOAWAY from client",
		"last_stream_id", lastStreamID,
		"error_code", ErrCodeString(errCode))
	// Cancel the context to stop accepting new streams.
	cc.cancel()
	return nil
}

// handleWindowUpdateFrame processes a WINDOW_UPDATE frame.
func (cc *clientConn) handleWindowUpdateFrame(f *frame.Frame) error {
	return cc.h2conn.HandleWindowUpdate(f)
}

// handleRSTStreamFrame processes a RST_STREAM frame.
func (cc *clientConn) handleRSTStreamFrame(f *frame.Frame) error {
	errCode, err := cc.h2conn.HandleRSTStream(f)
	if err != nil {
		return err
	}
	streamID := f.Header.StreamID
	// Clean up pending stream state.
	delete(cc.pendingStreams, streamID)
	if cc.decodedHeaders != nil {
		delete(cc.decodedHeaders, streamID)
	}
	// If we were in the middle of a header block for this stream, clear it.
	if cc.headerStreamID == streamID {
		cc.headerStreamID = 0
	}
	cc.logger.Debug("received RST_STREAM",
		"stream_id", streamID,
		"error_code", ErrCodeString(errCode))
	return nil
}

// dispatchStream builds an http.Request from the decoded headers and body,
// then invokes the stream handler in a new goroutine.
func (cc *clientConn) dispatchStream(streamID uint32, headers []hpack.HeaderField, body []byte) error {
	req, err := buildHTTPRequest(cc.ctx, headers, body)
	if err != nil {
		return &StreamError{
			StreamID: streamID,
			Code:     ErrCodeProtocol,
			Reason:   fmt.Sprintf("build request: %v", err),
		}
	}

	rw := newFrameResponseWriter(cc, streamID)

	// Clean up pending state before dispatching.
	delete(cc.pendingStreams, streamID)
	if cc.decodedHeaders != nil {
		delete(cc.decodedHeaders, streamID)
	}

	cc.active.Add(1)
	go func() {
		defer func() {
			rw.finish()
			if cc.active.Add(-1) == 0 {
				cc.cond.Signal()
			}
		}()
		cc.streamHandler(cc.ctx, rw, req)
	}()

	return nil
}

// sendGoAway sends a GOAWAY frame and cancels the connection.
func (cc *clientConn) sendGoAway(errCode uint32, reason string) {
	lastStreamID := cc.h2conn.Streams().LastPeerStreamID()
	cc.writeMu.Lock()
	cc.writer.WriteGoAway(lastStreamID, errCode, []byte(reason))
	cc.writeMu.Unlock()
	cc.h2conn.MarkGoAwaySent(lastStreamID)
	cc.cancel()
}

// sendRSTStream sends a RST_STREAM frame for the given stream.
func (cc *clientConn) sendRSTStream(streamID, errCode uint32) {
	cc.writeMu.Lock()
	cc.writer.WriteRSTStream(streamID, errCode)
	cc.writeMu.Unlock()
	cc.h2conn.Streams().Transition(streamID, EventSendRST)
}

// buildHTTPRequest constructs a *http.Request from decoded HPACK header fields
// and an optional body. It extracts pseudo-headers (:method, :scheme, :authority,
// :path) per RFC 9113 Section 8.3.1.
func buildHTTPRequest(ctx context.Context, headers []hpack.HeaderField, body []byte) (*gohttp.Request, error) {
	var method, scheme, authority, path string
	httpHeaders := make(gohttp.Header)

	for _, hf := range headers {
		if strings.HasPrefix(hf.Name, ":") {
			switch hf.Name {
			case ":method":
				method = hf.Value
			case ":scheme":
				scheme = hf.Value
			case ":authority":
				authority = hf.Value
			case ":path":
				path = hf.Value
			}
		} else {
			httpHeaders.Add(hf.Name, hf.Value)
		}
	}

	if method == "" {
		return nil, fmt.Errorf("missing :method pseudo-header")
	}
	if path == "" && method != "CONNECT" {
		return nil, fmt.Errorf("missing :path pseudo-header")
	}

	if scheme == "" {
		scheme = "http"
	}

	host := authority
	if host == "" {
		host = httpHeaders.Get("Host")
	}

	reqURL := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: "", // will be parsed from path
	}
	// path may contain query string.
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		reqURL.Path = path[:idx]
		reqURL.RawQuery = path[idx+1:]
	}

	var bodyReader io.ReadCloser
	if len(body) > 0 {
		bodyReader = io.NopCloser(bytes.NewReader(body))
	} else {
		bodyReader = gohttp.NoBody
	}

	req := &gohttp.Request{
		Method:     method,
		URL:        reqURL,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     httpHeaders,
		Body:       bodyReader,
		Host:       host,
		RequestURI: path,
	}
	req = req.WithContext(ctx)

	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	}

	return req, nil
}

// isConnectionClosed reports whether the error indicates a closed connection.
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer")
}

// frameResponseWriter implements http.ResponseWriter by writing HTTP/2 frames
// back to the client connection. Write() sends DATA frames immediately
// (chunked to peer's MaxFrameSize) to support gRPC streaming.
type frameResponseWriter struct {
	cc       *clientConn
	streamID uint32

	mu           sync.Mutex
	wroteHeader  bool
	headersSent  bool // true after HEADERS frame has been sent to the wire
	statusCode   int
	headers      gohttp.Header
	trailers     gohttp.Header
	bytesWritten int // total body bytes written via Write()
}

// newFrameResponseWriter creates a new frameResponseWriter for the given stream.
func newFrameResponseWriter(cc *clientConn, streamID uint32) *frameResponseWriter {
	return &frameResponseWriter{
		cc:       cc,
		streamID: streamID,
		headers:  make(gohttp.Header),
	}
}

// Header returns the header map that will be sent by WriteHeader.
func (rw *frameResponseWriter) Header() gohttp.Header {
	return rw.headers
}

// Write writes the data to the connection as part of an HTTP reply body.
// If WriteHeader has not yet been called, Write calls WriteHeader(200).
// Data is sent immediately as DATA frames chunked to peer's MaxFrameSize,
// which is required for gRPC streaming to work correctly.
func (rw *frameResponseWriter) Write(data []byte) (int, error) {
	rw.mu.Lock()
	if !rw.wroteHeader {
		rw.mu.Unlock()
		rw.WriteHeader(gohttp.StatusOK)
		rw.mu.Lock()
	}
	rw.mu.Unlock()

	// Ensure HEADERS frame has been sent before any DATA frames.
	if err := rw.ensureHeadersSent(); err != nil {
		return 0, err
	}

	return rw.writeDataChunked(data)
}

// WriteHeader sends an HTTP response header with the provided status code.
func (rw *frameResponseWriter) WriteHeader(statusCode int) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.wroteHeader {
		return
	}
	rw.wroteHeader = true
	rw.statusCode = statusCode
}

// Flush implements http.Flusher. It ensures the HEADERS frame has been sent.
func (rw *frameResponseWriter) Flush() {
	rw.mu.Lock()
	if !rw.wroteHeader {
		rw.mu.Unlock()
		rw.WriteHeader(gohttp.StatusOK)
	} else {
		rw.mu.Unlock()
	}
	rw.ensureHeadersSent()
}

// ensureHeadersSent sends the response HEADERS frame if not yet sent.
// This is called before the first DATA frame and on Flush().
func (rw *frameResponseWriter) ensureHeadersSent() error {
	rw.mu.Lock()
	if rw.headersSent {
		rw.mu.Unlock()
		return nil
	}
	rw.headersSent = true
	statusCode := rw.statusCode
	respHeaders := rw.headers.Clone()
	rw.mu.Unlock()

	var hpackFields []hpack.HeaderField
	hpackFields = append(hpackFields, hpack.HeaderField{
		Name:  ":status",
		Value: fmt.Sprintf("%d", statusCode),
	})
	for key, vals := range respHeaders {
		if strings.HasPrefix(key, gohttp.TrailerPrefix) {
			continue // trailer-prefixed headers are handled in finish()
		}
		for _, val := range vals {
			hpackFields = append(hpackFields, hpack.HeaderField{
				Name:  strings.ToLower(key),
				Value: val,
			})
		}
	}

	cc := rw.cc
	cc.writeMu.Lock()
	encoded := cc.encoder.Encode(hpackFields)
	err := cc.writer.WriteHeaders(rw.streamID, false, true, encoded)
	cc.writeMu.Unlock()
	if err != nil {
		cc.logger.Debug("failed to write response HEADERS", "stream_id", rw.streamID, "error", err)
	}
	return err
}

// writeDataChunked sends data as DATA frames, chunking to the peer's
// MaxFrameSize to comply with HTTP/2 frame size limits.
func (rw *frameResponseWriter) writeDataChunked(p []byte) (int, error) {
	cc := rw.cc
	maxSize := int(cc.h2conn.PeerSettings().MaxFrameSize)
	written := 0

	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxSize {
			chunk = p[:maxSize]
		}
		cc.writeMu.Lock()
		err := cc.writer.WriteData(rw.streamID, false, chunk)
		cc.writeMu.Unlock()
		if err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}

	rw.mu.Lock()
	rw.bytesWritten += written
	rw.mu.Unlock()

	return written, nil
}

// finish sends the end-of-stream marker after the handler returns.
// If HEADERS were already sent (via Write/Flush), it sends either an
// empty DATA(END_STREAM) or trailer HEADERS(END_STREAM). If HEADERS
// were never sent (no body written), it sends HEADERS(END_STREAM).
func (rw *frameResponseWriter) finish() {
	rw.mu.Lock()
	if !rw.wroteHeader {
		rw.statusCode = gohttp.StatusOK
		rw.wroteHeader = true
	}
	headersSent := rw.headersSent
	respHeaders := rw.headers.Clone()
	rw.mu.Unlock()

	// Collect trailers from the header map.
	rw.collectTrailers(respHeaders)
	hasTrailers := len(rw.trailers) > 0

	cc := rw.cc

	if !headersSent {
		// No Write() or Flush() was called — send HEADERS with END_STREAM.
		rw.finishWithHeaders(respHeaders, hasTrailers)
	} else if hasTrailers {
		// HEADERS already sent; send trailers as HEADERS(END_STREAM).
		rw.finishWithTrailers()
	} else {
		// HEADERS already sent, no trailers; send empty DATA(END_STREAM).
		cc.writeMu.Lock()
		if err := cc.writer.WriteData(rw.streamID, true, nil); err != nil {
			cc.writeMu.Unlock()
			cc.logger.Debug("failed to write end-stream DATA", "stream_id", rw.streamID, "error", err)
			return
		}
		cc.writeMu.Unlock()
	}

	// Transition stream state.
	cc.h2conn.Streams().Transition(rw.streamID, EventSendEndStream)
}

// collectTrailers extracts trailer headers from the response header map.
func (rw *frameResponseWriter) collectTrailers(respHeaders gohttp.Header) {
	trailerKeyStr := respHeaders.Get("Trailer")
	if trailerKeyStr != "" {
		respHeaders.Del("Trailer")
		rw.trailers = make(gohttp.Header)
		for _, key := range strings.Split(trailerKeyStr, ",") {
			key = strings.TrimSpace(key)
			if val := respHeaders.Get(gohttp.TrailerPrefix + key); val != "" {
				rw.trailers.Set(key, val)
				respHeaders.Del(gohttp.TrailerPrefix + key)
			}
		}
	}
	for key, vals := range respHeaders {
		if strings.HasPrefix(key, gohttp.TrailerPrefix) {
			realKey := strings.TrimPrefix(key, gohttp.TrailerPrefix)
			if rw.trailers == nil {
				rw.trailers = make(gohttp.Header)
			}
			for _, v := range vals {
				rw.trailers.Add(realKey, v)
			}
			respHeaders.Del(key)
		}
	}
}

// finishWithHeaders sends a single HEADERS frame (possibly with END_STREAM)
// when no body was written via Write().
func (rw *frameResponseWriter) finishWithHeaders(respHeaders gohttp.Header, hasTrailers bool) {
	var hpackFields []hpack.HeaderField
	hpackFields = append(hpackFields, hpack.HeaderField{
		Name:  ":status",
		Value: fmt.Sprintf("%d", rw.statusCode),
	})
	for key, vals := range respHeaders {
		if strings.HasPrefix(key, gohttp.TrailerPrefix) {
			continue
		}
		for _, val := range vals {
			hpackFields = append(hpackFields, hpack.HeaderField{
				Name:  strings.ToLower(key),
				Value: val,
			})
		}
	}

	cc := rw.cc
	cc.writeMu.Lock()
	encoded := cc.encoder.Encode(hpackFields)
	endStream := !hasTrailers
	if err := cc.writer.WriteHeaders(rw.streamID, endStream, true, encoded); err != nil {
		cc.writeMu.Unlock()
		cc.logger.Debug("failed to write response HEADERS", "stream_id", rw.streamID, "error", err)
		return
	}
	cc.writeMu.Unlock()

	if hasTrailers {
		rw.finishWithTrailers()
	}
}

// finishWithTrailers sends trailers as a HEADERS frame with END_STREAM.
func (rw *frameResponseWriter) finishWithTrailers() {
	var trailerFields []hpack.HeaderField
	for key, vals := range rw.trailers {
		for _, val := range vals {
			trailerFields = append(trailerFields, hpack.HeaderField{
				Name:  strings.ToLower(key),
				Value: val,
			})
		}
	}

	cc := rw.cc
	cc.writeMu.Lock()
	trailerEncoded := cc.encoder.Encode(trailerFields)
	if err := cc.writer.WriteHeaders(rw.streamID, true, true, trailerEncoded); err != nil {
		cc.writeMu.Unlock()
		cc.logger.Debug("failed to write response trailers", "stream_id", rw.streamID, "error", err)
		return
	}
	cc.writeMu.Unlock()
}

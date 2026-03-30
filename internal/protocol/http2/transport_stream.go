package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// StreamOptions configures streaming behavior for RoundTripStream.
type StreamOptions struct {
	// OnSendFrame is called once per logical frame sent to the upstream server.
	// For HEADERS frames, it is invoked with a single reconstructed frame
	// (END_HEADERS=true, full header block) regardless of whether the actual
	// wire encoding was split into HEADERS + CONTINUATION frames. For DATA
	// frames, it is invoked per wire frame.
	// The frameBytes contain the complete raw frame (header + payload).
	// The callback must not retain the slice after returning.
	OnSendFrame func(frameBytes []byte)

	// OnRecvFrame is called for each frame received from the upstream server.
	// The frameBytes contain the complete raw frame (header + payload).
	// The callback must not retain the slice after returning.
	OnRecvFrame func(frameBytes []byte)
}

// StreamRoundTripResult holds the result of a streaming HTTP/2 round trip.
// The caller must read Body to completion before calling Trailers().
type StreamRoundTripResult struct {
	// StatusCode is the HTTP status code from the :status pseudo-header.
	StatusCode int
	// Headers contains the decoded response HPACK header fields (including
	// pseudo-headers).
	Headers []hpack.HeaderField
	// Body is a reader over the response DATA frame payloads. The caller
	// must read Body to completion (until io.EOF) to ensure trailers are
	// available and resources are released.
	Body io.ReadCloser
	// ServerAddr is the remote address of the upstream server.
	ServerAddr string

	// bodyDone indicates the Body reader has reached EOF.
	bodyDone bool
	// trailers are populated after the response body has been fully received
	// (END_STREAM on a trailing HEADERS frame or on the last DATA frame).
	trailers []hpack.HeaderField
	// trailersMu protects concurrent access to bodyDone and trailers.
	trailersMu sync.Mutex
}

// ErrBodyNotFullyRead is returned by Trailers() when the response body has
// not yet been read to completion.
var ErrBodyNotFullyRead = errors.New("trailers not available: body not fully read")

// Trailers returns the trailing header fields from the response.
// It returns ErrBodyNotFullyRead if Body has not been read to EOF.
func (r *StreamRoundTripResult) Trailers() ([]hpack.HeaderField, error) {
	r.trailersMu.Lock()
	defer r.trailersMu.Unlock()
	if !r.bodyDone {
		return nil, ErrBodyNotFullyRead
	}
	return r.trailers, nil
}

// markBodyDone marks the body as fully consumed and stores trailers.
func (r *StreamRoundTripResult) markBodyDone(trailers []hpack.HeaderField) {
	r.trailersMu.Lock()
	defer r.trailersMu.Unlock()
	r.bodyDone = true
	r.trailers = trailers
}

// RoundTripStream performs a streaming HTTP/2 round trip on a pre-established
// connection. Unlike RoundTripOnConn, it does not buffer the request body or
// response body in memory; instead, the request body is streamed as DATA frames
// and the response body is returned as a streaming io.ReadCloser.
//
// The connection must already have negotiated "h2" via ALPN. This method handles
// the HTTP/2 handshake (connection preface + settings exchange), sends the
// request headers and streams the body as HTTP/2 frames.
//
// The headers parameter must include HTTP/2 pseudo-headers (:method, :scheme,
// :authority, :path) and any regular headers. The body parameter may be nil
// for requests with no body.
//
// RoundTripStream takes ownership of conn and manages its lifecycle. The caller
// MUST call Body.Close() on the returned StreamRoundTripResult to release the
// underlying connection resources, even after reading the body to EOF. This
// follows the same contract as net/http.Response.Body.
func (t *Transport) RoundTripStream(ctx context.Context, conn net.Conn, headers []hpack.HeaderField, body io.Reader, opts StreamOptions) (*StreamRoundTripResult, error) {
	logger := t.logger()

	tc := newTransportConn(conn, logger)

	if err := tc.handshake(ctx); err != nil {
		tc.close()
		return nil, fmt.Errorf("h2 handshake: %w", err)
	}

	result, err := tc.roundTripStream(ctx, headers, body, opts)
	if err != nil {
		tc.close()
		return nil, fmt.Errorf("h2 stream round trip: %w", err)
	}

	// Wrap the body to close the transport connection when done reading.
	result.Body = &streamBodyCloser{
		ReadCloser: result.Body,
		tc:         tc,
	}

	return result, nil
}

// streamBodyCloser wraps the response body and closes the transport connection
// when the body is closed.
type streamBodyCloser struct {
	io.ReadCloser
	tc        *transportConn
	closeOnce sync.Once
}

func (s *streamBodyCloser) Close() error {
	err := s.ReadCloser.Close()
	s.closeOnce.Do(func() {
		s.tc.close()
	})
	return err
}

// closeIfCloser closes r if it implements io.Closer. This is used to unblock
// a sender goroutine that may be blocked in body.Read when the context is
// cancelled.
func closeIfCloser(r io.Reader) {
	if r == nil {
		return
	}
	if c, ok := r.(io.Closer); ok {
		_ = c.Close()
	}
}

// streamingStreamState extends the stream state for streaming round trips.
// It uses an io.Pipe to stream response DATA frame payloads to the caller
// instead of buffering them in memory.
type streamingStreamState struct {
	// headersDone is closed when the initial response HEADERS have been received.
	headersDone chan struct{}
	// headers collects decoded response header fields.
	headers []hpack.HeaderField
	// headerBuf accumulates HEADERS/CONTINUATION fragments before END_HEADERS.
	headerBuf []byte

	// bodyWriter is the write end of the response body pipe.
	bodyWriter *io.PipeWriter
	// bodyReader is the read end of the response body pipe.
	bodyReader *io.PipeReader

	// dataCh decouples the read loop from pipe writes. The read loop sends
	// copied DATA payloads (or nil to signal EOF) to this channel, and a
	// dedicated writer goroutine drains it into bodyWriter. This prevents
	// the read loop from blocking on slow application reads.
	dataCh chan []byte

	// abortCh is closed once to signal teardown of the streaming stream.
	// All senders into dataCh and the writer goroutine select on this channel
	// to avoid send-on-closed-channel and double-close panics.
	abortCh   chan struct{}
	abortOnce sync.Once

	// trailers collects decoded trailer header fields.
	trailers []hpack.HeaderField
	// done is sent when the stream has fully completed (END_STREAM received).
	done chan streamResult
	// endStream indicates END_STREAM has been received.
	endStream bool

	// result holds the StreamRoundTripResult for trailer population.
	result *StreamRoundTripResult

	// onRecvFrame callback for frame recording.
	onRecvFrame func(frameBytes []byte)
}

// abort performs idempotent cleanup of the streaming stream state.
// It signals all goroutines to stop (via abortCh) and closes the pipe writer
// with the given error. Safe to call from multiple goroutines concurrently.
func (sss *streamingStreamState) abort(err error) {
	sss.abortOnce.Do(func() {
		if err != nil {
			sss.bodyWriter.CloseWithError(err)
		} else {
			sss.bodyWriter.Close()
		}
		close(sss.abortCh)
	})
}

// writerLoop drains dataCh into the pipe writer. It exits when abortCh is
// closed. On exit it drains any remaining buffered payloads from dataCh to
// ensure data sent before abort is written to the pipe.
func (sss *streamingStreamState) writerLoop() {
	for {
		select {
		case payload := <-sss.dataCh:
			if payload == nil {
				// nil sentinel signals normal end-of-stream.
				sss.abort(nil)
				return
			}
			if _, err := sss.bodyWriter.Write(payload); err != nil {
				return
			}
		case <-sss.abortCh:
			// Drain any remaining buffered payloads before exiting.
			sss.drainDataCh()
			return
		}
	}
}

// drainDataCh writes any remaining buffered payloads from dataCh to the pipe.
// Called on abort to ensure data already enqueued is not lost.
func (sss *streamingStreamState) drainDataCh() {
	for {
		select {
		case payload := <-sss.dataCh:
			if payload == nil {
				return
			}
			if _, err := sss.bodyWriter.Write(payload); err != nil {
				return
			}
		default:
			return
		}
	}
}

// roundTripStream performs a streaming round trip on a single transportConn.
func (tc *transportConn) roundTripStream(ctx context.Context, headers []hpack.HeaderField, body io.Reader, opts StreamOptions) (*StreamRoundTripResult, error) {
	if tc.conn.IsClosed() {
		return nil, fmt.Errorf("connection closed")
	}
	if received, _, _ := tc.conn.GoAwayReceived(); received {
		return nil, fmt.Errorf("connection received GOAWAY")
	}

	streamID := tc.allocStreamID()

	pr, pw := io.Pipe()
	result := &StreamRoundTripResult{
		ServerAddr: tc.netConn.RemoteAddr().String(),
	}

	sss := &streamingStreamState{
		headersDone: make(chan struct{}),
		bodyWriter:  pw,
		bodyReader:  pr,
		dataCh:      make(chan []byte, 64),
		abortCh:     make(chan struct{}),
		done:        make(chan streamResult, 1),
		result:      result,
		onRecvFrame: opts.OnRecvFrame,
	}

	// Start a dedicated writer goroutine that drains dataCh into the pipe.
	// This decouples the read loop from application backpressure (C-7 fix).
	// The goroutine exits when abortCh is closed (via sss.abort).
	go sss.writerLoop()

	// Transition to open state.
	tc.conn.Streams().Transition(streamID, EventSendHeaders) //nolint:errcheck

	// Install the streaming dispatcher for this stream.
	tc.registerStreamingHandler(streamID, sss)

	// Send HEADERS frame(s) — determine endStream from body presence.
	fragment := tc.encodeHeaders(headers)
	endStream := body == nil

	tc.writeMu.Lock()
	err := tc.writeHeaderFrames(streamID, endStream, fragment)
	tc.writeMu.Unlock()
	if err != nil {
		tc.unregisterStreamingHandler(streamID)
		sss.abort(err)
		return nil, fmt.Errorf("send HEADERS on stream %d: %w", streamID, err)
	}

	// Record sent HEADERS frame.
	if opts.OnSendFrame != nil {
		// Reconstruct the raw frame bytes for the callback.
		headerFrame := buildHeadersFrameBytes(streamID, endStream, true, fragment)
		opts.OnSendFrame(headerFrame)
	}

	if endStream {
		tc.conn.Streams().Transition(streamID, EventSendEndStream) //nolint:errcheck
	}

	// Start sender goroutine for body streaming.
	senderDone := make(chan error, 1)
	if body != nil {
		go func() {
			senderDone <- tc.streamSendBody(ctx, streamID, body, opts)
		}()
	} else {
		close(senderDone)
	}

	// Wait for response headers (or sender/stream error).
	if err := tc.waitForStreamHeaders(ctx, streamID, sss, senderDone, body); err != nil {
		return nil, err
	}

	// Extract and validate status code.
	statusCode, err := extractStatusCode(sss.headers)
	if err != nil {
		tc.unregisterStreamingHandler(streamID)
		sss.abort(err)
		return nil, err
	}
	result.StatusCode = statusCode

	result.Headers = sss.headers
	result.Body = &streamingBody{
		reader:     pr,
		sss:        sss,
		tc:         tc,
		streamID:   streamID,
		senderDone: senderDone,
		reqBody:    body,
	}

	return result, nil
}

// waitForStreamHeaders blocks until response headers arrive, the stream
// completes, the sender fails, or the context is cancelled. It returns nil
// on success and an error on failure (after cleaning up resources).
func (tc *transportConn) waitForStreamHeaders(ctx context.Context, streamID uint32, sss *streamingStreamState, senderDone chan error, body io.Reader) error {
	for {
		select {
		case <-ctx.Done():
			tc.sendReset(streamID, ErrCodeCancel)
			tc.unregisterStreamingHandler(streamID)
			sss.abort(ctx.Err())
			closeIfCloser(body)
			return ctx.Err()
		case <-sss.headersDone:
			return nil
		case r := <-sss.done:
			tc.unregisterStreamingHandler(streamID)
			if r.err != nil {
				sss.abort(r.err)
				return r.err
			}
			return nil
		case err, ok := <-senderDone:
			if !ok || err == nil {
				senderDone = nil
				continue
			}
			tc.sendReset(streamID, ErrCodeCancel)
			tc.unregisterStreamingHandler(streamID)
			sss.abort(err)
			closeIfCloser(body)
			return err
		}
	}
}

// extractStatusCode finds and parses the :status pseudo-header from the
// response headers. Returns an error if missing or malformed.
func extractStatusCode(headers []hpack.HeaderField) (int, error) {
	for _, hf := range headers {
		if hf.Name == ":status" {
			code, err := strconv.Atoi(hf.Value)
			if err != nil {
				return 0, fmt.Errorf("invalid :status %q: %w", hf.Value, err)
			}
			return code, nil
		}
	}
	return 0, fmt.Errorf("no :status pseudo-header in response")
}

// streamingBody wraps the pipe reader and handles cleanup when the body is
// closed or fully read.
type streamingBody struct {
	reader     *io.PipeReader
	sss        *streamingStreamState
	tc         *transportConn
	streamID   uint32
	senderDone <-chan error
	reqBody    io.Reader // original request body; closed on Close() to unblock sender
	closeOnce  sync.Once
	readErr    error
}

func (sb *streamingBody) Read(p []byte) (int, error) {
	n, err := sb.reader.Read(p)
	if err == io.EOF {
		sb.readErr = io.EOF
		// Mark body done with trailers immediately — do not block on sender.
		// The server may send END_STREAM before the client finishes sending
		// (e.g., early error responses in bidirectional streaming).
		sb.sss.result.markBodyDone(sb.sss.trailers)

		// Propagate any sender error asynchronously: if the sender goroutine
		// failed, surface its error instead of io.EOF so the caller is aware.
		select {
		case sendErr := <-sb.senderDone:
			if sendErr != nil {
				return n, sendErr
			}
		default:
			// Sender still running — do not block.
		}
	}
	return n, err
}

func (sb *streamingBody) Close() error {
	var err error
	sb.closeOnce.Do(func() {
		// Abort the streaming state to signal the writer goroutine and close
		// the pipe writer. This ensures no goroutine leak even if the caller
		// closes the body before END_STREAM (C-15 fix).
		sb.sss.abort(fmt.Errorf("body closed"))
		err = sb.reader.Close()
		// Close the request body to unblock the sender goroutine if it is
		// blocked in body.Read (C-8 fix: prevent goroutine leak).
		closeIfCloser(sb.reqBody)
		sb.tc.unregisterStreamingHandler(sb.streamID)
	})
	return err
}

// registerStreamingHandler installs a streaming handler for the given stream ID.
func (tc *transportConn) registerStreamingHandler(streamID uint32, sss *streamingStreamState) {
	tc.streamsMu.Lock()
	if tc.streamingStreams == nil {
		tc.streamingStreams = make(map[uint32]*streamingStreamState)
	}
	tc.streamingStreams[streamID] = sss
	tc.streamsMu.Unlock()
}

// unregisterStreamingHandler removes the streaming handler for the given stream ID.
func (tc *transportConn) unregisterStreamingHandler(streamID uint32) {
	tc.streamsMu.Lock()
	delete(tc.streamingStreams, streamID)
	tc.streamsMu.Unlock()
}

// streamSendBody reads from body and sends DATA frames, respecting flow control.
// When body returns io.EOF, it sends END_STREAM to half-close the stream.
func (tc *transportConn) streamSendBody(ctx context.Context, streamID uint32, body io.Reader, opts StreamOptions) error {
	// Cap the read buffer to a reasonable I/O chunk size. MaxFrameSize can be
	// up to 16MB per the HTTP/2 spec, but the actual frame splitting is handled
	// by streamSendData which respects MaxFrameSize. The read buffer just needs
	// to be a practical I/O size (C-10 fix).
	const maxReadBuf = 32 * 1024 // 32KB
	bufSize := int(tc.conn.PeerSettings().MaxFrameSize)
	if bufSize > maxReadBuf {
		bufSize = maxReadBuf
	}
	buf := make([]byte, bufSize)

	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			data := buf[:n]
			if err := tc.streamSendData(ctx, streamID, data, readErr == io.EOF, opts); err != nil {
				return fmt.Errorf("send DATA on stream %d: %w", streamID, err)
			}
		}
		if readErr == io.EOF {
			// If n == 0 and we got EOF, we need to send an empty DATA with END_STREAM.
			if n == 0 {
				if err := tc.streamSendData(ctx, streamID, nil, true, opts); err != nil {
					return fmt.Errorf("send END_STREAM on stream %d: %w", streamID, err)
				}
			}
			tc.conn.Streams().Transition(streamID, EventSendEndStream) //nolint:errcheck
			return nil
		}
		if readErr != nil {
			// Non-EOF error from body reader — reset the stream.
			tc.sendReset(streamID, ErrCodeCancel)
			return fmt.Errorf("read body: %w", readErr)
		}
	}
}

// streamSendData sends a single chunk of data as DATA frame(s) with flow control.
// It sends partial frames when the available flow-control window is smaller than
// the chunk size, avoiding head-of-line blocking under constrained flow control.
func (tc *transportConn) streamSendData(ctx context.Context, streamID uint32, data []byte, endStream bool, opts StreamOptions) error {
	maxPayload := int(tc.conn.PeerSettings().MaxFrameSize)

	for len(data) > 0 || endStream {
		if len(data) > 0 {
			// Wait for any positive flow control window.
			available, err := tc.waitForSendWindow(ctx, streamID)
			if err != nil {
				return err
			}

			// Compute chunk as min(len(data), maxPayload, available).
			chunk := len(data)
			if chunk > maxPayload {
				chunk = maxPayload
			}
			if chunk > int(available) {
				chunk = int(available)
			}

			isLast := endStream && chunk >= len(data)

			// Consume flow control windows.
			n := int32(chunk)
			if err := tc.conn.ConsumeSendWindow(n); err != nil {
				return fmt.Errorf("connection flow control: %w", err)
			}
			if err := tc.conn.Streams().ConsumeSendWindow(streamID, n); err != nil {
				return fmt.Errorf("stream flow control: %w", err)
			}

			tc.writeMu.Lock()
			err = tc.writer.WriteData(streamID, isLast, data[:chunk])
			tc.writeMu.Unlock()
			if err != nil {
				return fmt.Errorf("write DATA frame: %w", err)
			}

			// Record sent DATA frame.
			if opts.OnSendFrame != nil {
				rawFrame := buildDataFrameBytes(streamID, isLast, data[:chunk])
				opts.OnSendFrame(rawFrame)
			}

			data = data[chunk:]
			if isLast {
				return nil
			}
			continue
		}

		// len(data) == 0 && endStream: send empty DATA with END_STREAM.
		tc.writeMu.Lock()
		err := tc.writer.WriteData(streamID, true, nil)
		tc.writeMu.Unlock()
		if err != nil {
			return fmt.Errorf("write DATA frame: %w", err)
		}

		if opts.OnSendFrame != nil {
			rawFrame := buildDataFrameBytes(streamID, true, nil)
			opts.OnSendFrame(rawFrame)
		}
		return nil
	}
	return nil
}

// waitForSendWindow waits until the connection and stream flow control windows
// have any positive space available, and returns the available window size.
// The caller should send min(data, maxPayload, available) to avoid head-of-line
// blocking under constrained flow control.
func (tc *transportConn) waitForSendWindow(ctx context.Context, streamID uint32) (int32, error) {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	for {
		connWindow := tc.conn.SendWindow()
		streamWindow, ok := tc.conn.Streams().GetSendWindow(streamID)
		if !ok {
			return 0, fmt.Errorf("stream %d does not exist", streamID)
		}
		available := connWindow
		if streamWindow < available {
			available = streamWindow
		}
		if available > 0 {
			return available, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-tc.readLoopDone:
			return 0, fmt.Errorf("connection closed while waiting for send window")
		case <-timer.C:
			timer.Reset(10 * time.Millisecond)
			// Retry after peer sends WINDOW_UPDATE.
		}
	}
}

// buildHeadersFrameBytes constructs raw HEADERS frame bytes for callback recording.
func buildHeadersFrameBytes(streamID uint32, endStream, endHeaders bool, fragment []byte) []byte {
	var flags frame.Flags
	if endStream {
		flags |= frame.FlagEndStream
	}
	if endHeaders {
		flags |= frame.FlagEndHeaders
	}
	hdr := frame.Header{
		Length:   uint32(len(fragment)),
		Type:     frame.TypeHeaders,
		Flags:    flags,
		StreamID: streamID,
	}
	buf := hdr.AppendTo(make([]byte, 0, frame.HeaderSize+len(fragment)))
	buf = append(buf, fragment...)
	return buf
}

// buildDataFrameBytes constructs raw DATA frame bytes for callback recording.
func buildDataFrameBytes(streamID uint32, endStream bool, data []byte) []byte {
	var flags frame.Flags
	if endStream {
		flags |= frame.FlagEndStream
	}
	hdr := frame.Header{
		Length:   uint32(len(data)),
		Type:     frame.TypeData,
		Flags:    flags,
		StreamID: streamID,
	}
	buf := hdr.AppendTo(make([]byte, 0, frame.HeaderSize+len(data)))
	buf = append(buf, data...)
	return buf
}

// handleStreamingHeaders processes a HEADERS frame for a streaming stream.
func (tc *transportConn) handleStreamingHeaders(f *frame.Frame, sss *streamingStreamState) error {
	streamID := f.Header.StreamID

	if sss.onRecvFrame != nil {
		sss.onRecvFrame(f.RawBytes)
	}

	fragment, err := f.HeaderBlockFragment()
	if err != nil {
		return fmt.Errorf("stream %d header block: %w", streamID, err)
	}

	if f.Header.Flags.Has(frame.FlagEndHeaders) {
		fields, decErr := tc.decoder.Decode(fragment)
		if decErr != nil {
			return fmt.Errorf("stream %d HPACK decode: %w", streamID, decErr)
		}
		tc.processStreamingDecodedHeaders(sss, f, fields)
	} else {
		sss.headerBuf = append(sss.headerBuf[:0], fragment...)
	}

	return nil
}

// handleStreamingContinuation processes a CONTINUATION frame for a streaming stream.
func (tc *transportConn) handleStreamingContinuation(f *frame.Frame, sss *streamingStreamState) error {
	streamID := f.Header.StreamID

	if sss.onRecvFrame != nil {
		sss.onRecvFrame(f.RawBytes)
	}

	fragment, err := f.ContinuationFragment()
	if err != nil {
		return fmt.Errorf("stream %d continuation: %w", streamID, err)
	}

	sss.headerBuf = append(sss.headerBuf, fragment...)

	if f.Header.Flags.Has(frame.FlagEndHeaders) {
		fields, decErr := tc.decoder.Decode(sss.headerBuf)
		if decErr != nil {
			return fmt.Errorf("stream %d HPACK decode: %w", streamID, decErr)
		}
		sss.headerBuf = sss.headerBuf[:0]
		tc.processStreamingDecodedHeaders(sss, f, fields)
	}

	return nil
}

// handleStreamingData processes a DATA frame for a streaming stream.
func (tc *transportConn) handleStreamingData(f *frame.Frame, sss *streamingStreamState) error {
	streamID := f.Header.StreamID

	if sss.onRecvFrame != nil {
		sss.onRecvFrame(f.RawBytes)
	}

	payload, err := f.DataPayload()
	if err != nil {
		return fmt.Errorf("stream %d data payload: %w", streamID, err)
	}

	// Wait for headers to be done before writing data.
	<-sss.headersDone

	// Send a copy of the payload to the writer goroutine via the data channel.
	// The copy is necessary because the frame buffer may be reused by the reader.
	// This decouples the read loop from application backpressure (C-7 fix).
	// The send is guarded by abortCh to prevent send-on-closed-channel panic.
	if len(payload) > 0 {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		select {
		case sss.dataCh <- cp:
		case <-sss.abortCh:
			return nil
		}
	}

	// Consume receive window and send WINDOW_UPDATE asynchronously.
	if len(payload) > 0 {
		n := int32(len(payload))
		tc.conn.ConsumeRecvWindow(n)                               //nolint:errcheck
		tc.conn.Streams().ConsumeRecvWindow(streamID, n)           //nolint:errcheck
		tc.conn.IncrementRecvWindow(uint32(n))                     //nolint:errcheck
		tc.conn.Streams().IncrementRecvWindow(streamID, uint32(n)) //nolint:errcheck

		go func() {
			tc.writeMu.Lock()
			defer tc.writeMu.Unlock()
			tc.writer.WriteWindowUpdate(0, uint32(n))        //nolint:errcheck
			tc.writer.WriteWindowUpdate(streamID, uint32(n)) //nolint:errcheck
		}()
	}

	if f.Header.Flags.Has(frame.FlagEndStream) {
		sss.endStream = true
		tc.conn.Streams().Transition(streamID, EventRecvEndStream) //nolint:errcheck
		// Send nil sentinel to signal the writer goroutine to close the pipe.
		select {
		case sss.dataCh <- nil:
		case <-sss.abortCh:
		}
		select {
		case sss.done <- streamResult{}:
		default:
		}
	}

	return nil
}

// processStreamingDecodedHeaders routes decoded headers to initial headers or
// trailers for a streaming stream.
func (tc *transportConn) processStreamingDecodedHeaders(sss *streamingStreamState, f *frame.Frame, fields []hpack.HeaderField) {
	select {
	case <-sss.headersDone:
		// Already received initial headers — these are trailers.
		sss.trailers = append(sss.trailers, fields...)
	default:
		sss.headers = append(sss.headers, fields...)
		close(sss.headersDone)
	}

	endStream := f.Header.Flags.Has(frame.FlagEndStream)
	if endStream {
		sss.endStream = true
		tc.conn.Streams().Transition(f.Header.StreamID, EventRecvEndStream) //nolint:errcheck
		// Send nil sentinel to signal the writer goroutine to close the pipe.
		select {
		case sss.dataCh <- nil:
		case <-sss.abortCh:
		}
		select {
		case sss.done <- streamResult{}:
		default:
		}
	}
}

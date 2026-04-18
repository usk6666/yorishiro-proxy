package http2

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// readerLoop drives the frame-reader goroutine. One per Layer/connection.
// Exits on read error, EOF, or shutdown signal.
func (l *Layer) readerLoop() {
	defer close(l.readerDone)
	defer l.broadcastShutdown()

	for {
		f, err := l.frameReader.ReadFrame()
		if err != nil {
			l.handleReadError(err)
			return
		}

		// Connection-level frame dispatch (stream ID 0).
		if f.Header.StreamID == 0 {
			if err := l.handleConnFrame(f); err != nil {
				l.handleReadError(err)
				return
			}
			continue
		}

		if err := l.handleStreamFrame(f); err != nil {
			l.handleReadError(err)
			return
		}
	}
}

// handleConnFrame processes a frame with stream ID 0.
func (l *Layer) handleConnFrame(f *frame.Frame) error {
	switch f.Header.Type {
	case frame.TypeSettings:
		return l.handleSettingsFrame(f)
	case frame.TypePing:
		return l.handlePingFrame(f)
	case frame.TypeGoAway:
		return l.handleGoAwayFrame(f)
	case frame.TypeWindowUpdate:
		if err := l.conn.HandleWindowUpdate(f); err != nil {
			return err
		}
		l.signalWindowUpdate()
		return nil
	default:
		// Unknown connection-level frames are ignored per RFC 9113 §5.1.
		return nil
	}
}

func (l *Layer) handleSettingsFrame(f *frame.Frame) error {
	params, err := l.conn.HandleSettings(f)
	if err != nil {
		return err
	}
	if params == nil {
		// SETTINGS ACK — already recorded by Conn.
		return nil
	}
	// Apply peer's settings to our reader/writer state.
	peer := l.conn.PeerSettings()
	if peer.MaxFrameSize >= frame.DefaultMaxFrameSize && peer.MaxFrameSize <= frame.MaxAllowedFrameSize {
		_ = l.frameReader.SetMaxFrameSize(peer.MaxFrameSize)
	}
	// Send SETTINGS ACK.
	l.enqueueWrite(writeRequest{settingsAck: &writeSettingsAck{}})
	// If the peer adjusted INITIAL_WINDOW_SIZE, the writer may have new
	// capacity; signal it.
	l.signalWindowUpdate()
	return nil
}

func (l *Layer) handlePingFrame(f *frame.Frame) error {
	needsAck, data, err := l.conn.HandlePing(f)
	if err != nil {
		return err
	}
	if needsAck {
		l.enqueueWrite(writeRequest{pingAck: &writePingAck{data: data}})
	}
	return nil
}

func (l *Layer) handleGoAwayFrame(f *frame.Frame) error {
	lastStreamID, _, _, err := l.conn.HandleGoAway(f)
	if err != nil {
		return err
	}
	// Notify all open streams with id > lastStreamID.
	l.failStreamsAfterGoAway(lastStreamID, &layer.StreamError{
		Code:   layer.ErrorRefused,
		Reason: "GOAWAY",
	})
	return nil
}

// handleStreamFrame dispatches a frame with non-zero stream ID.
func (l *Layer) handleStreamFrame(f *frame.Frame) error {
	switch f.Header.Type {
	case frame.TypeHeaders:
		return l.handleStreamHeaders(f)
	case frame.TypeContinuation:
		return l.handleStreamContinuation(f)
	case frame.TypeData:
		return l.handleStreamData(f)
	case frame.TypeRSTStream:
		return l.handleStreamRST(f)
	case frame.TypeWindowUpdate:
		if err := l.conn.HandleWindowUpdate(f); err != nil {
			// Stream-level window update errors are stream errors; reply
			// with RST_STREAM and drop the stream.
			var se *StreamError
			if errors.As(err, &se) {
				l.enqueueWrite(writeRequest{rst: &writeRST{streamID: se.StreamID, code: se.Code}})
				l.failStream(se.StreamID, &layer.StreamError{
					Code:   layer.ErrorProtocol,
					Reason: se.Reason,
				})
				return nil
			}
			return err
		}
		l.signalWindowUpdate()
		return nil
	case frame.TypePushPromise:
		return l.handleStreamPushPromise(f)
	case frame.TypePriority:
		// PRIORITY is deprecated (RFC 9113 §5.3.2) and not propagated.
		return nil
	default:
		// Unknown frame types on a stream are ignored per RFC 9113 §5.1.
		return nil
	}
}

func (l *Layer) handleStreamHeaders(f *frame.Frame) error {
	fragment, err := f.HeaderBlockFragment()
	if err != nil {
		return err
	}
	endHeaders := f.Header.Flags.Has(frame.FlagEndHeaders)
	endStream := f.Header.Flags.Has(frame.FlagEndStream)

	asm, ch, isNew := l.assemblerFor(f.Header.StreamID, true)
	if asm == nil {
		return nil
	}
	if isNew {
		_ = l.conn.Streams().Transition(f.Header.StreamID, EventRecvHeaders)
		if l.role == ServerRole {
			l.emitChannel(ch)
		}
	}
	l.updatePendingHeaderStream(f.Header.StreamID, endHeaders)

	if asm.phase == asmPassthrough {
		return l.dropPassthroughTrailers(asm, fragment, endHeaders, f.Header.StreamID)
	}

	direction := l.headerDirection(asm)
	env, _, err := asm.handleHeadersFrame(fragment, f.RawBytes, endHeaders, endStream, l.decoder, direction)
	if err != nil {
		return err
	}
	if env != nil {
		l.deliverEnvelope(ch, env, asm)
	}
	if endHeaders && endStream {
		_ = l.conn.Streams().Transition(f.Header.StreamID, EventRecvEndStream)
	}
	return nil
}

// updatePendingHeaderStream tracks which stream is mid-CONTINUATION so a
// subsequent CONTINUATION frame can be routed correctly.
func (l *Layer) updatePendingHeaderStream(streamID uint32, endHeaders bool) {
	if !endHeaders {
		l.pendingHeaderStream = streamID
	} else {
		l.pendingHeaderStream = 0
	}
}

// dropPassthroughTrailers consumes a trailer header block while a stream is
// in passthrough mode, decoding it (to keep HPACK state coherent) but not
// delivering it to the consumer.
func (l *Layer) dropPassthroughTrailers(asm *streamAssembler, fragment []byte, endHeaders bool, streamID uint32) error {
	if endHeaders {
		if _, dErr := l.decoder.Decode(fragment); dErr != nil {
			return fmt.Errorf("http2: decode trailer block (passthrough, stream %d): %w", streamID, dErr)
		}
		l.passthroughMu.Lock()
		l.passthroughTrailerCount++
		l.passthroughMu.Unlock()
		return nil
	}
	asm.fragBuf = append(asm.fragBuf, fragment...)
	return nil
}

// headerDirection picks the direction for envelopes built from the next
// HEADERS frame: Send on the server-facing reader, Receive on the
// client-facing reader, or the in-flight envelope's direction for trailers.
func (l *Layer) headerDirection(asm *streamAssembler) envelope.Direction {
	if asm.phase == asmCollectingTrailers && asm.inflight != nil {
		return asm.inflight.Direction
	}
	if l.role == ServerRole {
		return envelope.Send
	}
	return envelope.Receive
}

func (l *Layer) handleStreamContinuation(f *frame.Frame) error {
	if l.pendingHeaderStream != f.Header.StreamID {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("CONTINUATION on unexpected stream %d (pending %d)", f.Header.StreamID, l.pendingHeaderStream),
		}
	}
	fragment, err := f.ContinuationFragment()
	if err != nil {
		return err
	}
	endHeaders := f.Header.Flags.Has(frame.FlagEndHeaders)

	asm, ch, _ := l.assemblerFor(f.Header.StreamID, false)
	if asm == nil {
		return nil
	}

	direction := envelope.Receive
	if l.role == ServerRole && asm.phase != asmCollectingTrailers {
		direction = envelope.Send
	}
	if asm.inflight != nil {
		direction = asm.inflight.Direction
	}

	env, _, err := asm.handleHeadersFrame(fragment, f.RawBytes, endHeaders, false, l.decoder, direction)
	if err != nil {
		return err
	}
	if endHeaders {
		l.pendingHeaderStream = 0
	}
	if env != nil {
		l.deliverEnvelope(ch, env, asm)
	}
	return nil
}

func (l *Layer) handleStreamData(f *frame.Frame) error {
	payload, err := f.DataPayload()
	if err != nil {
		return err
	}
	endStream := f.Header.Flags.Has(frame.FlagEndStream)

	// Consume connection-level recv window using full frame length (incl.
	// padding) per RFC 9113 §6.9.1.
	if f.Header.Length > 0 {
		if err := l.conn.ConsumeRecvWindow(int32(f.Header.Length)); err != nil {
			return err
		}
		if err := l.conn.Streams().ConsumeRecvWindow(f.Header.StreamID, int32(f.Header.Length)); err != nil {
			return err
		}
	}

	asm, ch, _ := l.assemblerFor(f.Header.StreamID, false)
	if asm == nil {
		return nil
	}

	env, _, err := asm.handleDataFrame(payload, f.RawBytes, endStream)
	if err != nil {
		return err
	}

	// Eagerly emit WINDOW_UPDATE if recv windows have drained ≥50%.
	l.maybeWindowUpdate(f.Header.StreamID, f.Header.Length)

	if env != nil {
		l.deliverEnvelope(ch, env, asm)
	}
	if endStream {
		_ = l.conn.Streams().Transition(f.Header.StreamID, EventRecvEndStream)
	}
	return nil
}

func (l *Layer) handleStreamRST(f *frame.Frame) error {
	code, err := l.conn.HandleRSTStream(f)
	if err != nil {
		return err
	}
	se := &layer.StreamError{
		Code:   translateH2StreamError(code),
		Reason: ErrCodeString(code),
	}
	l.failStream(f.Header.StreamID, se)
	return nil
}

func (l *Layer) handleStreamPushPromise(f *frame.Frame) error {
	promisedID, fragment, err := f.PushPromiseFields()
	if err != nil {
		return err
	}
	if l.role == ServerRole {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: "server received PUSH_PROMISE",
		}
	}
	endHeaders := f.Header.Flags.Has(frame.FlagEndHeaders)

	if !endHeaders {
		// Fragmented PUSH_PROMISE not supported in this minimum implementation
		// — most servers fit promises in a single frame because they are
		// usually small. Treat as a connection error so we surface the gap.
		return &ConnError{
			Code:   ErrCodeInternal,
			Reason: "PUSH_PROMISE without END_HEADERS not supported",
		}
	}

	decoded, dErr := l.decoder.Decode(fragment)
	if dErr != nil {
		return fmt.Errorf("http2: decode PUSH_PROMISE header block: %w", dErr)
	}

	// Build a synthetic request envelope on the original stream's channel.
	originAsm, originCh, _ := l.assemblerFor(f.Header.StreamID, false)
	if originAsm == nil {
		// No origin channel? Refuse the promise.
		l.enqueueWrite(writeRequest{rst: &writeRST{streamID: promisedID, code: ErrCodeRefusedStream}})
		return nil
	}

	syntheticMsg, anomalies := buildHTTPMessage(decoded, envelope.Send)
	syntheticMsg.Anomalies = append(syntheticMsg.Anomalies, anomalies...)
	syntheticMsg.Anomalies = append(syntheticMsg.Anomalies, envelope.Anomaly{
		Type:   envelope.H2PushPromise,
		Detail: fmt.Sprintf("promised_stream_id=%d", promisedID),
	})

	envSyn := &envelope.Envelope{
		StreamID:  originCh.streamID,
		FlowID:    uuid.New().String(),
		Sequence:  originCh.nextSequence(),
		Direction: envelope.Receive, // pushed onto our connection by the server
		Protocol:  envelope.ProtocolHTTP,
		Raw:       cloneBytes(f.RawBytes),
		Message:   syntheticMsg,
		Context:   l.envelopeContextWithTime(),
	}
	l.deliverEnvelope(originCh, envSyn, nil)

	// Create a new push channel for the promised stream.
	pushCh := newChannel(l, promisedID, true)
	l.registerChannel(promisedID, pushCh)
	l.emitChannel(pushCh)
	// Ensure the server's stream state reflects "reserved (remote)".
	_ = l.conn.Streams().Transition(promisedID, EventRecvPushPromise)
	return nil
}

// assemblerFor returns (assembler, channel) for streamID, optionally creating
// the assembler+channel if missing (createIfMissing=true). Returns (nil, nil, false)
// if the stream is closed or the layer is shut down.
//
// `isNew` is true when a new channel was created.
func (l *Layer) assemblerFor(streamID uint32, createIfMissing bool) (*streamAssembler, *channel, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil, nil, false
	}

	if asm, ok := l.assemblers[streamID]; ok {
		return asm, asm.channel, false
	}
	if !createIfMissing {
		return nil, nil, false
	}

	ch := newChannel(l, streamID, false)
	l.channels[streamID] = ch
	asm := newStreamAssembler(streamID, ch)
	l.assemblers[streamID] = asm
	l.conn.Streams().SetLastPeerStreamID(streamID)
	return asm, ch, true
}

// registerChannel stores ch under streamID and creates an assembler for it.
// Used for client-initiated streams (OpenStream) and for promised streams.
func (l *Layer) registerChannel(streamID uint32, ch *channel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.channels[streamID] = ch
	l.assemblers[streamID] = newStreamAssembler(streamID, ch)
}

// emitChannel sends ch on the Channels() output channel. Non-blocking on
// shutdown; drops the channel emission if the consumer has already torn down.
func (l *Layer) emitChannel(ch *channel) {
	select {
	case l.channelOut <- ch:
	case <-l.shutdown:
	}
}

// deliverEnvelope sends env on ch's recv chan, applying backpressure.
// Returns false if the layer is shutting down.
func (l *Layer) deliverEnvelope(ch *channel, env *envelope.Envelope, asm *streamAssembler) {
	if env.FlowID == "" {
		env.FlowID = uuid.New().String()
	}
	if env.Context.ReceivedAt.IsZero() {
		env.Context = l.envelopeContextWithTime()
	}

	select {
	case ch.recv <- env:
	case <-l.shutdown:
		return
	}

	// If the assembler reached terminal state, close the channel's recv side.
	if asm != nil && asm.phase == asmDone {
		l.closeChannelRecv(ch)
	}
}

// closeChannelRecv idempotently closes ch's recv chan.
func (l *Layer) closeChannelRecv(ch *channel) {
	ch.closeRecvOnce.Do(func() {
		close(ch.recv)
	})
}

// failStream delivers a stream error to ch and closes its recv side.
func (l *Layer) failStream(streamID uint32, se *layer.StreamError) {
	l.mu.Lock()
	ch, ok := l.channels[streamID]
	asm := l.assemblers[streamID]
	l.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch.errCh <- se:
	default:
	}
	if asm != nil {
		asm.phase = asmDone
	}
	l.closeChannelRecv(ch)
}

// failStreamsAfterGoAway notifies every open stream with id > lastStreamID.
func (l *Layer) failStreamsAfterGoAway(lastStreamID uint32, se *layer.StreamError) {
	l.mu.Lock()
	channels := make([]*channel, 0)
	for id, ch := range l.channels {
		if id > lastStreamID {
			channels = append(channels, ch)
		}
	}
	l.mu.Unlock()
	for _, ch := range channels {
		select {
		case ch.errCh <- se:
		default:
		}
		l.closeChannelRecv(ch)
	}
}

// broadcastShutdown closes all per-channel recv chans and the channelOut chan.
// Idempotent via sync.Once on each channel.
func (l *Layer) broadcastShutdown() {
	l.mu.Lock()
	channels := make([]*channel, 0, len(l.channels))
	for _, ch := range l.channels {
		channels = append(channels, ch)
	}
	l.mu.Unlock()

	for _, ch := range channels {
		l.closeChannelRecv(ch)
	}
	l.closeChannelOutOnce.Do(func() {
		close(l.channelOut)
	})
}

// signalWindowUpdate wakes the writer if it is blocked waiting for a window.
// Non-blocking; coalesces multiple updates.
func (l *Layer) signalWindowUpdate() {
	select {
	case l.windowUpdated <- struct{}{}:
	default:
	}
}

// handleReadError is called when the reader cannot proceed. It triggers
// shutdown so the writer drains and Layer.Close completes.
func (l *Layer) handleReadError(err error) {
	if errors.Is(err, io.EOF) {
		// Normal shutdown — close all channels and shut down.
		l.shutdownOnce.Do(func() { close(l.shutdown) })
		return
	}

	// Capture for diagnostic.
	l.lastErrMu.Lock()
	l.lastErr = err
	l.lastErrMu.Unlock()

	// Connection error: send GOAWAY, then shut down.
	var ce *ConnError
	if errors.As(err, &ce) {
		l.enqueueWrite(writeRequest{goAway: &writeGoAway{
			lastStreamID: l.conn.Streams().LastPeerStreamID(),
			code:         ce.Code,
		}})
	}
	l.shutdownOnce.Do(func() { close(l.shutdown) })
}

// maybeWindowUpdate enqueues WINDOW_UPDATE frames matching the consumed
// dataLen. The simple "replace what was consumed" strategy keeps us well
// inside the recv windows for streaming bodies; the writer goroutine is
// single-threaded so frames go out in order. Per RFC 9113 §6.9, this is
// permitted and matches go-http2 behavior.
func (l *Layer) maybeWindowUpdate(streamID uint32, dataLen uint32) {
	if dataLen == 0 {
		return
	}
	// Connection-level WINDOW_UPDATE.
	l.enqueueWrite(writeRequest{windowUpdate: &writeWindowUpdate{streamID: 0, increment: dataLen}})
	// Stream-level WINDOW_UPDATE.
	l.enqueueWrite(writeRequest{windowUpdate: &writeWindowUpdate{streamID: streamID, increment: dataLen}})
}

// envelopeContextWithTime returns the layer's context template with a fresh
// ReceivedAt timestamp.
func (l *Layer) envelopeContextWithTime() envelope.EnvelopeContext {
	c := l.opts.ctx
	c.ReceivedAt = time.Now()
	return c
}

// cloneBytes returns a copy of b, or nil if b is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

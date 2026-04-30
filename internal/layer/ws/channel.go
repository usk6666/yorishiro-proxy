package ws

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// wsChannel implements layer.Channel for a single WebSocket bidirectional
// stream. Read goroutine model is Next-driven (no background read pump):
// each Next call consumes one frame from the wire and emits one Envelope.
//
// The terminal-state contract follows the RFC-001 N1 design:
//
//   - termErr is populated via markTerminated BEFORE recvDone is closed,
//     so any observer of Closed() reading Err() sees a stable value.
//   - markTerminated is first-writer-wins (sync.Once on the close side,
//     guarded by termMu on the err side).
//   - Close on the Channel itself is a no-op: the Layer owns the wire
//     resources (matches the http1 channel.Close pattern).
type wsChannel struct {
	layer    *Layer
	streamID string
	role     Role

	mu        sync.Mutex
	nextSeq   int
	closeSeen bool // a Close-frame envelope has been emitted; next Next returns io.EOF

	// Per-direction deflate state. Lazily initialised from options the
	// first time a frame in that direction is seen.
	clientDS *deflateState
	serverDS *deflateState
	opts     *options

	// Per-direction reassembly buffer for compressed fragmented messages.
	// When a frame with Compressed=true && Fin=false is observed, its
	// payload bytes are appended; the FIN frame triggers decompression
	// over the concatenated buffer per RFC 7692 fragmentation rules.
	clientFragBuf []byte
	clientFragOn  bool
	serverFragBuf []byte
	serverFragOn  bool

	// Termination state.
	termOnce sync.Once
	termMu   sync.Mutex
	termErr  error
	recvDone chan struct{}
}

// newChannel constructs a wsChannel under the given Layer. The Layer
// holds the canonical reference and the Channel borrows reader/writer/
// closer pointers via the Layer struct.
func newChannel(l *Layer, streamID string, role Role, opts *options) *wsChannel {
	c := &wsChannel{
		layer:    l,
		streamID: streamID,
		role:     role,
		opts:     opts,
		recvDone: make(chan struct{}),
	}
	if opts.deflateEnabled {
		if opts.clientDeflate.enabled {
			c.clientDS = newDeflateState(opts.clientDeflate)
		}
		if opts.serverDeflate.enabled {
			c.serverDS = newDeflateState(opts.serverDeflate)
		}
	}
	return c
}

// StreamID returns the caller-supplied stream identifier.
func (c *wsChannel) StreamID() string { return c.streamID }

// Closed returns a channel that fires when the wsChannel has reached its
// terminal state. termErr is populated before this fires.
func (c *wsChannel) Closed() <-chan struct{} { return c.recvDone }

// Err returns the cached terminal error (nil before recvDone fires;
// io.EOF on graceful termination; *layer.StreamError on abnormal).
func (c *wsChannel) Err() error {
	c.termMu.Lock()
	defer c.termMu.Unlock()
	return c.termErr
}

// Close is a no-op. The Layer owns the underlying reader/writer/closer
// triple; the wrapper channel does not directly close transport
// resources. Mirrors the internal/layer/http1 channel.Close contract.
func (c *wsChannel) Close() error { return nil }

// markTerminated caches err as the terminal error (first call wins,
// guarded by termMu) and closes recvDone exactly once. Safe to call from
// multiple goroutines.
//
// On the first call we also fire the configured pluginv2 state release
// for this Channel's WS upgrade-pair scope. The call is sequenced AFTER
// close(recvDone) so a USK-671 dispatch path observing the close can run
// any terminal-event hook (e.g. ws.on_close) before the backing dict is
// cleared.
func (c *wsChannel) markTerminated(err error) {
	c.termOnce.Do(func() {
		c.termMu.Lock()
		if c.termErr == nil {
			c.termErr = err
		}
		c.termMu.Unlock()
		close(c.recvDone)
		c.releaseTransactionState()
	})
}

// releaseTransactionState fires the configured pluginv2.StateReleaser for
// this Channel's (ConnID, StreamID) — the WS upgrade-pair scope. No-op
// when no releaser was configured or when the Layer's EnvelopeContext
// has no ConnID.
func (c *wsChannel) releaseTransactionState() {
	if c.opts == nil || c.opts.stateReleaser == nil {
		return
	}
	if c.opts.ctxTmpl.ConnID == "" {
		return
	}
	c.opts.stateReleaser.ReleaseTransaction(c.opts.ctxTmpl.ConnID, c.streamID)
}

// readDirection returns the Direction stamped on envelopes produced by
// Next(). It is driven by Role: RoleServer reads client→server frames
// (Direction=Send); RoleClient reads server→client frames (Direction=
// Receive).
func (c *wsChannel) readDirection() envelope.Direction {
	if c.role == RoleServer {
		return envelope.Send
	}
	return envelope.Receive
}

// sendDirection returns the Direction stamped on envelopes produced by
// Send(). RoleServer writes server→client frames (Direction=Receive);
// RoleClient writes client→server frames (Direction=Send).
func (c *wsChannel) sendDirection() envelope.Direction {
	if c.role == RoleServer {
		return envelope.Receive
	}
	return envelope.Send
}

// Next consumes the next WebSocket frame from the wire and returns one
// Envelope per call. Returns io.EOF on graceful termination (peer
// half-closed before sending a frame, OR after a Close-frame envelope
// was emitted). Returns *layer.StreamError on protocol violations,
// mid-frame reader errors, deflate failures, etc.
func (c *wsChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Cached terminal state from a previous Next or a prior Send error:
	// surface immediately. Checked BEFORE the closeSeen short-circuit so a
	// prior StreamError is never masked by io.EOF if a future refactor
	// allows both flags to coexist.
	if termErr := c.Err(); termErr != nil {
		return nil, termErr
	}

	c.mu.Lock()
	if c.closeSeen {
		c.mu.Unlock()
		c.markTerminated(io.EOF)
		return nil, io.EOF
	}
	c.mu.Unlock()

	frame, raw, err := ReadFrameRaw(c.layer.reader)
	if err != nil {
		return nil, c.mapReadError(err, raw)
	}

	dir := c.readDirection()
	env, buildErr := c.buildEnvelope(frame, raw, dir)
	if buildErr != nil {
		c.markTerminated(buildErr)
		return nil, buildErr
	}
	return env, nil
}

// mapReadError maps a frame.go error into the contract specified in
// Friction 11. raw may be partial bytes consumed up to the error point;
// it is currently discarded but available to a future error envelope.
func (c *wsChannel) mapReadError(err error, raw []byte) error {
	_ = raw
	if errors.Is(err, io.EOF) {
		// Graceful pre-frame EOF — peer abandoned without Close. MITM
		// principle: forward what we see.
		c.markTerminated(io.EOF)
		return io.EOF
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		// Mid-frame EOF / TCP RST: treat as Aborted.
		se := &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: "ws: " + err.Error(),
		}
		c.markTerminated(se)
		return se
	}
	// Any other ReadFrame failure is malformed-frame territory.
	se := &layer.StreamError{
		Code:   layer.ErrorProtocol,
		Reason: "ws: " + err.Error(),
	}
	c.markTerminated(se)
	return se
}

// buildEnvelope constructs the WSMessage + outer Envelope for a parsed
// Frame. Handles Close-frame mapping, deflate decompression, and
// fragmented-compressed reassembly per RFC 7692.
func (c *wsChannel) buildEnvelope(frame *Frame, raw []byte, dir envelope.Direction) (*envelope.Envelope, *layer.StreamError) {
	c.mu.Lock()
	seq := c.nextSeq
	c.nextSeq++
	c.mu.Unlock()

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSOpcode(frame.Opcode),
		Fin:     frame.Fin,
		Masked:  frame.Masked,
		Mask:    frame.MaskKey,
		Payload: frame.Payload,
	}

	// Per-message-deflate handling. RSV1 indicates compression on this
	// message (the FIRST data frame of a message; continuations carry
	// RSV1=0 per RFC 7692 §6.1). For the FIN frame of a fragmented
	// compressed message, decompress the reassembled buffer; for a
	// continuation, append to the buffer and surface the verbatim
	// compressed bytes as Payload.
	ds := c.deflateForDirection(dir)
	compressedDirEnabled := ds != nil
	if compressedDirEnabled {
		if se := c.applyDeflate(frame, dir, msg); se != nil {
			return nil, se
		}
	}

	// Close-frame structured fields. If the wire payload is at least
	// 2 bytes, the first 2 are the CloseCode big-endian and the rest is
	// the (UTF-8) reason string.
	if msg.Opcode == envelope.WSClose {
		c.populateCloseFields(msg, frame)
		c.mu.Lock()
		c.closeSeen = true
		c.mu.Unlock()
	}

	envCtx := c.opts.ctxTmpl

	out := &envelope.Envelope{
		StreamID:  c.streamID,
		FlowID:    uuid.New().String(),
		Sequence:  seq,
		Direction: dir,
		Protocol:  envelope.ProtocolWebSocket,
		Raw:       cloneBytes(raw),
		Message:   msg,
		Context:   envCtx,
	}
	return out, nil
}

// applyDeflate handles Compressed-flag detection, fragment buffering,
// and decompression. Sets msg.Compressed and may overwrite msg.Payload.
//
// The cumulative size of the per-direction continuation buffer is capped at
// maxCompressedPayloadSize to prevent unbounded memory growth from a peer
// chaining many continuation frames (mirror of the USK-640 / USK-641
// decompression-bomb defense, applied to the pre-decompress accumulator).
func (c *wsChannel) applyDeflate(frame *Frame, dir envelope.Direction, msg *envelope.WSMessage) *layer.StreamError {
	ds := c.deflateForDirection(dir)
	bufPtr, onPtr := c.fragStateForDirection(dir)

	// A non-continuation data frame with RSV1 starts a (possibly
	// fragmented) compressed message. Continuation frames inherit
	// the compression flag from the start frame.
	startsCompressed := frame.RSV1 && frame.Opcode != OpcodeContinuation
	if startsCompressed {
		msg.Compressed = true
		if !frame.Fin {
			// Buffer payload for later reassembly; surface verbatim.
			// Reset to start fresh (any prior buffer state is discarded
			// by validateFragmentAppend's len-only-check on the new total).
			if se := validateFragmentAppend(0, len(frame.Payload)); se != nil {
				return se
			}
			*bufPtr = append((*bufPtr)[:0], frame.Payload...)
			*onPtr = true
			return nil
		}
		// Single-frame compressed message: decompress the payload.
		decoded, err := ds.decompress(frame.Payload, maxFramePayloadSize)
		if err != nil {
			return &layer.StreamError{
				Code:   layer.ErrorProtocol,
				Reason: "ws: deflate: " + err.Error(),
			}
		}
		msg.Payload = decoded
		return nil
	}

	if frame.Opcode == OpcodeContinuation && *onPtr {
		// Continuation of a compressed message.
		msg.Compressed = true
		if se := validateFragmentAppend(len(*bufPtr), len(frame.Payload)); se != nil {
			// Reset accumulator on overflow so a future legitimate message
			// is not contaminated by truncated state.
			*bufPtr = (*bufPtr)[:0]
			*onPtr = false
			return se
		}
		if !frame.Fin {
			// Append; surface verbatim.
			*bufPtr = append(*bufPtr, frame.Payload...)
			return nil
		}
		// FIN continuation: reassemble + decompress, surface decoded.
		*bufPtr = append(*bufPtr, frame.Payload...)
		decoded, err := ds.decompress(*bufPtr, maxFramePayloadSize)
		if err != nil {
			return &layer.StreamError{
				Code:   layer.ErrorProtocol,
				Reason: "ws: deflate: " + err.Error(),
			}
		}
		// Reset the buffer state.
		*bufPtr = (*bufPtr)[:0]
		*onPtr = false
		msg.Payload = decoded
		return nil
	}

	// Uncompressed frame — leave msg.Compressed=false and Payload as-is.
	return nil
}

// validateFragmentAppend rejects a continuation-buffer append that would
// exceed maxCompressedPayloadSize. The cap matches the cumulative cap that
// (*deflateState).decompress enforces on its compressed input, so a chain
// of fragments cannot grow the accumulator past what decompress will accept
// on the FIN frame anyway.
func validateFragmentAppend(have, add int) *layer.StreamError {
	if int64(have)+int64(add) > maxCompressedPayloadSize {
		return &layer.StreamError{
			Code:   layer.ErrorProtocol,
			Reason: fmt.Sprintf("ws: deflate: fragment buffer overflow: %d + %d > %d", have, add, maxCompressedPayloadSize),
		}
	}
	return nil
}

// deflateForDirection returns the per-direction deflate state, or nil if
// permessage-deflate is disabled (master switch off) or this direction
// did not negotiate the extension.
func (c *wsChannel) deflateForDirection(dir envelope.Direction) *deflateState {
	if !c.opts.deflateEnabled {
		return nil
	}
	// Direction=Send is client→server (clientDS owns it).
	if dir == envelope.Send {
		return c.clientDS
	}
	return c.serverDS
}

// fragStateForDirection returns pointers to the per-direction
// fragmentation buffer + on-flag. Used to assemble RFC 7692 fragmented
// compressed messages.
func (c *wsChannel) fragStateForDirection(dir envelope.Direction) (*[]byte, *bool) {
	if dir == envelope.Send {
		return &c.clientFragBuf, &c.clientFragOn
	}
	return &c.serverFragBuf, &c.serverFragOn
}

// populateCloseFields parses an RFC 6455 §5.5.1 Close frame body into
// CloseCode + CloseReason. A 0-length payload is valid (no code, no
// reason). A 1-byte payload is malformed but we surface what we have to
// avoid hiding wire reality.
func (c *wsChannel) populateCloseFields(msg *envelope.WSMessage, frame *Frame) {
	if len(frame.Payload) >= 2 {
		msg.CloseCode = binary.BigEndian.Uint16(frame.Payload[:2])
		if len(frame.Payload) > 2 {
			msg.CloseReason = string(frame.Payload[2:])
		}
	}
}

// Send writes one WebSocket frame to the wire derived from env.Message.
// Send-direction is set by Role (RoleServer→Receive frame, RoleClient→
// Send frame). The Layer never reads env.Direction — it could differ
// from the role's expected outgoing direction (e.g., Pipeline-replayed
// envelopes), but the wire shape is determined by Role.
//
// Concurrency: Send is NOT safe for concurrent invocation from multiple
// goroutines on the same Channel. The Pipeline / Session driver is
// expected to serialize Send (single-flight). When permessage-deflate is
// enabled, two concurrent Sends would race on the per-direction LZ77
// dictionary inside (*deflateState).compress and produce frames the peer
// cannot decompress. Concurrent Send + Next is safe because they use
// disjoint deflateState instances per Role (Send uses the opposite
// direction's state from Next).
//
// Mask handling:
//   - RoleClient (writes client→server frames per RFC 6455 §5.3): the
//     mask key is generated freshly via crypto/rand for every frame.
//     env.Message.WSMessage.Mask is informational; the Layer does not
//     re-use it.
//   - RoleServer (writes server→client frames): unmasked.
//
// Compression: if env.Message.WSMessage.Compressed is true and the
// corresponding direction's deflateState is configured, the Layer
// compresses Payload and sets RSV1 in the wire frame. Otherwise the
// payload is written verbatim.
func (c *wsChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if env == nil || env.Message == nil {
		return errors.New("ws: Send: nil envelope or Message")
	}
	msg, ok := env.Message.(*envelope.WSMessage)
	if !ok {
		return fmt.Errorf("ws: Send: unsupported Message type %T", env.Message)
	}

	wireDir := c.sendDirection()

	frame := &Frame{
		Fin:    msg.Fin,
		Opcode: byte(msg.Opcode),
		// RSV2/RSV3 zeroed on Send per design decision (we never preserve
		// these from WSMessage; observed RSV bits live only on
		// Envelope.Raw at Receive time).
	}

	// Build the wire payload. For Close frames, prefer the structured
	// fields (CloseCode + CloseReason) over the raw Payload to make
	// pipeline-modified close events trivially round-trippable.
	payload, err := c.buildSendPayload(msg, wireDir)
	if err != nil {
		se := &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: "ws: " + err.Error(),
		}
		c.markTerminated(se)
		return se
	}

	// Apply per-direction compression if requested.
	if msg.Compressed && c.opts.deflateEnabled {
		ds := c.deflateForDirection(wireDir)
		if ds != nil {
			compressed, cerr := ds.compress(payload, c.opts.maxFrameSize)
			if cerr != nil {
				se := &layer.StreamError{
					Code:   layer.ErrorAborted,
					Reason: "ws: deflate compress: " + cerr.Error(),
				}
				c.markTerminated(se)
				return se
			}
			payload = compressed
			frame.RSV1 = true
		}
	}

	// Cap pre-mask payload size.
	maxSize := c.opts.maxFrameSize
	if maxSize <= 0 {
		maxSize = maxFramePayloadSize
	}
	if int64(len(payload)) > maxSize {
		se := &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: fmt.Sprintf("ws: send: payload too large: %d > %d", len(payload), maxSize),
		}
		c.markTerminated(se)
		return se
	}
	frame.Payload = payload

	// Mask iff RoleClient. crypto/rand for entropy per RFC 6455 §5.3.
	if c.role == RoleClient {
		var key [4]byte
		if _, rerr := rand.Read(key[:]); rerr != nil {
			se := &layer.StreamError{
				Code:   layer.ErrorAborted,
				Reason: "ws: send: mask gen: " + rerr.Error(),
			}
			c.markTerminated(se)
			return se
		}
		frame.Masked = true
		frame.MaskKey = key
	}

	if werr := WriteFrame(c.layer.writer, frame); werr != nil {
		se := &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: "ws: send: " + werr.Error(),
		}
		c.markTerminated(se)
		return se
	}
	return nil
}

// buildSendPayload reconstructs the wire payload from a WSMessage. For
// Close frames it prefers structured CloseCode+CloseReason; for other
// opcodes it returns Payload verbatim.
//
// wireDir is currently unused (kept for symmetry with Receive-side
// helpers in case future versions distinguish per-direction).
func (c *wsChannel) buildSendPayload(msg *envelope.WSMessage, wireDir envelope.Direction) ([]byte, error) {
	_ = wireDir
	if msg.Opcode != envelope.WSClose {
		return msg.Payload, nil
	}
	// Close: prefer structured fields when set.
	if msg.CloseCode == 0 && msg.CloseReason == "" && len(msg.Payload) == 0 {
		return nil, nil
	}
	if msg.CloseCode == 0 && len(msg.Payload) > 0 {
		// Caller filled Payload directly without using structured fields.
		return msg.Payload, nil
	}
	// CloseCode is set; reason may or may not be set.
	out := make([]byte, 2+len(msg.CloseReason))
	binary.BigEndian.PutUint16(out[:2], msg.CloseCode)
	copy(out[2:], msg.CloseReason)
	return out, nil
}

// cloneBytes returns a copy of b, or nil if b is nil/empty.
func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

package ws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// sendRawWins writes a raw-authoritative envelope's bytes (a plugin's
// msg["raw"], RFC-001 §9.3 D4) to the wire verbatim in a single Write.
// A write failure terminates the Channel exactly like a Message-path
// WriteFrame failure.
//
// permessage-deflate (RFC 7692): when the send direction negotiated
// deflate with context takeover, the peer's inflater appends every
// compressed message it decodes to its LZ77 window. The verbatim bytes
// bypass compress, so the Layer replays them through resyncSendDeflate
// to advance its own window identically; otherwise the next Message-path
// compressed frame would back-reference bytes the peer does not have
// at that distance and decode to garbage.
func (c *wsChannel) sendRawWins(ctx context.Context, raw []byte) error {
	if _, err := c.layer.writer.Write(raw); err != nil {
		se := &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: "ws: send: " + err.Error(),
		}
		c.markTerminated(se)
		return se
	}
	c.resyncSendDeflate(ctx, raw)
	return nil
}

// resyncSendDeflate parses raw as a sequence of frames and feeds the
// compressed data messages it carries through the send direction's
// deflateState, so its dictionary advances exactly as the peer's
// inflater does. Fragmented compressed messages are reassembled in the
// send-side fragment buffer, which may span several raw-wins envelopes.
//
// No-op when deflate is not negotiated for the send direction or
// no_context_takeover is in effect (every message then starts from an
// empty window on both ends). The bytes are already on the wire, so a
// parse or decompress failure only logs a Warn: the peer's window is
// unknown from here on and later compressed frames may not decode.
func (c *wsChannel) resyncSendDeflate(ctx context.Context, raw []byte) {
	wireDir := c.sendDirection()
	ds := c.deflateForDirection(wireDir)
	if ds == nil || !ds.params.contextTakeover {
		return
	}
	bufPtr, onPtr := c.fragStateForDirection(wireDir)
	r := bytes.NewReader(raw)
	for r.Len() > 0 {
		// Reject a frame whose header claims more bytes than raw holds
		// before ReadFrameRaw allocates the claimed payload length.
		err := checkRawFrameFits(raw[len(raw)-r.Len():])
		var frame *Frame
		if err == nil {
			frame, _, err = ReadFrameRaw(r)
		}
		if err == nil {
			err = advanceSendDeflate(ds, frame, bufPtr, onPtr, c.opts.decompressCap())
		}
		if err != nil {
			*bufPtr = (*bufPtr)[:0]
			*onPtr = false
			slog.WarnContext(ctx, "ws: raw-wins: deflate context resync failed; subsequent compressed frames may desync",
				slog.String("stream_id", c.streamID),
				slog.String("error", err.Error()),
			)
			return
		}
	}
}

// checkRawFrameFits reports an error when b does not hold the whole
// frame its header describes (header + extended length + mask key +
// claimed payload). It bounds the resync parse only; the bytes have
// already been written to the wire verbatim.
func checkRawFrameFits(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("truncated frame header: %d bytes", len(b))
	}
	r := bytes.NewReader(b[2:])
	payloadLen, err := decodePayloadLength(r, b[1]&0x7F)
	if err != nil {
		return err
	}
	avail := uint64(r.Len())
	if b[1]&0x80 != 0 {
		if avail < 4 {
			return fmt.Errorf("truncated frame: mask key needs 4 bytes, %d available", avail)
		}
		avail -= 4
	}
	if payloadLen > avail {
		return fmt.Errorf("truncated frame: header claims %d payload bytes, %d available", payloadLen, avail)
	}
	return nil
}

// advanceSendDeflate applies one parsed frame to the send-side deflate
// state: a compressed message's payload is decompressed (on its FIN
// frame) so ds's dictionary takes in the plaintext. Mirrors the
// receive-side applyDeflate state machine. Control frames are not
// compressed and do not interrupt a fragmented message.
func advanceSendDeflate(ds *deflateState, frame *Frame, bufPtr *[]byte, onPtr *bool, inflateCap int64) error {
	if frame.IsControl() {
		return nil
	}
	switch {
	case frame.Opcode != OpcodeContinuation:
		// A new data message; any unfinished one is abandoned.
		*bufPtr = (*bufPtr)[:0]
		*onPtr = false
		if !frame.RSV1 {
			return nil
		}
		if !frame.Fin {
			*bufPtr = append(*bufPtr, frame.Payload...)
			*onPtr = true
			return nil
		}
		_, err := ds.decompress(frame.Payload, inflateCap)
		return err
	case *onPtr:
		if se := validateFragmentAppend(len(*bufPtr), len(frame.Payload)); se != nil {
			return errors.New(se.Reason)
		}
		*bufPtr = append(*bufPtr, frame.Payload...)
		if !frame.Fin {
			return nil
		}
		_, err := ds.decompress(*bufPtr, inflateCap)
		*bufPtr = (*bufPtr)[:0]
		*onPtr = false
		return err
	default:
		// Continuation of an uncompressed message.
		return nil
	}
}

// resetRawWinsFragState discards a fragmented compressed message that
// raw-wins Sends started but did not finish when a Message-path data frame
// is about to be written on the same direction. Mixing raw-wins and
// Message-path fragments of one compressed message is not supported
// (USK-1238 D1); the partial state is dropped so it cannot leak into a
// later raw-wins message.
//
// Control frames (Close / Ping / Pong) leave the state alone: RFC 6455
// §5.4 allows them between the fragments of a data message, e.g. a
// relayed Ping or the USK-854 keepalive Ping during an intercept hold.
func (c *wsChannel) resetRawWinsFragState(ctx context.Context, wireDir envelope.Direction, opcode byte) {
	if (&Frame{Opcode: opcode}).IsControl() {
		return
	}
	bufPtr, onPtr := c.fragStateForDirection(wireDir)
	if !*onPtr {
		return
	}
	*bufPtr = (*bufPtr)[:0]
	*onPtr = false
	slog.DebugContext(ctx, "ws: raw-wins: Message-path frame interleaved with an unfinished raw-wins compressed message; send-side fragment state reset",
		slog.String("stream_id", c.streamID),
	)
}

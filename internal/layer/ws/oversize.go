package ws

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// Over-cap permessage-deflate messages (USK-1321).
//
// The receiving Layer inflates a compressed message for the L7 view and
// keeps at most decompressCap() bytes of it as WSMessage.Payload. When a
// message decompresses past the cap, the payload is a truncated view; the
// wire frame in Envelope.Raw is still complete. Such a message is marked
// with envelope.AnomalyWSDecompressedTooLarge (recorded with the flow) and
// carries a receivedFrame snapshot on Envelope.Opaque. On Send the
// relaying Layer writes the received frame verbatim when the message is
// unchanged, and refuses it otherwise — "cut the record, never the wire".
//
// Both relay legs are built from the same negotiated extension header and
// transport mode (session.go), so a frame received on one leg is valid on
// the other: same deflate parameters, masked toward the server on an
// HTTP/1.1 Upgrade, unmasked toward the client and on h2 (RFC 8441).
//
// The snapshot is only created for truncated messages (U1 of the design
// review); messages under the cap keep the re-compress path. Widening
// verbatim forwarding to every unmodified compressed frame means creating
// the snapshot for all compressed messages in markDecompressedTooLarge's
// caller and letting a modified, non-truncated message fall back to
// re-compression in Send.

// receivedFrame is the Layer-private Envelope.Opaque snapshot of an
// over-cap compressed message, taken by the receiving Channel and read by
// the relaying Channel's Send.
type receivedFrame struct {
	// raw is the received wire frame (shares Envelope.Raw's backing
	// array; wire bytes are never modified in place).
	raw []byte

	// The WSMessage fields as emitted, compared on Send to detect a
	// modification. Mask / Masked are excluded (as RecordStep's
	// wsMessageModified does); Payload is compared by length + SHA-256 so
	// an in-place edit of the slice is caught without a 16 MiB copy.
	opcode      envelope.WSOpcode
	fin         bool
	compressed  bool
	closeCode   uint16
	closeReason string
	payloadLen  int
	payloadSum  [sha256.Size]byte

	// inflateCap is the cap the payload was truncated at.
	inflateCap int64

	// contextTakeover and the windows before / after this message on the
	// receiving leg (nil without context takeover).
	contextTakeover bool
	windowBefore    []byte
	windowAfter     []byte
}

// unchanged reports whether msg still carries what the receiving Layer
// emitted.
func (r *receivedFrame) unchanged(msg *envelope.WSMessage) bool {
	if msg.Opcode != r.opcode || msg.Fin != r.fin || msg.Compressed != r.compressed {
		return false
	}
	if msg.CloseCode != r.closeCode || msg.CloseReason != r.closeReason {
		return false
	}
	return len(msg.Payload) == r.payloadLen && sha256.Sum256(msg.Payload) == r.payloadSum
}

// decompressedTooLargeDetail is the anomaly Detail for a message truncated
// at inflateCap. fullSize < 0 means the full size is unknown (no context
// takeover: the message is not inflated past the cap).
func decompressedTooLargeDetail(inflateCap, fullSize int64) string {
	d := fmt.Sprintf("decompressed payload exceeds %d bytes; recorded payload is the first %d bytes", inflateCap, inflateCap)
	if fullSize >= 0 {
		d += fmt.Sprintf(" of %d", fullSize)
	}
	return d
}

// markDecompressedTooLarge records the over-cap anomaly on msg and attaches
// the receivedFrame snapshot to env. Called by buildEnvelope after env.Raw
// and every msg field are final.
func (c *wsChannel) markDecompressedTooLarge(env *envelope.Envelope, msg *envelope.WSMessage, res *inflateResult, params deflateParams) {
	inflateCap := c.opts.decompressCap()
	msg.Anomalies = append(msg.Anomalies, envelope.Anomaly{
		Type:   envelope.AnomalyWSDecompressedTooLarge,
		Detail: decompressedTooLargeDetail(inflateCap, res.fullSize),
	})
	env.Opaque = &receivedFrame{
		raw:             env.Raw,
		opcode:          msg.Opcode,
		fin:             msg.Fin,
		compressed:      msg.Compressed,
		closeCode:       msg.CloseCode,
		closeReason:     msg.CloseReason,
		payloadLen:      len(msg.Payload),
		payloadSum:      sha256.Sum256(msg.Payload),
		inflateCap:      inflateCap,
		contextTakeover: params.contextTakeover,
		windowBefore:    res.windowBefore,
		windowAfter:     res.windowAfter,
	}
	slog.Debug("ws: permessage-deflate message exceeds the decompression cap; payload truncated for the record, wire frame kept",
		slog.String("stream_id", c.streamID),
		slog.Int64("cap", inflateCap),
		slog.Int64("full_size", res.fullSize),
	)
}

// receivedFrameOf returns the receivedFrame snapshot to send env with and
// whether Send must take the over-cap path: either the snapshot is
// present, or msg carries the over-cap anomaly without it (the envelope
// was cloned — e.g. an intercept modify_and_forward — and the snapshot
// dropped), in which case snap is nil and Send fails closed.
func receivedFrameOf(env *envelope.Envelope, msg *envelope.WSMessage) (snap *receivedFrame, ok bool) {
	if snap, ok = env.Opaque.(*receivedFrame); ok && snap != nil {
		return snap, true
	}
	for _, a := range msg.Anomalies {
		if a.Type == envelope.AnomalyWSDecompressedTooLarge {
			return nil, true
		}
	}
	return nil, false
}

// sendReceivedFrame writes an over-cap message's received wire frame
// verbatim when it may be forwarded unchanged, and otherwise refuses it.
//
// Refused (StreamError ErrorAborted, nothing written, Channel terminated):
//   - the snapshot is gone (cloned envelope) or msg was modified;
//   - this leg cannot carry the frame as received (deflate not negotiated
//     here, or a masking shape this Role must not emit);
//   - the frame's payload exceeds this leg's max_frame_size, the same
//     pre-mask cap a Message-path frame is held to;
//   - under context takeover, this leg's send window differs from the
//     receiving leg's window before the message — an earlier compressed
//     message in this direction was modified or dropped, so the frame's
//     back-references would decode to different bytes at the peer.
//
// After a verbatim write under context takeover the send window is set to
// the receiving leg's window after the message, so later re-compressed
// messages reference what the peer's inflater holds.
func (c *wsChannel) sendReceivedFrame(ctx context.Context, snap *receivedFrame, msg *envelope.WSMessage) error {
	if snap == nil {
		return c.refuseTruncated(c.opts.decompressCap(), "the Layer's received-frame snapshot was dropped (the envelope was cloned, e.g. by an intercept modify_and_forward)")
	}
	if !snap.unchanged(msg) {
		return c.refuseTruncated(snap.inflateCap, "the message was modified")
	}
	wireDir := c.sendDirection()
	ds := c.deflateForDirection(wireDir)
	if ds == nil || ds.params.contextTakeover != snap.contextTakeover {
		return c.refuseTruncated(snap.inflateCap, "permessage-deflate parameters differ on the sending leg")
	}
	if len(snap.raw) < 2 || (snap.raw[1]&0x80 != 0) != c.sendMasks() {
		return c.refuseTruncated(snap.inflateCap, "the received frame's masking does not fit the sending leg")
	}
	if se := c.checkReceivedFrameSize(snap.raw); se != nil {
		return se
	}
	if snap.contextTakeover && !ds.windowMatches(snap.windowBefore) {
		return c.refuseTruncated(snap.inflateCap, "the deflate window diverged (an earlier message in this direction was modified or dropped)")
	}

	c.resetRawWinsFragState(ctx, wireDir, byte(msg.Opcode))
	if _, err := c.layer.writer.Write(snap.raw); err != nil {
		se := &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: "ws: send: " + err.Error(),
		}
		c.markTerminated(se)
		return se
	}
	if snap.contextTakeover {
		ds.setWindow(snap.windowAfter)
	}
	return nil
}

// checkReceivedFrameSize applies the send-side max_frame_size to the
// payload length declared in raw's frame header (len(raw) >= 2 is checked
// by the caller).
func (c *wsChannel) checkReceivedFrameSize(raw []byte) *layer.StreamError {
	n, err := decodePayloadLength(bytes.NewReader(raw[2:]), raw[1]&0x7F)
	if err != nil {
		se := &layer.StreamError{
			Code:   layer.ErrorAborted,
			Reason: "ws: send: received frame header: " + err.Error(),
		}
		c.markTerminated(se)
		return se
	}
	return c.checkSendPayloadSize(n)
}

// sendMasks reports whether frames this Channel writes carry a mask: only
// client→server frames on an RFC 6455 transport (see applySendMask).
func (c *wsChannel) sendMasks() bool {
	return c.role == RoleClient && (c.opts == nil || !c.opts.h2Mode)
}

// refuseTruncated terminates the Channel with the StreamError reported for
// an over-cap message that cannot be forwarded intact.
func (c *wsChannel) refuseTruncated(inflateCap int64, why string) error {
	se := &layer.StreamError{
		Code: layer.ErrorAborted,
		Reason: fmt.Sprintf("ws: send: refusing to forward a message truncated at the %d-byte decompression cap: %s",
			inflateCap, why),
	}
	c.markTerminated(se)
	return se
}

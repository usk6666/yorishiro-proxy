package job

import (
	"context"
	"io"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// WSResendSource is an EnvelopeSource that yields a single WSMessage
// Envelope built from caller-supplied frame fields. Subsequent Next
// calls return io.EOF.
//
// The shape mirrors HTTPResendSource (one-shot, immutable spec) so the
// JobRunner can drive WS resends and fuzz variants through the same
// engine. The MCP resend_ws handler may use this source directly or
// build the envelope inline; both paths produce the same Envelope shape.
type WSResendSource struct {
	streamID string
	connID   string
	upgradeP string
	upgradeQ string
	msg      *envelope.WSMessage
	rawBytes []byte
	yielded  bool
}

// WSResendOverrides bundles the per-frame fields that fully describe a
// WS resend. Mask is supplied verbatim; the upstream-facing Layer (RoleClient)
// regenerates a fresh per-frame mask before write, so this field exists
// for variant/encoder symmetry rather than to influence the wire mask.
type WSResendOverrides struct {
	Opcode      envelope.WSOpcode
	Fin         bool
	Masked      bool
	Mask        [4]byte
	Payload     []byte
	CloseCode   uint16
	CloseReason string
	Compressed  bool

	// RawBytes seeds Envelope.Raw on the produced envelope. When set, the
	// PluginStepPost path treats unmodified envelopes as zero-copy and
	// RecordStep records these bytes as the Send Flow's RawBytes. nil =
	// leave Raw unset (RecordStep records empty RawBytes for unmodified).
	RawBytes []byte
}

// NewWSResendSource builds a one-shot WS source. streamID is stamped on
// the produced Envelope (RecordStep keys the new Stream row off it).
// connID + upgradePath + upgradeQuery populate EnvelopeContext so
// pluginv2 transaction-state lookups (USK-670) and downstream Pipeline
// Steps that consult upgrade fields see consistent values.
func NewWSResendSource(streamID, connID, upgradePath, upgradeQuery string, ov WSResendOverrides) *WSResendSource {
	msg := &envelope.WSMessage{
		Opcode:      ov.Opcode,
		Fin:         ov.Fin,
		Masked:      ov.Masked,
		Mask:        ov.Mask,
		Payload:     ov.Payload,
		CloseCode:   ov.CloseCode,
		CloseReason: ov.CloseReason,
		Compressed:  ov.Compressed,
	}
	return &WSResendSource{
		streamID: streamID,
		connID:   connID,
		upgradeP: upgradePath,
		upgradeQ: upgradeQuery,
		msg:      msg,
		rawBytes: ov.RawBytes,
	}
}

// Next returns the Envelope on first call, io.EOF on every subsequent
// call. The returned Envelope is freshly allocated; the caller may
// mutate it without affecting the source.
func (s *WSResendSource) Next(_ context.Context) (*envelope.Envelope, error) {
	if s.yielded {
		return nil, io.EOF
	}
	s.yielded = true

	env := &envelope.Envelope{
		StreamID:  s.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Raw:       s.rawBytes,
		Message:   s.msg,
		Context: envelope.EnvelopeContext{
			ConnID:       s.connID,
			UpgradePath:  s.upgradeP,
			UpgradeQuery: s.upgradeQ,
		},
	}
	return env, nil
}

package job

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// RawResendOverrides holds user-specified overrides for a raw resend.
type RawResendOverrides struct {
	// OverrideBytes, when non-nil, replaces the entire raw payload.
	// This is mutually exclusive with Patches.
	OverrideBytes []byte

	// Patches applies offset-based byte patches to the original raw bytes.
	// Ignored when OverrideBytes is non-nil.
	Patches []BytePatch
}

// RawResendSource is an EnvelopeSource that yields a single RawMessage
// Envelope reconstructed from a recorded flow with optional byte overrides.
type RawResendSource struct {
	reader    flow.Reader
	streamID  string
	overrides RawResendOverrides
	yielded   bool
}

// NewRawResendSource creates a source that fetches the send flow for the
// given stream and yields it as a RawMessage Envelope with overrides applied.
func NewRawResendSource(reader flow.Reader, streamID string, overrides RawResendOverrides) *RawResendSource {
	return &RawResendSource{
		reader:    reader,
		streamID:  streamID,
		overrides: overrides,
	}
}

// Next returns the Envelope on first call, io.EOF on subsequent calls.
func (s *RawResendSource) Next(ctx context.Context) (*envelope.Envelope, error) {
	if s.yielded {
		return nil, io.EOF
	}
	s.yielded = true

	sendFlow, err := s.fetchSendFlow(ctx)
	if err != nil {
		return nil, fmt.Errorf("raw resend source: %w", err)
	}

	rawBytes := s.resolveBytes(sendFlow)
	rawBytes = s.applyOverrides(rawBytes)

	env := &envelope.Envelope{
		FlowID:    uuid.NewString(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Raw:       rawBytes,
		Message:   &envelope.RawMessage{Bytes: rawBytes},
	}

	return env, nil
}

// fetchSendFlow retrieves the first send-direction flow for the stream.
func (s *RawResendSource) fetchSendFlow(ctx context.Context) (*flow.Flow, error) {
	flows, err := s.reader.GetFlows(ctx, s.streamID, flow.FlowListOptions{
		Direction: "send",
	})
	if err != nil {
		return nil, fmt.Errorf("get flows for stream %s: %w", s.streamID, err)
	}
	if len(flows) == 0 {
		return nil, fmt.Errorf("no send flow found for stream %s", s.streamID)
	}
	return flows[0], nil
}

// resolveBytes extracts raw bytes from the flow. Prefers RawBytes (wire-observed);
// falls back to Body if RawBytes is nil.
func (s *RawResendSource) resolveBytes(f *flow.Flow) []byte {
	if f.RawBytes != nil {
		return f.RawBytes
	}
	return f.Body
}

// applyOverrides applies the configured byte overrides to the raw bytes.
func (s *RawResendSource) applyOverrides(raw []byte) []byte {
	if s.overrides.OverrideBytes != nil {
		return s.overrides.OverrideBytes
	}
	if len(s.overrides.Patches) > 0 {
		return ApplyPatches(raw, s.overrides.Patches)
	}
	// No overrides — return a copy to avoid aliasing with the flow store.
	dst := make([]byte, len(raw))
	copy(dst, raw)
	return dst
}

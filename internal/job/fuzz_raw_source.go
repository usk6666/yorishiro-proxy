package job

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// RawFuzzPosition defines a byte-offset position for raw payload injection.
type RawFuzzPosition struct {
	// ID is the unique identifier for this position.
	ID string
	// Offset is the byte offset in the raw data where the payload is injected.
	Offset int
	// Length is the number of bytes to replace. If 0, the payload is inserted.
	Length int
	// PayloadSet is the name of the payload set for this position.
	PayloadSet string
}

// FuzzRawSource is an EnvelopeSource that yields RawMessage Envelopes
// with fuzz payloads injected at byte-offset positions. Supports
// sequential iteration (one position at a time, all payloads).
type FuzzRawSource struct {
	reader   flow.Reader
	streamID string
	kvStore  map[string]string

	positions        []RawFuzzPosition
	resolvedPayloads map[string][]string

	baseBytes   []byte
	initialized bool
	posIdx      int
	payloadIdx  int
	index       int
	total       int
}

// FuzzRawConfig configures a FuzzRawSource.
type FuzzRawConfig struct {
	// Reader provides access to the flow store.
	Reader flow.Reader
	// StreamID is the base flow stream to fuzz.
	StreamID string
	// Positions defines byte-offset injection points.
	Positions []RawFuzzPosition
	// ResolvedPayloads maps payload set name to resolved payload strings.
	ResolvedPayloads map[string][]string
	// KVStore for template expansion. May be nil.
	KVStore map[string]string
}

// NewFuzzRawSource creates a fuzz source for raw byte payloads.
func NewFuzzRawSource(cfg FuzzRawConfig) (*FuzzRawSource, error) {
	total := 0
	for _, pos := range cfg.Positions {
		payloads, ok := cfg.ResolvedPayloads[pos.PayloadSet]
		if !ok {
			return nil, fmt.Errorf("fuzz raw source: payload set %q not found for position %q", pos.PayloadSet, pos.ID)
		}
		total += len(payloads)
	}

	return &FuzzRawSource{
		reader:           cfg.Reader,
		streamID:         cfg.StreamID,
		positions:        cfg.Positions,
		resolvedPayloads: cfg.ResolvedPayloads,
		kvStore:          cfg.KVStore,
		total:            total,
	}, nil
}

// Total returns the total number of fuzz iterations.
func (s *FuzzRawSource) Total() int {
	return s.total
}

// Next returns the next fuzz Envelope or io.EOF when exhausted.
func (s *FuzzRawSource) Next(ctx context.Context) (*envelope.Envelope, error) {
	if !s.initialized {
		if err := s.init(ctx); err != nil {
			return nil, err
		}
	}

	for s.posIdx < len(s.positions) {
		pos := s.positions[s.posIdx]
		payloads := s.resolvedPayloads[pos.PayloadSet]

		if s.payloadIdx >= len(payloads) {
			s.posIdx++
			s.payloadIdx = 0
			continue
		}

		payload := payloads[s.payloadIdx]
		s.payloadIdx++
		s.index++

		data := s.applyRawFuzz(pos, []byte(payload))

		env := &envelope.Envelope{
			FlowID:    uuid.NewString(),
			Sequence:  s.index - 1,
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolRaw,
			Raw:       data,
			Message:   &envelope.RawMessage{Bytes: data},
		}

		if len(s.kvStore) > 0 {
			if err := ExpandEnvelopeTemplates(env, s.kvStore); err != nil {
				return nil, fmt.Errorf("fuzz raw source: template expansion: %w", err)
			}
		}

		return env, nil
	}

	return nil, io.EOF
}

// init fetches the base flow raw bytes.
func (s *FuzzRawSource) init(ctx context.Context) error {
	flows, err := s.reader.GetFlows(ctx, s.streamID, flow.FlowListOptions{
		Direction: "send",
	})
	if err != nil {
		return fmt.Errorf("fuzz raw source: get flows: %w", err)
	}
	if len(flows) == 0 {
		return fmt.Errorf("fuzz raw source: no send flow for stream %s", s.streamID)
	}

	f := flows[0]
	if f.RawBytes != nil {
		s.baseBytes = f.RawBytes
	} else {
		s.baseBytes = f.Body
	}
	s.initialized = true
	return nil
}

// applyRawFuzz replaces bytes at the position's offset with the payload.
func (s *FuzzRawSource) applyRawFuzz(pos RawFuzzPosition, payload []byte) []byte {
	src := s.baseBytes
	if pos.Offset > len(src) {
		pos.Offset = len(src)
	}

	length := pos.Length
	if pos.Offset+length > len(src) {
		length = len(src) - pos.Offset
	}

	// Build: prefix + payload + suffix
	var b strings.Builder
	b.Grow(pos.Offset + len(payload) + (len(src) - pos.Offset - length))
	b.Write(src[:pos.Offset])
	b.Write(payload)
	if pos.Offset+length < len(src) {
		b.Write(src[pos.Offset+length:])
	}

	return []byte(b.String())
}

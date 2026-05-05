package pipeline

import (
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// WireEncoderRegistry maps envelope.Protocol to per-protocol WireEncoder.
//
// One instance is shared between RecordStep (which uses encoders to produce
// the post-mutation "modified" variant's recorded bytes) and PluginStepPost
// (which uses encoders to regenerate Envelope.Raw after a plugin's
// MessageOnly mutation so the bytes shipped on the wire reflect the plugin's
// edit). The orchestrator constructs one registry, registers every available
// per-protocol encoder, and passes the same pointer to both Steps.
//
// A nil receiver is safe — Lookup returns (nil, false). This lets callers
// defer registry construction without nil-checking at every Step.
type WireEncoderRegistry struct {
	mu       sync.RWMutex
	encoders map[envelope.Protocol]WireEncoder
}

// NewWireEncoderRegistry returns an empty registry.
func NewWireEncoderRegistry() *WireEncoderRegistry {
	return &WireEncoderRegistry{encoders: make(map[envelope.Protocol]WireEncoder)}
}

// Register installs fn as the encoder for proto. Passing a nil fn removes
// any prior registration. Re-registering replaces the existing encoder.
func (r *WireEncoderRegistry) Register(proto envelope.Protocol, fn WireEncoder) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.encoders == nil {
		r.encoders = make(map[envelope.Protocol]WireEncoder)
	}
	if fn == nil {
		delete(r.encoders, proto)
		return
	}
	r.encoders[proto] = fn
}

// Lookup returns the encoder registered for proto. The second return value
// is false when no encoder is registered (or the registry is nil).
func (r *WireEncoderRegistry) Lookup(proto envelope.Protocol) (WireEncoder, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.encoders[proto]
	return fn, ok
}

// Len reports the number of registered encoders. Used by tests.
func (r *WireEncoderRegistry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.encoders)
}

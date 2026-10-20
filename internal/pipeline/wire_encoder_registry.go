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
// The registry also carries per-protocol RawWinsPolicy predicates that
// PluginStepPre/Post consult before honouring a plugin's msg["raw"]
// (RFC-001 §9.3 D4; see RawWinsSupported).
//
// A nil receiver is safe — Lookup returns (nil, false). This lets callers
// defer registry construction without nil-checking at every Step.
type WireEncoderRegistry struct {
	mu       sync.RWMutex
	encoders map[envelope.Protocol]WireEncoder
	rawWins  map[envelope.Protocol]RawWinsPolicy
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

// RawWinsPolicy reports whether the Layer that writes env to the wire can
// honour a plugin's msg["raw"] verbatim (RFC-001 §9.3 D4 "Raw wins").
// Policies are owned by the Layer packages (next to their EncodeWireBytes)
// and registered per route, because the same envelope.Protocol can reach
// Layers with different abilities: an HTTPMessage bound for HTTP/1.x can
// be written verbatim, one bound for HTTP/2 cannot (its Raw is unframed
// HPACK against the source connection's dynamic table).
type RawWinsPolicy func(env *envelope.Envelope) bool

// RegisterRawWinsPolicy installs fn as the raw-wins policy for proto.
// Passing a nil fn removes any prior registration.
func (r *WireEncoderRegistry) RegisterRawWinsPolicy(proto envelope.Protocol, fn RawWinsPolicy) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rawWins == nil {
		r.rawWins = make(map[envelope.Protocol]RawWinsPolicy)
	}
	if fn == nil {
		delete(r.rawWins, proto)
		return
	}
	r.rawWins[proto] = fn
}

// RawWinsSupported reports whether a plugin-authored Raw on env can be
// written verbatim by the destination Layer. A nil registry, a nil env,
// or a protocol without a registered policy defaults to supported — the
// pre-policy behaviour, under which the Layer itself decides.
func (r *WireEncoderRegistry) RawWinsSupported(env *envelope.Envelope) bool {
	if r == nil || env == nil {
		return true
	}
	r.mu.RLock()
	fn, ok := r.rawWins[env.Protocol]
	r.mu.RUnlock()
	if !ok {
		return true
	}
	return fn(env)
}

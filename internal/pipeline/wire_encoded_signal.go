package pipeline

import "context"

// wireEncodedKey is the private context.Context key under which Pipeline.Run
// installs a *wireEncodedState sidecar for cross-Step signaling that
// Envelope.Raw IS the WireEncoder output for the envelope's current Message.
//
// Semantic — "Raw IS encoder output for current Message". The flag is
// generic; it does NOT mean "PluginStepPost was here." Any Step that
// re-renders Raw from a per-protocol WireEncoder may set it.
//
// When set, RecordStep skips a second call to the same encoder when
// recording the modified variant — Envelope.Raw, copied into
// flow.Flow.RawBytes by envelopeToFlow, already equals what the encoder
// would re-produce.
//
// Lifetime — bounded to one Pipeline.Run call. Pipeline.Run installs the
// sidecar once before the Step loop, mirroring the snapshotKey precedent
// in snapshot.go. The Step loop is single-goroutine per envelope, so the
// embedded bool needs no synchronization.
//
// NOT set when:
//   - The encoder failed soft (returned (nil, nil)).
//   - The encoder returned ErrPartialWireBytes (or any non-nil error).
//   - No encoder was registered for the envelope's Protocol.
//   - The mutation took a path that did not invoke the encoder
//     (RawOnly / Both — Raw is verbatim user bytes per RFC §9.3 D4).
//
// In all those cases env.Raw is NOT the encoder output for the current
// Message; RecordStep must run applyWireEncode so the modified variant
// gets the correct `wire_bytes=unavailable` / `wire_bytes=partial`
// Metadata tag (or, for RawOnly/Both, the encoder-rendered modified-variant
// bytes per the existing pre-USK-684 behavior — the cousin "raw wins"
// observation in the modified-variant record path is intentionally
// out of scope for USK-684).
type wireEncodedKey struct{}

// wireEncodedState is the per-Run sidecar carrying the flag. Pipeline.Run
// installs one before the Step loop; Steps that consume or mutate it look
// up the pointer via wireEncodedStateFromContext and read/write Encoded
// directly.
//
// The struct is intentionally tiny (one bool) because we expect to grow it
// only if a future Step needs additional Pipeline-internal signals along
// the same lifetime.
type wireEncodedState struct {
	Encoded bool
}

// withWireEncodedState installs a fresh *wireEncodedState in ctx. Called
// once by Pipeline.Run before the Step loop.
func withWireEncodedState(ctx context.Context) context.Context {
	return context.WithValue(ctx, wireEncodedKey{}, &wireEncodedState{})
}

// wireEncodedStateFromContext retrieves the *wireEncodedState installed by
// Pipeline.Run. Returns nil when ctx was not produced by Pipeline.Run
// (e.g., a Step exercised directly from a unit test) — callers must
// nil-check and treat the absence as "do not skip", matching pre-USK-684
// behavior.
func wireEncodedStateFromContext(ctx context.Context) *wireEncodedState {
	v, _ := ctx.Value(wireEncodedKey{}).(*wireEncodedState)
	return v
}

// wireEncodedFromContext is the read-only convenience used by RecordStep:
// reports true only when Pipeline.Run installed a sidecar AND a preceding
// Step flipped Encoded to true. Absence of the sidecar (direct-Step unit
// tests) reports false, matching pre-USK-684 behavior.
func wireEncodedFromContext(ctx context.Context) bool {
	state := wireEncodedStateFromContext(ctx)
	return state != nil && state.Encoded
}

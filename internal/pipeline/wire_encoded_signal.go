package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// wireEncodedKey is the private context.Context key under which Pipeline.Run
// installs a *wireEncodedState sidecar for cross-Step signaling about the
// relationship between Envelope.Raw and Envelope.Message after each Step.
//
// The state carries one flag, Encoded (USK-684): Raw IS the WireEncoder
// output for the envelope's current Message. Set by PluginStepPost's
// regenerateRaw on encoder success; lets RecordStep skip a redundant
// second encoder call when recording the modified variant.
//
// RFC §9.3 D4 "raw wins" (USK-686) used to be a second flag here. It now
// lives on the envelope (Envelope.RawAuthoritative, USK-1079): the Layer
// writes the wire after Pipeline.Run returns, with a different ctx, so a
// ctx-scoped flag could never reach it. RecordStep consults both — see
// shouldSkipEncoder.
//
// Lifetime — bounded to one Pipeline.Run call. Pipeline.Run installs the
// sidecar once before the Step loop, mirroring the snapshotKey precedent
// in snapshot.go. The Step loop is single-goroutine per envelope, so the
// embedded bool needs no synchronization.
type wireEncodedKey struct{}

// wireEncodedState is the per-Run sidecar carrying the flag. Pipeline.Run
// installs one before the Step loop; Steps that consume or mutate it look
// up the pointer via wireEncodedStateFromContext and read/write through
// the marker helpers below.
type wireEncodedState struct {
	// Encoded reports that env.Raw IS the WireEncoder output for the
	// envelope's current Message (USK-684). Set on regenerateRaw success.
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

// wireEncodedFromContext reports whether the Encoded flag is set.
func wireEncodedFromContext(ctx context.Context) bool {
	state := wireEncodedStateFromContext(ctx)
	return state != nil && state.Encoded
}

// shouldSkipEncoder reports whether RecordStep should skip its
// applyWireEncode call for the modified variant of env. Returns true when
// env.Raw already matches the desired record bytes:
//
//   - env.RawWins() (RFC §9.3 D4, USK-686 / USK-1079): Raw is
//     user-verbatim and is what the Layer writes; the encoder would
//     overwrite the plugin's bytes with a "cleaned-up" form.
//   - Encoded (USK-684): a prior Step rendered Raw via the encoder, so
//     another call would be redundant. Requires a non-empty Raw — a later
//     Step (intercept modify) may have replaced the envelope with Raw=nil,
//     and skipping then would record nil RawBytes.
func shouldSkipEncoder(ctx context.Context, env *envelope.Envelope) bool {
	if env.RawWins() {
		return true
	}
	return wireEncodedFromContext(ctx) && len(env.Raw) > 0
}

// markWireEncoded sets Encoded=true. Used by regenerateRaw on encoder
// success: env.Raw is now the encoder output for the current Message.
func markWireEncoded(ctx context.Context) {
	if state := wireEncodedStateFromContext(ctx); state != nil {
		state.Encoded = true
	}
}

// clearWireEncoded clears the Encoded flag. Used on regenerateRaw
// fail-soft / partial / error / no-encoder paths where env.Raw is
// preserved as originalRaw, and on a plugin msg["raw"] write where Raw is
// user-verbatim. No-op when ctx was not produced by Pipeline.Run.
func clearWireEncoded(ctx context.Context) {
	if state := wireEncodedStateFromContext(ctx); state != nil {
		state.Encoded = false
	}
}

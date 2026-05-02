package pipeline

import "context"

// wireEncodedKey is the private context.Context key under which Pipeline.Run
// installs a *wireEncodedState sidecar for cross-Step signaling about the
// relationship between Envelope.Raw and Envelope.Message after each Step.
//
// Two orthogonal flags are carried on the state:
//
//   - Encoded (USK-684): Raw IS the WireEncoder output for the envelope's
//     current Message. Set by PluginStepPost's regenerateRaw on encoder
//     success; lets RecordStep skip a redundant second encoder call when
//     recording the modified variant.
//
//   - RawAuthoritative (USK-686): Raw IS user-verbatim bytes the plugin
//     injected via msg["raw"] (RFC §9.3 D4 "raw wins"). Set by
//     PluginStepPost's applyMutation on MutationRawOnly / MutationBoth. The
//     encoder MUST NOT run when this flag is set — running it would
//     overwrite the user's smuggling-test bytes with a "cleaned-up"
//     re-encoded form, destroying the diagnostic signal that motivated D4.
//
// The two flags are mutually exclusive in practice: Raw cannot be both
// encoder output AND user-verbatim. Setters preserve this invariant by
// clearing the opposite flag.
//
// RecordStep skips applyWireEncode when EITHER flag is set. The shared
// shouldSkipEncoder helper hides this from the consumer site.
//
// Lifetime — bounded to one Pipeline.Run call. Pipeline.Run installs the
// sidecar once before the Step loop, mirroring the snapshotKey precedent
// in snapshot.go. The Step loop is single-goroutine per envelope, so the
// embedded bools need no synchronization.
type wireEncodedKey struct{}

// wireEncodedState is the per-Run sidecar carrying the flags. Pipeline.Run
// installs one before the Step loop; Steps that consume or mutate it look
// up the pointer via wireEncodedStateFromContext and read/write through
// the marker helpers below.
type wireEncodedState struct {
	// Encoded reports that env.Raw IS the WireEncoder output for the
	// envelope's current Message (USK-684). Set on regenerateRaw success.
	Encoded bool
	// RawAuthoritative reports that env.Raw IS user-verbatim bytes per
	// RFC §9.3 D4 raw-wins (USK-686). Set on MutationRawOnly /
	// MutationBoth.
	RawAuthoritative bool
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

// wireEncodedFromContext reports whether the Encoded flag is set. Used by
// callers that specifically care about the USK-684 dedup semantic. Most
// consumers want shouldSkipEncoder instead.
func wireEncodedFromContext(ctx context.Context) bool {
	state := wireEncodedStateFromContext(ctx)
	return state != nil && state.Encoded
}

// rawAuthoritativeFromContext reports whether the RawAuthoritative flag is
// set. Used by callers that specifically care about the RFC §9.3 D4
// raw-wins semantic. Most consumers want shouldSkipEncoder instead.
func rawAuthoritativeFromContext(ctx context.Context) bool {
	state := wireEncodedStateFromContext(ctx)
	return state != nil && state.RawAuthoritative
}

// shouldSkipEncoder reports whether RecordStep should skip its
// applyWireEncode call for the modified variant. Returns true when env.Raw
// already matches the desired record bytes — either because a prior Step
// rendered Raw via the encoder (Encoded) or because Raw is user-verbatim
// per RFC §9.3 D4 (RawAuthoritative). In both cases another encoder call
// would be redundant or actively destructive.
func shouldSkipEncoder(ctx context.Context) bool {
	state := wireEncodedStateFromContext(ctx)
	return state != nil && (state.Encoded || state.RawAuthoritative)
}

// markWireEncoded sets Encoded=true and clears RawAuthoritative. Used by
// regenerateRaw on encoder success: env.Raw is now the encoder output for
// the current Message and is no longer (whatever it was before — possibly
// user-verbatim from a prior RawOnly arm in the same hook chain).
func markWireEncoded(ctx context.Context) {
	if state := wireEncodedStateFromContext(ctx); state != nil {
		state.Encoded = true
		state.RawAuthoritative = false
	}
}

// markRawAuthoritative sets RawAuthoritative=true and clears Encoded. Used
// by applyMutation's MutationRawOnly and MutationBoth arms: env.Raw is the
// user-supplied verbatim bytes and the encoder must not be invoked
// downstream (RFC §9.3 D4).
func markRawAuthoritative(ctx context.Context) {
	if state := wireEncodedStateFromContext(ctx); state != nil {
		state.RawAuthoritative = true
		state.Encoded = false
	}
}

// clearWireEncoded clears both flags. Used on regenerateRaw fail-soft /
// partial / error / no-encoder paths where env.Raw is preserved as
// originalRaw and neither "encoder output" nor "user-verbatim" applies to
// the post-mutation Raw. No-op when ctx was not produced by Pipeline.Run.
func clearWireEncoded(ctx context.Context) {
	if state := wireEncodedStateFromContext(ctx); state != nil {
		state.Encoded = false
		state.RawAuthoritative = false
	}
}

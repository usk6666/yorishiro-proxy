package pipeline

import (
	"context"
	"testing"
)

func TestWireEncodedFromContext_AbsentDefaultsFalse(t *testing.T) {
	if wireEncodedFromContext(context.Background()) {
		t.Error("absent state must default to false")
	}
}

func TestRawAuthoritativeFromContext_AbsentDefaultsFalse(t *testing.T) {
	if rawAuthoritativeFromContext(context.Background()) {
		t.Error("absent state must default to false")
	}
}

func TestShouldSkipEncoder_AbsentDefaultsFalse(t *testing.T) {
	if shouldSkipEncoder(context.Background()) {
		t.Error("absent state must default to false")
	}
}

func TestWireEncodedStateFromContext_AbsentReturnsNil(t *testing.T) {
	if got := wireEncodedStateFromContext(context.Background()); got != nil {
		t.Errorf("absent state must return nil, got %+v", got)
	}
}

func TestWithWireEncodedState_InstallsFreshState(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	if state == nil {
		t.Fatal("withWireEncodedState must install a non-nil state")
	}
	if state.Encoded {
		t.Error("freshly installed state must have Encoded=false")
	}
	if state.RawAuthoritative {
		t.Error("freshly installed state must have RawAuthoritative=false")
	}
}

func TestWireEncodedFromContext_ReadsAfterStateMutation(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	if state == nil {
		t.Fatal("state nil")
	}

	if wireEncodedFromContext(ctx) {
		t.Error("Encoded=false must read as false")
	}

	state.Encoded = true
	if !wireEncodedFromContext(ctx) {
		t.Error("Encoded=true must read as true via the same ctx")
	}

	state.Encoded = false
	if wireEncodedFromContext(ctx) {
		t.Error("clearing Encoded must read as false")
	}
}

func TestRawAuthoritativeFromContext_ReadsAfterStateMutation(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	if state == nil {
		t.Fatal("state nil")
	}

	if rawAuthoritativeFromContext(ctx) {
		t.Error("RawAuthoritative=false must read as false")
	}

	state.RawAuthoritative = true
	if !rawAuthoritativeFromContext(ctx) {
		t.Error("RawAuthoritative=true must read as true via the same ctx")
	}

	state.RawAuthoritative = false
	if rawAuthoritativeFromContext(ctx) {
		t.Error("clearing RawAuthoritative must read as false")
	}
}

// TestShouldSkipEncoder_OrsBothFlags verifies the helper's semantics:
// returns true when EITHER flag is set, false when both are clear.
func TestShouldSkipEncoder_OrsBothFlags(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	if shouldSkipEncoder(ctx) {
		t.Error("both flags clear must yield false")
	}

	state.Encoded = true
	if !shouldSkipEncoder(ctx) {
		t.Error("Encoded=true must yield true")
	}
	state.Encoded = false

	state.RawAuthoritative = true
	if !shouldSkipEncoder(ctx) {
		t.Error("RawAuthoritative=true must yield true")
	}
	state.RawAuthoritative = false

	if shouldSkipEncoder(ctx) {
		t.Error("clearing both flags must yield false again")
	}
}

func TestClearWireEncoded_NoOpWhenStateAbsent(t *testing.T) {
	// Must not panic even when ctx has no state.
	clearWireEncoded(context.Background())
}

// TestClearWireEncoded_FlipsBothFlagsToFalse verifies that the broadened
// clear (USK-686) zeroes out both Encoded and RawAuthoritative — the
// fail-soft / no-encoder paths in regenerateRaw rely on this to wipe any
// prior chain step's flags.
func TestClearWireEncoded_FlipsBothFlagsToFalse(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	state.Encoded = true
	state.RawAuthoritative = true

	clearWireEncoded(ctx)
	if state.Encoded {
		t.Error("clearWireEncoded must flip Encoded to false")
	}
	if state.RawAuthoritative {
		t.Error("clearWireEncoded must flip RawAuthoritative to false")
	}
}

// TestMarkWireEncoded_SetsEncodedAndClearsRawAuthoritative verifies the
// mutual-exclusion invariant: marking Encoded must clear RawAuthoritative
// (Raw cannot be both encoder output AND user-verbatim).
func TestMarkWireEncoded_SetsEncodedAndClearsRawAuthoritative(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	state.RawAuthoritative = true

	markWireEncoded(ctx)
	if !state.Encoded {
		t.Error("markWireEncoded must set Encoded=true")
	}
	if state.RawAuthoritative {
		t.Error("markWireEncoded must clear RawAuthoritative")
	}
}

// TestMarkRawAuthoritative_SetsRawAuthoritativeAndClearsEncoded verifies
// the mutual-exclusion invariant in the other direction.
func TestMarkRawAuthoritative_SetsRawAuthoritativeAndClearsEncoded(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	state.Encoded = true

	markRawAuthoritative(ctx)
	if !state.RawAuthoritative {
		t.Error("markRawAuthoritative must set RawAuthoritative=true")
	}
	if state.Encoded {
		t.Error("markRawAuthoritative must clear Encoded")
	}
}

func TestMarkWireEncoded_NoOpWhenStateAbsent(t *testing.T) {
	// Must not panic when ctx has no state.
	markWireEncoded(context.Background())
}

func TestMarkRawAuthoritative_NoOpWhenStateAbsent(t *testing.T) {
	// Must not panic when ctx has no state.
	markRawAuthoritative(context.Background())
}

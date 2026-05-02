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

func TestClearWireEncoded_NoOpWhenStateAbsent(t *testing.T) {
	// Must not panic even when ctx has no state.
	clearWireEncoded(context.Background())
}

func TestClearWireEncoded_FlipsToFalseWhenStatePresent(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	state.Encoded = true

	clearWireEncoded(ctx)
	if state.Encoded {
		t.Error("clearWireEncoded must flip Encoded to false")
	}
}

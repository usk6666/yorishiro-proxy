package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestWireEncodedFromContext_AbsentDefaultsFalse(t *testing.T) {
	if wireEncodedFromContext(context.Background()) {
		t.Error("absent state must default to false")
	}
}

func TestShouldSkipEncoder_AbsentDefaultsFalse(t *testing.T) {
	if shouldSkipEncoder(context.Background(), &envelope.Envelope{Raw: []byte("x")}) {
		t.Error("absent state on an unmarked envelope must default to false")
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

// TestShouldSkipEncoder_Signals verifies the helper's semantics: skip when
// the envelope is raw-wins (RFC §9.3 D4) or when Raw is encoder output
// (USK-684) and still present; otherwise run the encoder.
func TestShouldSkipEncoder_Signals(t *testing.T) {
	tests := []struct {
		name    string
		encoded bool
		auth    bool
		raw     []byte
		want    bool
	}{
		{name: "no signal", raw: []byte("x"), want: false},
		{name: "encoded", encoded: true, raw: []byte("x"), want: true},
		{name: "encoded but Raw cleared", encoded: true, raw: nil, want: false},
		{name: "raw wins", auth: true, raw: []byte("x"), want: true},
		{name: "raw-wins marker but Raw cleared", auth: true, raw: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := withWireEncodedState(context.Background())
			wireEncodedStateFromContext(ctx).Encoded = tt.encoded
			env := &envelope.Envelope{Raw: tt.raw, RawAuthoritative: tt.auth}
			if got := shouldSkipEncoder(ctx, env); got != tt.want {
				t.Errorf("shouldSkipEncoder = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClearWireEncoded_NoOpWhenStateAbsent(t *testing.T) {
	// Must not panic even when ctx has no state.
	clearWireEncoded(context.Background())
}

func TestClearWireEncoded_FlipsEncodedToFalse(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)
	state.Encoded = true

	clearWireEncoded(ctx)
	if state.Encoded {
		t.Error("clearWireEncoded must flip Encoded to false")
	}
}

func TestMarkWireEncoded_SetsEncoded(t *testing.T) {
	ctx := withWireEncodedState(context.Background())
	state := wireEncodedStateFromContext(ctx)

	markWireEncoded(ctx)
	if !state.Encoded {
		t.Error("markWireEncoded must set Encoded=true")
	}
}

func TestMarkWireEncoded_NoOpWhenStateAbsent(t *testing.T) {
	// Must not panic when ctx has no state.
	markWireEncoded(context.Background())
}

package layer

import (
	"errors"
	"fmt"
	"testing"
)

func TestStreamError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *StreamError
		want string
	}{
		{
			name: "with reason",
			err:  &StreamError{Code: ErrorCanceled, Reason: "user abort"},
			want: "stream error canceled: user abort",
		},
		{
			name: "without reason",
			err:  &StreamError{Code: ErrorProtocol},
			want: "stream error protocol_error",
		},
		{
			name: "internal error with reason",
			err:  &StreamError{Code: ErrorInternalError, Reason: "panic recovered"},
			want: "stream error internal_error: panic recovered",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStreamError_Is(t *testing.T) {
	canceled := &StreamError{Code: ErrorCanceled, Reason: "ctx done"}
	canceledOther := &StreamError{Code: ErrorCanceled, Reason: "different reason"}
	protocol := &StreamError{Code: ErrorProtocol}

	// Same code matches regardless of reason
	if !errors.Is(canceled, canceledOther) {
		t.Error("errors.Is should match StreamErrors with same Code")
	}

	// Different code does not match
	if errors.Is(canceled, protocol) {
		t.Error("errors.Is should not match StreamErrors with different Code")
	}

	// Wrapped StreamError is findable
	wrapped := fmt.Errorf("wrapper: %w", canceled)
	if !errors.Is(wrapped, canceledOther) {
		t.Error("errors.Is should find wrapped StreamError")
	}

	// Non-StreamError target does not match
	if errors.Is(canceled, errors.New("something else")) {
		t.Error("errors.Is should not match non-StreamError target")
	}
}

func TestErrorCode_String(t *testing.T) {
	tests := []struct {
		code ErrorCode
		want string
	}{
		{ErrorCanceled, "canceled"},
		{ErrorAborted, "aborted"},
		{ErrorInternalError, "internal_error"},
		{ErrorRefused, "refused"},
		{ErrorProtocol, "protocol_error"},
		{ErrorCode(9999), "unknown(9999)"},
	}
	for _, tt := range tests {
		if got := tt.code.String(); got != tt.want {
			t.Errorf("ErrorCode(%d).String() = %q, want %q", tt.code, got, tt.want)
		}
	}
}

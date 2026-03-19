package proxy

import (
	"context"
	"testing"
)

func TestForwardTargetContext(t *testing.T) {
	tests := []struct {
		name      string
		target    string
		setEmpty  bool // when true, call ContextWithForwardTarget even for empty target
		wantFound bool
		wantValue string
	}{
		{
			name:      "set target",
			target:    "example.com:8080",
			wantFound: true,
			wantValue: "example.com:8080",
		},
		{
			name:      "empty target treated as not set",
			target:    "", // explicitly set via ContextWithForwardTarget below
			setEmpty:  true,
			wantFound: false,
			wantValue: "",
		},
		{
			name:      "ip:port target",
			target:    "192.168.1.1:443",
			wantFound: true,
			wantValue: "192.168.1.1:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.target != "" || tt.setEmpty {
				ctx = ContextWithForwardTarget(ctx, tt.target)
			}
			got, found := ForwardTargetFromContext(ctx)
			if found != tt.wantFound {
				t.Errorf("ForwardTargetFromContext() found = %v, want %v", found, tt.wantFound)
			}
			if got != tt.wantValue {
				t.Errorf("ForwardTargetFromContext() = %q, want %q", got, tt.wantValue)
			}
		})
	}
}

func TestForwardTargetFromContext_NoValue(t *testing.T) {
	ctx := context.Background()
	got, found := ForwardTargetFromContext(ctx)
	if found {
		t.Error("ForwardTargetFromContext() on empty context returned found=true")
	}
	if got != "" {
		t.Errorf("ForwardTargetFromContext() = %q, want empty string", got)
	}
}

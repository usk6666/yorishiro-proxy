package proxy

import (
	"context"
	"testing"
)

func TestResolveUpstreamTarget(t *testing.T) {
	tests := []struct {
		name          string
		forwardTarget string
		fallback      string
		want          string
	}{
		{
			name:     "no forwarding target uses fallback",
			fallback: "example.com:443",
			want:     "example.com:443",
		},
		{
			name:          "forwarding target overrides fallback",
			forwardTarget: "backend.internal:8080",
			fallback:      "localhost:50051",
			want:          "backend.internal:8080",
		},
		{
			name:     "empty fallback with no target",
			fallback: "",
			want:     "",
		},
		{
			name:          "forwarding target with empty fallback",
			forwardTarget: "api.example.com:443",
			fallback:      "",
			want:          "api.example.com:443",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.forwardTarget != "" {
				ctx = ContextWithForwardTarget(ctx, tt.forwardTarget)
			}

			got := ResolveUpstreamTarget(ctx, tt.fallback)
			if got != tt.want {
				t.Errorf("ResolveUpstreamTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

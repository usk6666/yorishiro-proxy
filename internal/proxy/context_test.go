package proxy_test

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

func TestContextWithForwardTarget(t *testing.T) {
	ctx := context.Background()

	// Empty context should return empty string.
	if got := proxy.ForwardTargetFromContext(ctx); got != "" {
		t.Errorf("ForwardTargetFromContext(empty ctx) = %q, want empty", got)
	}

	// Set a target and verify retrieval.
	target := "api.example.com:50051"
	ctx = proxy.ContextWithForwardTarget(ctx, target)
	if got := proxy.ForwardTargetFromContext(ctx); got != target {
		t.Errorf("ForwardTargetFromContext = %q, want %q", got, target)
	}
}

func TestForwardTargetFromContext_EmptyString(t *testing.T) {
	// Setting an empty string should still be retrievable (but returns "").
	ctx := proxy.ContextWithForwardTarget(context.Background(), "")
	if got := proxy.ForwardTargetFromContext(ctx); got != "" {
		t.Errorf("ForwardTargetFromContext(empty target) = %q, want empty", got)
	}
}

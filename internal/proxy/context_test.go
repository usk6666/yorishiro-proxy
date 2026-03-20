package proxy_test

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

func TestContextWithForwardTarget(t *testing.T) {
	ctx := context.Background()

	// Empty context should return empty string and false.
	got, ok := proxy.ForwardTargetFromContext(ctx)
	if ok {
		t.Error("ForwardTargetFromContext(empty ctx) returned ok=true, want false")
	}
	if got != "" {
		t.Errorf("ForwardTargetFromContext(empty ctx) = %q, want empty", got)
	}

	// Set a target and verify retrieval.
	target := "api.example.com:50051"
	ctx = proxy.ContextWithForwardTarget(ctx, target)
	got, ok = proxy.ForwardTargetFromContext(ctx)
	if !ok {
		t.Error("ForwardTargetFromContext returned ok=false, want true")
	}
	if got != target {
		t.Errorf("ForwardTargetFromContext = %q, want %q", got, target)
	}
}

func TestForwardTargetFromContext_EmptyString(t *testing.T) {
	// Setting an empty string should be treated as not set.
	ctx := proxy.ContextWithForwardTarget(context.Background(), "")
	got, ok := proxy.ForwardTargetFromContext(ctx)
	if ok {
		t.Error("ForwardTargetFromContext(empty target) returned ok=true, want false")
	}
	if got != "" {
		t.Errorf("ForwardTargetFromContext(empty target) = %q, want empty", got)
	}
}

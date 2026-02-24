package proxy_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

func TestGenerateConnID_Length(t *testing.T) {
	id := proxy.GenerateConnID()
	if len(id) != 8 {
		t.Errorf("GenerateConnID() length = %d, want 8", len(id))
	}
}

func TestGenerateConnID_Hex(t *testing.T) {
	id := proxy.GenerateConnID()
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("GenerateConnID() = %q, contains non-hex character %c", id, c)
			break
		}
	}
}

func TestGenerateConnID_Unique(t *testing.T) {
	seen := make(map[string]struct{})
	for range 100 {
		id := proxy.GenerateConnID()
		if _, ok := seen[id]; ok {
			t.Errorf("GenerateConnID() produced duplicate: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestContextWithConnID_RoundTrip(t *testing.T) {
	ctx := context.Background()
	connID := "abcd1234"

	ctx = proxy.ContextWithConnID(ctx, connID)
	got := proxy.ConnIDFromContext(ctx)

	if got != connID {
		t.Errorf("ConnIDFromContext() = %q, want %q", got, connID)
	}
}

func TestConnIDFromContext_EmptyContext(t *testing.T) {
	ctx := context.Background()
	got := proxy.ConnIDFromContext(ctx)
	if got != "" {
		t.Errorf("ConnIDFromContext(empty) = %q, want empty string", got)
	}
}

func TestContextWithLogger_RoundTrip(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	ctx = proxy.ContextWithLogger(ctx, logger)
	got := proxy.LoggerFromContext(ctx, nil)

	if got != logger {
		t.Error("LoggerFromContext() did not return the stored logger")
	}
}

func TestLoggerFromContext_FallbackToProvided(t *testing.T) {
	ctx := context.Background()
	fallback := slog.Default()

	got := proxy.LoggerFromContext(ctx, fallback)
	if got != fallback {
		t.Error("LoggerFromContext() did not return the fallback logger")
	}
}

func TestLoggerFromContext_FallbackToDefault(t *testing.T) {
	ctx := context.Background()
	got := proxy.LoggerFromContext(ctx, nil)
	if got == nil {
		t.Error("LoggerFromContext(nil fallback) returned nil, want slog.Default()")
	}
}

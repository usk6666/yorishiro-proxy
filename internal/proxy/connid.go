package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
)

// connIDSize is the number of random bytes used to generate a connection ID.
// This produces a 8-character hex string.
const connIDSize = 4

type contextKey int

const (
	ctxKeyConnID contextKey = iota
	ctxKeyLogger
)

// GenerateConnID returns a random 8-character hex string for connection identification.
func GenerateConnID() string {
	b := make([]byte, connIDSize)
	if _, err := rand.Read(b); err != nil {
		// Fallback: this should never happen in practice.
		return "00000000"
	}
	return hex.EncodeToString(b)
}

// ContextWithConnID returns a new context with the given connection ID.
func ContextWithConnID(ctx context.Context, connID string) context.Context {
	return context.WithValue(ctx, ctxKeyConnID, connID)
}

// ConnIDFromContext returns the connection ID stored in the context, or empty string.
func ConnIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyConnID).(string); ok {
		return v
	}
	return ""
}

// ContextWithLogger returns a new context with the given logger.
func ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKeyLogger, logger)
}

// LoggerFromContext returns the logger stored in the context, or the fallback logger.
// If fallback is nil, slog.Default() is returned.
func LoggerFromContext(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if v, ok := ctx.Value(ctxKeyLogger).(*slog.Logger); ok {
		return v
	}
	if fallback != nil {
		return fallback
	}
	return slog.Default()
}

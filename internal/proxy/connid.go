package proxy

// This file is a backward-compatibility shim. The real implementations live
// in internal/connector/. The wrappers here keep existing internal/proxy/
// handlers compiling during the M36-M44 architecture rewrite; both the
// wrappers and the legacy proxy package are scheduled for deletion in M44.

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// GenerateConnID returns a random 8-character hex string for connection
// identification. Delegates to connector.GenerateConnID.
func GenerateConnID() string {
	return connector.GenerateConnID()
}

// ContextWithConnID returns a new context with the given connection ID.
// Delegates to connector.ContextWithConnID.
func ContextWithConnID(ctx context.Context, connID string) context.Context {
	return connector.ContextWithConnID(ctx, connID)
}

// ConnIDFromContext returns the connection ID stored in the context, or empty
// string. Delegates to connector.ConnIDFromContext.
func ConnIDFromContext(ctx context.Context) string {
	return connector.ConnIDFromContext(ctx)
}

// ContextWithClientAddr returns a new context with the given client address.
// Delegates to connector.ContextWithClientAddr.
func ContextWithClientAddr(ctx context.Context, addr string) context.Context {
	return connector.ContextWithClientAddr(ctx, addr)
}

// ClientAddrFromContext returns the client address stored in the context, or
// empty string. Delegates to connector.ClientAddrFromContext.
func ClientAddrFromContext(ctx context.Context) string {
	return connector.ClientAddrFromContext(ctx)
}

// ContextWithListenerName returns a new context with the given listener name.
// Delegates to connector.ContextWithListenerName.
func ContextWithListenerName(ctx context.Context, name string) context.Context {
	return connector.ContextWithListenerName(ctx, name)
}

// ListenerNameFromContext returns the listener name stored in the context,
// or empty string. Delegates to connector.ListenerNameFromContext.
func ListenerNameFromContext(ctx context.Context) string {
	return connector.ListenerNameFromContext(ctx)
}

// ContextWithLogger returns a new context with the given logger.
// Delegates to connector.ContextWithLogger.
func ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return connector.ContextWithLogger(ctx, logger)
}

// LoggerFromContext returns the logger stored in the context, or the fallback
// logger. Delegates to connector.LoggerFromContext.
func LoggerFromContext(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	return connector.LoggerFromContext(ctx, fallback)
}

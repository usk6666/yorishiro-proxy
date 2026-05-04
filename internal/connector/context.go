package connector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
)

// connIDSize is the number of random bytes used to generate a connection ID.
// This produces an 8-character hex string.
const connIDSize = 4

type contextKey int

const (
	ctxKeyConnID contextKey = iota
	ctxKeyLogger
	ctxKeyClientAddr
	ctxKeyListenerName
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

// ContextWithClientAddr returns a new context with the given client address.
func ContextWithClientAddr(ctx context.Context, addr string) context.Context {
	return context.WithValue(ctx, ctxKeyClientAddr, addr)
}

// ClientAddrFromContext returns the client address stored in the context, or empty string.
func ClientAddrFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyClientAddr).(string); ok {
		return v
	}
	return ""
}

// ContextWithListenerName returns a new context with the given listener name.
func ContextWithListenerName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxKeyListenerName, name)
}

// ListenerNameFromContext returns the listener name stored in the context, or empty string.
func ListenerNameFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyListenerName).(string); ok {
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

// Forward target context key for storing TCP forwarding metadata, used by TCP
// forward listeners to pass the target to L7 protocol handlers without
// requiring CONNECT or other protocol-level target resolution.

type forwardTargetCtxKey struct{}

// ContextWithForwardTarget stores the TCP forward target address in the context.
// This is used by TCP forward listeners to pass the target to L7 protocol
// handlers so they can resolve the upstream connection without requiring
// CONNECT or other protocol-level target resolution.
func ContextWithForwardTarget(ctx context.Context, target string) context.Context {
	return context.WithValue(ctx, forwardTargetCtxKey{}, target)
}

// ForwardTargetFromContext retrieves the TCP forward target address from the
// context. Returns the target and true if set, or empty string and false if
// not present (i.e. the connection did not come through a TCP forward
// listener).
func ForwardTargetFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(forwardTargetCtxKey{}).(string); ok && v != "" {
		return v, true
	}
	return "", false
}

// SOCKS5 context keys for storing SOCKS5 tunnel metadata. The SOCKS5
// negotiator stores the target/auth metadata; downstream protocol handlers
// read it back via the accessors below.

type socks5TargetCtxKey struct{}
type socks5AuthMethodCtxKey struct{}
type socks5AuthUserCtxKey struct{}

// ContextWithSOCKS5Target stores the SOCKS5 target address in the context.
func ContextWithSOCKS5Target(ctx context.Context, target string) context.Context {
	return context.WithValue(ctx, socks5TargetCtxKey{}, target)
}

// SOCKS5TargetFromContext retrieves the SOCKS5 target address from the context.
// Returns empty string if not present.
func SOCKS5TargetFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(socks5TargetCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// ContextWithSOCKS5AuthMethod stores the SOCKS5 authentication method in the context.
// Values are "none" or "username_password".
func ContextWithSOCKS5AuthMethod(ctx context.Context, method string) context.Context {
	return context.WithValue(ctx, socks5AuthMethodCtxKey{}, method)
}

// SOCKS5AuthMethodFromContext retrieves the SOCKS5 authentication method from the context.
// Returns empty string if not present.
func SOCKS5AuthMethodFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(socks5AuthMethodCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// ContextWithSOCKS5AuthUser stores the authenticated SOCKS5 username in the context.
func ContextWithSOCKS5AuthUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, socks5AuthUserCtxKey{}, user)
}

// SOCKS5AuthUserFromContext retrieves the SOCKS5 authenticated username from the context.
// Returns empty string if not present.
func SOCKS5AuthUserFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(socks5AuthUserCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// SOCKS5Protocol returns the protocol string with a "SOCKS5+" prefix if the
// request arrived through a SOCKS5 tunnel (detected via context metadata).
// For example, "HTTPS" becomes "SOCKS5+HTTPS" and "HTTP/1.x" becomes "SOCKS5+HTTP".
func SOCKS5Protocol(ctx context.Context, base string) string {
	if SOCKS5TargetFromContext(ctx) != "" {
		switch base {
		case "HTTP/1.x":
			return "SOCKS5+HTTP"
		default:
			return "SOCKS5+" + base
		}
	}
	return base
}

// MergeSOCKS5Tags adds SOCKS5 metadata tags to the given tags map if the
// request arrived through a SOCKS5 tunnel. If tags is nil, a new map is
// created. Returns the (possibly new) tags map.
func MergeSOCKS5Tags(ctx context.Context, tags map[string]string) map[string]string {
	target := SOCKS5TargetFromContext(ctx)
	if target == "" {
		return tags
	}
	if tags == nil {
		tags = make(map[string]string)
	}
	tags["socks5_target"] = target
	if authMethod := SOCKS5AuthMethodFromContext(ctx); authMethod != "" {
		tags["socks5_auth_method"] = authMethod
	}
	if authUser := SOCKS5AuthUserFromContext(ctx); authUser != "" {
		tags["socks5_auth_user"] = authUser
	}
	return tags
}

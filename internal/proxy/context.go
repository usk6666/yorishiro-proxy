package proxy

import "context"

// Forward target context keys for storing TCP forwarding metadata.
// These are defined in the proxy package (rather than protocol/tcp) to
// avoid import cycles: protocol handlers depend on proxy, and need access
// to the forwarding target from context.

type forwardTargetCtxKey struct{}

// ContextWithForwardTarget stores the TCP forward target address in the context.
// This is used by TCPForwardListener to pass the target to L7 protocol handlers
// so they can resolve the upstream connection without requiring CONNECT or other
// protocol-level target resolution.
func ContextWithForwardTarget(ctx context.Context, target string) context.Context {
	return context.WithValue(ctx, forwardTargetCtxKey{}, target)
}

// ForwardTargetFromContext retrieves the TCP forward target address from the context.
// Returns the target and true if set, or empty string and false if not present
// (i.e. the connection did not come through a TCP forward listener).
func ForwardTargetFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(forwardTargetCtxKey{}).(string); ok && v != "" {
		return v, true
	}
	return "", false
}

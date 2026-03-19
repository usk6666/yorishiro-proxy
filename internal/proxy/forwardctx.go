package proxy

import "context"

// forwardTargetCtxKey is the context key for storing the TCP forwarding target address.
type forwardTargetCtxKey struct{}

// ContextWithForwardTarget returns a new context with the forwarding target address.
// The target is the upstream "host:port" that the proxy should connect to when
// the connection arrives via TCP forwarding (rather than CONNECT or absolute URL).
func ContextWithForwardTarget(ctx context.Context, target string) context.Context {
	return context.WithValue(ctx, forwardTargetCtxKey{}, target)
}

// ForwardTargetFromContext extracts the forwarding target from the context.
// Returns the target and true if set, or empty string and false if not.
func ForwardTargetFromContext(ctx context.Context) (string, bool) {
	if v, ok := ctx.Value(forwardTargetCtxKey{}).(string); ok && v != "" {
		return v, true
	}
	return "", false
}

package proxy

import "context"

// SOCKS5 context keys for storing SOCKS5 tunnel metadata.
// These are defined in the proxy package (rather than protocol/socks5) to
// avoid import cycles: both protocol/socks5 and protocol/http depend on
// proxy, and both need access to these context values.

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

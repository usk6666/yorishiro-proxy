package proxy

// This file is a backward-compatibility shim. The real implementations live
// in internal/connector/. The wrappers here keep existing internal/proxy/
// handlers compiling during the M36-M44 architecture rewrite; both the
// wrappers and the legacy proxy package are scheduled for deletion in M44.

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// ContextWithSOCKS5Target stores the SOCKS5 target address in the context.
// Delegates to connector.ContextWithSOCKS5Target.
func ContextWithSOCKS5Target(ctx context.Context, target string) context.Context {
	return connector.ContextWithSOCKS5Target(ctx, target)
}

// SOCKS5TargetFromContext retrieves the SOCKS5 target address from the
// context. Delegates to connector.SOCKS5TargetFromContext.
func SOCKS5TargetFromContext(ctx context.Context) string {
	return connector.SOCKS5TargetFromContext(ctx)
}

// ContextWithSOCKS5AuthMethod stores the SOCKS5 authentication method in the
// context. Delegates to connector.ContextWithSOCKS5AuthMethod.
func ContextWithSOCKS5AuthMethod(ctx context.Context, method string) context.Context {
	return connector.ContextWithSOCKS5AuthMethod(ctx, method)
}

// SOCKS5AuthMethodFromContext retrieves the SOCKS5 authentication method from
// the context. Delegates to connector.SOCKS5AuthMethodFromContext.
func SOCKS5AuthMethodFromContext(ctx context.Context) string {
	return connector.SOCKS5AuthMethodFromContext(ctx)
}

// ContextWithSOCKS5AuthUser stores the authenticated SOCKS5 username in the
// context. Delegates to connector.ContextWithSOCKS5AuthUser.
func ContextWithSOCKS5AuthUser(ctx context.Context, user string) context.Context {
	return connector.ContextWithSOCKS5AuthUser(ctx, user)
}

// SOCKS5AuthUserFromContext retrieves the SOCKS5 authenticated username from
// the context. Delegates to connector.SOCKS5AuthUserFromContext.
func SOCKS5AuthUserFromContext(ctx context.Context) string {
	return connector.SOCKS5AuthUserFromContext(ctx)
}

// SOCKS5Protocol returns the protocol string with a "SOCKS5+" prefix if the
// request arrived through a SOCKS5 tunnel. Delegates to
// connector.SOCKS5Protocol.
func SOCKS5Protocol(ctx context.Context, base string) string {
	return connector.SOCKS5Protocol(ctx, base)
}

// MergeSOCKS5Tags adds SOCKS5 metadata tags to the given tags map if the
// request arrived through a SOCKS5 tunnel. Delegates to
// connector.MergeSOCKS5Tags.
func MergeSOCKS5Tags(ctx context.Context, tags map[string]string) map[string]string {
	return connector.MergeSOCKS5Tags(ctx, tags)
}

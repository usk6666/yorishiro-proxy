// upstream_proxy_ctx.go carries the per-flow upstream-proxy URL override
// for control-plane resend / fuzz dial paths. Used by per-iteration
// rotation (residential proxy IP switching) where each fuzz variant /
// resend invocation tunnels through a distinct upstream proxy URL.
//
// The override is consulted by EffectiveUpstreamProxyForCtx ahead of the
// per-listener and process-global resolution chain, so a ctx-attached
// override always wins. This is distinct from the per-listener override
// (USK-826), which scopes a URL to a named listener for chained-MITM
// setups but cannot vary per-iteration.
package connector

import (
	"context"
	"net/url"
)

type upstreamProxyOverrideCtxKey struct{}

// upstreamProxyOverrideValue distinguishes "ctx carries an explicit nil
// override (direct dial; skip upstream proxy)" from "ctx carries no
// override (fall back to per-listener / global resolution)". The
// wrapper presence is the signal; URL nullity carries the direct-dial
// semantics.
type upstreamProxyOverrideValue struct {
	URL *url.URL
}

// ContextWithUpstreamProxyOverride attaches a per-flow upstream proxy
// URL override to ctx. The dial path consults this first via
// EffectiveUpstreamProxyForCtx, taking precedence over per-listener
// (USK-826) and process-global / boot-time configuration (USK-734).
//
// Passing a nil URL is an explicit "direct dial" override — the caller
// has decided this flow bypasses any configured upstream proxy. To
// remove an override, do not derive a child ctx; pass the parent ctx
// that does not carry the override.
func ContextWithUpstreamProxyOverride(ctx context.Context, u *url.URL) context.Context {
	return context.WithValue(ctx, upstreamProxyOverrideCtxKey{}, &upstreamProxyOverrideValue{URL: u})
}

// UpstreamProxyOverrideFromContext returns the per-flow upstream proxy
// URL override attached via ContextWithUpstreamProxyOverride, and a
// presence flag.
//
// When present is true and url is nil, the caller MUST perform a direct
// dial (skip all proxy configuration). When present is false, the ctx
// carries no override and the caller falls back to per-listener /
// global resolution.
func UpstreamProxyOverrideFromContext(ctx context.Context) (u *url.URL, present bool) {
	v, ok := ctx.Value(upstreamProxyOverrideCtxKey{}).(*upstreamProxyOverrideValue)
	if !ok {
		return nil, false
	}
	return v.URL, true
}

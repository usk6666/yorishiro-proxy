package proxy

import "context"

// ResolveUpstreamTarget determines the upstream target address for a request.
// It first checks the context for a TCP forwarding target (set by
// TCPForwardListener). If not present, it returns the fallback value, which is
// typically derived from the request URL host, CONNECT authority, or :authority
// pseudo-header depending on the protocol.
func ResolveUpstreamTarget(ctx context.Context, fallback string) string {
	if target, ok := ForwardTargetFromContext(ctx); ok {
		return target
	}
	return fallback
}

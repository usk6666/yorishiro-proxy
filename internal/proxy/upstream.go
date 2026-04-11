package proxy

// Upstream-proxy helpers were moved to internal/connector/upstream_proxy.go
// as part of USK-562 (M39 Connector). The functions below are thin forwards
// kept for backward compatibility while existing callers in internal/protocol
// and internal/mcp are migrated. internal/protocol is scheduled for deletion
// in M44; these forwards will be removed at that time.

import (
	"context"
	"net"
	gohttp "net/http"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// ParseUpstreamProxy forwards to connector.ParseUpstreamProxy.
func ParseUpstreamProxy(rawURL string) (*url.URL, error) {
	return connector.ParseUpstreamProxy(rawURL)
}

// RedactProxyURL forwards to connector.RedactProxyURL.
func RedactProxyURL(rawURL string) string {
	return connector.RedactProxyURL(rawURL)
}

// DialViaUpstreamProxy forwards to connector.DialViaUpstreamProxy.
func DialViaUpstreamProxy(ctx context.Context, proxyURL *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	return connector.DialViaUpstreamProxy(ctx, proxyURL, targetAddr, timeout)
}

// TransportProxyFunc returns an HTTP transport-compatible Proxy function for
// the given upstream proxy URL. Returns nil (direct connection) when proxyURL
// is nil. For HTTP proxies the standard library's transport handles CONNECT
// automatically; for SOCKS5 proxies the caller is expected to convert the
// URL into something the transport understands.
//
// This helper is retained in internal/proxy because it is consumed by
// net/http-oriented code in internal/protocol/http* which is scheduled for
// deletion in M44. It does not belong in internal/connector (which is
// net/http-free).
func TransportProxyFunc(proxyURL *url.URL) func(*gohttp.Request) (*url.URL, error) {
	if proxyURL == nil {
		return nil
	}
	return func(_ *gohttp.Request) (*url.URL, error) {
		return proxyURL, nil
	}
}

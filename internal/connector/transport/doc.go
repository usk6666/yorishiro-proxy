// Package transport contains control-plane TLS plumbing used by the MCP
// typed-resend tools (resend_http / resend_grpc / resend_ws) and by
// proxy_start_tool runtime swap.
//
// The package was rehomed from internal/protocol/httputil/ as part of the
// USK-697 split (USK-704). The legacy copies in internal/protocol/httputil/
// remain temporarily until USK-697 (final) deletes the internal/protocol/
// tree. Files only consumed by the dying tree (decode.go, headers.go,
// variant.go, error.go, status.go, fingerprint.go) stay behind and die
// with it.
//
// Provided types:
//   - TLSTransport / StandardTransport / UTLSTransport — TLS dialer abstraction
//   - HostTLSRegistry / HostTLSConfig / ParseBrowserProfile — per-host TLS
//   - ConnPool — upstream TCP/TLS connection pool used by the typed-resend tools
//   - H1Transport / RoundTripResult / RoundTripTiming — net/http-free HTTP/1.x
//     client transport built on internal/layer/http1/parser
package transport

// Package transport contains control-plane TLS plumbing used by the MCP
// typed-resend tools (resend_http / resend_grpc / resend_ws) and by
// proxy_start_tool runtime swap.
//
// The package was rehomed from internal/protocol/httputil/ at USK-697 when
// the legacy data-path tree (internal/protocol/, internal/codec/,
// internal/exchange/, internal/proxy/) was deleted. The TLS bits that
// outlived the legacy live data path moved here, while the parts only
// consumed by the dying tree (decode.go, headers.go, variant.go, error.go,
// status.go, timing.go, fingerprint.go) died with it.
//
// Provided types:
//   - TLSTransport / StandardTransport / UTLSTransport — TLS dialer abstraction
//   - HostTLSRegistry / HostTLSConfig / ParseBrowserProfile — per-host TLS
//   - ConnPool — upstream TCP/TLS connection pool used by the typed-resend tools
package transport

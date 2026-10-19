// Package transport contains control-plane TLS plumbing used by the MCP
// typed-resend tools (resend_http / resend_grpc / resend_ws) and by
// proxy_start_tool runtime swap.
//
// Provided types:
//   - TLSTransport / StandardTransport / UTLSTransport — TLS dialer abstraction
//   - HostTLSRegistry / HostTLSConfig / ParseBrowserProfile — per-host TLS
package transport

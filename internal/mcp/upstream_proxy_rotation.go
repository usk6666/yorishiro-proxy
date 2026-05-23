// upstream_proxy_rotation.go retains the MCP package's public alias for
// the per-iteration upstream proxy configuration. The implementation
// now lives in internal/connector/upstream_proxy_rotation.go (USK-959
// lift) so the live MITM data path and the control-plane resend / fuzz
// path share one resolver + macro-expansion engine. The wire schema is
// unchanged.
//
// Reserved variables (prefix "__") cannot be set or shadowed by
// user-supplied macros — see internal/macro/reserved.go and the
// InjectVarsRespectingReserved guard in internal/mcp/fuzz_macro_common.go.
package mcp

import (
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// UpstreamProxyConfig aliases the connector package's type so the MCP
// JSON schema continues to expose `upstream_proxy.url_template` exactly
// as it did pre-USK-959.
type UpstreamProxyConfig = connector.UpstreamProxyConfig

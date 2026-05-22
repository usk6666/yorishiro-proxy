// upstream_proxy_rotation.go implements per-iteration upstream proxy URL
// expansion for fuzz / resend MCP tools. Used by the residential proxy
// IP switching workflow: each fuzz variant (or resend invocation) tunnels
// through a distinct upstream proxy URL, so the upstream observes a
// rotating client IP.
//
// The resolver expands a user-supplied URL template once per iteration
// against a tiny runtime-supplied KV Store carrying the reserved
// variables §__iteration§ and §__nonce§. The parsed URL is then attached
// to ctx via connector.ContextWithUpstreamProxyOverride; downstream dial
// helpers (connector.MaybeDialViaUpstreamProxy) read the override and
// tunnel through the chosen upstream proxy.
//
// Reserved variables (prefix "__") cannot be set or shadowed by
// user-supplied macros — see internal/macro/reserved.go and the
// mergeKVStore guard in internal/job/job.go.
package mcp

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// UpstreamProxyConfig is the per-iteration upstream proxy configuration
// for fuzz / resend MCP tools. Optional — when nil or URLTemplate is
// empty, the iteration uses the default (direct) dial path without
// attaching any upstream-proxy override to ctx.
//
// URLTemplate supports the §var§ macro template syntax with the
// following runtime-reserved variables (always present per iteration):
//
//	§__iteration§ — zero-based iteration index for the current MCP call
//	§__nonce§     — fresh UUID minted per iteration
//
// Reserved variables cannot be overridden by user input. The parsed
// upstream proxy URL must use scheme http:// or socks5:// (validated by
// connector.ParseUpstreamProxy). CRLF guards (CWE-93) apply to the
// expanded URL so a §__nonce§-substituted credential cannot smuggle a
// Proxy-Authorization header injection into the downstream CONNECT
// request.
//
// The struct is intentionally a single-field carrier so future
// extensions (rotation policy, session-id sticky window, error-driven
// rotation) can land as additional optional fields without breaking the
// MCP wire schema.
type UpstreamProxyConfig struct {
	URLTemplate string `json:"url_template,omitempty" jsonschema:"upstream proxy URL template (http:// or socks5://). Supports §var§ macro syntax with reserved variables §__iteration§ (zero-based index) and §__nonce§ (per-iteration UUID) for residential-proxy IP rotation. Example: http://user-session-§__nonce§:password@residential.example:8080"`
}

// ResolveForIteration expands the URL template for iteration N, parses
// the result as an upstream proxy URL, and returns a ctx carrying the
// per-flow override (connector.ContextWithUpstreamProxyOverride).
// Returns the input ctx unchanged when the configuration is nil or
// URLTemplate is empty — the caller falls through to the default dial
// path.
//
// Errors are returned with the user-facing prefix "upstream_proxy.url_template"
// so MCP tool handlers can surface them verbatim.
func (c *UpstreamProxyConfig) ResolveForIteration(ctx context.Context, iteration int) (context.Context, error) {
	if c == nil || c.URLTemplate == "" {
		return ctx, nil
	}

	kvStore := map[string]string{
		macro.ReservedKeyPrefix + "iteration": strconv.Itoa(iteration),
		macro.ReservedKeyPrefix + "nonce":     uuid.NewString(),
	}

	expanded, err := macro.ExpandTemplate(c.URLTemplate, kvStore)
	if err != nil {
		return nil, fmt.Errorf("upstream_proxy.url_template: expand: %w", err)
	}

	if strings.ContainsAny(expanded, "\r\n") {
		return nil, fmt.Errorf("upstream_proxy.url_template: expanded URL contains CR/LF (CWE-93 guard)")
	}

	parsed, err := connector.ParseUpstreamProxy(expanded)
	if err != nil {
		return nil, fmt.Errorf("upstream_proxy.url_template: %w", err)
	}

	return connector.ContextWithUpstreamProxyOverride(ctx, parsed), nil
}

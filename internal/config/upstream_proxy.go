// upstream_proxy.go carries the per-listener upstream-proxy
// configuration (USK-959). The wire schema is polymorphic: the
// "upstream_proxy" config key accepts either a plain string (legacy
// USK-826 shape: literal URL applied to the default listener) OR an
// object with {url|url_template, rotation}.
//
// ProxyConfig.UnmarshalJSON (in config.go) dispatches the polymorphism;
// this file owns the validation + types only.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// UpstreamProxyConfig is the file-level structured per-listener
// upstream-proxy configuration (USK-959). Exactly one of URL /
// URLTemplate must be set; Rotation is required when URLTemplate is
// set and forbidden when URL is set (a static URL has nothing to
// rotate).
//
// The wire surface accepts the legacy ProxyConfig.UpstreamProxy string
// for backwards compatibility — the string is parsed into
// UpstreamProxyConfig{URL: s} by ProxyConfig.UnmarshalJSON.
type UpstreamProxyConfig struct {
	// URL is a literal upstream proxy URL (http:// or socks5://). When
	// set, the listener dials through this URL on every request without
	// rotation. Mutually exclusive with URLTemplate.
	URL string `json:"url,omitempty" jsonschema:"literal upstream proxy URL (http:// or socks5://); mutually exclusive with url_template"`

	// URLTemplate is the macro-template form (USK-959). Supports
	// §__nonce§ (per-resolution UUID) for residential-proxy IP
	// rotation. Mutually exclusive with URL; requires Rotation.
	URLTemplate string `json:"url_template,omitempty" jsonschema:"upstream proxy URL template; supports §__nonce§ (per-resolution UUID); requires rotation"`

	// Rotation selects the rotation policy. Required when URLTemplate
	// is set; forbidden when URL is set.
	Rotation *UpstreamProxyRotation `json:"rotation,omitempty" jsonschema:"rotation policy; required with url_template"`
}

// UpstreamProxyRotation describes how often a URLTemplate is expanded
// during the listener's lifetime (USK-959).
type UpstreamProxyRotation struct {
	// Policy selects how often the resolver mints a fresh URL.
	//
	// Valid values:
	//   - per_request: expand at every outbound TCP dial
	//   - per_connection: cache by inbound proxy ConnID
	//   - per_target_host: cache by (listener, upstream host)
	//   - sticky: mint once for the listener's lifetime
	Policy string `json:"policy" jsonschema:"rotation policy: per_request | per_connection | per_target_host | sticky"`
}

// Validate reports the first problem with the structured per-listener
// upstream-proxy config. It enforces the URL ⊕ URLTemplate exclusivity,
// rotation policy whitelist, and probe-expands the template once with
// a synthetic nonce so a clearly-malformed template surfaces at
// config-apply time rather than at the first live dial (Stage 1
// fail-closed in the binding decisions).
func (c *UpstreamProxyConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.URL != "" && c.URLTemplate != "" {
		return fmt.Errorf("upstream_proxy: url and url_template are mutually exclusive")
	}
	if c.URL == "" && c.URLTemplate == "" {
		return fmt.Errorf("upstream_proxy: one of url or url_template is required")
	}
	if c.URL != "" {
		if c.Rotation != nil {
			return fmt.Errorf("upstream_proxy: rotation is not valid with url (set url_template to enable rotation)")
		}
		// USK-826 string form: defer URL parsing to the runtime
		// connector.ParseUpstreamProxy (the file-level config layer
		// historically did not parse, so a malformed URL surfaces at
		// proxy_start). Match that behaviour.
		return nil
	}
	// URLTemplate path
	if c.Rotation == nil {
		return fmt.Errorf("upstream_proxy: rotation is required with url_template")
	}
	if err := c.Rotation.Validate(); err != nil {
		return fmt.Errorf("upstream_proxy: %w", err)
	}
	// Probe-expand with a synthetic nonce so a malformed template (bad
	// scheme, missing port, CRLF) fails at config-apply time rather
	// than at the first live dial. The probe does not commit any
	// resolver state — it is a pure validation step.
	if err := probeExpandTemplate(c.URLTemplate); err != nil {
		return fmt.Errorf("upstream_proxy.url_template: %w", err)
	}
	return nil
}

// Validate reports the first problem with the rotation config. Currently
// limited to the policy whitelist; future extensions (cooldown
// intervals, error-driven rotation) land here.
func (r *UpstreamProxyRotation) Validate() error {
	if r == nil {
		return nil
	}
	switch r.Policy {
	case "per_request", "per_connection", "per_target_host", "sticky":
		return nil
	case "":
		return fmt.Errorf("rotation.policy is required (per_request | per_connection | per_target_host | sticky)")
	default:
		return fmt.Errorf("rotation.policy %q not supported (per_request | per_connection | per_target_host | sticky)", r.Policy)
	}
}

// IsRotating reports whether the config carries a rotating template
// (URLTemplate set + Rotation policy validated). False for the legacy
// static URL form.
func (c *UpstreamProxyConfig) IsRotating() bool {
	return c != nil && c.URLTemplate != "" && c.Rotation != nil
}

// MarshalJSON serialises the structured form verbatim. The legacy
// string form is round-tripped by ProxyConfig.UnmarshalJSON, which
// promotes a JSON-string value into UpstreamProxyConfig{URL: s} on
// load; the symmetric promotion on save would require a heuristic and
// is out of scope.
func (c *UpstreamProxyConfig) MarshalJSON() ([]byte, error) {
	type alias UpstreamProxyConfig
	return json.Marshal((*alias)(c))
}

// UnmarshalJSON accepts either a string (legacy literal URL) or an
// object (USK-959 structured shape). String values are stored as
// {URL: s}; object values are decoded verbatim.
func (c *UpstreamProxyConfig) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("upstream_proxy: must be a string or object: %w", err)
		}
		c.URL = s
		c.URLTemplate = ""
		c.Rotation = nil
		return nil
	}
	type alias UpstreamProxyConfig
	var tmp alias
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("upstream_proxy: %w", err)
	}
	*c = UpstreamProxyConfig(tmp)
	return nil
}

// probeExpandTemplate runs macro expansion + CRLF guard +
// supportedUpstreamSchemes check against a synthetic nonce. Imports
// the macro engine + scheme whitelist locally to avoid pulling in
// internal/connector at config-time (which would create an import
// cycle: connector → config → connector).
//
// The KV provided here must match the runtime resolver's KV exactly
// (`internal/connector/upstream_proxy_rotation.go`), otherwise a
// template that probes clean here can still fail at first live dial
// (Stage 2). The live resolver populates only `__nonce`; do not add
// `__iteration` or any other key — `§__iteration§` is intentionally
// not exposed on the live data path (USK-959 binding decision #7).
func probeExpandTemplate(tpl string) error {
	if tpl == "" {
		return fmt.Errorf("url_template is empty")
	}
	kv := map[string]string{
		macro.ReservedKeyPrefix + "nonce": uuid.NewString(),
	}
	expanded, err := macro.ExpandTemplate(tpl, kv)
	if err != nil {
		return fmt.Errorf("expand: %w", err)
	}
	if strings.ContainsAny(expanded, "\r\n") {
		return fmt.Errorf("expanded URL contains CR/LF (CWE-93 guard)")
	}
	// Lightweight scheme + host:port check; the canonical parse lives
	// in connector.ParseUpstreamProxy which the live dial path calls
	// per request. We do not depend on that package here to avoid the
	// import cycle described above, but the checks below mirror what
	// ParseUpstreamProxy does so that any input that probes clean here
	// will also pass the runtime parse — Stage 1 / Stage 2 parity.
	if !strings.HasPrefix(expanded, "http://") && !strings.HasPrefix(expanded, "socks5://") {
		return fmt.Errorf("expanded URL must use scheme http:// or socks5://")
	}
	u, err := url.Parse(expanded)
	if err != nil {
		// e.g. an unsubstituted §-macro left in the URL — the section
		// sign is rejected by url.Parse as invalid userinfo. Surfacing
		// it here means the operator sees the error at config-apply
		// time rather than at the first live dial (Stage 2 fail-closed
		// also catches it, but later).
		return fmt.Errorf("parse expanded URL: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("expanded URL has no host")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return fmt.Errorf("expanded URL must include a port (e.g. %s://host:port)", u.Scheme)
	}
	if host == "" || port == "" {
		return fmt.Errorf("expanded URL has empty host or port")
	}
	return nil
}

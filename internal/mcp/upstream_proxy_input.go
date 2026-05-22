// upstream_proxy_input.go carries the polymorphic input shape for the
// MCP-tool surface (configure_tool / proxy_start_tool) accepting an
// upstream-proxy configuration as either a literal URL string (legacy
// USK-826) or a structured rotation object (USK-959).
//
// This wraps internal/config.UpstreamProxyConfig with MCP-specific
// validation hooks; the config struct itself is shared between file
// config and runtime tools.
package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// configureUpstreamProxyInput is the polymorphic JSON shape for the
// configure / proxy_start tool's upstream_proxy field. Exactly one of
// the URL form (URL set, IsLiteralEmpty true on the empty-string
// signal) or the URLTemplate form (URLTemplate + Rotation set) is
// active per call.
type configureUpstreamProxyInput struct {
	// URL carries the legacy literal-URL form (USK-826). An empty
	// string is honoured as "disable upstream proxy" only when
	// SuppliedAsString=true so the wire shape can distinguish "no
	// upstream_proxy field" from "upstream_proxy: ''".
	URL string `json:"url,omitempty"`

	// URLTemplate carries the rotating-template form (USK-959).
	// Mutually exclusive with URL.
	URLTemplate string `json:"url_template,omitempty"`

	// Rotation describes how often the template is expanded. Required
	// when URLTemplate is set; forbidden when URL is set.
	Rotation *configureUpstreamProxyRotationInput `json:"rotation,omitempty"`

	// suppliedAsString is set by UnmarshalJSON when the caller passed
	// a JSON string (rather than an object). Distinguishes
	// "upstream_proxy: ''" (disable) from "upstream_proxy: {}" (
	// arguably also disable, but operators may intend something else
	// — we reject empty-object form to surface the mistake).
	suppliedAsString bool
}

// configureUpstreamProxyRotationInput is the JSON shape for the
// rotation sub-object. Mirrors config.UpstreamProxyRotation.
type configureUpstreamProxyRotationInput struct {
	Policy string `json:"policy" jsonschema:"rotation policy: per_request | per_connection | per_target_host | sticky"`
}

// UnmarshalJSON accepts either a JSON string (legacy literal URL,
// optionally empty for disable) or a JSON object (USK-959 structured
// form). Other shapes return a typed error.
func (c *configureUpstreamProxyInput) UnmarshalJSON(data []byte) error {
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
		c.suppliedAsString = true
		return nil
	}
	type alias configureUpstreamProxyInput
	var tmp alias
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("upstream_proxy: %w", err)
	}
	*c = configureUpstreamProxyInput(tmp)
	c.suppliedAsString = false
	return nil
}

// Validate runs Stage 1 validation (URL ⊕ URLTemplate exclusivity,
// rotation policy whitelist). The connector / config layer's own
// validators run on the value derived from this input, so the rules
// applied here match the file-config path.
//
// Returns nil for the empty-disable string form (URL="") so callers
// can fall through to the "clear" branch without an extra null check.
func (c *configureUpstreamProxyInput) Validate() error {
	if c == nil {
		return nil
	}
	if c.suppliedAsString {
		// Literal URL form. Empty is "disable". Parsing is deferred
		// to applyUpstreamProxy → connector.ParseUpstreamProxy.
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
		return nil
	}
	// URLTemplate form
	if c.Rotation == nil {
		return fmt.Errorf("upstream_proxy: rotation is required with url_template")
	}
	policy := connector.RotationPolicy(c.Rotation.Policy)
	if !policy.IsValid() {
		if c.Rotation.Policy == "" {
			return fmt.Errorf("upstream_proxy.rotation.policy is required (per_request | per_connection | per_target_host | sticky)")
		}
		return fmt.Errorf("upstream_proxy.rotation.policy %q not supported (per_request | per_connection | per_target_host | sticky)", c.Rotation.Policy)
	}
	return nil
}

// IsLiteralDisable reports whether the input is the legacy
// empty-string form (set explicitly to clear the upstream proxy).
// Distinct from the "omitted entirely" case (the caller is nil).
func (c *configureUpstreamProxyInput) IsLiteralDisable() bool {
	return c != nil && c.suppliedAsString && c.URL == ""
}

// IsLiteralURL reports whether the input is the legacy literal-URL
// form (non-empty URL via string). Equivalent to "USK-826 set this
// URL on the listener".
func (c *configureUpstreamProxyInput) IsLiteralURL() bool {
	return c != nil && c.suppliedAsString && c.URL != ""
}

// IsRotation reports whether the input is the USK-959 structured
// rotation form (URLTemplate + Rotation populated). Returns false for
// the object form WITHOUT rotation (the URL-as-object shape, mainly
// useful for parity with the file config; equivalent to a literal URL
// when present).
func (c *configureUpstreamProxyInput) IsRotation() bool {
	return c != nil && !c.suppliedAsString && c.URLTemplate != "" && c.Rotation != nil
}

// RotationConfig returns the connector-side RotationConfig derived
// from the input, or nil when the input is not a rotation form.
// Callers must call Validate() first.
func (c *configureUpstreamProxyInput) RotationConfig() *connector.RotationConfig {
	if !c.IsRotation() {
		return nil
	}
	return &connector.RotationConfig{
		Template: c.URLTemplate,
		Policy:   connector.RotationPolicy(c.Rotation.Policy),
	}
}

// LiteralURL returns the literal URL portion of the input — either
// the string form's URL or the object form's URL field. Empty when
// the input is a rotation form.
func (c *configureUpstreamProxyInput) LiteralURL() string {
	if c == nil {
		return ""
	}
	if c.suppliedAsString {
		return c.URL
	}
	return c.URL
}

// parseUpstreamProxyInput coerces an `any` value (as decoded from
// the MCP-tool JSON input) into a *configureUpstreamProxyInput. The
// MCP wire-shape is polymorphic (string or object); we accept both
// shapes here and a nil value (caller omitted the field entirely).
//
// Returns:
//   - nil, nil — caller omitted the field; downstream skips
//     upstream_proxy processing.
//   - input, nil — parsed input ready for Validate().
//   - nil, err — input shape unrecognised (not string, object, or nil).
//
// Accepted shapes:
//   - nil: omitted (no change)
//   - string: legacy USK-826 literal URL (empty for disable)
//   - map[string]any: USK-959 structured (url|url_template + rotation)
//   - *configureUpstreamProxyInput / configureUpstreamProxyInput:
//     pre-typed (test harnesses, programmatic callers)
func parseUpstreamProxyInput(raw any) (*configureUpstreamProxyInput, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case string:
		return &configureUpstreamProxyInput{URL: v, suppliedAsString: true}, nil
	case map[string]any:
		out := &configureUpstreamProxyInput{}
		if u, ok := v["url"].(string); ok {
			out.URL = u
		}
		if tpl, ok := v["url_template"].(string); ok {
			out.URLTemplate = tpl
		}
		if rot, ok := v["rotation"].(map[string]any); ok {
			r := &configureUpstreamProxyRotationInput{}
			if p, ok := rot["policy"].(string); ok {
				r.Policy = p
			}
			out.Rotation = r
		}
		return out, nil
	case *configureUpstreamProxyInput:
		return v, nil
	case configureUpstreamProxyInput:
		// Defensive copy so the returned pointer is unique.
		cp := v
		return &cp, nil
	default:
		return nil, fmt.Errorf("upstream_proxy: must be a string or object, got %T", raw)
	}
}

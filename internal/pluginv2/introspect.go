package pluginv2

// PluginIntrospectInfo is the per-plugin record returned by
// Engine.Introspect. It surfaces the loaded plugin name, source path, the
// (Protocol, Event, Phase) tuples its register_hook calls created, and the
// PluginConfig.Vars after RedactKeys redaction. The MCP plugin_introspect
// tool (USK-676) serialises this directly.
type PluginIntrospectInfo struct {
	// Name is the plugin's stable identifier. Falls back to the basename
	// of Path (without extension) when PluginConfig.Name is empty.
	Name string

	// Path is the filesystem path to the plugin script. Operators may use
	// this to confirm which file produced the listed registrations.
	Path string

	// Enabled reports whether the engine considers the plugin live. All
	// successfully loaded plugins are Enabled=true today; the field exists
	// so the MCP schema is forward-compatible with future
	// disable-without-unload semantics.
	Enabled bool

	// Registrations records each register_hook call this plugin made, in
	// script order.
	Registrations []HookRegistration

	// Vars is PluginConfig.Vars with RedactKeys applied: every key listed
	// in PluginConfig.RedactKeys has its value replaced by the literal
	// string "<redacted>". Other values pass through verbatim, with strings
	// and []byte truncated to 8 KiB (with a trailing "...(truncated)"
	// marker) to bound the introspect response size.
	Vars map[string]any
}

// HookRegistration mirrors a single register_hook call.
type HookRegistration struct {
	Protocol string
	Event    string
	Phase    string
}

// Introspect returns one PluginIntrospectInfo per loaded plugin, in load
// order. Safe for concurrent use; takes the engine read lock.
//
// Vars are processed via redactVars: keys named in PluginConfig.RedactKeys
// are replaced with "<redacted>", and large string/[]byte values are
// truncated to redactValueCap. The original PluginConfig is not mutated.
func (e *Engine) Introspect() []PluginIntrospectInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]PluginIntrospectInfo, 0, len(e.plugins))
	for _, lp := range e.plugins {
		name := lp.config.Name
		if name == "" {
			name = pluginName(lp.config.Path)
		}
		info := PluginIntrospectInfo{
			Name:    name,
			Path:    lp.config.Path,
			Enabled: true,
			Vars:    redactVars(lp.config.Vars, lp.config.RedactKeys),
		}
		if len(lp.registrations) > 0 {
			info.Registrations = make([]HookRegistration, 0, len(lp.registrations))
			for _, r := range lp.registrations {
				info.Registrations = append(info.Registrations, HookRegistration(r))
			}
		}
		out = append(out, info)
	}
	return out
}

// redactValueCap is the maximum size in bytes for an individual leaf string
// or []byte in an introspected Vars value. Larger values are truncated and
// suffixed with redactTruncationMarker. The 8 KiB cap is a defensive bound
// against accidental multi-MB Vars values blowing up an MCP response; it
// is intentionally well above any realistic plugin variable.
const redactValueCap = 8 * 1024

// redactTruncationMarker is appended to a value that hit redactValueCap.
const redactTruncationMarker = "...(truncated)"

// redactedPlaceholder is the value substituted for any Vars key listed in
// PluginConfig.RedactKeys.
const redactedPlaceholder = "<redacted>"

// redactVars copies the Vars map, replacing every key in redactKeys with
// redactedPlaceholder and truncating other leaf string/[]byte values to
// redactValueCap. Maps and slices are walked recursively so a nested
// secret-like leaf is also bounded. The original map is not mutated.
//
// The function returns nil when the input map is empty so the JSON
// serialiser can omit the "vars" field via `omitempty`.
func redactVars(vars map[string]any, redactKeys []string) map[string]any {
	if len(vars) == 0 {
		return nil
	}
	redact := make(map[string]struct{}, len(redactKeys))
	for _, k := range redactKeys {
		redact[k] = struct{}{}
	}
	out := make(map[string]any, len(vars))
	for k, v := range vars {
		if _, drop := redact[k]; drop {
			out[k] = redactedPlaceholder
			continue
		}
		out[k] = capValue(v)
	}
	return out
}

// capValue caps a single Vars leaf, recursing into maps and slices. Scalar
// numeric / bool values pass through unchanged.
func capValue(v any) any {
	switch x := v.(type) {
	case string:
		return capString(x)
	case []byte:
		return capBytes(x)
	case map[string]any:
		nested := make(map[string]any, len(x))
		for k, vv := range x {
			nested[k] = capValue(vv)
		}
		return nested
	case []any:
		nested := make([]any, len(x))
		for i, vv := range x {
			nested[i] = capValue(vv)
		}
		return nested
	default:
		return v
	}
}

// capString truncates s to redactValueCap bytes, appending the truncation
// marker if any bytes were dropped.
func capString(s string) string {
	if len(s) <= redactValueCap {
		return s
	}
	return s[:redactValueCap] + redactTruncationMarker
}

// capBytes truncates b to redactValueCap bytes, appending the truncation
// marker if any bytes were dropped. Returns a string so the JSON output is
// stable (raw []byte serialises as base64 which would obscure truncation).
func capBytes(b []byte) any {
	if len(b) <= redactValueCap {
		return b
	}
	out := make([]byte, redactValueCap)
	copy(out, b[:redactValueCap])
	return string(out) + redactTruncationMarker
}

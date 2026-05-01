package mcp

import (
	"context"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// pluginIntrospectInput is the JSON input for the plugin_introspect MCP
// tool. Today the tool accepts no parameters: it always returns the full
// list of loaded pluginv2 plugins. The struct exists so the gomcp SDK can
// generate a JSON schema and reject unexpected fields.
type pluginIntrospectInput struct{}

// pluginIntrospectResult is the structured response for plugin_introspect.
// One entry per loaded pluginv2 plugin. The legacy plugin engine is
// intentionally not surfaced here — it has its own listing tool — and will
// be retired alongside the legacy intercept queue in RFC-001 N9.
type pluginIntrospectResult struct {
	Plugins []pluginIntrospectPlugin `json:"plugins"`
}

// pluginIntrospectPlugin is one element of pluginIntrospectResult.Plugins.
type pluginIntrospectPlugin struct {
	// Name is the plugin's stable identifier.
	Name string `json:"name"`

	// Path is the filesystem location of the plugin script.
	Path string `json:"path"`

	// Enabled indicates whether the engine considers the plugin live.
	// All successfully loaded plugins are reported as enabled today.
	Enabled bool `json:"enabled"`

	// Registrations enumerates each register_hook call the plugin made,
	// in script order.
	Registrations []hookRegistration `json:"registrations"`

	// Vars is the plugin's PluginConfig.Vars with RedactKeys applied.
	// Keys named in RedactKeys carry the literal string "<redacted>";
	// large values are truncated by the engine.
	Vars map[string]any `json:"vars,omitempty"`
}

// hookRegistration mirrors pluginv2.HookRegistration in the MCP wire
// schema. Kept as a separate struct so the JSON tags are explicit and
// `omitempty` on optional future fields stays under MCP's control.
type hookRegistration struct {
	Protocol string `json:"protocol"`
	Event    string `json:"event"`
	Phase    string `json:"phase"`
}

// registerPluginIntrospect registers the plugin_introspect MCP tool.
func (s *Server) registerPluginIntrospect() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "plugin_introspect",
		Description: "Return the list of loaded pluginv2 plugins together with their (protocol, event, phase) " +
			"register_hook registrations and the PluginConfig.Vars map after applying redact_keys. " +
			"Returns an empty list when the pluginv2 engine is not configured. " +
			"Note: the legacy plugin engine is surfaced by the 'plugin' tool, not this one.",
	}, s.handlePluginIntrospect)
}

// handlePluginIntrospect is the plugin_introspect tool handler.
func (s *Server) handlePluginIntrospect(_ context.Context, _ *gomcp.CallToolRequest, _ pluginIntrospectInput) (*gomcp.CallToolResult, *pluginIntrospectResult, error) {
	if s.pluginEngine == nil || s.pluginEngine.pluginv2 == nil {
		return nil, &pluginIntrospectResult{Plugins: []pluginIntrospectPlugin{}}, nil
	}

	infos := s.pluginEngine.pluginv2.Introspect()
	plugins := make([]pluginIntrospectPlugin, 0, len(infos))
	for _, info := range infos {
		regs := make([]hookRegistration, 0, len(info.Registrations))
		for _, r := range info.Registrations {
			regs = append(regs, hookRegistration{
				Protocol: r.Protocol,
				Event:    r.Event,
				Phase:    r.Phase,
			})
		}
		plugins = append(plugins, pluginIntrospectPlugin{
			Name:          info.Name,
			Path:          info.Path,
			Enabled:       info.Enabled,
			Registrations: regs,
			Vars:          info.Vars,
		})
	}
	return nil, &pluginIntrospectResult{Plugins: plugins}, nil
}

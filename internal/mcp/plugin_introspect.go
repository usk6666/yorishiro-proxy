package mcp

import (
	"context"
	"time"
	"unicode/utf8"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// pluginIntrospectInput is the JSON input for the plugin_introspect MCP
// tool. Today the tool accepts no parameters: it always returns the full
// list of loaded pluginv2 plugins. The struct exists so the gomcp SDK can
// generate a JSON schema and reject unexpected fields.
type pluginIntrospectInput struct{}

// pluginIntrospectResult is the structured response for plugin_introspect.
// One entry per loaded pluginv2 plugin.
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

	// FailOpenCount counts this plugin's hook outcomes that the engine
	// refused or could not evaluate and treated as CONTINUE. Always
	// present (0 when none).
	FailOpenCount int64 `json:"fail_open_count"`

	// FailOpenByKind breaks FailOpenCount down per kind token.
	FailOpenByKind map[string]int64 `json:"fail_open_by_kind,omitempty"`

	// LastFailOpen is the most recent fail-open outcome.
	LastFailOpen *pluginFailOpenRecord `json:"last_fail_open,omitempty"`
}

// pluginFailOpenRecord mirrors pluginv2.FailOpenRecord in the MCP wire
// schema.
type pluginFailOpenRecord struct {
	Kind     string `json:"kind"`
	Action   string `json:"action,omitempty"`
	Protocol string `json:"protocol"`
	Event    string `json:"event"`
	Phase    string `json:"phase"`
	Reason   string `json:"reason"`
	At       string `json:"at"`
}

// hookRegistration mirrors pluginv2.HookRegistration in the MCP wire
// schema. Kept as a separate struct so the JSON tags are explicit and
// `omitempty` on optional future fields stays under MCP's control.
type hookRegistration struct {
	Protocol string `json:"protocol"`
	Event    string `json:"event"`
	Phase    string `json:"phase"`
}

// failOpenReasonOutputCap bounds last_fail_open.reason in the MCP response.
// Applied after Output Filter masking so a sensitive value straddling the
// cut is masked whole before it is truncated.
const failOpenReasonOutputCap = 256

// registerPluginIntrospect registers the plugin_introspect MCP tool.
func (s *Server) registerPluginIntrospect() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "plugin_introspect",
		Description: "List loaded plugins with their (protocol, event, phase) hook registrations and " +
			"the redacted PluginConfig.Vars map. fail_open_count counts hook outcomes the engine refused or could not " +
			"evaluate and treated as CONTINUE (e.g. a RESPOND whose shape does not match the hook, a hook runtime error) — " +
			"the message was forwarded anyway; last_fail_open shows the most recent one. " +
			"Returns an empty list when no plugin engine is configured. " +
			"Full reference: call docs(topic=\"plugin_introspect\").",
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
		p := pluginIntrospectPlugin{
			Name:          info.Name,
			Path:          info.Path,
			Enabled:       info.Enabled,
			Registrations: regs,
			Vars:          info.Vars,
			FailOpenCount: info.FailOpen.Total,
		}
		if len(info.FailOpen.ByKind) > 0 {
			p.FailOpenByKind = make(map[string]int64, len(info.FailOpen.ByKind))
			for k, v := range info.FailOpen.ByKind {
				p.FailOpenByKind[string(k)] = v
			}
		}
		if last := info.FailOpen.Last; last != nil {
			p.LastFailOpen = &pluginFailOpenRecord{
				Kind:     string(last.Kind),
				Action:   last.Action,
				Protocol: last.Protocol,
				Event:    last.Event,
				Phase:    last.Phase,
				Reason:   s.failOpenReasonForOutput(last.Reason),
				At:       last.At.UTC().Format(time.RFC3339),
			}
		}
		plugins = append(plugins, p)
	}
	return nil, &pluginIntrospectResult{Plugins: plugins}, nil
}

// failOpenReasonForOutput prepares a fail-open reason for the agent. A
// hook_error reason is the plugin's own error text, which can carry values
// the plugin read from traffic, so every reason goes through the Output
// Filter (RFC-001 §3.7) before it leaves the MCP boundary, then is cut to
// failOpenReasonOutputCap bytes on a rune boundary.
func (s *Server) failOpenReasonForOutput(reason string) string {
	masked := string(s.filterOutputBody([]byte(reason)))
	if len(masked) <= failOpenReasonOutputCap {
		return masked
	}
	cut := failOpenReasonOutputCap
	for cut > 0 && !utf8.RuneStart(masked[cut]) {
		cut--
	}
	return masked[:cut]
}

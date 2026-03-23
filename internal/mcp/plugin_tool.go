package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// pluginInput is the typed input for the plugin tool.
type pluginInput struct {
	// Action specifies the plugin management action.
	// Available actions: list, reload, enable, disable.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	// It is optional; the list action does not require params.
	Params *pluginParams `json:"params,omitempty"`
}

// pluginParams holds the union of all plugin action-specific parameters.
type pluginParams struct {
	// Name is the plugin name (used by reload, enable, disable).
	// If empty for reload, all plugins are reloaded.
	Name string `json:"name,omitempty"`
}

// availablePluginActions lists the valid action names for the plugin tool.
var availablePluginActions = []string{"list", "reload", "enable", "disable"}

// registerPlugin registers the plugin MCP tool.
func (s *Server) registerPlugin() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "plugin",
		Description: "Manage Starlark plugins. " +
			"Available actions: " +
			"'list' returns all registered plugins with metadata (name, path, enabled, hooks); " +
			"'reload' reloads a plugin by name from disk (if name is empty, reloads all); " +
			"'enable' enables a disabled plugin by name; " +
			"'disable' disables a plugin by name (hooks are skipped during dispatch).",
	}, s.handlePlugin)
}

// handlePlugin routes the plugin tool invocation to the appropriate action handler.
func (s *Server) handlePlugin(ctx context.Context, _ *gomcp.CallToolRequest, input pluginInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()

	params := pluginParams{}
	if input.Params != nil {
		params = *input.Params
	}

	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "plugin",
		"action", input.Action,
		"name", params.Name,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "plugin",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if s.deps.pluginEngine == nil {
		return nil, nil, fmt.Errorf("plugin engine is not initialized: configure plugins in the config file (-config flag) with a 'plugins' section")
	}

	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availablePluginActions, ", "))
	case "list":
		return s.handlePluginList()
	case "reload":
		return s.handlePluginReload(ctx, params)
	case "enable":
		return s.handlePluginEnable(params)
	case "disable":
		return s.handlePluginDisable(params)
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %s", input.Action, strings.Join(availablePluginActions, ", "))
	}
}

// pluginListResult is the structured output of the list action.
type pluginListResult struct {
	Plugins []plugin.PluginInfo `json:"plugins"`
	Count   int                 `json:"count"`
}

// handlePluginList returns all loaded plugins with metadata.
func (s *Server) handlePluginList() (*gomcp.CallToolResult, *pluginListResult, error) {
	infos := s.deps.pluginEngine.Plugins()
	return nil, &pluginListResult{
		Plugins: infos,
		Count:   len(infos),
	}, nil
}

// pluginReloadResult is the structured output of the reload action.
type pluginReloadResult struct {
	Reloaded string `json:"reloaded"`
	Message  string `json:"message"`
}

// handlePluginReload reloads a specific plugin or all plugins.
func (s *Server) handlePluginReload(ctx context.Context, params pluginParams) (*gomcp.CallToolResult, *pluginReloadResult, error) {
	if params.Name == "" {
		err := s.deps.pluginEngine.ReloadAll(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("reload all plugins: %w", err)
		}
		return nil, &pluginReloadResult{
			Reloaded: "all",
			Message:  "all plugins reloaded successfully",
		}, nil
	}

	if err := s.deps.pluginEngine.ReloadPlugin(ctx, params.Name); err != nil {
		return nil, nil, fmt.Errorf("reload plugin: %w", err)
	}
	return nil, &pluginReloadResult{
		Reloaded: params.Name,
		Message:  fmt.Sprintf("plugin %q reloaded successfully", params.Name),
	}, nil
}

// pluginToggleResult is the structured output of the enable/disable actions.
type pluginToggleResult struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// handlePluginEnable enables a plugin by name.
func (s *Server) handlePluginEnable(params pluginParams) (*gomcp.CallToolResult, *pluginToggleResult, error) {
	if params.Name == "" {
		return nil, nil, fmt.Errorf("params.name is required for enable action")
	}
	if err := s.deps.pluginEngine.SetPluginEnabled(params.Name, true); err != nil {
		return nil, nil, fmt.Errorf("enable plugin: %w", err)
	}
	return nil, &pluginToggleResult{
		Name:    params.Name,
		Enabled: true,
	}, nil
}

// handlePluginDisable disables a plugin by name.
func (s *Server) handlePluginDisable(params pluginParams) (*gomcp.CallToolResult, *pluginToggleResult, error) {
	if params.Name == "" {
		return nil, nil, fmt.Errorf("params.name is required for disable action")
	}
	if err := s.deps.pluginEngine.SetPluginEnabled(params.Name, false); err != nil {
		return nil, nil, fmt.Errorf("disable plugin: %w", err)
	}
	return nil, &pluginToggleResult{
		Name:    params.Name,
		Enabled: false,
	}, nil
}

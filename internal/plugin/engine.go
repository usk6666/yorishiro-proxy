package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

// Engine manages the lifecycle of Starlark-based plugins.
// It loads scripts, initializes the Starlark runtime, and registers
// hook handlers with the Registry for dispatch.
type Engine struct {
	mu       sync.RWMutex
	registry *Registry
	plugins  []*loadedPlugin
	logger   *slog.Logger
}

// loadedPlugin represents a successfully loaded and initialized plugin.
type loadedPlugin struct {
	config  PluginConfig
	globals starlark.StringDict
	enabled bool
}

// PluginInfo describes a loaded plugin for external consumers (e.g. MCP tools).
type PluginInfo struct {
	// Name is a human-readable name derived from the script path.
	Name string `json:"name"`
	// Path is the filesystem path to the Starlark script.
	Path string `json:"path"`
	// Protocol is the protocol this plugin applies to.
	Protocol string `json:"protocol"`
	// Hooks lists the hook names this plugin subscribes to.
	Hooks []string `json:"hooks"`
	// Enabled indicates whether the plugin is currently active.
	Enabled bool `json:"enabled"`
}

// NewEngine creates a new plugin Engine with the given logger.
// If logger is nil, a default no-op logger is used.
func NewEngine(logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return &Engine{
		registry: NewRegistry(),
		logger:   logger,
	}
}

// Registry returns the hook registry used by this engine.
func (e *Engine) Registry() *Registry {
	return e.registry
}

// LoadPlugins loads and initializes all plugins from the given configurations.
// Plugins are loaded in order; each plugin's hook functions are registered
// with the engine's Registry. If a plugin fails to load, the error is
// handled according to the plugin's OnError setting.
//
// This method is not safe for concurrent use; call it during initialization.
func (e *Engine) LoadPlugins(ctx context.Context, configs []PluginConfig) error {
	for i, cfg := range configs {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("plugin config at index %d: %w", i, err)
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, cfg := range configs {
		if err := e.loadPlugin(ctx, cfg); err != nil {
			behavior := cfg.onErrorBehavior()
			if behavior == OnErrorAbort {
				return fmt.Errorf("load plugin %q: %w", cfg.Path, err)
			}
			e.logger.WarnContext(ctx, "skipping plugin due to load error",
				slog.String("plugin", cfg.Path),
				slog.String("error", err.Error()),
			)
			continue
		}
		e.logger.InfoContext(ctx, "loaded plugin",
			slog.String("plugin", cfg.Path),
			slog.String("protocol", cfg.Protocol),
			slog.Any("hooks", cfg.Hooks),
		)
	}

	return nil
}

// loadPlugin loads a single Starlark script and registers its hook functions.
func (e *Engine) loadPlugin(_ context.Context, cfg PluginConfig) error {
	data, err := os.ReadFile(cfg.Path)
	if err != nil {
		return fmt.Errorf("read script: %w", err)
	}

	thread := &starlark.Thread{
		Name: cfg.Path,
		Print: func(_ *starlark.Thread, msg string) {
			e.logger.Info("plugin print", slog.String("plugin", cfg.Path), slog.String("message", msg))
		},
	}

	predeclared := starlark.StringDict{
		"action": newActionModule(),
		"crypto": newCryptoModule(),
	}

	globals, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread,
		cfg.Path,
		data,
		predeclared,
	)
	if err != nil {
		return fmt.Errorf("exec script: %w", err)
	}

	lp := &loadedPlugin{
		config:  cfg,
		globals: globals,
		enabled: true,
	}
	e.plugins = append(e.plugins, lp)

	// Register hook handlers for each configured hook.
	onError := cfg.onErrorBehavior()
	for _, hookName := range cfg.Hooks {
		hook := Hook(hookName)
		fn, ok := globals[hookName]
		if !ok {
			e.logger.WarnContext(context.Background(), "hook function not found in script",
				slog.String("plugin", cfg.Path),
				slog.String("hook", hookName),
			)
			continue
		}
		callable, ok := fn.(starlark.Callable)
		if !ok {
			e.logger.WarnContext(context.Background(), "hook is not callable",
				slog.String("plugin", cfg.Path),
				slog.String("hook", hookName),
			)
			continue
		}

		handler := e.makeHandler(cfg.Path, hook, callable, cfg.maxSteps())
		e.registry.Register(cfg.Path, hook, handler, onError)
	}

	return nil
}

// makeHandler creates a HookHandler that calls a Starlark function.
// A new starlark.Thread is created for each invocation to ensure thread safety,
// since starlark.Thread is not safe for concurrent use.
func (e *Engine) makeHandler(pluginName string, hook Hook, fn starlark.Callable, maxSteps uint64) HookHandler {
	return func(ctx context.Context, data map[string]any) (*HookResult, error) {
		// Create a new Thread per call to avoid data races.
		thread := &starlark.Thread{
			Name: pluginName,
			Print: func(_ *starlark.Thread, msg string) {
				e.logger.Info("plugin print", slog.String("plugin", pluginName), slog.String("message", msg))
			},
		}

		// Set execution step limit to prevent infinite loops (DoS).
		if maxSteps > 0 {
			thread.SetMaxExecutionSteps(maxSteps)
		}

		// Connect context cancellation to thread cancellation.
		if ctx.Done() != nil {
			go func() {
				<-ctx.Done()
				thread.Cancel(ctx.Err().Error())
			}()
		}

		// Convert Go map to Starlark dict.
		starlarkData, err := goToStarlark(data)
		if err != nil {
			return nil, fmt.Errorf("convert hook data: %w", err)
		}

		// Call the Starlark function with the data dict.
		result, err := starlark.Call(thread, fn, starlark.Tuple{starlarkData}, nil)
		if err != nil {
			return nil, fmt.Errorf("call hook %q in plugin %q: %w", string(hook), pluginName, err)
		}

		// Parse the result into a HookResult.
		return parseHookResult(hook, result)
	}
}

// parseHookResult converts a Starlark return value into a HookResult.
// Expected return format is a dict with:
//
//	{"action": "CONTINUE"} or {"action": "CONTINUE", "data": {...}}
//	{"action": "DROP"}
//	{"action": "RESPOND", "response": {...}}
//
// A None return is treated as CONTINUE with no modifications.
func parseHookResult(hook Hook, val starlark.Value) (*HookResult, error) {
	if val == starlark.None {
		return &HookResult{Action: ActionContinue}, nil
	}

	dict, ok := val.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("hook must return a dict or None, got %s", val.Type())
	}

	// Parse action.
	actionVal, found, err := dict.Get(starlark.String("action"))
	if err != nil {
		return nil, fmt.Errorf("get action from result: %w", err)
	}
	if !found {
		return &HookResult{Action: ActionContinue}, nil
	}

	actionStr, ok := starlark.AsString(actionVal)
	if !ok {
		return nil, fmt.Errorf("action must be a string, got %s", actionVal.Type())
	}

	action, err := ParseActionType(actionStr)
	if err != nil {
		return nil, err
	}

	if err := ValidateAction(hook, action); err != nil {
		return nil, err
	}

	result := &HookResult{Action: action}

	// Parse data if present.
	dataVal, found, err := dict.Get(starlark.String("data"))
	if err != nil {
		return nil, fmt.Errorf("get data from result: %w", err)
	}
	if found && dataVal != starlark.None {
		goData, err := starlarkToGo(dataVal)
		if err != nil {
			return nil, fmt.Errorf("convert result data: %w", err)
		}
		if m, ok := goData.(map[string]any); ok {
			result.Data = m
		}
	}

	// Parse response data if present (for RESPOND action).
	if action == ActionRespond {
		respVal, found, err := dict.Get(starlark.String("response"))
		if err != nil {
			return nil, fmt.Errorf("get response from result: %w", err)
		}
		if found && respVal != starlark.None {
			goResp, err := starlarkToGo(respVal)
			if err != nil {
				return nil, fmt.Errorf("convert response data: %w", err)
			}
			if m, ok := goResp.(map[string]any); ok {
				result.ResponseData = m
			}
		}
	}

	return result, nil
}

// Dispatch dispatches a hook through the registry.
// This is a convenience method that delegates to the underlying Registry.
func (e *Engine) Dispatch(ctx context.Context, hook Hook, data map[string]any) (*HookResult, error) {
	return e.registry.Dispatch(ctx, hook, data)
}

// Plugins returns information about all loaded plugins.
func (e *Engine) Plugins() []PluginInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	infos := make([]PluginInfo, 0, len(e.plugins))
	for _, lp := range e.plugins {
		infos = append(infos, PluginInfo{
			Name:     pluginName(lp.config.Path),
			Path:     lp.config.Path,
			Protocol: lp.config.Protocol,
			Hooks:    lp.config.Hooks,
			Enabled:  lp.enabled,
		})
	}
	return infos
}

// SetPluginEnabled sets the enabled state for the named plugin.
// The name is matched against the human-readable name derived from the script path.
// Returns an error if the plugin is not found.
func (e *Engine) SetPluginEnabled(name string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, lp := range e.plugins {
		if pluginName(lp.config.Path) == name {
			lp.enabled = enabled
			e.registry.SetEnabled(lp.config.Path, enabled)
			return nil
		}
	}
	return fmt.Errorf("plugin %q not found", name)
}

// ReloadPlugin reloads a single plugin by name.
// The plugin is unregistered from the registry, re-loaded from disk,
// and re-registered. The enabled state is preserved.
func (e *Engine) ReloadPlugin(ctx context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, lp := range e.plugins {
		if pluginName(lp.config.Path) != name {
			continue
		}
		wasEnabled := lp.enabled
		e.registry.RemoveByPlugin(lp.config.Path)

		if err := e.loadPlugin(ctx, lp.config); err != nil {
			// Remove the stale entry from plugins slice.
			e.plugins = append(e.plugins[:i], e.plugins[i+1:]...)
			return fmt.Errorf("reload plugin %q: %w", name, err)
		}

		// The new plugin was appended at the end by loadPlugin.
		newPlugin := e.plugins[len(e.plugins)-1]
		newPlugin.enabled = wasEnabled
		if !wasEnabled {
			e.registry.SetEnabled(newPlugin.config.Path, false)
		}

		// Remove the old entry at index i.
		e.plugins = append(e.plugins[:i], e.plugins[i+1:]...)
		return nil
	}
	return fmt.Errorf("plugin %q not found", name)
}

// ReloadAll reloads all loaded plugins from disk.
// Each plugin's enabled state is preserved.
func (e *Engine) ReloadAll(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Snapshot the current configs and enabled states.
	type snapshot struct {
		config  PluginConfig
		enabled bool
	}
	snapshots := make([]snapshot, 0, len(e.plugins))
	for _, lp := range e.plugins {
		snapshots = append(snapshots, snapshot{config: lp.config, enabled: lp.enabled})
	}

	// Clear everything.
	e.registry.Clear()
	e.plugins = nil

	// Reload all plugins.
	var firstErr error
	for _, s := range snapshots {
		if err := e.loadPlugin(ctx, s.config); err != nil {
			e.logger.WarnContext(ctx, "failed to reload plugin",
				slog.String("plugin", s.config.Path),
				slog.String("error", err.Error()),
			)
			if firstErr == nil {
				firstErr = fmt.Errorf("reload plugin %q: %w", s.config.Path, err)
			}
			continue
		}
		newPlugin := e.plugins[len(e.plugins)-1]
		newPlugin.enabled = s.enabled
		if !s.enabled {
			e.registry.SetEnabled(newPlugin.config.Path, false)
		}
	}
	return firstErr
}

// Close releases all resources held by the engine.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.registry.Clear()
	e.plugins = nil
	return nil
}

// PluginCount returns the number of loaded plugins.
func (e *Engine) PluginCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.plugins)
}

// pluginName derives a human-readable name from a script path.
// It returns the base filename without the extension (e.g., "add_auth_header"
// from "/path/to/add_auth_header.star").
func pluginName(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

// newActionModule creates the predeclared "action" module available to scripts.
// It exposes constants: action.CONTINUE, action.DROP, action.RESPOND.
func newActionModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "action",
		Members: starlark.StringDict{
			"CONTINUE": starlark.String("CONTINUE"),
			"DROP":     starlark.String("DROP"),
			"RESPOND":  starlark.String("RESPOND"),
		},
	}
}

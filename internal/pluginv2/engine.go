package pluginv2

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// Engine is the v2 Starlark plugin engine. It loads scripts, runs them
// once at load time so they can call register_hook(), and exposes the
// resulting Registry for runtime dispatch (consumed by USK-671 et al.).
//
// Reload, dispatch, and per-call thread management are intentionally not
// part of USK-665. Subsequent N8 issues build them on top of the registry.
type Engine struct {
	mu         sync.RWMutex
	registry   *Registry
	plugins    []*loadedPlugin
	states     map[string]*PluginState
	stores     map[string]*PluginStore
	db         *sql.DB
	logger     *slog.Logger
	shutdownFn ShutdownFunc

	// transactionStore and streamStore back ctx.transaction_state and
	// ctx.stream_state respectively (USK-670 / RFC §9.3 D6). Lifetime is
	// owned by Layers via the StateReleaser interface; engine.NewCtx
	// looks up (or creates) the per-(ConnID, key) ScopedState for each
	// hook invocation.
	transactionStore *scopeStore
	streamStore      *scopeStore

	// registerHookBuiltin is shared across all plugin loads. Each load sets
	// the active registry on the calling Starlark thread so the builtin
	// records hooks against the right Registry.
	registerHookBuiltin *starlark.Builtin
}

// loadedPlugin tracks a successfully loaded script so future reload work
// (out of scope for USK-665) can find it.
//
// registrations records the (Protocol, Event, Phase) tuples that the
// register_hook builtin appended for this plugin during script execution.
// The plugin_introspect MCP tool (USK-676) reads this slice to surface the
// loaded surface back to operators.
type loadedPlugin struct {
	config        PluginConfig
	globals       starlark.StringDict
	registrations []registeredHook
}

// registeredHook is the per-plugin record of one register_hook call. The
// fields are pure strings (Phase carried as its string form) so that
// plugin_introspect can serialise the slice to JSON without re-deriving the
// surface from the registry. Order matches the script's register_hook call
// order — which is also the registry's append order for that plugin.
type registeredHook struct {
	Protocol string
	Event    string
	Phase    string
}

// NewEngine constructs an Engine. A nil logger falls back to a stderr
// error-level logger to match legacy behavior.
func NewEngine(logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return &Engine{
		registry:            NewRegistry(),
		states:              make(map[string]*PluginState),
		stores:              make(map[string]*PluginStore),
		logger:              logger,
		transactionStore:    newScopeStore(logger, "transaction"),
		streamStore:         newScopeStore(logger, "stream"),
		registerHookBuiltin: makeRegisterHookBuiltin(),
	}
}

// Registry returns the engine's hook registry. Callers should use Lookup
// to find hooks at runtime.
func (e *Engine) Registry() *Registry {
	return e.registry
}

// SetShutdownFunc sets the callback proxy.shutdown(reason) calls. Must be
// set before LoadPlugins to take effect for newly loaded plugins.
func (e *Engine) SetShutdownFunc(fn ShutdownFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdownFn = fn
}

// SetDB attaches a SQLite connection that the predeclared "store" module
// uses for per-plugin persistent KV. Must be called before LoadPlugins
// to expose store to those plugins.
func (e *Engine) SetDB(ctx context.Context, db *sql.DB) error {
	if err := EnsureTable(ctx, db); err != nil {
		return fmt.Errorf("pluginv2: set db: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.db = db
	return nil
}

// LoadPlugins validates each PluginConfig (rejecting legacy fields with
// the migration message) then executes each script once with register_hook
// + the predeclared module set bound to the Starlark thread. A failed
// load is handled per cfg.OnError: skip logs and continues; abort returns.
func (e *Engine) LoadPlugins(ctx context.Context, configs []PluginConfig) error {
	for i := range configs {
		if err := configs[i].Validate(); err != nil {
			return fmt.Errorf("pluginv2: plugin config at index %d: %w", i, err)
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range configs {
		cfg := configs[i]
		if err := e.loadPlugin(ctx, cfg); err != nil {
			behavior := cfg.onErrorBehavior()
			if behavior == OnErrorAbort {
				return fmt.Errorf("pluginv2: load plugin %q: %w", cfg.Path, err)
			}
			e.logger.WarnContext(ctx, "pluginv2: skipping plugin due to load error",
				slog.String("plugin", cfg.Path),
				slog.String("error", err.Error()),
			)
			continue
		}
		e.logger.InfoContext(ctx, "pluginv2: loaded plugin",
			slog.String("plugin", cfg.Path),
		)
	}
	return nil
}

// maxScriptSize caps a plugin script at 10 MiB. Plugin scripts are operator-
// controlled, but a defensive cap prevents an accidental multi-GB file from
// OOMing the proxy at load time.
const maxScriptSize = 10 << 20

// loadPlugin executes one plugin script with the engine's predeclared
// modules and register_hook builtin. The script's register_hook() calls
// populate e.registry as a side effect. ctx cancellation is bridged into
// the Starlark thread so a runaway top-level statement aborts cleanly on
// SIGINT instead of waiting for the per-thread step limit to trip.
func (e *Engine) loadPlugin(ctx context.Context, cfg PluginConfig) error {
	data, err := readBoundedScript(cfg.Path)
	if err != nil {
		return err
	}

	name := cfg.Name
	if name == "" {
		name = pluginName(cfg.Path)
	}

	thread := &starlark.Thread{
		Name: cfg.Path,
		Print: func(_ *starlark.Thread, msg string) {
			e.logger.Info("pluginv2: plugin print",
				slog.String("plugin", cfg.Path),
				slog.String("message", msg),
			)
		},
	}
	thread.SetLocal(threadLocalRegistry, e.registry)
	thread.SetLocal(threadLocalPluginName, name)

	// loadedPlugin must be allocated up-front so the register_hook builtin
	// can append to its registrations slice via the threadLocalCurrentPlugin
	// pointer. We finalize globals and append to e.plugins after
	// ExecFileOptions returns successfully.
	lp := &loadedPlugin{config: cfg}
	thread.SetLocal(threadLocalCurrentPlugin, lp)

	// Apply step budget at load time as well as at runtime — a malicious or
	// runaway top-level statement would otherwise hang LoadPlugins.
	if steps := cfg.maxSteps(); steps > 0 {
		thread.SetMaxExecutionSteps(steps)
	}

	// Bridge ctx cancellation into thread.Cancel so external signals
	// (SIGINT, deadline) abort script execution promptly. The done channel
	// stops the watcher when ExecFileOptions returns, preventing a goroutine
	// leak. Pattern mirrors legacy internal/plugin Engine.makeHandler.
	done := make(chan struct{})
	defer close(done)
	if ctx != nil && ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				thread.Cancel(ctx.Err().Error())
			case <-done:
			}
		}()
	}

	configDict, err := newConfigDict(cfg.Vars)
	if err != nil {
		return fmt.Errorf("config dict: %w", err)
	}

	predeclared := starlark.StringDict{
		"action":        newActionModule(),
		"crypto":        newCryptoModule(),
		"config":        configDict,
		"state":         newStateModule(e.ensureState(name)),
		"proxy":         newProxyModule(e.shutdownFn),
		"register_hook": e.registerHookBuiltin,
	}
	if e.db != nil {
		predeclared["store"] = newStoreModule(e.ensureStore(name))
	}

	globals, err := starlark.ExecFileOptions(
		&syntax.FileOptions{},
		thread,
		cfg.Path,
		data,
		predeclared,
	)
	if err != nil {
		return wrapExecError(err, cfg.Path, name)
	}

	lp.globals = globals
	e.plugins = append(e.plugins, lp)
	return nil
}

// readBoundedScript stat+reads a plugin script, enforcing maxScriptSize as
// a defense-in-depth cap against accidental multi-GB files.
func readBoundedScript(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat script: %w", err)
	}
	if info.Size() > maxScriptSize {
		return nil, fmt.Errorf("script %q size %d exceeds limit %d bytes", path, info.Size(), maxScriptSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read script: %w", err)
	}
	return data, nil
}

// wrapExecError surfaces a *LoadError unwrapped (so callers can errors.As
// cleanly) and otherwise wraps the Starlark exec error with context.
func wrapExecError(err error, path, name string) error {
	var le *LoadError
	if errors.As(err, &le) {
		if le.Path == "" {
			le.Path = path
		}
		if le.PluginName == "" {
			le.PluginName = name
		}
		return le
	}
	return fmt.Errorf("exec script: %w", err)
}

func (e *Engine) ensureState(name string) *PluginState {
	if ps, ok := e.states[name]; ok {
		return ps
	}
	ps := NewPluginState()
	e.states[name] = ps
	return ps
}

func (e *Engine) ensureStore(name string) *PluginStore {
	if ps, ok := e.stores[name]; ok {
		return ps
	}
	ps := NewPluginStore(e.db, name)
	e.stores[name] = ps
	return ps
}

// PluginCount returns the number of successfully loaded plugins.
func (e *Engine) PluginCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.plugins)
}

// Close releases engine resources. Plugin state and store caches are
// cleared so sensitive data does not linger in memory.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.plugins = nil
	for _, ps := range e.states {
		ps.mu.Lock()
		ps.data = nil
		ps.mu.Unlock()
	}
	e.states = nil
	for _, ps := range e.stores {
		ps.mu.Lock()
		ps.cache = nil
		ps.loaded = false
		ps.mu.Unlock()
	}
	e.stores = nil
	if e.transactionStore != nil {
		e.transactionStore.purge()
	}
	if e.streamStore != nil {
		e.streamStore.purge()
	}
	return nil
}

// pluginName derives a stable identifier from a script path: the basename
// without the extension. (Sibling: legacy internal/plugin.pluginName.)
func pluginName(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

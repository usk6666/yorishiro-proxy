package proxybuild

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// shutdownTimeout bounds the wait for a listener goroutine to exit during
// graceful shutdown. Mirrors proxy.Manager.shutdownTimeout.
const shutdownTimeout = 30 * time.Second

// DefaultListenerName is the implicit listener name when callers omit one.
// Mirrors proxy.DefaultListenerName.
const DefaultListenerName = "default"

// defaultListenAddr is the bind address used when StartNamed is called
// with an empty addr. Mirrors proxy.Manager's hard-coded default.
const defaultListenAddr = "127.0.0.1:8080"

// listenerEntry tracks a single named listener plus its lifecycle state.
type listenerEntry struct {
	stack      *Stack
	cancel     context.CancelFunc
	done       chan struct{}
	listenAddr string
	startedAt  time.Time
}

// ManagerConfig configures a Manager. The factory is invoked per StartNamed
// call to produce the per-listener Stack — making engine, store, build
// config, and policy a process-singleton view passed into every listener.
//
// The factory pattern keeps Manager a thin orchestrator (it does not own
// the lifetime of the engine, store, etc.) while letting callers decide
// per-listener variation (different scopes, different listen addresses).
type ManagerConfig struct {
	// Logger is used for manager-level Info/Debug logs.
	Logger *slog.Logger

	// StackFactory builds a per-listener Stack. The factory receives the
	// listener name and addr resolved by StartNamed (defaults applied).
	// All other Deps fields the factory must source from its closure.
	StackFactory func(ctx context.Context, name, addr string) (*Stack, error)
}

// Manager orchestrates one or more named live Stacks. It exposes
// Start/Stop/Status/SetMaxConnections/SetPeekTimeout/SetUpstreamProxy and
// the related methods consumed by the MCP proxy_start / proxy_stop tools.
//
// Caveats:
//
//   - StartTCPForwardsNamed / TCPForwardAddrs are stub methods returning
//     ErrTCPForwardsNotSupported. Real TCP forward orchestration is
//     tracked separately (see doc.go).
//   - SetMaxConnections / SetPeekTimeout fan-out applies to the wrapped
//     Listener.SetMaxConnections / SetPeekTimeout (which mutate the
//     underlying connector.FullListener).
type Manager struct {
	logger        *slog.Logger
	factory       func(ctx context.Context, name, addr string) (*Stack, error)
	peekTimeout   time.Duration
	maxConns      int
	upstreamProxy string

	mu        sync.Mutex
	listeners map[string]*listenerEntry
}

// NewManager constructs a Manager. cfg.StackFactory is required; nil
// returns an error so the bug surfaces at construction rather than at
// the first StartNamed call.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.StackFactory == nil {
		return nil, fmt.Errorf("proxybuild: NewManager: StackFactory is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		logger:    logger,
		factory:   cfg.StackFactory,
		listeners: make(map[string]*listenerEntry),
	}, nil
}

// Start is shorthand for StartNamed(ctx, DefaultListenerName, listenAddr).
// Returns ErrAlreadyRunning when the default listener is already running
// (mirrors proxy.Manager.Start).
func (m *Manager) Start(ctx context.Context, listenAddr string) error {
	return m.StartNamed(ctx, DefaultListenerName, listenAddr)
}

// StartNamed builds a Stack via the configured factory, starts the
// listener, and waits for Ready (or an early Start error) before returning.
//
// Returns ErrAlreadyRunning when name is the default listener name and a
// default listener is already running. Returns ErrListenerExists for
// non-default names that already exist.
//
// listenAddr defaults to "127.0.0.1:8080" when empty.
func (m *Manager) StartNamed(ctx context.Context, name string, listenAddr string) error {
	if name == "" {
		name = DefaultListenerName
	}
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[name]; exists {
		if name == DefaultListenerName {
			return ErrAlreadyRunning
		}
		return fmt.Errorf("listener %q: %w", name, ErrListenerExists)
	}

	stack, err := m.factory(ctx, name, listenAddr)
	if err != nil {
		return fmt.Errorf("proxybuild: build live stack %q: %w", name, err)
	}

	// Apply manager-level tunables to the new Listener so a runtime
	// SetMaxConnections / SetPeekTimeout call before any listener
	// existed is honored when the listener comes up.
	if m.maxConns > 0 {
		stack.Listener.SetMaxConnections(m.maxConns)
	}
	if m.peekTimeout > 0 {
		stack.Listener.SetPeekTimeout(m.peekTimeout)
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		defer close(done)
		errCh <- stack.Listener.Start(listenerCtx)
	}()

	// Wait for Ready (success) or an early error from Start.
	select {
	case <-stack.Listener.Ready():
	case err := <-errCh:
		cancel()
		if err != nil {
			return fmt.Errorf("start proxy %q: %w", name, err)
		}
		return fmt.Errorf("start proxy %q: listener exited unexpectedly", name)
	}

	m.listeners[name] = &listenerEntry{
		stack:      stack,
		cancel:     cancel,
		done:       done,
		listenAddr: stack.Listener.Addr(),
		startedAt:  time.Now(),
	}

	m.logger.Info("proxy started", "name", name, "listen_addr", stack.Listener.Addr())
	return nil
}

// Stop is shorthand for StopNamed(ctx, DefaultListenerName).
func (m *Manager) Stop(ctx context.Context) error {
	return m.StopNamed(ctx, DefaultListenerName)
}

// StopNamed gracefully shuts down the named listener. Returns ErrNotRunning
// for the default listener and ErrListenerNotFound for other names.
func (m *Manager) StopNamed(ctx context.Context, name string) error {
	if name == "" {
		name = DefaultListenerName
	}

	m.mu.Lock()
	entry, exists := m.listeners[name]
	if !exists {
		m.mu.Unlock()
		if name == DefaultListenerName {
			return ErrNotRunning
		}
		return fmt.Errorf("listener %q: %w", name, ErrListenerNotFound)
	}
	delete(m.listeners, name)
	m.mu.Unlock()

	return m.shutdownEntry(ctx, name, entry)
}

// StopAll gracefully shuts down every running listener. Returns the first
// error encountered; remaining listeners are still shut down.
func (m *Manager) StopAll(ctx context.Context) error {
	m.mu.Lock()
	if len(m.listeners) == 0 {
		m.mu.Unlock()
		return nil
	}
	entries := m.listeners
	m.listeners = make(map[string]*listenerEntry)
	m.mu.Unlock()

	var firstErr error
	for name, entry := range entries {
		if err := m.shutdownEntry(ctx, name, entry); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// shutdownEntry cancels the listener's context and waits for the goroutine
// to exit (bounded by shutdownTimeout or ctx).
func (m *Manager) shutdownEntry(ctx context.Context, name string, entry *listenerEntry) error {
	entry.cancel()

	select {
	case <-entry.done:
		m.logger.Info("proxy stopped", "name", name, "listen_addr", entry.listenAddr)
		return nil
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("stop proxy %q: shutdown timed out after %v", name, shutdownTimeout)
	case <-ctx.Done():
		return fmt.Errorf("stop proxy %q: %w", name, ctx.Err())
	}
}

// Status returns whether the default listener is running and its listen
// address. Mirrors proxy.Manager.Status's "default-only" semantics.
func (m *Manager) Status() (running bool, listenAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[DefaultListenerName]
	if !exists {
		return false, ""
	}
	return true, entry.listenAddr
}

// ListenerStatus describes a single running listener. Mirrors
// proxy.ListenerStatus.
type ListenerStatus struct {
	Name              string `json:"name"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections int    `json:"active_connections"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
}

// ListenerStatuses returns a snapshot of every running listener. Returns
// nil when no listeners are running.
func (m *Manager) ListenerStatuses() []ListenerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.listeners) == 0 {
		return nil
	}

	out := make([]ListenerStatus, 0, len(m.listeners))
	for name, entry := range m.listeners {
		var uptime int64
		if !entry.startedAt.IsZero() {
			uptime = int64(time.Since(entry.startedAt).Seconds())
		}
		out = append(out, ListenerStatus{
			Name:              name,
			ListenAddr:        entry.listenAddr,
			ActiveConnections: entry.stack.Listener.ActiveConnections(),
			UptimeSeconds:     uptime,
		})
	}
	return out
}

// ListenerCount returns the number of currently running listeners.
func (m *Manager) ListenerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.listeners)
}

// ActiveConnections sums the active-connection counts across all running
// listeners.
func (m *Manager) ActiveConnections() int {
	m.mu.Lock()
	entries := make([]*listenerEntry, 0, len(m.listeners))
	for _, entry := range m.listeners {
		entries = append(entries, entry)
	}
	m.mu.Unlock()

	total := 0
	for _, entry := range entries {
		total += entry.stack.Listener.ActiveConnections()
	}
	return total
}

// Uptime reports how long the default listener has been running. Returns
// 0 when the default listener is not running. Mirrors proxy.Manager.Uptime.
func (m *Manager) Uptime() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[DefaultListenerName]
	if !exists || entry.startedAt.IsZero() {
		return 0
	}
	return time.Since(entry.startedAt)
}

// SetMaxConnections updates the concurrent-connection cap for new accepts.
// The change applies immediately to all running listeners; in-flight
// connections drain naturally.
func (m *Manager) SetMaxConnections(n int) {
	m.mu.Lock()
	m.maxConns = n
	listeners := make([]*Listener, 0, len(m.listeners))
	for _, entry := range m.listeners {
		listeners = append(listeners, entry.stack.Listener)
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l.SetMaxConnections(n)
	}
}

// MaxConnections returns the configured cap. When any listener is running,
// returns the first listener's current value (matches proxy.Manager
// semantics including the "first-running-wins" detail).
func (m *Manager) MaxConnections() int {
	m.mu.Lock()
	stored := m.maxConns
	var first *Listener
	for _, entry := range m.listeners {
		first = entry.stack.Listener
		break
	}
	m.mu.Unlock()
	if first != nil {
		return first.MaxConnections()
	}
	return stored
}

// SetPeekTimeout updates the protocol-detection timeout. Applies
// immediately to all running listeners.
func (m *Manager) SetPeekTimeout(d time.Duration) {
	m.mu.Lock()
	m.peekTimeout = d
	listeners := make([]*Listener, 0, len(m.listeners))
	for _, entry := range m.listeners {
		listeners = append(listeners, entry.stack.Listener)
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l.SetPeekTimeout(d)
	}
}

// PeekTimeout returns the configured peek timeout. When any listener is
// running, returns the first listener's current value.
func (m *Manager) PeekTimeout() time.Duration {
	m.mu.Lock()
	stored := m.peekTimeout
	var first *Listener
	for _, entry := range m.listeners {
		first = entry.stack.Listener
		break
	}
	m.mu.Unlock()
	if first != nil {
		return first.PeekTimeout()
	}
	return stored
}

// SetUpstreamProxy stores an upstream proxy URL. The string form is
// reflected back via UpstreamProxy() for status reporting; the live data
// path is wired by USK-690.
func (m *Manager) SetUpstreamProxy(proxyURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamProxy = proxyURL
}

// UpstreamProxy returns the stored upstream proxy URL, or empty string.
func (m *Manager) UpstreamProxy() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upstreamProxy
}

// Listener returns the Stack's Listener wrapper for the named listener,
// or nil if no such listener is running. Useful for tests and for callers
// that need to reach the bound pluginv2.Engine via Listener.PluginV2Engine().
func (m *Manager) Listener(name string) *Listener {
	if name == "" {
		name = DefaultListenerName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[name]
	if !exists {
		return nil
	}
	return entry.stack.Listener
}

// Stack returns the named listener's full Stack, or nil if no such
// listener is running.
func (m *Manager) Stack(name string) *Stack {
	if name == "" {
		name = DefaultListenerName
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[name]
	if !exists {
		return nil
	}
	return entry.stack
}

// StartTCPForwardsNamed is a stub that returns ErrTCPForwardsNotSupported.
// Real TCP forward orchestration is deferred to USK-697 (or a follow-up
// issue); the stub preserves signature compatibility with proxy.Manager.
//
// The first parameter is unused; the signature accepts a generic params
// argument so the eventual real implementation can extend it without
// breaking callers.
func (m *Manager) StartTCPForwardsNamed(_ context.Context, _ string, _ any) error {
	return ErrTCPForwardsNotSupported
}

// StartTCPForwardsNamedAny is the any-typed adapter mirroring the bridge
// method on proxy.Manager. Both manager types satisfy the same MCP
// connector interface (internal/mcp/components.go) via this name. proxybuild
// already accepts `any` natively, so this is a thin alias delegating to
// StartTCPForwardsNamed.
func (m *Manager) StartTCPForwardsNamedAny(ctx context.Context, name string, params any) error {
	return m.StartTCPForwardsNamed(ctx, name, params)
}

// StartTCPForwards is shorthand for StartTCPForwardsNamed on the default
// listener. Stub.
func (m *Manager) StartTCPForwards(ctx context.Context, params any) error {
	return m.StartTCPForwardsNamed(ctx, DefaultListenerName, params)
}

// TCPForwardAddrs returns nil. Stub.
func (m *Manager) TCPForwardAddrs() map[string]string {
	return nil
}

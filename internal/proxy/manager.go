package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// shutdownTimeout is the maximum time to wait for graceful shutdown.
const shutdownTimeout = 30 * time.Second

// DefaultListenerName is the name used for the default listener when no name is specified.
const DefaultListenerName = "default"

// ErrAlreadyRunning is returned when Start is called while the proxy is already running.
var ErrAlreadyRunning = errors.New("proxy is already running")

// ErrNotRunning is returned when Stop is called while the proxy is not running.
var ErrNotRunning = errors.New("proxy is not running")

// ErrListenerExists is returned when StartNamed is called with a name that is already in use.
var ErrListenerExists = errors.New("listener with this name already exists")

// ErrListenerNotFound is returned when StopNamed is called with a name that does not exist.
var ErrListenerNotFound = errors.New("listener not found")

// listenerEntry tracks a single named proxy listener and its lifecycle state.
type listenerEntry struct {
	listener   *Listener
	cancel     context.CancelFunc
	done       chan struct{}
	listenAddr string
	startedAt  time.Time
	// tcpForwards tracks active TCP forward listeners keyed by local port.
	tcpForwards map[string]*tcpForwardEntry
}

// Manager controls the lifecycle of proxy listeners and TCP forward listeners.
// It supports multiple named listeners running simultaneously.
// Start/Stop/Status methods operate on the "default" listener for backward compatibility.
type Manager struct {
	detector       ProtocolDetector
	logger         *slog.Logger
	peekTimeout    time.Duration
	maxConnections int

	mu        sync.Mutex
	listeners map[string]*listenerEntry

	// upstreamProxy holds the current upstream proxy URL.
	// Access is protected by mu.
	upstreamProxy string
}

// tcpForwardEntry tracks a single TCP forward listener and its done channel.
type tcpForwardEntry struct {
	listener *TCPForwardListener
	cancel   context.CancelFunc
	done     chan struct{}
}

// NewManager creates a new Manager with the given protocol detector and logger.
func NewManager(detector ProtocolDetector, logger *slog.Logger) *Manager {
	return &Manager{
		detector:  detector,
		logger:    logger,
		listeners: make(map[string]*listenerEntry),
	}
}

// Start begins the proxy on the specified listen address using the default listener name.
// If listenAddr is empty, it defaults to "127.0.0.1:8080".
// Returns ErrAlreadyRunning if the default listener is already started.
func (m *Manager) Start(ctx context.Context, listenAddr string) error {
	return m.StartNamed(ctx, DefaultListenerName, listenAddr)
}

// StartNamed begins a named proxy listener on the specified listen address.
// If listenAddr is empty, it defaults to "127.0.0.1:8080".
// Returns ErrListenerExists if a listener with the given name already exists.
func (m *Manager) StartNamed(ctx context.Context, name string, listenAddr string) error {
	if name == "" {
		name = DefaultListenerName
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[name]; exists {
		// Return ErrAlreadyRunning for the default listener to maintain backward compatibility.
		if name == DefaultListenerName {
			return ErrAlreadyRunning
		}
		return fmt.Errorf("listener %q: %w", name, ErrListenerExists)
	}

	if listenAddr == "" {
		listenAddr = "127.0.0.1:8080"
	}

	listener := NewListener(ListenerConfig{
		Addr:           listenAddr,
		Detector:       m.detector,
		Logger:         m.logger,
		PeekTimeout:    m.peekTimeout,
		MaxConnections: m.maxConnections,
	})
	listenerCtx, cancel := context.WithCancel(ctx)

	done := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		defer close(done)
		errCh <- listener.Start(listenerCtx)
	}()

	// Wait for the listener to be ready or fail.
	select {
	case <-listener.Ready():
		// Listener is accepting connections.
	case err := <-errCh:
		cancel()
		if err != nil {
			return fmt.Errorf("start proxy %q: %w", name, err)
		}
		return fmt.Errorf("start proxy %q: listener exited unexpectedly", name)
	}

	entry := &listenerEntry{
		listener:   listener,
		cancel:     cancel,
		done:       done,
		listenAddr: listener.Addr(),
		startedAt:  time.Now(),
	}
	m.listeners[name] = entry

	m.logger.Info("proxy started", "name", name, "listen_addr", entry.listenAddr)

	return nil
}

// StartTCPForwards creates and starts a TCP forward listener for each entry in
// the forwards map on the default listener.
// The map keys are local port numbers and values are upstream
// addresses in "host:port" format. The handler is the protocol handler that
// will process connections on each forward listener (typically the raw TCP handler).
//
// This method must be called while the default listener is running (after Start).
// All forward listeners share the listener's lifecycle and are stopped when Stop is called.
// If any listener fails to start, all previously started listeners in this call are
// cleaned up and an error is returned.
func (m *Manager) StartTCPForwards(ctx context.Context, forwards map[string]string, handler ProtocolHandler) error {
	return m.StartTCPForwardsNamed(ctx, DefaultListenerName, forwards, handler)
}

// StartTCPForwardsNamed creates and starts TCP forward listeners associated with the named listener.
func (m *Manager) StartTCPForwardsNamed(ctx context.Context, name string, forwards map[string]string, handler ProtocolHandler) error {
	if name == "" {
		name = DefaultListenerName
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.listeners[name]
	if !exists {
		return ErrNotRunning
	}

	if entry.tcpForwards == nil {
		entry.tcpForwards = make(map[string]*tcpForwardEntry)
	}

	// Track newly started listeners for rollback on failure.
	var started []string

	for port := range forwards {
		if _, exists := entry.tcpForwards[port]; exists {
			// Skip ports that already have a forward listener.
			continue
		}

		addr := fmt.Sprintf("127.0.0.1:%s", port)
		fl := NewTCPForwardListener(addr, handler, m.logger)
		flCtx, flCancel := context.WithCancel(ctx)

		done := make(chan struct{})
		errCh := make(chan error, 1)

		go func() {
			defer close(done)
			errCh <- fl.Start(flCtx)
		}()

		// Wait for the listener to be ready or fail.
		select {
		case <-fl.Ready():
			// Listener is accepting connections.
		case err := <-errCh:
			flCancel()
			// Rollback previously started listeners.
			m.stopTCPForwardsLocked(entry, started)
			if err != nil {
				return fmt.Errorf("start tcp forward on port %s: %w", port, err)
			}
			return fmt.Errorf("start tcp forward on port %s: listener exited unexpectedly", port)
		}

		entry.tcpForwards[port] = &tcpForwardEntry{
			listener: fl,
			cancel:   flCancel,
			done:     done,
		}
		started = append(started, port)

		m.logger.Info("tcp forward listener started", "name", name, "port", port, "upstream", forwards[port], "listen_addr", fl.Addr())
	}

	return nil
}

// stopTCPForwardsLocked stops the specified TCP forward listeners on the given entry.
// Must be called with m.mu held.
func (m *Manager) stopTCPForwardsLocked(entry *listenerEntry, ports []string) {
	for _, port := range ports {
		fwd, ok := entry.tcpForwards[port]
		if !ok {
			continue
		}
		fwd.cancel()
		<-fwd.done
		delete(entry.tcpForwards, port)
	}
}

// TCPForwardAddrs returns a map of port -> actual listen address for all active
// TCP forward listeners on the default listener. Returns nil when no forwards are active.
func (m *Manager) TCPForwardAddrs() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, exists := m.listeners[DefaultListenerName]
	if !exists || len(entry.tcpForwards) == 0 {
		return nil
	}
	addrs := make(map[string]string, len(entry.tcpForwards))
	for port, fwd := range entry.tcpForwards {
		addrs[port] = fwd.listener.Addr()
	}
	return addrs
}

// Stop gracefully shuts down the default listener and its TCP forward listeners.
// Returns ErrNotRunning if the default listener is not started.
func (m *Manager) Stop(ctx context.Context) error {
	return m.StopNamed(ctx, DefaultListenerName)
}

// StopNamed gracefully shuts down a named listener and its TCP forward listeners.
// Returns ErrListenerNotFound if the named listener does not exist.
// Returns ErrNotRunning for the default listener to maintain backward compatibility.
func (m *Manager) StopNamed(ctx context.Context, name string) error {
	if name == "" {
		name = DefaultListenerName
	}

	m.mu.Lock()

	entry, exists := m.listeners[name]
	if !exists {
		m.mu.Unlock()
		// Return ErrNotRunning for the default listener to maintain backward compatibility.
		if name == DefaultListenerName {
			return ErrNotRunning
		}
		return fmt.Errorf("listener %q: %w", name, ErrListenerNotFound)
	}

	// Remove from map before releasing the lock to prevent double-stop races.
	delete(m.listeners, name)

	m.mu.Unlock()

	return m.shutdownEntry(ctx, name, entry)
}

// StopAll gracefully shuts down all running listeners.
// Returns nil if no listeners are running.
func (m *Manager) StopAll(ctx context.Context) error {
	m.mu.Lock()

	if len(m.listeners) == 0 {
		m.mu.Unlock()
		return nil
	}

	// Snapshot and clear all entries.
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

// shutdownEntry performs the actual shutdown of a listener entry.
// It cancels TCP forwards and the main listener, then waits for completion.
func (m *Manager) shutdownEntry(ctx context.Context, name string, entry *listenerEntry) error {
	// Cancel all TCP forward listeners first.
	for _, fwd := range entry.tcpForwards {
		fwd.cancel()
	}

	// Cancel the main listener context to initiate shutdown.
	entry.cancel()

	// Wait for TCP forward listener goroutines to complete.
	for port, fwd := range entry.tcpForwards {
		select {
		case <-fwd.done:
			m.logger.Info("tcp forward listener stopped", "name", name, "port", port)
		case <-time.After(shutdownTimeout):
			m.logger.Warn("tcp forward listener shutdown timed out", "name", name, "port", port)
		}
	}

	// Wait for the main listener goroutine to complete, with a timeout.
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

// SetPeekTimeout sets the protocol detection timeout for new connections.
// If any listeners are already running, the change takes effect immediately
// for the next incoming connection on all listeners.
func (m *Manager) SetPeekTimeout(d time.Duration) {
	m.mu.Lock()
	m.peekTimeout = d
	listeners := make([]*Listener, 0, len(m.listeners))
	for _, entry := range m.listeners {
		listeners = append(listeners, entry.listener)
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l.SetPeekTimeout(d)
	}
}

// SetMaxConnections sets the maximum number of concurrent connections.
// If any listeners are already running, the change takes effect immediately
// for the next incoming connection on all listeners. Existing connections are not interrupted.
func (m *Manager) SetMaxConnections(n int) {
	m.mu.Lock()
	m.maxConnections = n
	listeners := make([]*Listener, 0, len(m.listeners))
	for _, entry := range m.listeners {
		listeners = append(listeners, entry.listener)
	}
	m.mu.Unlock()
	for _, l := range listeners {
		l.SetMaxConnections(n)
	}
}

// MaxConnections returns the configured maximum connections limit.
// When any listener is running, returns the first listener's current value.
// Otherwise returns the stored configuration value.
func (m *Manager) MaxConnections() int {
	m.mu.Lock()
	maxConns := m.maxConnections
	var l *Listener
	for _, entry := range m.listeners {
		l = entry.listener
		break
	}
	m.mu.Unlock()
	if l != nil {
		return l.MaxConnections()
	}
	if maxConns == 0 {
		return defaultMaxConnections
	}
	return maxConns
}

// PeekTimeout returns the configured protocol detection timeout.
// When any listener is running, returns the first listener's current value.
// Otherwise returns the stored configuration value.
func (m *Manager) PeekTimeout() time.Duration {
	m.mu.Lock()
	pt := m.peekTimeout
	var l *Listener
	for _, entry := range m.listeners {
		l = entry.listener
		break
	}
	m.mu.Unlock()
	if l != nil {
		return l.PeekTimeout()
	}
	if pt == 0 {
		return defaultPeekTimeout
	}
	return pt
}

// SetUpstreamProxy sets the upstream proxy URL. An empty string disables
// upstream proxy (direct connections). This can be called while the proxy
// is running to dynamically change the upstream proxy.
func (m *Manager) SetUpstreamProxy(proxyURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamProxy = proxyURL
}

// UpstreamProxy returns the current upstream proxy URL.
// Returns an empty string when no upstream proxy is configured.
func (m *Manager) UpstreamProxy() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upstreamProxy
}

// Status returns whether the default listener is running and its listen address.
// For backward compatibility with single-listener callers.
func (m *Manager) Status() (running bool, listenAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[DefaultListenerName]
	if !exists {
		return false, ""
	}
	return true, entry.listenAddr
}

// ListenerStatus holds the status information for a single named listener.
type ListenerStatus struct {
	Name              string `json:"name"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections int    `json:"active_connections"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
}

// ListenerStatuses returns the status of all running listeners.
// Returns nil when no listeners are running.
func (m *Manager) ListenerStatuses() []ListenerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.listeners) == 0 {
		return nil
	}

	statuses := make([]ListenerStatus, 0, len(m.listeners))
	for name, entry := range m.listeners {
		var uptime int64
		if !entry.startedAt.IsZero() {
			uptime = int64(time.Since(entry.startedAt).Seconds())
		}
		statuses = append(statuses, ListenerStatus{
			Name:              name,
			ListenAddr:        entry.listenAddr,
			ActiveConnections: entry.listener.ActiveConnections(),
			UptimeSeconds:     uptime,
		})
	}
	return statuses
}

// ListenerCount returns the number of currently running listeners.
func (m *Manager) ListenerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.listeners)
}

// ActiveConnections returns the total number of connections currently being handled
// across all running listeners. Returns 0 when no listeners are running.
func (m *Manager) ActiveConnections() int {
	m.mu.Lock()
	entries := make([]*listenerEntry, 0, len(m.listeners))
	for _, entry := range m.listeners {
		entries = append(entries, entry)
	}
	m.mu.Unlock()

	total := 0
	for _, entry := range entries {
		total += entry.listener.ActiveConnections()
	}
	return total
}

// Uptime returns the duration since the default listener was started.
// Returns 0 when the default listener is not running.
func (m *Manager) Uptime() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, exists := m.listeners[DefaultListenerName]
	if !exists || entry.startedAt.IsZero() {
		return 0
	}
	return time.Since(entry.startedAt)
}

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

// ErrAlreadyRunning is returned when Start is called while the proxy is already running.
var ErrAlreadyRunning = errors.New("proxy is already running")

// ErrNotRunning is returned when Stop is called while the proxy is not running.
var ErrNotRunning = errors.New("proxy is not running")

// Manager controls the lifecycle of a proxy Listener and TCP forward listeners.
// It provides Start/Stop methods with thread-safe state management.
type Manager struct {
	detector       ProtocolDetector
	logger         *slog.Logger
	peekTimeout    time.Duration
	maxConnections int

	mu         sync.Mutex
	running    bool
	listenAddr string
	listener   *Listener
	cancel     context.CancelFunc
	done       chan struct{}
	startedAt  time.Time // zero value when not running

	// tcpForwards tracks active TCP forward listeners keyed by local port.
	tcpForwards map[string]*tcpForwardEntry

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
		detector: detector,
		logger:   logger,
	}
}

// Start begins the proxy on the specified listen address.
// If listenAddr is empty, it defaults to "127.0.0.1:8080".
// Returns ErrAlreadyRunning if the proxy is already started.
func (m *Manager) Start(ctx context.Context, listenAddr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return ErrAlreadyRunning
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
			return fmt.Errorf("start proxy: %w", err)
		}
		return fmt.Errorf("start proxy: listener exited unexpectedly")
	}

	m.running = true
	m.listenAddr = listener.Addr()
	m.listener = listener
	m.cancel = cancel
	m.done = done
	m.startedAt = time.Now()

	m.logger.Info("proxy started", "listen_addr", m.listenAddr)

	return nil
}

// StartTCPForwards creates and starts a TCP forward listener for each entry in
// the forwards map. The map keys are local port numbers and values are upstream
// addresses in "host:port" format. The handler is the protocol handler that
// will process connections on each forward listener (typically the raw TCP handler).
//
// This method must be called while the Manager is running (after Start).
// All forward listeners share the Manager's lifecycle and are stopped when Stop is called.
// If any listener fails to start, all previously started listeners in this call are
// cleaned up and an error is returned.
func (m *Manager) StartTCPForwards(ctx context.Context, forwards map[string]string, handler ProtocolHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return ErrNotRunning
	}

	if m.tcpForwards == nil {
		m.tcpForwards = make(map[string]*tcpForwardEntry)
	}

	// Track newly started listeners for rollback on failure.
	var started []string

	for port := range forwards {
		if _, exists := m.tcpForwards[port]; exists {
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
			m.stopTCPForwardsLocked(started)
			if err != nil {
				return fmt.Errorf("start tcp forward on port %s: %w", port, err)
			}
			return fmt.Errorf("start tcp forward on port %s: listener exited unexpectedly", port)
		}

		m.tcpForwards[port] = &tcpForwardEntry{
			listener: fl,
			cancel:   flCancel,
			done:     done,
		}
		started = append(started, port)

		m.logger.Info("tcp forward listener started", "port", port, "upstream", forwards[port], "listen_addr", fl.Addr())
	}

	return nil
}

// stopTCPForwardsLocked stops the specified TCP forward listeners.
// Must be called with m.mu held.
func (m *Manager) stopTCPForwardsLocked(ports []string) {
	for _, port := range ports {
		entry, ok := m.tcpForwards[port]
		if !ok {
			continue
		}
		entry.cancel()
		<-entry.done
		delete(m.tcpForwards, port)
	}
}

// TCPForwardAddrs returns a map of port -> actual listen address for all active
// TCP forward listeners. Returns nil when no forwards are active.
func (m *Manager) TCPForwardAddrs() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tcpForwards) == 0 {
		return nil
	}
	addrs := make(map[string]string, len(m.tcpForwards))
	for port, entry := range m.tcpForwards {
		addrs[port] = entry.listener.Addr()
	}
	return addrs
}

// Stop gracefully shuts down the proxy and all TCP forward listeners.
// It cancels the listener context and waits for existing connections to
// complete, with a timeout.
// Returns ErrNotRunning if the proxy is not started.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()

	if !m.running {
		m.mu.Unlock()
		return ErrNotRunning
	}

	cancel := m.cancel
	done := m.done
	addr := m.listenAddr

	// Collect TCP forward entries for shutdown.
	tcpEntries := m.tcpForwards

	// Clear state before releasing the lock to prevent double-stop races.
	m.running = false
	m.listenAddr = ""
	m.listener = nil
	m.cancel = nil
	m.done = nil
	m.startedAt = time.Time{}
	m.tcpForwards = nil

	m.mu.Unlock()

	// Cancel all TCP forward listeners first.
	for _, entry := range tcpEntries {
		entry.cancel()
	}

	// Cancel the main listener context to initiate shutdown.
	cancel()

	// Wait for TCP forward listener goroutines to complete.
	for port, entry := range tcpEntries {
		select {
		case <-entry.done:
			m.logger.Info("tcp forward listener stopped", "port", port)
		case <-time.After(shutdownTimeout):
			m.logger.Warn("tcp forward listener shutdown timed out", "port", port)
		}
	}

	// Wait for the main listener goroutine to complete, with a timeout.
	select {
	case <-done:
		m.logger.Info("proxy stopped", "listen_addr", addr)
		return nil
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("stop proxy: shutdown timed out after %v", shutdownTimeout)
	case <-ctx.Done():
		return fmt.Errorf("stop proxy: %w", ctx.Err())
	}
}

// SetPeekTimeout sets the protocol detection timeout for new connections.
// If the proxy is already running, the change takes effect immediately
// for the next incoming connection.
func (m *Manager) SetPeekTimeout(d time.Duration) {
	m.mu.Lock()
	m.peekTimeout = d
	l := m.listener
	m.mu.Unlock()
	if l != nil {
		l.SetPeekTimeout(d)
	}
}

// SetMaxConnections sets the maximum number of concurrent connections.
// If the proxy is already running, the change takes effect immediately
// for the next incoming connection. Existing connections are not interrupted.
func (m *Manager) SetMaxConnections(n int) {
	m.mu.Lock()
	m.maxConnections = n
	l := m.listener
	m.mu.Unlock()
	if l != nil {
		l.SetMaxConnections(n)
	}
}

// MaxConnections returns the configured maximum connections limit.
// When the proxy is running, returns the listener's current value.
// Otherwise returns the stored configuration value.
func (m *Manager) MaxConnections() int {
	m.mu.Lock()
	l := m.listener
	maxConns := m.maxConnections
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
// When the proxy is running, returns the listener's current value.
// Otherwise returns the stored configuration value.
func (m *Manager) PeekTimeout() time.Duration {
	m.mu.Lock()
	l := m.listener
	pt := m.peekTimeout
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

// Status returns whether the proxy is running and its listen address.
func (m *Manager) Status() (running bool, listenAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running, m.listenAddr
}

// ActiveConnections returns the number of connections currently being handled.
// Returns 0 when the proxy is not running.
func (m *Manager) ActiveConnections() int {
	m.mu.Lock()
	l := m.listener
	m.mu.Unlock()
	if l == nil {
		return 0
	}
	return l.ActiveConnections()
}

// Uptime returns the duration since the proxy was started.
// Returns 0 when the proxy is not running.
func (m *Manager) Uptime() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running || m.startedAt.IsZero() {
		return 0
	}
	return time.Since(m.startedAt)
}

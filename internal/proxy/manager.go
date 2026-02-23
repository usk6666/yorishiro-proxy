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

// Manager controls the lifecycle of a proxy Listener.
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

	m.logger.Info("proxy started", "listen_addr", m.listenAddr)

	return nil
}

// Stop gracefully shuts down the proxy. It cancels the listener context and
// waits for existing connections to complete, with a timeout.
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

	// Clear state before releasing the lock to prevent double-stop races.
	m.running = false
	m.listenAddr = ""
	m.listener = nil
	m.cancel = nil
	m.done = nil

	m.mu.Unlock()

	// Cancel the listener context to initiate shutdown.
	cancel()

	// Wait for the listener goroutine to complete, with a timeout.
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
func (m *Manager) SetPeekTimeout(d time.Duration) {
	m.peekTimeout = d
}

// SetMaxConnections sets the maximum number of concurrent connections.
func (m *Manager) SetMaxConnections(n int) {
	m.maxConnections = n
}

// Status returns whether the proxy is running and its listen address.
func (m *Manager) Status() (running bool, listenAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running, m.listenAddr
}

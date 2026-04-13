package connector

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// OnStackFunc is the callback signature for when a ConnectionStack is ready.
// The callback owns the session lifecycle (Pipeline + RunSession wiring).
// The connector package does not import pipeline or session — this callback
// bridges the boundary.
type OnStackFunc func(ctx context.Context, stack *ConnectionStack, snap *envelope.TLSSnapshot, target string)

// CoordinatorConfig holds the parameters for constructing a Coordinator.
// Shared policy objects are passed here and wired into every FullListener
// created by StartNamed.
type CoordinatorConfig struct {
	// Logger for coordinator and listener logging. Nil uses slog.Default().
	Logger *slog.Logger

	// PluginEngine dispatches on_connect / on_disconnect lifecycle hooks.
	// Nil disables hook dispatch. Shared across all listeners.
	PluginEngine *plugin.Engine

	// PeekTimeout is the default protocol detection timeout for new listeners.
	// Zero means DefaultPeekTimeout.
	PeekTimeout time.Duration

	// MaxConnections is the default concurrent connection cap for new listeners.
	// Zero means DefaultMaxConnections. Negative disables the limit.
	MaxConnections int

	// --- Negotiators ---

	// CONNECTNegotiator parses HTTP CONNECT requests. Required for CONNECT
	// tunnel support; nil means no CONNECT handler is wired.
	CONNECTNegotiator *CONNECTNegotiator

	// SOCKS5Negotiator handles SOCKS5 handshakes. Required for SOCKS5 tunnel
	// support; nil means no SOCKS5 handler is wired.
	//
	// Unlike the CONNECT path (where Scope/RateLimiter are checked by the
	// handler after negotiation), the SOCKS5Negotiator checks Scope and
	// RateLimiter inline during the handshake so that denied targets receive
	// the correct SOCKS5 reply code before the connection is torn down.
	// Therefore, the caller must set Scope and RateLimiter on the negotiator
	// itself — the Coordinator does not override them.
	SOCKS5Negotiator *SOCKS5Negotiator

	// --- Shared policy objects ---

	// Scope validates tunnel targets against policy rules. Nil disables.
	Scope *TargetScope

	// RateLimiter checks per-host rate limits. Nil disables.
	RateLimiter *RateLimiter

	// PassthroughList identifies hosts whose TLS traffic is relayed without
	// MITM. Nil disables.
	PassthroughList *PassthroughList

	// BuildCfg configures ConnectionStack construction (TLS, upstream proxy,
	// per-host TLS, ALPN cache). Shared across all listeners.
	BuildCfg *BuildConfig

	// OnStack is called when a ConnectionStack is ready. The callback owns
	// session lifecycle wiring (Pipeline, flow.Store, RunSession). Required
	// for CONNECT and SOCKS5 handling; nil causes stacks to be closed
	// immediately (useful for tests that only verify listener lifecycle).
	OnStack OnStackFunc

	// --- Optional handler overrides ---

	// OnHTTP1, OnHTTP2, OnTCP are optional handlers for protocols that are not
	// yet handled by the Coordinator's built-in wiring. When non-nil, they are
	// passed through to FullListenerConfig for each new listener.
	OnHTTP1 HandlerFunc
	OnHTTP2 HandlerFunc
	OnTCP   HandlerFunc
}

// Coordinator manages multiple FullListener instances that share the same
// policy objects, BuildConfig, and OnStack callback. It replaces the old
// Connector type (which used M39-era Detector+Dispatcher) for the RFC-001
// architecture. The old Connector coexists until N9 cleanup.
type Coordinator struct {
	logger       *slog.Logger
	pluginEngine *plugin.Engine
	peekTimeout  time.Duration
	maxConns     int

	connectNeg  *CONNECTNegotiator
	socks5Neg   *SOCKS5Negotiator
	scope       *TargetScope
	rateLimiter *RateLimiter
	passthrough *PassthroughList
	buildCfg    *BuildConfig
	onStack     OnStackFunc

	onHTTP1 HandlerFunc
	onHTTP2 HandlerFunc
	onTCP   HandlerFunc

	mu        sync.Mutex
	listeners map[string]*coordEntry
}

// coordEntry tracks a single named FullListener's lifecycle state.
// Named differently from the old Connector's listenerEntry to avoid
// redeclaration within the same package.
type coordEntry struct {
	listener   *FullListener
	cancel     context.CancelFunc
	done       chan struct{}
	listenAddr string
	startedAt  time.Time
}

// NewCoordinator creates a Coordinator with no listeners running. Listeners
// are started via Start or StartNamed.
func NewCoordinator(cfg CoordinatorConfig) *Coordinator {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Coordinator{
		logger:       logger,
		pluginEngine: cfg.PluginEngine,
		peekTimeout:  cfg.PeekTimeout,
		maxConns:     cfg.MaxConnections,
		connectNeg:   cfg.CONNECTNegotiator,
		socks5Neg:    cfg.SOCKS5Negotiator,
		scope:        cfg.Scope,
		rateLimiter:  cfg.RateLimiter,
		passthrough:  cfg.PassthroughList,
		buildCfg:     cfg.BuildCfg,
		onStack:      cfg.OnStack,
		onHTTP1:      cfg.OnHTTP1,
		onHTTP2:      cfg.OnHTTP2,
		onTCP:        cfg.OnTCP,
		listeners:    make(map[string]*coordEntry),
	}
}

// Start begins a listener under the DefaultListenerName. It is shorthand
// for StartNamed(ctx, DefaultListenerName, addr).
func (c *Coordinator) Start(ctx context.Context, addr string) error {
	return c.StartNamed(ctx, DefaultListenerName, addr)
}

// StartNamed begins a new named FullListener on the given address. Returns
// ErrListenerExists if the name is already in use. The listener runs in a
// background goroutine until its context is cancelled or StopNamed/StopAll
// is called.
func (c *Coordinator) StartNamed(ctx context.Context, name, addr string) error {
	if name == "" {
		name = DefaultListenerName
	}

	// NOTE: The lock is held across listener creation and the Ready()/errCh
	// wait. This serializes concurrent StartNamed calls, which is acceptable
	// because listeners are created at startup (a handful at most). If
	// high-concurrency listener creation becomes a requirement, the lock
	// should be released after NewFullListener and re-acquired for map
	// insertion (CWE-667 consideration, low practical risk since TCP
	// net.Listen is non-blocking).
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.listeners[name]; exists {
		return fmt.Errorf("%q: %w", name, ErrListenerExists)
	}

	fl := NewFullListener(FullListenerConfig{
		Name:           name,
		Addr:           addr,
		Logger:         c.logger,
		PeekTimeout:    c.peekTimeout,
		MaxConnections: c.maxConns,
		PluginEngine:   c.pluginEngine,
		OnCONNECT:      c.buildCONNECTHandler(),
		OnSOCKS5:       c.buildSOCKS5Handler(),
		OnHTTP1:        c.onHTTP1,
		OnHTTP2:        c.onHTTP2,
		OnTCP:          c.onTCP,
	})

	listenerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		defer close(done)
		errCh <- fl.Start(listenerCtx)
	}()

	// Wait for Ready (listener bound) or an early error from Start.
	select {
	case <-fl.Ready():
	case err := <-errCh:
		cancel()
		if err != nil {
			return fmt.Errorf("start listener %q: %w", name, err)
		}
		return fmt.Errorf("start listener %q: listener exited unexpectedly", name)
	}

	c.listeners[name] = &coordEntry{
		listener:   fl,
		cancel:     cancel,
		done:       done,
		listenAddr: fl.Addr(),
		startedAt:  time.Now(),
	}

	c.logger.Info("coordinator: listener started",
		"name", name,
		"listen_addr", fl.Addr())
	return nil
}

// StopNamed gracefully shuts down the named listener. Returns
// ErrListenerNotFound if no listener has the given name.
func (c *Coordinator) StopNamed(ctx context.Context, name string) error {
	if name == "" {
		name = DefaultListenerName
	}

	c.mu.Lock()
	entry, exists := c.listeners[name]
	if !exists {
		c.mu.Unlock()
		return fmt.Errorf("%q: %w", name, ErrListenerNotFound)
	}
	delete(c.listeners, name)
	c.mu.Unlock()

	entry.cancel()

	select {
	case <-entry.done:
		c.logger.Info("coordinator: listener stopped",
			"name", name,
			"listen_addr", entry.listenAddr)
		return nil
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("stop listener %q: shutdown timed out after %v", name, shutdownTimeout)
	case <-ctx.Done():
		return fmt.Errorf("stop listener %q: %w", name, ctx.Err())
	}
}

// StopAll gracefully shuts down every running listener. It returns the
// first error encountered; remaining listeners are still shut down.
func (c *Coordinator) StopAll(ctx context.Context) error {
	c.mu.Lock()
	if len(c.listeners) == 0 {
		c.mu.Unlock()
		return nil
	}
	entries := c.listeners
	c.listeners = make(map[string]*coordEntry)
	c.mu.Unlock()

	var firstErr error
	for name, entry := range entries {
		entry.cancel()
		select {
		case <-entry.done:
			c.logger.Info("coordinator: listener stopped",
				"name", name,
				"listen_addr", entry.listenAddr)
		case <-time.After(shutdownTimeout):
			if firstErr == nil {
				firstErr = fmt.Errorf("stop listener %q: shutdown timed out after %v", name, shutdownTimeout)
			}
		case <-ctx.Done():
			if firstErr == nil {
				firstErr = fmt.Errorf("stop listener %q: %w", name, ctx.Err())
			}
		}
	}
	return firstErr
}

// ListenerStatuses returns a snapshot of all currently running listeners.
func (c *Coordinator) ListenerStatuses() []ListenerStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.listeners) == 0 {
		return nil
	}

	out := make([]ListenerStatus, 0, len(c.listeners))
	for name, entry := range c.listeners {
		var uptime int64
		if !entry.startedAt.IsZero() {
			uptime = int64(time.Since(entry.startedAt).Seconds())
		}
		out = append(out, ListenerStatus{
			Name:              name,
			ListenAddr:        entry.listenAddr,
			ActiveConnections: entry.listener.ActiveConnections(),
			UptimeSeconds:     uptime,
		})
	}
	return out
}

// ListenerCount returns the number of running listeners.
func (c *Coordinator) ListenerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.listeners)
}

// buildCONNECTHandler constructs a CONNECT HandlerFunc from the shared
// policy objects. Returns nil if no CONNECTNegotiator is configured.
func (c *Coordinator) buildCONNECTHandler() HandlerFunc {
	if c.connectNeg == nil {
		return nil
	}
	return NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:      c.connectNeg,
		BuildCfg:        c.buildCfg,
		Scope:           c.scope,
		RateLimiter:     c.rateLimiter,
		PassthroughList: c.passthrough,
		OnStack:         c.onStack,
		Logger:          c.logger,
	})
}

// buildSOCKS5Handler constructs a SOCKS5 HandlerFunc from the shared
// policy objects. Returns nil if no SOCKS5Negotiator is configured.
func (c *Coordinator) buildSOCKS5Handler() HandlerFunc {
	if c.socks5Neg == nil {
		return nil
	}
	return NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator:      c.socks5Neg,
		BuildCfg:        c.buildCfg,
		PassthroughList: c.passthrough,
		OnStack:         c.onStack,
		Logger:          c.logger,
	})
}

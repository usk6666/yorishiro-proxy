package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// DefaultPeekTimeout is the maximum time the listener waits for the client's
// initial bytes before protocol detection. It protects against Slowloris-style
// stalls without being so short that real clients on slow links fail.
const DefaultPeekTimeout = 30 * time.Second

// DefaultMaxConnections limits concurrent connections to bound worst-case
// memory footprint. Operators can override via ListenerConfig or at runtime.
const DefaultMaxConnections = 128

// hookTimeout is the maximum time allowed for lifecycle hook dispatches.
// Lifecycle hooks are observe-only, so a short timeout prevents slow plugins
// from blocking connection acceptance.
const hookTimeout = 5 * time.Second

// Dispatcher routes an accepted and protocol-detected connection to its
// handler. The listener calls Dispatch once per connection after it has
// cleared the peek deadline and enriched the context with connection
// metadata. Dispatch owns the connection from that point on — it must close
// it when processing completes.
//
// M39 scope: the concrete Dispatchers are implemented in USK-560
// (CONNECT Negotiator + TunnelHandler) and USK-561 (SOCKS5 Negotiator).
// This Issue ships a pluggable interface so the downstream work can slot in
// without modifying the listener.
type Dispatcher interface {
	// Dispatch takes ownership of conn for the given ProtocolKind. The
	// factory argument is the CodecFactory that the Detector matched, or
	// nil if the listener decided to reject the connection before any
	// factory was looked up. kind is provided separately so dispatchers
	// can log or instrument detection decisions even when no factory is
	// registered yet (as with HTTP/2 in M39 — see Q3 in the Issue).
	Dispatch(ctx context.Context, conn *PeekConn, kind ProtocolKind, factory CodecFactory) error
}

// DispatcherFunc adapts an ordinary function to the Dispatcher interface.
type DispatcherFunc func(ctx context.Context, conn *PeekConn, kind ProtocolKind, factory CodecFactory) error

// Dispatch calls f(ctx, conn, kind, factory).
func (f DispatcherFunc) Dispatch(ctx context.Context, conn *PeekConn, kind ProtocolKind, factory CodecFactory) error {
	return f(ctx, conn, kind, factory)
}

// ErrNoHandler is returned by a Dispatcher when no handler is available for
// the detected ProtocolKind. The listener logs this at Debug level and
// closes the connection.
var ErrNoHandler = errors.New("connector: no handler for detected protocol")

// ListenerConfig holds the parameters needed to construct a Listener.
// All fields except Addr have sensible defaults; Addr must be non-empty.
type ListenerConfig struct {
	// Name is used for logging and context propagation. It defaults to
	// "default" when empty.
	Name string

	// Addr is the TCP listen address, e.g. "127.0.0.1:8080". Required.
	Addr string

	// Detector selects a CodecFactory from peeked bytes. Must be non-nil.
	Detector *Detector

	// Dispatch receives each accepted connection after protocol detection.
	// Must be non-nil. See Dispatcher for the lifecycle contract.
	Dispatch Dispatcher

	// Logger is used for all listener logging. When nil, slog.Default()
	// is used.
	Logger *slog.Logger

	// PeekTimeout bounds the duration of protocol detection. Zero means
	// DefaultPeekTimeout.
	PeekTimeout time.Duration

	// MaxConnections limits concurrent in-flight connections. Zero means
	// DefaultMaxConnections. Negative values disable the limit.
	MaxConnections int
}

// Listener accepts TCP connections on a single address, runs two-stage
// protocol detection on each, and hands each connection to a Dispatcher.
//
// A Listener tracks its active-connections count atomically and exposes
// that count (plus the max) as runtime-adjustable state: SetMaxConnections
// and SetPeekTimeout take effect on the next accepted connection. Existing
// connections that were admitted under a higher cap are allowed to drain
// naturally.
type Listener struct {
	name     string
	addr     string
	detector *Detector
	dispatch Dispatcher
	logger   *slog.Logger

	peekTimeoutNs  atomic.Int64 // nanoseconds
	maxConnections int
	activeConns    atomic.Int64

	pluginEngine *plugin.Engine

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	wg       sync.WaitGroup

	// semMu is a separate mutex guarding maxConnections so that
	// SetMaxConnections can safely update the limit while the accept loop
	// holds an RLock across the check-then-increment sequence.
	semMu sync.RWMutex
}

// NewListener builds a Listener from the given configuration. It does not
// start accepting; call Start for that.
func NewListener(cfg ListenerConfig) *Listener {
	name := cfg.Name
	if name == "" {
		name = "default"
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	peekTimeout := cfg.PeekTimeout
	if peekTimeout == 0 {
		peekTimeout = DefaultPeekTimeout
	}
	maxConns := cfg.MaxConnections
	if maxConns == 0 {
		maxConns = DefaultMaxConnections
	}
	l := &Listener{
		name:           name,
		addr:           cfg.Addr,
		detector:       cfg.Detector,
		dispatch:       cfg.Dispatch,
		logger:         logger,
		maxConnections: maxConns,
		ready:          make(chan struct{}),
	}
	l.peekTimeoutNs.Store(int64(peekTimeout))
	return l
}

// SetPluginEngine wires the plugin engine that will receive on_connect and
// on_disconnect lifecycle hooks. Nil disables hook dispatch.
func (l *Listener) SetPluginEngine(engine *plugin.Engine) {
	l.pluginEngine = engine
}

// PluginEngine returns the listener's current plugin engine, or nil.
func (l *Listener) PluginEngine() *plugin.Engine {
	return l.pluginEngine
}

// Start begins accepting connections. It blocks until ctx is cancelled or
// the underlying listener fails to accept. The returned error is nil on
// graceful shutdown (ctx cancellation).
func (l *Listener) Start(ctx context.Context) error {
	if l.detector == nil {
		return errors.New("connector.Listener: detector is required")
	}
	if l.dispatch == nil {
		return errors.New("connector.Listener: dispatcher is required")
	}

	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", l.addr, err)
	}

	l.mu.Lock()
	l.listener = ln
	l.mu.Unlock()
	close(l.ready)

	defer ln.Close()

	// Close the listener when ctx is cancelled so Accept returns immediately.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				l.wg.Wait()
				return nil
			default:
				l.wg.Wait()
				return fmt.Errorf("accept: %w", err)
			}
		}

		// Capacity check — hold the RLock across the increment so that
		// a concurrent SetMaxConnections cannot lower the ceiling
		// between reading the limit and committing the increment.
		l.semMu.RLock()
		maxConns := l.maxConnections
		rejected := false
		if maxConns > 0 {
			if current := l.activeConns.Add(1); current > int64(maxConns) {
				l.activeConns.Add(-1)
				rejected = true
			}
		}
		l.semMu.RUnlock()

		if rejected {
			l.logger.Warn("connection rejected: at capacity",
				"remote_addr", conn.RemoteAddr().String(),
				"max_connections", maxConns)
			conn.Close()
			continue
		}

		if l.logger.Enabled(ctx, slog.LevelDebug) {
			l.logger.Debug("connection accepted",
				"remote_addr", conn.RemoteAddr().String(),
				"active_connections", l.activeConns.Load(),
				"max_connections", maxConns,
			)
		}

		l.wg.Go(func() {
			if maxConns > 0 {
				defer l.activeConns.Add(-1)
			}
			l.handleConn(ctx, conn)
		})
	}
}

// handleConn runs protocol detection and dispatch for a single accepted
// connection. It is responsible for all per-connection observability:
// connection ID, logger enrichment, plugin lifecycle hooks, and the peek
// deadline.
func (l *Listener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	pc := NewPeekConn(conn)
	remoteAddr := conn.RemoteAddr().String()
	connStart := time.Now()

	// Generate a unique connection ID for log correlation.
	connID := GenerateConnID()
	connLogger := l.logger.With("conn_id", connID, "remote_addr", remoteAddr)

	ctx = ContextWithConnID(ctx, connID)
	ctx = ContextWithClientAddr(ctx, remoteAddr)
	ctx = ContextWithListenerName(ctx, l.name)
	ctx = ContextWithLogger(ctx, connLogger)

	l.dispatchOnConnect(ctx, remoteAddr, connLogger)
	defer l.dispatchOnDisconnect(remoteAddr, connStart, connLogger)

	// Bound protocol detection by the peek deadline (Slowloris protection).
	peekTimeout := time.Duration(l.peekTimeoutNs.Load())
	if peekTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(peekTimeout))
	}

	kind, factory, peek, ok := l.detectProtocol(pc, connLogger)

	// Reset the deadline before handing off to the dispatcher. The dispatch
	// path has its own timeouts scoped to individual request/response
	// exchanges.
	_ = conn.SetReadDeadline(time.Time{})

	if !ok {
		connLogger.Debug("protocol detection failed",
			"peek_bytes", fmt.Sprintf("%x", peek))
		return
	}

	connLogger.Debug("connection dispatched",
		"protocol", kind.String(),
		"peek_len", len(peek))

	if err := l.dispatch.Dispatch(ctx, pc, kind, factory); err != nil {
		if errors.Is(err, ErrNoHandler) {
			connLogger.Debug("no handler for detected protocol",
				"protocol", kind.String())
			return
		}
		connLogger.Error("dispatcher error",
			"protocol", kind.String(),
			"error", err)
		return
	}

	if connLogger.Enabled(ctx, slog.LevelDebug) {
		connLogger.Debug("connection closed",
			"protocol", kind.String(),
			"duration_ms", time.Since(connStart).Milliseconds(),
		)
	}
}

// detectProtocol performs the two-stage peek. Stage 1 reads a single byte so
// that short-greeting protocols (SOCKS5) can be matched without waiting for
// PeekSize bytes. Stage 2 refines the decision when either more bytes are
// already buffered, or stage 1 did not find a confident match.
func (l *Listener) detectProtocol(pc *PeekConn, logger *slog.Logger) (ProtocolKind, CodecFactory, []byte, bool) {
	peek, err := pc.Peek(QuickPeekSize)
	if err != nil && len(peek) == 0 {
		logger.Debug("quick peek failed", "error", err)
		return ProtocolUnknown, nil, nil, false
	}

	quickKind := DetectKind(peek)
	quickFactory := l.detector.Lookup(quickKind)

	kind, factory, peek := l.refineDetection(pc, quickKind, quickFactory, peek)
	return kind, factory, peek, kind != ProtocolUnknown
}

// refineDetection is stage 2 of the peek. When the quick peek's single byte
// left Buffered() > QuickPeekSize — which happens whenever the first TCP
// segment delivered multiple bytes at once — refineDetection re-runs
// DetectKind on the buffered bytes to disambiguate protocols that share a
// first byte (HTTP/1.x and HTTP/2 both start with 'P'; CONNECT and all
// methods start with a letter).
//
// If the client only sent a single byte, refineDetection returns the Stage
// 1 decision unchanged. This is deliberate: blocking for a full peek on
// such a stream would stall any legitimate raw-TCP client that opens the
// conversation with a short write, and it would turn a peek deadline miss
// into an unrecoverable listener error for otherwise valid traffic.
func (l *Listener) refineDetection(pc *PeekConn, quickKind ProtocolKind, quickFactory CodecFactory, peek []byte) (ProtocolKind, CodecFactory, []byte) {
	kind := quickKind
	factory := quickFactory

	// SOCKS5 is definitive on one byte; never refine.
	if quickKind == ProtocolSOCKS5 {
		return kind, factory, peek
	}

	buffered := pc.Buffered()
	if buffered <= QuickPeekSize {
		return kind, factory, peek
	}

	n := buffered
	if n > PeekSize {
		n = PeekSize
	}
	if fullPeek, err := pc.Peek(n); err == nil && len(fullPeek) > 0 {
		fullKind := DetectKind(fullPeek)
		kind = fullKind
		factory = l.detector.Lookup(fullKind)
		peek = fullPeek
	}
	return kind, factory, peek
}

// dispatchOnConnect delivers the plugin on_connect hook. Errors are logged
// and ignored (fail-open) so that a buggy plugin cannot stall accept.
func (l *Listener) dispatchOnConnect(ctx context.Context, clientAddr string, logger *slog.Logger) {
	if l.pluginEngine == nil {
		return
	}

	hookCtx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()

	connInfo := &plugin.ConnInfo{ClientAddr: clientAddr}
	data := map[string]any{
		"event":     "connect",
		"conn_info": connInfo.ToMap(),
	}

	if _, err := l.pluginEngine.Dispatch(hookCtx, plugin.HookOnConnect, data); err != nil {
		logger.Warn("plugin on_connect hook error", "error", err)
	}
}

// dispatchOnDisconnect delivers the plugin on_disconnect hook. It uses a
// fresh context derived from Background so that disconnect hooks still fire
// during graceful shutdown, when the parent context has already been
// cancelled.
func (l *Listener) dispatchOnDisconnect(clientAddr string, connStart time.Time, logger *slog.Logger) {
	if l.pluginEngine == nil {
		return
	}

	dispatchCtx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()

	durationMs := time.Since(connStart).Milliseconds()
	connInfo := &plugin.ConnInfo{ClientAddr: clientAddr}
	data := map[string]any{
		"event":       "disconnect",
		"conn_info":   connInfo.ToMap(),
		"duration_ms": durationMs,
	}

	if _, err := l.pluginEngine.Dispatch(dispatchCtx, plugin.HookOnDisconnect, data); err != nil {
		logger.Warn("plugin on_disconnect hook error", "error", err)
	}
}

// Addr returns the listener's bound address, or empty string if Start has
// not progressed past net.Listen.
func (l *Listener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return ""
}

// Ready returns a channel that is closed when the listener is accepting.
// It is intended for test synchronization.
func (l *Listener) Ready() <-chan struct{} {
	return l.ready
}

// ActiveConnections returns the number of connections currently in flight.
func (l *Listener) ActiveConnections() int {
	return int(l.activeConns.Load())
}

// MaxConnections returns the current concurrent-connection cap.
func (l *Listener) MaxConnections() int {
	l.semMu.RLock()
	defer l.semMu.RUnlock()
	return l.maxConnections
}

// PeekTimeout returns the current protocol detection timeout.
func (l *Listener) PeekTimeout() time.Duration {
	return time.Duration(l.peekTimeoutNs.Load())
}

// SetMaxConnections changes the concurrent-connection cap. n must be > 0.
// The change takes effect for the next accepted connection; in-flight
// connections are not interrupted.
func (l *Listener) SetMaxConnections(n int) {
	if n <= 0 {
		return
	}
	l.semMu.Lock()
	defer l.semMu.Unlock()
	l.maxConnections = n
}

// SetPeekTimeout changes the protocol detection timeout. d must be > 0.
func (l *Listener) SetPeekTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	l.peekTimeoutNs.Store(int64(d))
}

// Connector manages one or more named Listeners and is the connection-level
// entry point for the whole proxy. It is the M39 replacement for the
// internal/proxy.Manager, limited to the responsibilities that actually
// belong on the connection layer: start/stop listeners, expose listener
// status, and own the shared Detector and policy objects (TargetScope,
// RateLimiter, PassthroughList).
//
// Features that used to live on Manager but belong elsewhere — upstream
// proxy URL, TCP forward listeners, dial rule integration — are out of
// scope for USK-559 and will be revisited by USK-562 and later Issues.
type Connector struct {
	detector       *Detector
	dispatch       Dispatcher
	logger         *slog.Logger
	pluginEngine   *plugin.Engine
	peekTimeout    time.Duration
	maxConnections int

	mu        sync.Mutex
	listeners map[string]*listenerEntry
}

// listenerEntry tracks a single named listener's lifecycle state.
type listenerEntry struct {
	listener   *Listener
	cancel     context.CancelFunc
	done       chan struct{}
	listenAddr string
	startedAt  time.Time
}

// ConnectorConfig holds the parameters needed to construct a Connector.
type ConnectorConfig struct {
	Detector       *Detector
	Dispatch       Dispatcher
	Logger         *slog.Logger
	PluginEngine   *plugin.Engine
	PeekTimeout    time.Duration
	MaxConnections int
}

// Sentinel errors returned by Connector.
var (
	ErrListenerExists   = errors.New("connector: listener with this name already exists")
	ErrListenerNotFound = errors.New("connector: listener not found")
)

// NewConnector creates a Connector with no listeners running. Listeners are
// started via Start or StartNamed.
func NewConnector(cfg ConnectorConfig) *Connector {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Connector{
		detector:       cfg.Detector,
		dispatch:       cfg.Dispatch,
		logger:         logger,
		pluginEngine:   cfg.PluginEngine,
		peekTimeout:    cfg.PeekTimeout,
		maxConnections: cfg.MaxConnections,
		listeners:      make(map[string]*listenerEntry),
	}
}

// DefaultListenerName is the name assigned when the caller does not pass an
// explicit listener name.
const DefaultListenerName = "default"

// Start begins a listener under the DefaultListenerName. It is shorthand
// for StartNamed(ctx, DefaultListenerName, addr).
func (c *Connector) Start(ctx context.Context, addr string) error {
	return c.StartNamed(ctx, DefaultListenerName, addr)
}

// StartNamed begins a new named listener on the given address. Returns
// ErrListenerExists if the name is already in use.
func (c *Connector) StartNamed(ctx context.Context, name, addr string) error {
	if name == "" {
		name = DefaultListenerName
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.listeners[name]; exists {
		return fmt.Errorf("%q: %w", name, ErrListenerExists)
	}

	listener := NewListener(ListenerConfig{
		Name:           name,
		Addr:           addr,
		Detector:       c.detector,
		Dispatch:       c.dispatch,
		Logger:         c.logger,
		PeekTimeout:    c.peekTimeout,
		MaxConnections: c.maxConnections,
	})
	if c.pluginEngine != nil {
		listener.SetPluginEngine(c.pluginEngine)
	}

	listenerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		defer close(done)
		errCh <- listener.Start(listenerCtx)
	}()

	// Wait for Ready (success) or an early error from Start.
	select {
	case <-listener.Ready():
	case err := <-errCh:
		cancel()
		if err != nil {
			return fmt.Errorf("start listener %q: %w", name, err)
		}
		return fmt.Errorf("start listener %q: listener exited unexpectedly", name)
	}

	c.listeners[name] = &listenerEntry{
		listener:   listener,
		cancel:     cancel,
		done:       done,
		listenAddr: listener.Addr(),
		startedAt:  time.Now(),
	}

	c.logger.Info("listener started", "name", name, "listen_addr", listener.Addr())
	return nil
}

// shutdownTimeout is the maximum time StopNamed waits for a listener
// goroutine to exit before reporting a timeout error.
const shutdownTimeout = 30 * time.Second

// StopNamed gracefully shuts down the named listener.
func (c *Connector) StopNamed(ctx context.Context, name string) error {
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
		c.logger.Info("listener stopped", "name", name, "listen_addr", entry.listenAddr)
		return nil
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("stop listener %q: shutdown timed out after %v", name, shutdownTimeout)
	case <-ctx.Done():
		return fmt.Errorf("stop listener %q: %w", name, ctx.Err())
	}
}

// StopAll gracefully shuts down every running listener. It returns the
// first error encountered; remaining listeners are still shut down.
func (c *Connector) StopAll(ctx context.Context) error {
	c.mu.Lock()
	if len(c.listeners) == 0 {
		c.mu.Unlock()
		return nil
	}
	entries := c.listeners
	c.listeners = make(map[string]*listenerEntry)
	c.mu.Unlock()

	var firstErr error
	for name, entry := range entries {
		entry.cancel()
		select {
		case <-entry.done:
			c.logger.Info("listener stopped", "name", name, "listen_addr", entry.listenAddr)
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

// ListenerStatus describes a single running listener. It is returned by
// ListenerStatuses so callers can build a status view without touching
// Listener internals.
type ListenerStatus struct {
	Name              string `json:"name"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections int    `json:"active_connections"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
}

// ListenerStatuses returns a snapshot of all currently running listeners.
func (c *Connector) ListenerStatuses() []ListenerStatus {
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
func (c *Connector) ListenerCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.listeners)
}

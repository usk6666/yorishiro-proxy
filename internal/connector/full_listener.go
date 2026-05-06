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
)

// HandlerFunc is the callback signature for per-protocol connection handling.
// The handler receives a PeekConn with the peeked bytes still available and
// context enriched with ConnID, ClientAddr, ListenerName, and Logger.
// The handler owns the connection lifetime: it must close pc when done.
type HandlerFunc func(ctx context.Context, pc *PeekConn) error

// ProtocolRejectedFunc is invoked when an inbound connection is rejected
// because its detected ProtocolKind is not in the listener's
// EnabledProtocols allow-list. The callback runs after detection but
// before any per-protocol handler is dispatched. Implementations are
// expected to record the rejection (e.g. as a Stream with State="error")
// and may inspect the peeked bytes via pc — they MUST NOT close pc; the
// caller (FullListener.handleConn) closes the underlying connection.
//
// The callback is allowed to be nil, in which case the rejection is
// observed only through the debug log emitted by FullListener. The
// proxybuild layer wires a flow-recording implementation so MITM
// observability of the rejection is preserved (USK-732).
type ProtocolRejectedFunc func(ctx context.Context, pc *PeekConn, kind ProtocolKind, name string)

// FullListenerConfig holds parameters for constructing a FullListener.
type FullListenerConfig struct {
	// Name is used for logging and context propagation. Defaults to "default".
	Name string

	// Addr is the TCP listen address, e.g. "127.0.0.1:8080". Required.
	Addr string

	// Logger for all listener logging. When nil, slog.Default() is used.
	Logger *slog.Logger

	// PeekTimeout bounds the duration of protocol detection. Zero means
	// DefaultPeekTimeout.
	PeekTimeout time.Duration

	// MaxConnections limits concurrent in-flight connections. Zero means
	// DefaultMaxConnections. Negative values disable the limit.
	MaxConnections int

	// EnabledProtocols, when non-empty, restricts which detected protocol
	// kinds are accepted. Members are user-facing protocol names accepted
	// by the proxy_start MCP tool ("HTTP/1.x", "HTTPS", "HTTP/2",
	// "SOCKS5", "TCP", and protocol names that are subsets of HTTPS such
	// as "WebSocket", "gRPC"). When empty (the zero value), all detected
	// kinds are accepted (backward-compatible default).
	EnabledProtocols []string

	// OnProtocolRejected is invoked when EnabledProtocols is non-empty and
	// the detected ProtocolKind does not map to any allowed name. nil is
	// permitted; the rejection is then observable only via debug logs.
	OnProtocolRejected ProtocolRejectedFunc

	// Handler callbacks per ProtocolKind. Each handler receives a PeekConn
	// with detection bytes still buffered and an enriched context.
	// Nil handlers cause the connection to be closed with a debug log.
	OnCONNECT HandlerFunc
	OnSOCKS5  HandlerFunc
	OnHTTP1   HandlerFunc
	OnHTTP2   HandlerFunc
	OnTCP     HandlerFunc
}

// FullListener accepts TCP connections, performs two-stage protocol detection,
// and dispatches to per-protocol handler callbacks. It is the connector
// package's sole listener implementation: production features include
// max_connections enforcement, peek timeout (Slowloris protection), and
// graceful shutdown.
type FullListener struct {
	name   string
	addr   string
	logger *slog.Logger

	peekTimeoutNs  atomic.Int64 // nanoseconds
	maxConnections int
	activeConns    atomic.Int64

	onCONNECT HandlerFunc
	onSOCKS5  HandlerFunc
	onHTTP1   HandlerFunc
	onHTTP2   HandlerFunc
	onTCP     HandlerFunc

	// enabledProtocols points at an immutable user-facing protocol-name
	// slice. Nil or empty means "all protocols allowed" (default).
	// Stored as an atomic pointer so SetEnabledProtocols can update the
	// allow-list without synchronising with the accept loop.
	enabledProtocols atomic.Pointer[[]string]

	// onProtocolRejected is the rejection callback configured at
	// construction. Treated as immutable for the lifetime of the listener;
	// runtime reconfiguration of EnabledProtocols does NOT swap callbacks.
	onProtocolRejected ProtocolRejectedFunc

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	wg       sync.WaitGroup

	// semMu guards maxConnections so that SetMaxConnections can safely update
	// the limit while the accept loop holds an RLock across check-then-increment.
	semMu sync.RWMutex
}

// NewFullListener builds a FullListener from the given configuration.
// It does not start accepting; call Start for that.
func NewFullListener(cfg FullListenerConfig) *FullListener {
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

	fl := &FullListener{
		name:               name,
		addr:               cfg.Addr,
		logger:             logger,
		maxConnections:     maxConns,
		onCONNECT:          cfg.OnCONNECT,
		onSOCKS5:           cfg.OnSOCKS5,
		onHTTP1:            cfg.OnHTTP1,
		onHTTP2:            cfg.OnHTTP2,
		onTCP:              cfg.OnTCP,
		onProtocolRejected: cfg.OnProtocolRejected,
		ready:              make(chan struct{}),
	}
	fl.peekTimeoutNs.Store(int64(peekTimeout))
	if len(cfg.EnabledProtocols) > 0 {
		// Defensive copy so callers cannot mutate the slice after passing
		// it in.
		cp := make([]string, len(cfg.EnabledProtocols))
		copy(cp, cfg.EnabledProtocols)
		fl.enabledProtocols.Store(&cp)
	}
	return fl
}

// Start begins accepting connections. It blocks until ctx is cancelled or
// the underlying listener fails to accept. Returns nil on graceful shutdown.
func (fl *FullListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", fl.addr)
	if err != nil {
		return fmt.Errorf("connector: listen on %s: %w", fl.addr, err)
	}

	fl.mu.Lock()
	fl.listener = ln
	fl.mu.Unlock()
	close(fl.ready)

	defer ln.Close()

	fl.logger.Info("connector: full listener started",
		"name", fl.name,
		"addr", ln.Addr().String(),
	)

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
				fl.wg.Wait()
				return nil
			default:
				fl.wg.Wait()
				return fmt.Errorf("connector: accept: %w", err)
			}
		}

		// Capacity check — hold the RLock across the increment so that a
		// concurrent SetMaxConnections cannot lower the ceiling between
		// reading the limit and committing the increment.
		fl.semMu.RLock()
		maxConns := fl.maxConnections
		rejected := false
		if maxConns > 0 {
			if current := fl.activeConns.Add(1); current > int64(maxConns) {
				fl.activeConns.Add(-1)
				rejected = true
			}
		}
		fl.semMu.RUnlock()

		if rejected {
			fl.logger.Warn("connection rejected: at capacity",
				"remote_addr", conn.RemoteAddr().String(),
				"max_connections", maxConns)
			conn.Close()
			continue
		}

		if fl.logger.Enabled(ctx, slog.LevelDebug) {
			fl.logger.Debug("connection accepted",
				"remote_addr", conn.RemoteAddr().String(),
				"active_connections", fl.activeConns.Load(),
				"max_connections", maxConns,
			)
		}

		fl.wg.Go(func() {
			if maxConns > 0 {
				defer fl.activeConns.Add(-1)
			}
			fl.handleConn(ctx, conn)
		})
	}
}

// handleConn runs protocol detection and dispatch for a single accepted
// connection. It is responsible for per-connection observability: connection
// ID, logger enrichment, plugin lifecycle hooks, and the peek deadline.
func (fl *FullListener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	pc := NewPeekConn(conn)
	remoteAddr := conn.RemoteAddr().String()
	connStart := time.Now()

	connID := GenerateConnID()
	connLogger := fl.logger.With("conn_id", connID, "remote_addr", remoteAddr)

	ctx = ContextWithConnID(ctx, connID)
	ctx = ContextWithClientAddr(ctx, remoteAddr)
	ctx = ContextWithListenerName(ctx, fl.name)
	ctx = ContextWithLogger(ctx, connLogger)

	// Bound protocol detection by the peek deadline (Slowloris protection).
	peekTimeout := time.Duration(fl.peekTimeoutNs.Load())
	if peekTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(peekTimeout))
	}

	kind, peek, ok := fl.detectProtocol(pc, connLogger)

	// Reset the deadline before handing off to the handler. The handler
	// has its own timeouts scoped to individual exchanges.
	_ = conn.SetReadDeadline(time.Time{})

	if !ok {
		connLogger.Debug("protocol detection failed",
			"peek_bytes", fmt.Sprintf("%x", peek))
		return
	}

	connLogger.Debug("protocol detected",
		"protocol", kind.String(),
		"peek_len", len(peek))

	// Enforce the runtime EnabledProtocols allow-list (USK-732). When the
	// allow-list is non-empty and the detected kind does not map to any
	// allowed user-facing name, reject before stack construction. The
	// rejection is recorded via the OnProtocolRejected callback so MITM
	// observability is preserved (Issue acceptance: not a silent close).
	if !fl.protocolAllowed(kind) {
		allowed := fl.snapshotEnabledProtocols()
		// Debug, not Info: a connection arriving with a protocol outside
		// the configured subset is a client-side fact (akin to "client
		// sends invalid request"), not a proxy anomaly. Logging at Info
		// would flood the log under a port scan. The rejection is still
		// fully observable via the OnProtocolRejected callback (which
		// records a Stream with state="error" and
		// blocked_by="enabled_protocols").
		connLogger.Debug("protocol rejected by enabled_protocols filter",
			"detected", kind.String(),
			"enabled_protocols", allowed,
		)
		if fl.onProtocolRejected != nil {
			fl.onProtocolRejected(ctx, pc, kind, kind.UserName())
		}
		return
	}

	handler := fl.handlerFor(kind)
	if handler == nil {
		connLogger.Debug("no handler for detected protocol",
			"protocol", kind.String())
		return
	}

	if err := handler(ctx, pc); err != nil {
		if errors.Is(err, context.Canceled) {
			connLogger.Debug("connection cancelled",
				"protocol", kind.String())
			return
		}
		connLogger.Error("handler error",
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

// handlerFor returns the registered handler callback for the given protocol
// kind, or nil if no handler is registered.
func (fl *FullListener) handlerFor(kind ProtocolKind) HandlerFunc {
	switch kind {
	case ProtocolHTTPConnect:
		return fl.onCONNECT
	case ProtocolSOCKS5:
		return fl.onSOCKS5
	case ProtocolHTTP1:
		return fl.onHTTP1
	case ProtocolHTTP2:
		return fl.onHTTP2
	case ProtocolTCP:
		return fl.onTCP
	default:
		return nil
	}
}

// detectProtocol performs two-stage peek protocol detection.
//
// Stage 1 reads QuickPeekSize (1 byte) so short-greeting protocols (SOCKS5)
// can be matched without waiting for PeekSize bytes.
//
// Stage 2 refines the decision when more bytes are already buffered. SOCKS5
// (0x05) is definitive on one byte and is never refined.
func (fl *FullListener) detectProtocol(pc *PeekConn, logger *slog.Logger) (ProtocolKind, []byte, bool) {
	peek, err := pc.Peek(QuickPeekSize)
	if err != nil && len(peek) == 0 {
		logger.Debug("quick peek failed", "error", err)
		return ProtocolUnknown, nil, false
	}

	kind := DetectKind(peek)

	// SOCKS5 is definitive on one byte; never refine.
	if kind == ProtocolSOCKS5 {
		return kind, peek, true
	}

	// Stage 2: if more bytes are already buffered, re-run detection on the
	// larger buffer for disambiguation (e.g. HTTP/2 preface vs HTTP/1.x).
	buffered := pc.Buffered()
	if buffered > QuickPeekSize {
		n := buffered
		if n > PeekSize {
			n = PeekSize
		}
		if fullPeek, err := pc.Peek(n); err == nil && len(fullPeek) > 0 {
			kind = DetectKind(fullPeek)
			peek = fullPeek
		}
	}

	return kind, peek, kind != ProtocolUnknown
}

// Addr returns the listener's bound address, or empty string if Start has
// not progressed past net.Listen.
func (fl *FullListener) Addr() string {
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if fl.listener != nil {
		return fl.listener.Addr().String()
	}
	return ""
}

// Ready returns a channel that is closed when the listener is accepting.
// Intended for test synchronization.
func (fl *FullListener) Ready() <-chan struct{} {
	return fl.ready
}

// ActiveConnections returns the number of connections currently in flight.
func (fl *FullListener) ActiveConnections() int {
	return int(fl.activeConns.Load())
}

// MaxConnections returns the current concurrent-connection cap.
func (fl *FullListener) MaxConnections() int {
	fl.semMu.RLock()
	defer fl.semMu.RUnlock()
	return fl.maxConnections
}

// PeekTimeout returns the current protocol detection timeout.
func (fl *FullListener) PeekTimeout() time.Duration {
	return time.Duration(fl.peekTimeoutNs.Load())
}

// SetMaxConnections changes the concurrent-connection cap. n must be > 0.
// Takes effect on the next accepted connection; in-flight connections drain.
func (fl *FullListener) SetMaxConnections(n int) {
	if n <= 0 {
		return
	}
	fl.semMu.Lock()
	defer fl.semMu.Unlock()
	fl.maxConnections = n
}

// SetPeekTimeout changes the protocol detection timeout. d must be > 0.
func (fl *FullListener) SetPeekTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	fl.peekTimeoutNs.Store(int64(d))
}

// SetEnabledProtocols updates the runtime protocol allow-list. nil or
// empty restores the default ("all detected kinds accepted"). Mutations
// are atomic; in-flight detection on the accept loop sees the new
// allow-list on the next handleConn iteration.
func (fl *FullListener) SetEnabledProtocols(protocols []string) {
	if len(protocols) == 0 {
		fl.enabledProtocols.Store(nil)
		return
	}
	cp := make([]string, len(protocols))
	copy(cp, protocols)
	fl.enabledProtocols.Store(&cp)
}

// EnabledProtocols returns a snapshot of the currently-configured
// runtime allow-list, or nil when no filter is active.
func (fl *FullListener) EnabledProtocols() []string {
	return fl.snapshotEnabledProtocols()
}

// snapshotEnabledProtocols returns a copy of the current allow-list, or
// nil when none is configured. Internal helper used by both the accept
// loop and EnabledProtocols.
func (fl *FullListener) snapshotEnabledProtocols() []string {
	p := fl.enabledProtocols.Load()
	if p == nil || len(*p) == 0 {
		return nil
	}
	out := make([]string, len(*p))
	copy(out, *p)
	return out
}

// protocolAllowed reports whether the detected ProtocolKind is permitted
// under the current allow-list. Returns true when no filter is
// configured (nil or empty enabledProtocols), matching the legacy
// "accept all" behavior.
func (fl *FullListener) protocolAllowed(kind ProtocolKind) bool {
	p := fl.enabledProtocols.Load()
	if p == nil || len(*p) == 0 {
		return true
	}
	return kindMatchesEnabledNames(kind, *p)
}

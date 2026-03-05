package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const peekSize = 16

const defaultPeekTimeout = 30 * time.Second

// defaultMaxConnections limits concurrent connections to bound worst-case memory.
// With MaxBodySize=254MB, each connection may buffer up to 2×254MB (request + response).
// 128 connections × 508MB = ~63.5GB theoretical maximum.
// Operators can adjust via SetMaxConnections or the proxy_start MCP tool.
const defaultMaxConnections = 128

// ProtocolDetector selects a handler based on peeked bytes.
type ProtocolDetector interface {
	Detect(peek []byte) ProtocolHandler
}

// ListenerConfig holds configuration for creating a Listener.
type ListenerConfig struct {
	Addr           string
	Detector       ProtocolDetector
	Logger         *slog.Logger
	PeekTimeout    time.Duration // 0 = defaultPeekTimeout (30s)
	MaxConnections int           // 0 = defaultMaxConnections (128)
}

// Listener accepts TCP connections and dispatches them to protocol handlers.
type Listener struct {
	addr           string
	detector       ProtocolDetector
	logger         *slog.Logger
	peekTimeoutNs  atomic.Int64 // nanoseconds; read/written atomically
	maxConnections int
	activeConns    atomic.Int64 // current number of active connections

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	wg       sync.WaitGroup
	semMu    sync.RWMutex // protects maxConnections during dynamic resize
}

// NewListener creates a new TCP listener with the given configuration.
func NewListener(cfg ListenerConfig) *Listener {
	peekTimeout := cfg.PeekTimeout
	if peekTimeout == 0 {
		peekTimeout = defaultPeekTimeout
	}
	maxConns := cfg.MaxConnections
	if maxConns == 0 {
		maxConns = defaultMaxConnections
	}
	l := &Listener{
		addr:           cfg.Addr,
		detector:       cfg.Detector,
		logger:         cfg.Logger,
		maxConnections: maxConns,
		ready:          make(chan struct{}),
	}
	l.peekTimeoutNs.Store(int64(peekTimeout))
	return l
}

// Start begins accepting connections. It blocks until the context is cancelled.
func (l *Listener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", l.addr, err)
	}

	l.mu.Lock()
	l.listener = ln
	l.mu.Unlock()
	close(l.ready)

	defer ln.Close()

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
		// Capacity check: reject if at capacity.
		// Hold RLock through the entire increment-and-check to prevent
		// SetMaxConnections from lowering the limit between reading
		// maxConnections and incrementing activeConns, which would allow
		// connections beyond the new limit.
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

		l.wg.Go(func() {
			if maxConns > 0 {
				defer l.activeConns.Add(-1)
			}
			l.handleConn(ctx, conn)
		})
	}
}

func (l *Listener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	pc := NewPeekConn(conn)
	remoteAddr := conn.RemoteAddr().String()

	// Generate a unique connection ID for log correlation.
	connID := GenerateConnID()
	connLogger := l.logger.With("conn_id", connID, "remote_addr", remoteAddr)

	// Store connection ID, client address, and logger in context for downstream handlers.
	ctx = ContextWithConnID(ctx, connID)
	ctx = ContextWithClientAddr(ctx, remoteAddr)
	ctx = ContextWithLogger(ctx, connLogger)

	// Set read deadline for protocol detection (Slowloris protection).
	peekTimeout := time.Duration(l.peekTimeoutNs.Load())
	if peekTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(peekTimeout))
	}

	peek, err := pc.Peek(peekSize)
	if err != nil && len(peek) == 0 {
		connLogger.Debug("peek failed", "error", err)
		return
	}

	// Reset deadline before passing to handler.
	conn.SetReadDeadline(time.Time{})

	handler := l.detector.Detect(peek)
	if handler == nil {
		connLogger.Warn("no protocol handler matched", "peek_bytes", fmt.Sprintf("%x", peek))
		return
	}

	connLogger.Debug("connection dispatched", "protocol", handler.Name())

	if err := handler.Handle(ctx, pc); err != nil {
		connLogger.Error("handler error", "protocol", handler.Name(), "error", err)
	}
}

// Addr returns the listener's network address, or empty string if not started.
func (l *Listener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return ""
}

// Ready returns a channel that is closed when the listener is ready to accept connections.
func (l *Listener) Ready() <-chan struct{} {
	return l.ready
}

// ActiveConnections returns the number of connections currently being handled.
func (l *Listener) ActiveConnections() int {
	return int(l.activeConns.Load())
}

// MaxConnections returns the current maximum number of concurrent connections.
func (l *Listener) MaxConnections() int {
	l.semMu.RLock()
	defer l.semMu.RUnlock()
	return l.maxConnections
}

// PeekTimeout returns the current protocol detection timeout.
func (l *Listener) PeekTimeout() time.Duration {
	return time.Duration(l.peekTimeoutNs.Load())
}

// SetMaxConnections dynamically changes the maximum number of concurrent connections.
// The new limit takes effect for the next incoming connection. Existing connections
// that exceed the new limit are not interrupted; they drain naturally.
// n must be > 0; otherwise the call is ignored.
func (l *Listener) SetMaxConnections(n int) {
	if n <= 0 {
		return
	}
	l.semMu.Lock()
	defer l.semMu.Unlock()
	l.maxConnections = n
}

// SetPeekTimeout dynamically changes the protocol detection timeout.
// The new timeout takes effect for the next incoming connection.
// d must be > 0; otherwise the call is ignored.
func (l *Listener) SetPeekTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	l.peekTimeoutNs.Store(int64(d))
}

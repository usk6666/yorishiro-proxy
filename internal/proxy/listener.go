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

const defaultMaxConnections = 1024

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
	MaxConnections int           // 0 = defaultMaxConnections (1024)
}

// Listener accepts TCP connections and dispatches them to protocol handlers.
type Listener struct {
	addr           string
	detector       ProtocolDetector
	logger         *slog.Logger
	peekTimeoutNs  atomic.Int64 // nanoseconds; read/written atomically
	maxConnections int

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	wg       sync.WaitGroup
	sem      chan struct{} // nil if unlimited
	semMu    sync.RWMutex // protects sem during dynamic resize
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
	var sem chan struct{}
	if maxConns > 0 {
		sem = make(chan struct{}, maxConns)
	}
	l := &Listener{
		addr:           cfg.Addr,
		detector:       cfg.Detector,
		logger:         cfg.Logger,
		maxConnections: maxConns,
		ready:          make(chan struct{}),
		sem:            sem,
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
		// Non-blocking semaphore acquire: reject if at capacity.
		// Use RLock to allow concurrent Accept while preventing races
		// with SetMaxConnections which swaps the semaphore channel.
		l.semMu.RLock()
		sem := l.sem
		maxConns := l.maxConnections
		l.semMu.RUnlock()

		if sem != nil {
			select {
			case sem <- struct{}{}:
			default:
				l.logger.Warn("connection rejected: at capacity",
					"remote_addr", conn.RemoteAddr().String(),
					"max_connections", maxConns)
				conn.Close()
				continue
			}
		}

		l.wg.Go(func() {
			if sem != nil {
				defer func() { <-sem }()
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
// It returns 0 if the semaphore is not configured (unlimited connections).
func (l *Listener) ActiveConnections() int {
	l.semMu.RLock()
	sem := l.sem
	l.semMu.RUnlock()
	if sem == nil {
		return 0
	}
	return len(sem)
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
	l.sem = make(chan struct{}, n)
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

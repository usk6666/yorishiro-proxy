package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
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
	peekTimeout    time.Duration
	maxConnections int

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	wg       sync.WaitGroup
	sem      chan struct{} // nil if unlimited
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
	return &Listener{
		addr:           cfg.Addr,
		detector:       cfg.Detector,
		logger:         cfg.Logger,
		peekTimeout:    peekTimeout,
		maxConnections: maxConns,
		ready:          make(chan struct{}),
		sem:            sem,
	}
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
		if l.sem != nil {
			select {
			case l.sem <- struct{}{}:
			default:
				l.logger.Warn("connection rejected: at capacity",
					"remote_addr", conn.RemoteAddr().String(),
					"max_connections", l.maxConnections)
				conn.Close()
				continue
			}
		}

		l.wg.Go(func() {
			if l.sem != nil {
				defer func() { <-l.sem }()
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

	// Store connection ID and logger in context for downstream handlers.
	ctx = ContextWithConnID(ctx, connID)
	ctx = ContextWithLogger(ctx, connLogger)

	// Set read deadline for protocol detection (Slowloris protection).
	if l.peekTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(l.peekTimeout))
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
	if l.sem == nil {
		return 0
	}
	return len(l.sem)
}

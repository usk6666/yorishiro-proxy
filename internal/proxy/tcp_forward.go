package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

// TCPForwardListener accepts TCP connections on a local port and dispatches
// them to a ProtocolHandler (typically the raw TCP handler) without protocol
// detection. Each connection is annotated with a unique connection ID and
// client address in the context.
type TCPForwardListener struct {
	addr    string
	handler ProtocolHandler
	logger  *slog.Logger

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
	wg       sync.WaitGroup
}

// NewTCPForwardListener creates a new TCP forward listener.
// addr is the local address to listen on (e.g. "127.0.0.1:9998").
// handler is the protocol handler to dispatch connections to.
func NewTCPForwardListener(addr string, handler ProtocolHandler, logger *slog.Logger) *TCPForwardListener {
	return &TCPForwardListener{
		addr:    addr,
		handler: handler,
		logger:  logger,
		ready:   make(chan struct{}),
	}
}

// Start begins accepting connections. It blocks until the context is cancelled.
func (l *TCPForwardListener) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("tcp forward listen on %s: %w", l.addr, err)
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
				return fmt.Errorf("tcp forward accept: %w", err)
			}
		}

		l.wg.Go(func() {
			l.handleConn(ctx, conn)
		})
	}
}

// handleConn dispatches a single connection to the handler.
func (l *TCPForwardListener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	connID := GenerateConnID()
	connLogger := l.logger.With("conn_id", connID, "remote_addr", remoteAddr, "handler", l.handler.Name())

	ctx = ContextWithConnID(ctx, connID)
	ctx = ContextWithClientAddr(ctx, remoteAddr)
	ctx = ContextWithLogger(ctx, connLogger)

	connLogger.Debug("tcp forward connection dispatched")

	if err := l.handler.Handle(ctx, conn); err != nil {
		connLogger.Error("tcp forward handler error", "error", err)
	}
}

// Ready returns a channel that is closed when the listener is ready to accept connections.
func (l *TCPForwardListener) Ready() <-chan struct{} {
	return l.ready
}

// Addr returns the listener's network address, or empty string if not started.
func (l *TCPForwardListener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return ""
}

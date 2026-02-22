package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
)

const peekSize = 16

// ProtocolDetector selects a handler based on peeked bytes.
type ProtocolDetector interface {
	Detect(peek []byte) ProtocolHandler
}

// Listener accepts TCP connections and dispatches them to protocol handlers.
type Listener struct {
	addr     string
	detector ProtocolDetector

	mu       sync.Mutex
	listener net.Listener
	ready    chan struct{}
}

// NewListener creates a new TCP listener on the given address with a protocol detector.
func NewListener(addr string, detector ProtocolDetector) *Listener {
	return &Listener{
		addr:     addr,
		detector: detector,
		ready:    make(chan struct{}),
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
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}
		go l.handleConn(ctx, conn)
	}
}

func (l *Listener) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	pc := NewPeekConn(conn)

	peek, err := pc.Peek(peekSize)
	if err != nil && len(peek) == 0 {
		return
	}

	handler := l.detector.Detect(peek)
	if handler == nil {
		return
	}

	handler.Handle(ctx, pc)
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

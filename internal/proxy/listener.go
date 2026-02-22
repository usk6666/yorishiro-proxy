package proxy

import (
	"context"
	"fmt"
	"net"
)

// Listener accepts TCP connections and dispatches them to protocol handlers.
type Listener struct {
	addr     string
	listener net.Listener
}

// NewListener creates a new TCP listener on the given address.
func NewListener(addr string) *Listener {
	return &Listener{addr: addr}
}

// Start begins accepting connections. It blocks until the context is cancelled.
func (l *Listener) Start(ctx context.Context) error {
	var err error
	l.listener, err = net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", l.addr, err)
	}
	defer l.listener.Close()

	go func() {
		<-ctx.Done()
		l.listener.Close()
	}()

	for {
		conn, err := l.listener.Accept()
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
	// TODO: peek bytes, detect protocol, dispatch to handler
	_ = ctx
}

// Addr returns the listener's network address, or empty string if not started.
func (l *Listener) Addr() string {
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return ""
}

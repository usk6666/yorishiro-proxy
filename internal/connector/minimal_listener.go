package connector

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// MinimalListenerConfig configures the MinimalListener.
type MinimalListenerConfig struct {
	// BuildConfig is the stack construction configuration.
	BuildConfig *BuildConfig

	// OnStack is called when a ConnectionStack is ready for a new connection.
	// Session wiring (RunSession) should happen inside this callback.
	// The callback owns the stack and TLSSnapshot lifetime.
	OnStack func(ctx context.Context, stack *ConnectionStack, snap *envelope.TLSSnapshot, target string)
}

// MinimalListener is a TCP listener that handles CONNECT requests and builds
// ConnectionStacks for each tunneled connection. It is scoped to N2: only
// CONNECT-based tunneling is supported (no plain HTTP forward proxy).
//
// This listener coexists with the old connector/listener.go and will be
// replaced in N4 when full protocol detection is added.
type MinimalListener struct {
	ln        net.Listener
	cfg       MinimalListenerConfig
	neg       *CONNECTNegotiator
	wg        sync.WaitGroup
	done      chan struct{}
	closeOnce sync.Once
}

// NewMinimalListener creates a listener bound to the given address.
func NewMinimalListener(addr string, cfg MinimalListenerConfig) (*MinimalListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connector: listen %s: %w", addr, err)
	}
	return &MinimalListener{
		ln:   ln,
		cfg:  cfg,
		neg:  NewCONNECTNegotiator(nil),
		done: make(chan struct{}),
	}, nil
}

// NewMinimalListenerFromListener wraps an existing net.Listener.
// Useful for testing where the caller creates the listener.
func NewMinimalListenerFromListener(ln net.Listener, cfg MinimalListenerConfig) *MinimalListener {
	return &MinimalListener{
		ln:   ln,
		cfg:  cfg,
		neg:  NewCONNECTNegotiator(nil),
		done: make(chan struct{}),
	}
}

// Addr returns the listener's network address.
func (ml *MinimalListener) Addr() net.Addr {
	return ml.ln.Addr()
}

// Serve accepts connections in a loop. Blocks until Close is called or the
// listener errors out. Each accepted connection is handled in a goroutine.
func (ml *MinimalListener) Serve(ctx context.Context) error {
	slog.Info("connector: minimal listener started", "addr", ml.ln.Addr().String())

	for {
		conn, err := ml.ln.Accept()
		if err != nil {
			select {
			case <-ml.done:
				return nil // Clean shutdown
			default:
				return fmt.Errorf("connector: accept: %w", err)
			}
		}

		ml.wg.Add(1)
		go func() {
			defer ml.wg.Done()
			ml.handleConn(ctx, conn)
		}()
	}
}

// Close shuts down the listener and waits for active connections to finish.
// Close is idempotent and safe to call multiple times.
func (ml *MinimalListener) Close() error {
	var err error
	ml.closeOnce.Do(func() {
		close(ml.done)
		err = ml.ln.Close()
	})
	ml.wg.Wait()
	return err
}

// handleConn processes a single accepted connection: parse CONNECT, build
// the ConnectionStack, and call OnStack.
func (ml *MinimalListener) handleConn(ctx context.Context, conn net.Conn) {
	pc := NewPeekConn(conn)

	target, err := ml.neg.Negotiate(ctx, pc)
	if err != nil {
		slog.Debug("connector: CONNECT negotiation failed", "err", err, "remote", conn.RemoteAddr())
		conn.Close()
		return
	}

	slog.Debug("connector: CONNECT tunnel established",
		"target", target,
		"remote", conn.RemoteAddr(),
	)

	// Build the ConnectionStack. This performs client-side TLS MITM and
	// upstream dial+TLS inside BuildConnectionStack.
	stack, snap, err := BuildConnectionStack(ctx, pc, target, ml.cfg.BuildConfig)
	if err != nil {
		slog.Warn("connector: stack build failed",
			"target", target,
			"err", err,
		)
		conn.Close()
		return
	}

	// OnStack takes ownership of the stack. If nil, close the stack to
	// prevent connection leaks.
	if ml.cfg.OnStack != nil {
		ml.cfg.OnStack(ctx, stack, snap, target)
	} else {
		stack.Close()
	}
}

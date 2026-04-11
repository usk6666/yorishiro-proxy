// dispatcher.go wires concrete Dispatchers that the Listener hands accepted
// connections to. Each Dispatcher bridges the protocol-kind-keyed detection
// surface (Dispatcher.Dispatch) to a concrete handler for that kind.
//
// The Dispatchers defined here are thin composition objects: they own no
// goroutines of their own, they do not mutate their inputs, and they are
// safe to share across all listener connections.
package connector

import (
	"context"
	"errors"
	"fmt"
)

// KindDispatcher implements Dispatcher by routing to per-ProtocolKind
// handler functions. A nil handler for a given kind returns ErrNoHandler
// so the listener can close the connection cleanly.
//
// The zero value is usable: all kinds default to "no handler". Handlers
// are registered via With methods during construction.
type KindDispatcher struct {
	connect func(ctx context.Context, conn *PeekConn, factory CodecFactory) error
	plain   func(ctx context.Context, conn *PeekConn, kind ProtocolKind, factory CodecFactory) error
	socks5  func(ctx context.Context, conn *PeekConn, factory CodecFactory) error
}

// NewKindDispatcher returns an empty KindDispatcher.
func NewKindDispatcher() *KindDispatcher {
	return &KindDispatcher{}
}

// WithCONNECT installs a handler for ProtocolHTTPConnect. Typically this is
// CONNECTHandler(negotiator, tunnel).
func (d *KindDispatcher) WithCONNECT(h func(ctx context.Context, conn *PeekConn, factory CodecFactory) error) *KindDispatcher {
	d.connect = h
	return d
}

// WithSOCKS5 installs a handler for ProtocolSOCKS5. Wired by USK-561.
func (d *KindDispatcher) WithSOCKS5(h func(ctx context.Context, conn *PeekConn, factory CodecFactory) error) *KindDispatcher {
	d.socks5 = h
	return d
}

// WithPlain installs a catch-all for protocols the listener expects to
// drive directly via CodecFactory (HTTP/1.x forward proxy, raw TCP, etc.).
func (d *KindDispatcher) WithPlain(h func(ctx context.Context, conn *PeekConn, kind ProtocolKind, factory CodecFactory) error) *KindDispatcher {
	d.plain = h
	return d
}

// Dispatch implements Dispatcher.
func (d *KindDispatcher) Dispatch(ctx context.Context, conn *PeekConn, kind ProtocolKind, factory CodecFactory) error {
	switch kind {
	case ProtocolHTTPConnect:
		if d.connect == nil {
			return fmt.Errorf("%w: CONNECT", ErrNoHandler)
		}
		return d.connect(ctx, conn, factory)
	case ProtocolSOCKS5:
		if d.socks5 == nil {
			return fmt.Errorf("%w: SOCKS5", ErrNoHandler)
		}
		return d.socks5(ctx, conn, factory)
	case ProtocolHTTP1, ProtocolHTTP2, ProtocolTCP:
		if d.plain == nil {
			return fmt.Errorf("%w: %s", ErrNoHandler, kind)
		}
		return d.plain(ctx, conn, kind, factory)
	default:
		return fmt.Errorf("%w: unknown kind %d", ErrNoHandler, kind)
	}
}

// CONNECTHandler builds a Dispatcher-compatible handler function that
// negotiates the CONNECT verb and hands the resulting tunnel off to the
// TunnelHandler. Either argument may be nil — the handler returns an error
// in that case rather than silently dropping connections.
func CONNECTHandler(negotiator *CONNECTNegotiator, tunnel *TunnelHandler) func(ctx context.Context, conn *PeekConn, factory CodecFactory) error {
	return func(ctx context.Context, conn *PeekConn, _ CodecFactory) error {
		if negotiator == nil {
			return errors.New("connector: CONNECT negotiator not configured")
		}
		if tunnel == nil {
			return errors.New("connector: tunnel handler not configured")
		}
		target, err := negotiator.Negotiate(ctx, conn)
		if err != nil {
			return fmt.Errorf("connector: CONNECT negotiate: %w", err)
		}
		return tunnel.Handle(ctx, conn, target, "CONNECT")
	}
}

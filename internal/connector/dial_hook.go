package connector

import (
	"context"
	"net"
)

// Dial socket hook (USK-1316, transparent own-dial loop guard).
//
// The transparent listener must recognise a connection that is its own
// upstream socket REDIRECTed back to it. Through an upstream proxy the
// socket is the TCP connection to the proxy, and the looped CONNECT
// arrives while the dial is still waiting for the CONNECT answer — so
// the socket has to be known as soon as the TCP connect completes, not
// when the dial returns. The hook carried on the dial ctx is told about
// every TCP socket the dial path opens: the direct dial, or the
// connection to an HTTP CONNECT / SOCKS5 upstream proxy, before its
// handshake. Without a hook on ctx nothing changes.

type dialSocketHookKey struct{}

// contextWithDialSocketHook returns ctx carrying fn.
func contextWithDialSocketHook(ctx context.Context, fn func(net.Conn)) context.Context {
	return context.WithValue(ctx, dialSocketHookKey{}, fn)
}

// notifyDialSocket calls the hook on ctx, if any, with the freshly
// connected socket c.
func notifyDialSocket(ctx context.Context, c net.Conn) {
	if fn, ok := ctx.Value(dialSocketHookKey{}).(func(net.Conn)); ok && fn != nil {
		fn(c)
	}
}

// hookedDialer is a net.Dialer that reports each connected socket to the
// hook on the dial ctx (for the SOCKS5 forward dialer).
type hookedDialer struct {
	d   *net.Dialer
	ctx context.Context
}

// Dial implements proxy.Dialer.
func (h hookedDialer) Dial(network, addr string) (net.Conn, error) {
	return h.DialContext(h.ctx, network, addr)
}

// DialContext implements proxy.ContextDialer.
func (h hookedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := h.d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	notifyDialSocket(h.ctx, c)
	return c, nil
}

package connector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Transparent mode (USK-1316): a listener that receives connections an
// nftables / iptables REDIRECT rule diverted to it. The client does not
// know a proxy is there, so the request carries no proxy-addressing
// information (no CONNECT, no absolute-form); the destination the client
// actually dialed — the "original destination" — is read back from the
// kernel's connection-tracking entry with getsockopt(SO_ORIGINAL_DST).
//
// The original destination is resolved once, at accept, before a single
// byte is read (FullListenerConfig.OriginalDst). A connection whose
// original destination cannot be obtained, or is the connection's own
// local address (a client that dialed the proxy directly, or a REDIRECT
// rule that did not fire), is rejected and logged: dialing "where the
// client wanted to go" is meaningless for it, and dialing the proxy's own
// address would loop.

// OriginalDstResolver returns the original destination of an accepted
// connection that a REDIRECT rule diverted to the listener. Production
// wiring uses PlatformOriginalDstResolver; tests inject a fake, since a
// real REDIRECT needs root and an nftables rule.
type OriginalDstResolver interface {
	OriginalDst(conn net.Conn) (netip.AddrPort, error)
}

// OriginalDstFunc adapts a function to OriginalDstResolver.
type OriginalDstFunc func(conn net.Conn) (netip.AddrPort, error)

// OriginalDst calls f(conn).
func (f OriginalDstFunc) OriginalDst(conn net.Conn) (netip.AddrPort, error) { return f(conn) }

// PlatformOriginalDstResolver returns the REDIRECT resolver of this
// platform: getsockopt(SO_ORIGINAL_DST) / getsockopt(IP6T_SO_ORIGINAL_DST)
// on Linux. On every other platform each call fails with an error wrapping
// errors.ErrUnsupported (see TransparentSupported).
func PlatformOriginalDstResolver() OriginalDstResolver {
	return OriginalDstFunc(platformOriginalDst)
}

// TransparentSupported reports whether this platform can resolve the
// original destination of a REDIRECTed connection (Linux only).
func TransparentSupported() bool { return transparentSupported }

// ErrOriginalDstSelf reports that a connection's original destination is
// its own local address: the client dialed the proxy listener directly (or
// the REDIRECT rule did not fire), so there is nowhere else to relay it.
var ErrOriginalDstSelf = errors.New("original destination is the connection's own local address")

// ErrOriginalDstInvalid reports an original destination that cannot be
// dialed: the zero value, an unspecified address, or port 0.
var ErrOriginalDstInvalid = errors.New("original destination is not a dialable address")

// resolveTransparentDst resolves conn's original destination through r and
// validates it: the result is unmapped (an IPv4-mapped IPv6 address
// becomes the IPv4 address), must be a specified address with a non-zero
// port, and must differ from conn's own local address.
func resolveTransparentDst(r OriginalDstResolver, conn net.Conn) (netip.AddrPort, error) {
	dst, err := r.OriginalDst(conn)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("connector: original dst: %w", err)
	}
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	if !dst.IsValid() || dst.Addr().IsUnspecified() || dst.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("connector: original dst %v: %w", dst, ErrOriginalDstInvalid)
	}
	if local, ok := addrPortOf(conn.LocalAddr()); ok && local == netip.AddrPortFrom(dst.Addr().WithZone(""), dst.Port()) {
		return netip.AddrPort{}, fmt.Errorf("connector: original dst %v: %w", dst, ErrOriginalDstSelf)
	}
	return dst, nil
}

// addrPortOf returns a's unmapped AddrPort.
func addrPortOf(a net.Addr) (netip.AddrPort, bool) {
	if a == nil {
		return netip.AddrPort{}, false
	}
	if ta, ok := a.(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), ap.IsValid()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), true
}

type originalDstCtxKey struct{}

// ContextWithOriginalDst returns ctx carrying the original destination of
// the connection a transparent listener accepted.
func ContextWithOriginalDst(ctx context.Context, dst netip.AddrPort) context.Context {
	return context.WithValue(ctx, originalDstCtxKey{}, dst)
}

// OriginalDstFromContext returns the original destination stored by
// ContextWithOriginalDst. ok is false on a non-transparent connection.
func OriginalDstFromContext(ctx context.Context) (dst netip.AddrPort, ok bool) {
	dst, ok = ctx.Value(originalDstCtxKey{}).(netip.AddrPort)
	return dst, ok && dst.IsValid()
}

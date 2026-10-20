package connector

import (
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// proxiedConn marks a raw TCP connection that dialTCP established through
// an upstream proxy (USK-1116). It carries the credential-free proxy
// endpoint so the Layer built on top of the (possibly TLS-wrapped)
// connection can record which proxy the bytes actually traversed — the
// proxy URL is resolved per dial (per-listener override, rotation) and is
// otherwise not observable after the fact.
//
// Everything else is the embedded net.Conn: RemoteAddr() is the proxy's
// socket address, which is exactly the wire-observed upstream peer.
type proxiedConn struct {
	net.Conn
	proxy string
}

// CloseWrite half-closes the underlying connection when it supports it, so
// the wrapper does not hide the capability from callers that type-assert
// interface{ CloseWrite() error } (raw relays, bytechunk).
func (c *proxiedConn) CloseWrite() error {
	cw, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("connector: %T does not support CloseWrite: %w", c.Conn, errors.ErrUnsupported)
	}
	return cw.CloseWrite()
}

// NetConn returns the wrapped connection, mirroring (*tls.Conn).NetConn.
func (c *proxiedConn) NetConn() net.Conn { return c.Conn }

// proxyEndpoint renders the upstream proxy as "scheme://host:port" with
// any userinfo dropped entirely. A username alone can be a credential
// (API key / session token), so masking (RedactProxyURL) is not enough
// for a value that is persisted to the flow store.
func proxyEndpoint(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// UpstreamProxyOf reports the upstream proxy conn was dialed through, as
// "scheme://host:port" without credentials, or "" for a direct dial. It
// sees through TLS (crypto/tls and uTLS both expose NetConn) and any other
// wrapper that implements NetConn.
func UpstreamProxyOf(conn net.Conn) string {
	for conn != nil {
		if pc, ok := conn.(*proxiedConn); ok {
			return pc.proxy
		}
		nc, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			return ""
		}
		conn = nc.NetConn()
	}
	return ""
}

// WithUpstreamPeer returns envCtx with the upstream-leg peer stamped from
// conn (USK-1116): ServerAddr is conn.RemoteAddr() — the socket peer the
// proxy actually talked to, i.e. the upstream proxy when one was used —
// and UpstreamProxy is the credential-free proxy URL (or "" for a direct
// dial). Both fields are always overwritten so a template copied from a
// stale Layer (redial) cannot leak the old socket's peer.
//
// Call it only for the upstream-facing Layer's template; the client leg
// keeps ServerAddr nil (RFC-001 §3.1: context is per Layer).
func WithUpstreamPeer(envCtx envelope.EnvelopeContext, conn net.Conn) envelope.EnvelopeContext {
	if conn == nil {
		return envCtx
	}
	envCtx.ServerAddr = conn.RemoteAddr()
	envCtx.UpstreamProxy = UpstreamProxyOf(conn)
	return envCtx
}

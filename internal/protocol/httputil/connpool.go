package httputil

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"
)

// ProxyDialFunc is the signature for dialing through an upstream proxy.
// It establishes a TCP connection to targetAddr tunneled through proxyURL.
type ProxyDialFunc func(ctx context.Context, proxyURL *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error)

// ProxyRedactFunc is the signature for redacting proxy URL credentials for logging.
type ProxyRedactFunc func(rawURL string) string

// ConnPool manages upstream connections for the HTTP/1.x independent engine.
// In the initial implementation there is no connection pooling — a new
// connection is dialed for every request. This matches the existing behavior
// of raw_forward.go's dialRawUpstream and avoids premature complexity.
type ConnPool struct {
	// TLSTransport performs TLS handshakes on raw TCP connections.
	TLSTransport TLSTransport

	// UpstreamProxy is the optional upstream proxy URL (HTTP CONNECT or SOCKS5).
	// When non-nil, TCP connections are tunneled through this proxy using
	// DialViaProxy.
	UpstreamProxy *url.URL

	// DialTimeout is the timeout for the TCP dial (and upstream proxy CONNECT
	// handshake, if applicable). Defaults to defaultDialTimeout if zero.
	DialTimeout time.Duration

	// AllowH2 permits HTTP/2 ALPN negotiation results. When false (default),
	// Get() rejects connections that negotiate "h2" ALPN. When true, "h2" is
	// accepted and the caller (typically UpstreamRouter) is responsible for
	// routing the connection to an appropriate HTTP/2 transport.
	AllowH2 bool

	// DialViaProxy dials a TCP connection through the upstream proxy.
	// Must be set when UpstreamProxy is non-nil. Typically set to
	// proxy.DialViaUpstreamProxy by the caller to avoid a circular import
	// from httputil to proxy.
	DialViaProxy ProxyDialFunc

	// RedactProxyURL redacts credentials from the proxy URL for logging.
	// When nil, the raw URL string is logged as-is. Typically set to
	// proxy.RedactProxyURL.
	RedactProxyURL ProxyRedactFunc
}

// defaultDialTimeout is the fallback dial timeout when ConnPool.DialTimeout is zero.
const defaultDialTimeout = 30 * time.Second

// ConnResult holds the result of a connection dial, including timing metadata.
type ConnResult struct {
	// Conn is the established connection (possibly TLS-wrapped).
	Conn net.Conn

	// ALPN is the negotiated application-layer protocol from the TLS handshake
	// (e.g., "h2", "http/1.1"). Empty for plain-text connections.
	ALPN string

	// ConnectDuration is the wall-clock time spent establishing the connection,
	// including TCP dial, any upstream-proxy CONNECT handshake, and TLS handshake.
	ConnectDuration time.Duration
}

// Get dials a new connection to addr each time (no pooling).
// For TLS connections (useTLS=true), the TLS handshake is performed using the
// configured TLSTransport and the negotiated ALPN protocol is returned.
// The hostname parameter is used for TLS SNI; it should be the bare hostname
// without port.
func (p *ConnPool) Get(ctx context.Context, addr string, useTLS bool, hostname string) (*ConnResult, error) {
	start := time.Now()

	timeout := p.DialTimeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}

	// Dial TCP connection (direct or via upstream proxy).
	rawConn, err := p.dialTCP(ctx, addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connpool dial %s: %w", addr, err)
	}

	// For plain-text connections, return immediately.
	if !useTLS {
		return &ConnResult{
			Conn:            rawConn,
			ConnectDuration: time.Since(start),
		}, nil
	}

	// Derive TLS hostname from addr when the caller did not provide one.
	if hostname == "" {
		host, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil {
			hostname = host
		}
		if hostname == "" {
			rawConn.Close()
			return nil, fmt.Errorf("connpool TLS connect %s: empty hostname for SNI/certificate verification", addr)
		}
	}

	// Perform TLS handshake.
	tlsTransport := p.effectiveTLSTransport()
	tlsConn, alpn, tlsErr := tlsTransport.TLSConnect(ctx, rawConn, hostname)
	if tlsErr != nil {
		rawConn.Close()
		return nil, fmt.Errorf("connpool TLS connect %s: %w", addr, tlsErr)
	}

	// Reject HTTP/2 ALPN when AllowH2 is not set — the caller only has an
	// HTTP/1.x transport and cannot handle HTTP/2 frames.
	if alpn == "h2" && !p.AllowH2 {
		tlsConn.Close()
		return nil, fmt.Errorf("connpool TLS connect %s: negotiated h2 ALPN, but HTTP/1.x transport requires http/1.1 or no ALPN", addr)
	}

	return &ConnResult{
		Conn:            tlsConn,
		ALPN:            alpn,
		ConnectDuration: time.Since(start),
	}, nil
}

// Close releases any resources held by the pool. In the current no-pooling
// implementation this is a no-op, but callers should still call it for
// forward compatibility.
func (p *ConnPool) Close() {
	// No-op: no pooled connections to close.
}

// dialTCP establishes a raw TCP connection, optionally tunneled through an
// upstream proxy.
func (p *ConnPool) dialTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	if p.UpstreamProxy != nil {
		proxyStr := p.UpstreamProxy.String()
		if p.RedactProxyURL != nil {
			proxyStr = p.RedactProxyURL(proxyStr)
		}
		slog.Debug("connpool dialing via upstream proxy", "addr", addr, "proxy", proxyStr)
		if p.DialViaProxy == nil {
			return nil, fmt.Errorf("connpool: UpstreamProxy is set but DialViaProxy function is nil")
		}
		return p.DialViaProxy(ctx, p.UpstreamProxy, addr, timeout)
	}

	slog.Debug("connpool dialing direct", "addr", addr)
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// effectiveTLSTransport returns the configured TLS transport or a default
// StandardTransport with InsecureSkipVerify enabled (proxy use-case).
func (p *ConnPool) effectiveTLSTransport() TLSTransport {
	if p.TLSTransport != nil {
		return p.TLSTransport
	}
	protos := []string{"http/1.1"}
	if p.AllowH2 {
		protos = []string{"h2", "http/1.1"}
	}
	return &StandardTransport{
		InsecureSkipVerify: true,
		NextProtos:         protos,
	}
}

package http

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// ConnPool manages upstream connections for the HTTP/1.x independent engine.
// In the initial implementation there is no connection pooling — a new
// connection is dialed for every request. This matches the existing behavior
// of raw_forward.go's dialRawUpstream and avoids premature complexity.
type ConnPool struct {
	// TLSTransport performs TLS handshakes on raw TCP connections.
	TLSTransport httputil.TLSTransport

	// UpstreamProxy is the optional upstream proxy URL (HTTP CONNECT or SOCKS5).
	// When non-nil, TCP connections are tunneled through this proxy.
	UpstreamProxy *url.URL

	// DialTimeout is the timeout for the TCP dial (and upstream proxy CONNECT
	// handshake, if applicable). Defaults to defaultDialTimeout if zero.
	DialTimeout time.Duration
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

	// Reject HTTP/2 ALPN — this transport is for HTTP/1.x only.
	if alpn == "h2" {
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
		slog.Debug("connpool dialing via upstream proxy", "addr", addr, "proxy", proxy.RedactProxyURL(p.UpstreamProxy.String()))
		return proxy.DialViaUpstreamProxy(ctx, p.UpstreamProxy, addr, timeout)
	}

	slog.Debug("connpool dialing direct", "addr", addr)
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// effectiveTLSTransport returns the configured TLS transport or a default
// StandardTransport with InsecureSkipVerify enabled (proxy use-case).
func (p *ConnPool) effectiveTLSTransport() httputil.TLSTransport {
	if p.TLSTransport != nil {
		return p.TLSTransport
	}
	return &httputil.StandardTransport{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}
}

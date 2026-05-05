package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/tlslayer"
)

// defaultDialTimeout is the fallback dial timeout when DialRawOpts.DialTimeout
// is zero.
const defaultDialTimeout = 30 * time.Second

// DialRawOpts configures a DialUpstreamRaw call.
type DialRawOpts struct {
	// TLSConfig is the base TLS configuration. When non-nil, a TLS handshake
	// is performed after the TCP connection is established. ServerName must
	// be set for certificate verification.
	TLSConfig *tls.Config

	// InsecureSkipVerify disables server certificate verification.
	InsecureSkipVerify bool

	// UTLSProfile selects a uTLS browser fingerprint ("chrome", "firefox",
	// "safari", "edge", "random"). Empty uses the standard crypto/tls.
	UTLSProfile string

	// ClientCert, if non-nil, is used as the mTLS client certificate.
	ClientCert *tls.Certificate

	// OfferALPN is the list of ALPN protocols to offer during TLS.
	// For N2, ["http/1.1"] is sufficient. N6 integrates ALPN cache.
	OfferALPN []string

	// UpstreamProxy, if non-nil, tunnels through an HTTP CONNECT or SOCKS5
	// proxy before TLS.
	UpstreamProxy *url.URL

	// DialTimeout bounds the TCP dial and any TLS handshake.
	// Zero defaults to 30s.
	DialTimeout time.Duration
}

// DialUpstreamRaw establishes an upstream connection, returning the (possibly
// TLS-wrapped) net.Conn and TLSSnapshot without attaching any Layer. The
// caller wraps the returned conn with bytechunk.New or http1layer.New.
//
// This function reuses the dialTCP helper for TCP establishment and delegates
// TLS to tlslayer.Client.
func DialUpstreamRaw(ctx context.Context, target string, opts DialRawOpts) (net.Conn, *envelope.TLSSnapshot, error) {
	if err := validateTarget(target); err != nil {
		return nil, nil, err
	}

	timeout := opts.DialTimeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rawConn, err := dialTCP(dialCtx, target, opts.UpstreamProxy, timeout)
	if err != nil {
		return nil, nil, err
	}

	if opts.TLSConfig == nil {
		slog.Debug("connector: DialUpstreamRaw complete (plain TCP)", "target", target)
		return rawConn, nil, nil
	}

	// TLS handshake via tlslayer.Client.
	tlsConn, snap, err := tlslayer.Client(dialCtx, rawConn, tlslayer.ClientOpts{
		TLSConfig:          opts.TLSConfig,
		InsecureSkipVerify: opts.InsecureSkipVerify,
		UTLSProfile:        opts.UTLSProfile,
		ClientCert:         opts.ClientCert,
		OfferALPN:          opts.OfferALPN,
	})
	if err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("connector: DialUpstreamRaw TLS handshake with %s: %w", target, err)
	}

	slog.Debug("connector: DialUpstreamRaw complete (TLS)",
		"target", target,
		"alpn", snap.ALPN,
	)

	return tlsConn, snap, nil
}

// validateTarget enforces "host:port" form and rejects CRLF so that the
// target string cannot be smuggled into an HTTP CONNECT request line
// (CWE-93). It is deliberately stricter than net.SplitHostPort alone.
func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("connector: empty target address")
	}
	if strings.ContainsAny(target, "\r\n") {
		return fmt.Errorf("connector: target address contains CR/LF characters")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("connector: invalid target %q: %w", target, err)
	}
	if host == "" || port == "" {
		return fmt.Errorf("connector: target %q missing host or port", target)
	}
	return nil
}

// dialTCP establishes a raw TCP connection, optionally through an upstream
// proxy. Timeout is already bounded by the caller's context, but the proxy
// helpers require an explicit duration for compatibility with the
// DialViaUpstreamProxy API.
func dialTCP(ctx context.Context, target string, upstreamProxy *url.URL, timeout time.Duration) (net.Conn, error) {
	if upstreamProxy != nil {
		slog.Debug("connector: dialing via upstream proxy", "target", target, "proxy", RedactProxyURL(upstreamProxy.String()))
		conn, err := DialViaUpstreamProxy(ctx, upstreamProxy, target, timeout)
		if err != nil {
			return nil, fmt.Errorf("connector: dial via upstream proxy: %w", err)
		}
		return conn, nil
	}

	slog.Debug("connector: dialing direct", "target", target)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("connector: dial %s: %w", target, err)
	}
	return conn, nil
}

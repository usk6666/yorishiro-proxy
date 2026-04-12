package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/tlslayer"
)

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
// This function reuses the existing dialTCP helper for TCP establishment
// and delegates TLS to tlslayer.Client.
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

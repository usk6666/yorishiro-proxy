package tlslayer

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// Client performs a client-side TLS handshake on plain toward an upstream
// server. It supports standard crypto/tls and uTLS fingerprint evasion.
// Returns the TLS-wrapped connection and a TLSSnapshot.
//
// The handshake logic is copied from M39 connector/dial.go
// (performTLSHandshake, performStandardTLSHandshake, performUTLSHandshake)
// and is intentionally unchanged.
func Client(ctx context.Context, plain net.Conn, opts ClientOpts) (net.Conn, *envelope.TLSSnapshot, error) {
	if opts.TLSConfig == nil {
		return nil, nil, fmt.Errorf("tlslayer: ClientOpts.TLSConfig is nil")
	}
	if opts.UTLSProfile != "" {
		return clientUTLS(ctx, plain, opts)
	}
	return clientStandard(ctx, plain, opts)
}

// clientStandard uses crypto/tls.
// Copied from connector/dial.go performStandardTLSHandshake.
func clientStandard(ctx context.Context, conn net.Conn, opts ClientOpts) (net.Conn, *envelope.TLSSnapshot, error) {
	cfg := opts.TLSConfig.Clone()
	if opts.InsecureSkipVerify {
		cfg.InsecureSkipVerify = true //nolint:gosec // proxy requires MITM
	}
	if len(opts.OfferALPN) > 0 {
		cfg.NextProtos = append([]string(nil), opts.OfferALPN...)
	}
	if opts.ClientCert != nil {
		cfg.Certificates = []tls.Certificate{*opts.ClientCert}
	}

	slog.Debug("tlslayer: standard client handshake starting",
		"server", cfg.ServerName,
		"insecure_skip_verify", cfg.InsecureSkipVerify,
		"alpn_offer", cfg.NextProtos,
	)

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("tlslayer: standard client handshake with %s: %w", cfg.ServerName, err)
	}

	state := tlsConn.ConnectionState()
	snap := snapshotFromState(state)

	slog.Debug("tlslayer: standard client handshake complete",
		"server", cfg.ServerName,
		"alpn", snap.ALPN,
	)

	return tlsConn, snap, nil
}

// utlsProfileIDs maps the public profile name to its uTLS ClientHelloID.
// Copied from connector/dial.go.
var utlsProfileIDs = map[string]*utls.ClientHelloID{
	"chrome":  &utls.HelloChrome_Auto,
	"firefox": &utls.HelloFirefox_Auto,
	"safari":  &utls.HelloSafari_Auto,
	"edge":    &utls.HelloEdge_Auto,
	"random":  &utls.HelloRandomized,
}

// clientUTLS uses refraction-networking/utls to produce a browser-like TLS
// ClientHello.
// Copied from connector/dial.go performUTLSHandshake.
func clientUTLS(ctx context.Context, conn net.Conn, opts ClientOpts) (net.Conn, *envelope.TLSSnapshot, error) {
	profile := strings.ToLower(strings.TrimSpace(opts.UTLSProfile))
	helloID, ok := utlsProfileIDs[profile]
	if !ok {
		return nil, nil, fmt.Errorf("tlslayer: unsupported uTLS profile %q", opts.UTLSProfile)
	}

	base := opts.TLSConfig.Clone()
	ucfg := &utls.Config{
		ServerName:         base.ServerName,
		InsecureSkipVerify: base.InsecureSkipVerify, //nolint:gosec // proxy requires MITM
		RootCAs:            base.RootCAs,
		MinVersion:         tls.VersionTLS12,
	}
	if opts.InsecureSkipVerify {
		ucfg.InsecureSkipVerify = true //nolint:gosec // proxy requires MITM
	}
	if opts.ClientCert != nil {
		ucfg.Certificates = []utls.Certificate{{
			Certificate:                 opts.ClientCert.Certificate,
			PrivateKey:                  opts.ClientCert.PrivateKey,
			OCSPStaple:                  opts.ClientCert.OCSPStaple,
			SignedCertificateTimestamps: opts.ClientCert.SignedCertificateTimestamps,
			Leaf:                        opts.ClientCert.Leaf,
		}}
	}

	slog.Debug("tlslayer: uTLS client handshake starting",
		"server", ucfg.ServerName,
		"profile", profile,
		"insecure_skip_verify", ucfg.InsecureSkipVerify,
		"alpn_offer", opts.OfferALPN,
	)

	uConn := utls.UClient(conn, ucfg, *helloID)

	// Replace ALPN extension after BuildHandshakeState if the caller
	// requested a specific ALPN list. This preserves the rest of the browser
	// fingerprint while restricting ALPN.
	if len(opts.OfferALPN) > 0 {
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, nil, fmt.Errorf("tlslayer: uTLS build handshake state: %w", err)
		}
		replaced := false
		for _, ext := range uConn.Extensions {
			if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
				alpnExt.AlpnProtocols = append([]string(nil), opts.OfferALPN...)
				replaced = true
				break
			}
		}
		if !replaced {
			// Browser profile has no ALPN extension; append one so the
			// caller's OfferALPN is actually offered.
			uConn.Extensions = append(uConn.Extensions, &utls.ALPNExtension{
				AlpnProtocols: append([]string(nil), opts.OfferALPN...),
			})
		}
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("tlslayer: uTLS handshake with %s (profile=%s): %w", ucfg.ServerName, profile, err)
	}

	state := uConn.ConnectionState()
	snap := snapshotFromTLSState(state)

	slog.Debug("tlslayer: uTLS client handshake complete",
		"server", ucfg.ServerName,
		"profile", profile,
		"alpn", snap.ALPN,
	)

	return uConn, snap, nil
}

// snapshotFromState builds a TLSSnapshot from a crypto/tls ConnectionState.
func snapshotFromState(state tls.ConnectionState) *envelope.TLSSnapshot {
	snap := &envelope.TLSSnapshot{
		SNI:         state.ServerName,
		ALPN:        state.NegotiatedProtocol,
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
	}
	if len(state.PeerCertificates) > 0 {
		snap.PeerCertificate = state.PeerCertificates[0]
	}
	return snap
}

// snapshotFromTLSState builds a TLSSnapshot from a utls ConnectionState
// (which is structurally identical to crypto/tls.ConnectionState).
func snapshotFromTLSState(state utls.ConnectionState) *envelope.TLSSnapshot {
	snap := &envelope.TLSSnapshot{
		SNI:         state.ServerName,
		ALPN:        state.NegotiatedProtocol,
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
	}
	if len(state.PeerCertificates) > 0 {
		snap.PeerCertificate = state.PeerCertificates[0]
	}
	return snap
}

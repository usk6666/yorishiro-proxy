package tlslayer

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// Server performs a server-side TLS handshake on plain, presenting the MITM
// certificate from cfg. It returns the TLS-wrapped connection and a
// TLSSnapshot capturing the negotiated parameters.
//
// cfg must have at least one certificate configured (typically a dynamically
// issued MITM certificate from the cert package).
func Server(ctx context.Context, plain net.Conn, cfg *tls.Config) (net.Conn, *envelope.TLSSnapshot, error) {
	tlsConn := tls.Server(plain, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("tlslayer: server handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	snap := &envelope.TLSSnapshot{
		SNI:         state.ServerName,
		ALPN:        state.NegotiatedProtocol,
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
	}

	// Capture peer (client) certificate if presented (mTLS).
	if len(state.PeerCertificates) > 0 {
		snap.PeerCertificate = state.PeerCertificates[0]
	}

	slog.Debug("tlslayer: server handshake complete",
		"sni", snap.SNI,
		"alpn", snap.ALPN,
		"version", snap.Version,
		"cipher", snap.CipherSuite,
	)

	return tlsConn, snap, nil
}

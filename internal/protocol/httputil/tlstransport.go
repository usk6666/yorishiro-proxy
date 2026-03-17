package httputil

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// TLSTransport abstracts TLS connection establishment to upstream servers.
// Implementations may use the standard crypto/tls library or uTLS for
// browser-like TLS ClientHello fingerprinting.
type TLSTransport interface {
	// TLSConnect wraps an existing net.Conn with a TLS client connection and
	// performs the handshake. The serverName is used for SNI. The returned
	// connection is ready for application data exchange.
	//
	// The returned NegotiatedProtocol indicates the ALPN result (e.g., "h2",
	// "http/1.1", or "" if ALPN was not negotiated).
	TLSConnect(ctx context.Context, conn net.Conn, serverName string) (net.Conn, string, error)
}

// BrowserProfile selects which browser's TLS ClientHello to mimic when using
// uTLS. The zero value is invalid; use one of the defined constants.
type BrowserProfile int

const (
	// ProfileChrome mimics a Chrome browser TLS fingerprint.
	ProfileChrome BrowserProfile = iota + 1
	// ProfileFirefox mimics a Firefox browser TLS fingerprint.
	ProfileFirefox
	// ProfileSafari mimics a Safari browser TLS fingerprint.
	ProfileSafari
	// ProfileEdge mimics an Edge browser TLS fingerprint.
	ProfileEdge
	// ProfileRandom selects a random browser fingerprint per connection.
	ProfileRandom
)

// browserProfileNames maps BrowserProfile values to their string representations.
var browserProfileNames = map[BrowserProfile]string{
	ProfileChrome:  "chrome",
	ProfileFirefox: "firefox",
	ProfileSafari:  "safari",
	ProfileEdge:    "edge",
	ProfileRandom:  "random",
}

// String returns the lowercase name of the browser profile.
func (p BrowserProfile) String() string {
	if name, ok := browserProfileNames[p]; ok {
		return name
	}
	return fmt.Sprintf("BrowserProfile(%d)", int(p))
}

// ParseBrowserProfile parses a browser profile name (case-insensitive) into
// a BrowserProfile value. Returns an error for unrecognized names.
func ParseBrowserProfile(name string) (BrowserProfile, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome":
		return ProfileChrome, nil
	case "firefox":
		return ProfileFirefox, nil
	case "safari":
		return ProfileSafari, nil
	case "edge":
		return ProfileEdge, nil
	case "random":
		return ProfileRandom, nil
	default:
		return 0, fmt.Errorf("unknown browser profile: %q", name)
	}
}

// utlsClientHelloIDs maps BrowserProfile to the corresponding uTLS ClientHelloID.
var utlsClientHelloIDs = map[BrowserProfile]*utls.ClientHelloID{
	ProfileChrome:  &utls.HelloChrome_Auto,
	ProfileFirefox: &utls.HelloFirefox_Auto,
	ProfileSafari:  &utls.HelloSafari_Auto,
	ProfileEdge:    &utls.HelloEdge_Auto,
	ProfileRandom:  &utls.HelloRandomized,
}

// StandardTransport uses the standard crypto/tls library for TLS connections.
// This produces a Go-native TLS fingerprint.
type StandardTransport struct {
	// InsecureSkipVerify disables server certificate verification.
	// This is required for MITM proxy use cases.
	InsecureSkipVerify bool

	// HostTLS provides per-host TLS configuration (mTLS, custom CA, verification).
	// When set, serverName-based lookup is performed to apply host-specific settings.
	HostTLS *HostTLSRegistry

	// NextProtos specifies the ALPN protocols to offer during the TLS handshake.
	// When nil, defaults to ["h2", "http/1.1"].
	NextProtos []string
}

// TLSConnect establishes a TLS connection using the standard crypto/tls library.
// When HostTLS is configured, per-host settings (client certificates, CA bundles,
// verification) are applied based on the serverName.
func (t *StandardTransport) TLSConnect(ctx context.Context, conn net.Conn, serverName string) (net.Conn, string, error) {
	nextProtos := t.NextProtos
	if nextProtos == nil {
		nextProtos = []string{"h2", "http/1.1"}
	}
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: t.InsecureSkipVerify, //nolint:gosec // proxy requires MITM
		NextProtos:         append([]string(nil), nextProtos...),
		MinVersion:         tls.VersionTLS12,
	}

	if t.HostTLS != nil {
		if err := t.HostTLS.ApplyToTLSConfig(tlsConfig, serverName, t.InsecureSkipVerify); err != nil {
			return nil, "", fmt.Errorf("host TLS config for %s: %w", serverName, err)
		}
	}

	slog.Debug("upstream TLS handshake starting", "server", serverName, "transport", "standard",
		"insecure_skip_verify", tlsConfig.InsecureSkipVerify)
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, "", fmt.Errorf("standard TLS handshake with %s: %w", serverName, err)
	}

	state := tlsConn.ConnectionState()
	proto := state.NegotiatedProtocol
	slog.Debug("upstream TLS handshake complete", "server", serverName, "transport", "standard",
		"tls_version", tlsVersionName(state.Version), "alpn", proto)
	return tlsConn, proto, nil
}

// UTLSTransport uses the uTLS library to mimic a browser's TLS ClientHello
// fingerprint, evading JA3/JA4-based bot detection.
type UTLSTransport struct {
	// Profile selects which browser fingerprint to mimic.
	// Defaults to ProfileChrome if zero.
	Profile BrowserProfile

	// InsecureSkipVerify disables server certificate verification.
	InsecureSkipVerify bool

	// HostTLS provides per-host TLS configuration (mTLS, custom CA, verification).
	// When set, serverName-based lookup is performed to apply host-specific settings.
	// Note: uTLS supports client certificates and InsecureSkipVerify but custom
	// RootCAs are applied through the utls.Config (which supports them).
	HostTLS *HostTLSRegistry
}

// TLSConnect establishes a TLS connection using uTLS with the configured
// browser profile. When HostTLS is configured, per-host settings (client
// certificates, CA bundles, verification) are applied based on the serverName.
func (t *UTLSTransport) TLSConnect(ctx context.Context, conn net.Conn, serverName string) (net.Conn, string, error) {
	profile := t.Profile
	if profile == 0 {
		profile = ProfileChrome
	}

	helloID, ok := utlsClientHelloIDs[profile]
	if !ok {
		return nil, "", fmt.Errorf("unsupported browser profile: %s", profile)
	}

	tlsConfig := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: t.InsecureSkipVerify, //nolint:gosec // proxy requires MITM
		MinVersion:         tls.VersionTLS12,
	}

	// Apply per-host TLS configuration if registry is set.
	if t.HostTLS != nil {
		if err := t.applyHostTLS(tlsConfig, serverName); err != nil {
			return nil, "", fmt.Errorf("host TLS config for %s: %w", serverName, err)
		}
	}

	slog.Debug("upstream TLS handshake starting", "server", serverName, "transport", "utls",
		"profile", profile.String(), "insecure_skip_verify", tlsConfig.InsecureSkipVerify)
	utlsConn := utls.UClient(conn, tlsConfig, *helloID)
	if err := utlsConn.HandshakeContext(ctx); err != nil {
		return nil, "", fmt.Errorf("uTLS handshake with %s (profile=%s): %w", serverName, profile, err)
	}

	uState := utlsConn.ConnectionState()
	proto := uState.NegotiatedProtocol
	slog.Debug("upstream TLS handshake complete", "server", serverName, "transport", "utls",
		"profile", profile.String(), "tls_version", tlsVersionName(uState.Version), "alpn", proto)
	return utlsConn, proto, nil
}

// applyHostTLS applies per-host TLS settings from the registry to a utls.Config.
// uTLS uses its own tls types that mirror crypto/tls, so we convert as needed.
func (t *UTLSTransport) applyHostTLS(cfg *utls.Config, serverName string) error {
	hostCfg := t.HostTLS.Lookup(serverName)
	if hostCfg == nil {
		return nil
	}

	// Apply client certificate. uTLS Certificate type is compatible with crypto/tls.
	cert, err := hostCfg.LoadClientCert()
	if err != nil {
		return err
	}
	if cert != nil {
		// Convert crypto/tls.Certificate to utls.Certificate.
		utlsCert := utls.Certificate{
			Certificate:                 cert.Certificate,
			PrivateKey:                  cert.PrivateKey,
			OCSPStaple:                  cert.OCSPStaple,
			SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
			Leaf:                        cert.Leaf,
		}
		cfg.Certificates = []utls.Certificate{utlsCert}
	}

	// Apply TLS verification setting.
	if hostCfg.TLSVerify != nil {
		cfg.InsecureSkipVerify = !*hostCfg.TLSVerify //nolint:gosec // per-host TLS verify control
	} else {
		cfg.InsecureSkipVerify = t.InsecureSkipVerify //nolint:gosec // proxy requires MITM
	}

	// Apply custom CA bundle.
	pool, err := hostCfg.LoadCABundle()
	if err != nil {
		return err
	}
	if pool != nil {
		cfg.RootCAs = pool
	}

	return nil
}

// tlsVersionName converts a TLS version constant to a human-readable string.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

// TLSConnectionState extracts the TLS connection state from a net.Conn.
// It handles both standard *tls.Conn and *utls.UConn connections.
// Returns the state and true if the connection has TLS state,
// or a zero value and false otherwise.
func TLSConnectionState(conn net.Conn) (tls.ConnectionState, bool) {
	// Check for our adapter first, which already exposes the standard type.
	if adapter, ok := conn.(*tlsConnAdapter); ok {
		return adapter.ConnectionState(), true
	}
	switch tc := conn.(type) {
	case *tls.Conn:
		return tc.ConnectionState(), true
	case *utls.UConn:
		return convertUTLSState(tc.ConnectionState()), true
	default:
		return tls.ConnectionState{}, false
	}
}

// convertUTLSState converts a utls.ConnectionState to the standard
// tls.ConnectionState type.
func convertUTLSState(uState utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:            uState.Version,
		HandshakeComplete:  uState.HandshakeComplete,
		DidResume:          uState.DidResume,
		CipherSuite:        uState.CipherSuite,
		NegotiatedProtocol: uState.NegotiatedProtocol,
		ServerName:         uState.ServerName,
		PeerCertificates:   uState.PeerCertificates,
		VerifiedChains:     uState.VerifiedChains,
		OCSPResponse:       uState.OCSPResponse,
		TLSUnique:          uState.TLSUnique,
	}
}

// tlsConnAdapter wraps a net.Conn (typically *utls.UConn) and implements
// the ConnectionState() tls.ConnectionState method that Go's http.Transport
// expects. Without this adapter, http.Transport cannot detect that the
// connection is TLS and leaves resp.TLS nil.
type tlsConnAdapter struct {
	net.Conn
	state tls.ConnectionState
}

// ConnectionState returns the TLS connection state. This method signature
// matches what http.Transport checks via interface assertion to populate
// resp.TLS.
func (c *tlsConnAdapter) ConnectionState() tls.ConnectionState {
	return c.state
}

// WrapTLSConn wraps a TLS connection (standard or uTLS) with an adapter that
// exposes ConnectionState() tls.ConnectionState. This ensures http.Transport
// can detect TLS and populate resp.TLS.
// If the connection is already a *tls.Conn, it is returned as-is since
// http.Transport already handles that type natively.
func WrapTLSConn(conn net.Conn) net.Conn {
	switch tc := conn.(type) {
	case *tls.Conn:
		// Standard TLS conn already works with http.Transport.
		return tc
	case *utls.UConn:
		return &tlsConnAdapter{
			Conn:  tc,
			state: convertUTLSState(tc.ConnectionState()),
		}
	default:
		return conn
	}
}

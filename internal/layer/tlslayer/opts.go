package tlslayer

import "crypto/tls"

// ClientOpts configures a Client TLS handshake toward an upstream server.
type ClientOpts struct {
	// TLSConfig is the base TLS configuration. It is cloned before use.
	// ServerName must be set for certificate verification.
	TLSConfig *tls.Config

	// InsecureSkipVerify disables server certificate verification.
	// When true, it overrides TLSConfig.InsecureSkipVerify.
	InsecureSkipVerify bool

	// UTLSProfile selects a uTLS browser fingerprint ("chrome", "firefox",
	// "safari", "edge", "random"). Empty string selects the standard
	// crypto/tls library.
	UTLSProfile string

	// ClientCert, if non-nil, is used as the mTLS client certificate.
	// It overrides TLSConfig.Certificates.
	ClientCert *tls.Certificate

	// OfferALPN is the list of ALPN protocols to offer during the TLS
	// handshake (e.g. []string{"h2", "http/1.1"}). When empty, the TLS
	// stack default is used. For uTLS, when empty, the browser profile's
	// default ALPN extension is left untouched.
	OfferALPN []string
}

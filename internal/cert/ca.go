package cert

import (
	"crypto/tls"
	"crypto/x509"
)

// CA manages the root certificate authority for TLS interception.
type CA struct {
	cert    *x509.Certificate
	privKey interface{}
}

// NewCA creates a new CA instance. If no existing CA is provided,
// a self-signed root CA will be generated.
func NewCA() (*CA, error) {
	// TODO: Generate or load CA certificate
	return &CA{}, nil
}

// IssueServerCert generates a TLS certificate for the given hostname,
// signed by this CA. Used for MITM TLS interception.
func (ca *CA) IssueServerCert(hostname string) (*tls.Certificate, error) {
	// TODO: Generate server certificate signed by CA
	_ = hostname
	return nil, nil
}

// RootCert returns the CA's root certificate.
func (ca *CA) RootCert() *x509.Certificate {
	return ca.cert
}

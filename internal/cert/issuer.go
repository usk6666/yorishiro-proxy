package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// certValidity is the validity period for dynamically issued server certificates.
const certValidity = 24 * time.Hour

// cachedCert holds a TLS certificate and its expiration time for cache eviction.
type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// Issuer dynamically generates TLS server certificates signed by a CA.
// It caches certificates per hostname using sync.Map and coalesces concurrent
// requests for the same hostname using singleflight.Group.
type Issuer struct {
	ca    *CA
	cache sync.Map         // hostname -> *cachedCert
	group singleflight.Group
}

// NewIssuer creates a new Issuer that signs server certificates with the given CA.
func NewIssuer(ca *CA) *Issuer {
	return &Issuer{
		ca: ca,
	}
}

// GetCertificate returns a TLS certificate for the given hostname.
// If a valid cached certificate exists, it is returned immediately.
// Otherwise, a new certificate is generated, cached, and returned.
// Concurrent requests for the same hostname are coalesced via singleflight.
func (iss *Issuer) GetCertificate(hostname string) (*tls.Certificate, error) {
	// Check cache first.
	if val, ok := iss.cache.Load(hostname); ok {
		cc := val.(*cachedCert)
		if time.Now().Before(cc.expiresAt) {
			return cc.cert, nil
		}
		// Expired entry; delete and regenerate.
		iss.cache.Delete(hostname)
	}

	// Use singleflight to coalesce concurrent requests for the same hostname.
	result, err, _ := iss.group.Do(hostname, func() (interface{}, error) {
		// Double-check cache after acquiring the singleflight slot,
		// in case another goroutine populated it while we were waiting.
		if val, ok := iss.cache.Load(hostname); ok {
			cc := val.(*cachedCert)
			if time.Now().Before(cc.expiresAt) {
				return cc.cert, nil
			}
			iss.cache.Delete(hostname)
		}

		cert, expiresAt, err := iss.generate(hostname)
		if err != nil {
			return nil, err
		}

		cc := &cachedCert{
			cert:      cert,
			expiresAt: expiresAt,
		}
		iss.cache.Store(hostname, cc)

		return cert, nil
	})
	if err != nil {
		return nil, err
	}

	return result.(*tls.Certificate), nil
}

// GetCertificateForClientHello returns a TLS certificate for the hostname
// specified in the TLS ClientHello message. It implements the
// tls.Config.GetCertificate callback signature.
func (iss *Issuer) GetCertificateForClientHello(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return iss.GetCertificate(hello.ServerName)
}

// generate creates a new ECDSA P-256 server certificate for the given hostname,
// signed by the CA. It returns the TLS certificate and its expiration time.
func (iss *Issuer) generate(hostname string) (*tls.Certificate, time.Time, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate server key for %s: %w", hostname, err)
	}

	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("generate serial number for %s: %w", hostname, err)
	}

	now := time.Now()
	notAfter := now.Add(certValidity)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: now,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	// Set SAN based on whether hostname is an IP address or DNS name.
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, iss.ca.cert, &privKey.PublicKey, iss.ca.privKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("create server certificate for %s: %w", hostname, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	return tlsCert, notAfter, nil
}

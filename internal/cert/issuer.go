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
// It caches certificates per hostname using a size-limited LRU cache and
// coalesces concurrent requests for the same hostname using singleflight.Group.
type Issuer struct {
	ca    *CA
	cache *lruCache
	group singleflight.Group
}

// IssuerOption configures an Issuer.
type IssuerOption func(*Issuer)

// WithMaxCacheSize sets the maximum number of certificates to cache.
// If size is <= 0, defaultMaxCacheSize is used.
func WithMaxCacheSize(size int) IssuerOption {
	return func(iss *Issuer) {
		iss.cache = newLRUCache(size)
	}
}

// NewIssuer creates a new Issuer that signs server certificates with the given CA.
// Options can be provided to configure cache behavior.
func NewIssuer(ca *CA, opts ...IssuerOption) *Issuer {
	iss := &Issuer{
		ca:    ca,
		cache: newLRUCache(defaultMaxCacheSize),
	}
	for _, opt := range opts {
		opt(iss)
	}
	return iss
}

// GetCertificate returns a TLS certificate for the given hostname.
// If a valid cached certificate exists, it is returned immediately.
// Otherwise, a new certificate is generated, cached, and returned.
// Concurrent requests for the same hostname are coalesced via singleflight.
func (iss *Issuer) GetCertificate(hostname string) (*tls.Certificate, error) {
	// Check cache first.
	if cc, ok := iss.cache.Get(hostname); ok {
		return cc.cert, nil
	}

	// Use singleflight to coalesce concurrent requests for the same hostname.
	result, err, _ := iss.group.Do(hostname, func() (interface{}, error) {
		// Double-check cache after acquiring the singleflight slot,
		// in case another goroutine populated it while we were waiting.
		if cc, ok := iss.cache.Get(hostname); ok {
			return cc.cert, nil
		}

		cert, expiresAt, err := iss.generate(hostname)
		if err != nil {
			return nil, err
		}

		cc := &cachedCert{
			cert:      cert,
			expiresAt: expiresAt,
		}
		iss.cache.Put(hostname, cc)

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

// CacheLen returns the number of certificates currently in the cache.
// This is primarily useful for diagnostics and testing.
func (iss *Issuer) CacheLen() int {
	return iss.cache.Len()
}

// ClearCache removes all cached certificates. This should be called after
// the CA is regenerated to ensure subsequent TLS handshakes use the new CA.
func (iss *Issuer) ClearCache() {
	iss.cache.Clear()
}

// generate creates a new ECDSA P-256 server certificate for the given hostname,
// signed by the CA. It returns the TLS certificate and its expiration time.
func (iss *Issuer) generate(hostname string) (*tls.Certificate, time.Time, error) {
	// Take a consistent snapshot of the CA signing pair under read lock
	// to avoid data races during CA regeneration.
	caCert, caKey := iss.ca.SigningPair()
	if caCert == nil || caKey == nil {
		return nil, time.Time{}, fmt.Errorf("CA not initialized for signing %s", hostname)
	}

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

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("create server certificate for %s: %w", hostname, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}

	return tlsCert, notAfter, nil
}

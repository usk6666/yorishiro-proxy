package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"net"
	"strings"
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

	// serverCfgs caches *tls.Config values keyed by (hostname, alpnOffers)
	// so that crypto/tls's lazily-generated session ticket key is reused
	// across MITM connections to the same host. A fresh tls.Config per
	// connection generates a new random ticket key on first use, which
	// causes browsers to reject tickets from prior connections and (on
	// TLS 1.3 + h2) emit certificate_unknown alerts during the resulting
	// fallback handshake (USK-795). Each cached config installs a
	// GetCertificate callback so the live cert from the LRU cache is
	// always presented; the config itself never holds a stale cert.
	//
	// The cache is a bounded LRU sized identically to the cert cache so a
	// long-lived proxy seeing many distinct CONNECT targets cannot grow
	// memory without bound (CWE-770). Hostname keys are lowercased to
	// match crypto/tls's SNI normalisation and the cert LRU's key space,
	// so mixed-case CONNECT targets converge on a single cache entry.
	serverCfgs *configLRUCache
}

// serverCfgKey identifies a cached MITM server *tls.Config. Different ALPN
// offer lists MUST NOT share a Config — crypto/tls reads NextProtos at
// handshake time, and order matters (server picks the first NextProtos entry
// the client also offers). The hostname component is always lowercase;
// callers must lowercase before constructing this key. The alpnOffers
// component is the offer slice joined by NUL ("\x00"), an octet that cannot
// appear in a valid ALPN protocol id (RFC 7301), so distinct slices map to
// distinct strings unambiguously.
type serverCfgKey struct {
	hostname   string
	alpnOffers string
}

// IssuerOption configures an Issuer.
type IssuerOption func(*Issuer)

// WithMaxCacheSize sets the maximum number of certificates to cache.
// If size is <= 0, defaultMaxCacheSize is used. The same bound is applied to
// the MITM server *tls.Config cache so the two caches share an eviction
// budget and the Config cache cannot grow without bound (CWE-770).
func WithMaxCacheSize(size int) IssuerOption {
	return func(iss *Issuer) {
		iss.cache = newLRUCache(size)
		iss.serverCfgs = newConfigLRUCache(size)
	}
}

// NewIssuer creates a new Issuer that signs server certificates with the given CA.
// Options can be provided to configure cache behavior.
func NewIssuer(ca *CA, opts ...IssuerOption) *Issuer {
	iss := &Issuer{
		ca:         ca,
		cache:      newLRUCache(defaultMaxCacheSize),
		serverCfgs: newConfigLRUCache(defaultMaxCacheSize),
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
//
// Hostname lookups are case-insensitive (lowercased before keying the cache
// and singleflight) so mixed-case CONNECT targets converge on a single cache
// entry; this matches crypto/tls's SNI normalisation and prevents cache
// growth from per-casing entries (CWE-770).
func (iss *Issuer) GetCertificate(hostname string) (*tls.Certificate, error) {
	host := strings.ToLower(hostname)

	// Check cache first.
	if cc, ok := iss.cache.Get(host); ok {
		slog.Debug("certificate cache hit", "hostname", host)
		return cc.cert, nil
	}

	// Use singleflight to coalesce concurrent requests for the same hostname.
	result, err, shared := iss.group.Do(host, func() (interface{}, error) {
		// Double-check cache after acquiring the singleflight slot,
		// in case another goroutine populated it while we were waiting.
		if cc, ok := iss.cache.Get(host); ok {
			slog.Debug("certificate cache hit after singleflight", "hostname", host)
			return cc.cert, nil
		}

		slog.Debug("certificate cache miss, generating", "hostname", host)
		generateStart := time.Now()
		cert, expiresAt, err := iss.generate(host)
		if err != nil {
			return nil, err
		}

		cc := &cachedCert{
			cert:      cert,
			expiresAt: expiresAt,
		}
		iss.cache.Put(host, cc)

		slog.Debug("certificate issued", "hostname", host,
			"duration", time.Since(generateStart))
		return cert, nil
	})
	if shared {
		slog.Debug("certificate obtained via singleflight coalescing", "hostname", host)
	}
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
//
// The cached MITM server *tls.Config values (built by MITMServerConfig) are
// also evicted, since their session-ticket-encryption keys are bound to the
// CA-issued certificate identity; reusing them after a CA regen would let a
// new client resume a session sealed under the prior CA chain.
func (iss *Issuer) ClearCache() {
	iss.cache.Clear()
	iss.serverCfgs.Clear()
}

// MITMServerConfig returns a *tls.Config suitable for performing a server-side
// MITM TLS handshake against a client connecting to hostname. The same config
// is returned for every call with the same (hostname, alpnOffers) pair — this
// is critical so that crypto/tls's lazily-generated session ticket encryption
// key is stable across connections, allowing browsers to resume sessions
// instead of falling back to a full handshake on every connection.
//
// alpnOffers is the ordered list of ALPN protocol ids the proxy will advertise
// to the client (e.g. {"h2", "http/1.1"}, {"http/1.1"}, or nil for no ALPN).
// Different offer lists MUST get different Configs: crypto/tls reads NextProtos
// at handshake time, and the order is observable — the server picks the first
// NextProtos entry the client also offered. A defensive copy is taken so
// later mutation of the caller's slice cannot perturb the cached Config.
//
// Hostname keys are lowercased so mixed-case CONNECT targets converge on a
// single cache entry; the cache is a bounded LRU sharing the cert cache's
// size (CWE-770).
//
// The returned Config installs a GetCertificate callback that always fetches
// the live certificate from the Issuer's LRU cache. Callers must not mutate
// the returned Config; treat it as a shared, read-only handshake template.
//
// Thread-safe.
func (iss *Issuer) MITMServerConfig(hostname string, alpnOffers []string) *tls.Config {
	host := strings.ToLower(hostname)
	// NUL is not a valid ALPN protocol id octet (RFC 7301), so joining on
	// "\x00" gives a unique, order-preserving key string for any slice.
	key := serverCfgKey{hostname: host, alpnOffers: strings.Join(alpnOffers, "\x00")}

	cfg := &tls.Config{
		// MinVersion floors negotiation at TLS 1.2 to match the rest of
		// the proxy's TLS surface (internal/layer/tlslayer/client.go,
		// internal/connector/transport/tlstransport.go). This is the
		// proxy-as-server path presenting the MITM cert to the browser;
		// the upstream-dial MITM exception that allows weak TLS does NOT
		// apply here. All real browsers support TLS 1.2+ (CWE-757).
		MinVersion: tls.VersionTLS12,

		// GetCertificate is preferred over Certificates so the served cert
		// always reflects the current entry in iss.cache: when an entry
		// expires (LRU eviction or cert validity TTL), the next handshake
		// fetches a freshly issued cert without requiring this Config to
		// be rebuilt. The Config itself remains stable so its internally
		// managed session ticket key persists across connections.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Use the hostname captured in the closure rather than the
			// SNI from the ClientHelloInfo: BuildConnectionStack already
			// resolved the cert hostname from the CONNECT target, and we
			// must not let a divergent SNI silently route to a different
			// host's cert. host is already lowercased.
			return iss.GetCertificate(host)
		},
	}
	if len(alpnOffers) > 0 {
		// Defensive copy: tls.Config retains a reference to the slice and
		// the caller may reuse or mutate the source after this returns.
		cfg.NextProtos = append([]string(nil), alpnOffers...)
	}

	// LoadOrStore: concurrent first-time callers converge on a single
	// Config instance; the loser's freshly built Config is dropped.
	actual, _ := iss.serverCfgs.LoadOrStore(key, cfg)
	return actual
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

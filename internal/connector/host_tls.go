package connector

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// ResolvedHostTLS holds the per-host TLS overrides resolved by HostTLSResolver.
// Nil fields mean "use global default from BuildConfig".
type ResolvedHostTLS struct {
	// InsecureSkipVerify overrides the global InsecureSkipVerify when non-nil.
	InsecureSkipVerify *bool

	// ClientCert overrides the global mTLS client certificate when non-nil.
	ClientCert *tls.Certificate

	// RootCAs overrides the system CA pool when non-nil.
	RootCAs *x509.CertPool
}

// hostTLSEntry wraps a config.HostTLSEntry with lazy-loaded, cached TLS objects.
type hostTLSEntry struct {
	cfg *config.HostTLSEntry

	certOnce sync.Once
	cert     *tls.Certificate
	certErr  error

	caOnce sync.Once
	caPool *x509.CertPool
	caErr  error
}

// loadCert lazily loads and caches the client certificate.
func (e *hostTLSEntry) loadCert() (*tls.Certificate, error) {
	e.certOnce.Do(func() {
		if e.cfg.ClientCertPath == "" || e.cfg.ClientKeyPath == "" {
			return
		}
		cert, err := tls.LoadX509KeyPair(e.cfg.ClientCertPath, e.cfg.ClientKeyPath)
		if err != nil {
			e.certErr = fmt.Errorf("host_tls: load client cert %s: %w", e.cfg.ClientCertPath, err)
			return
		}
		e.cert = &cert
	})
	return e.cert, e.certErr
}

// loadCA lazily loads and caches the CA bundle.
func (e *hostTLSEntry) loadCA() (*x509.CertPool, error) {
	e.caOnce.Do(func() {
		if e.cfg.CABundlePath == "" {
			return
		}
		pem, err := os.ReadFile(e.cfg.CABundlePath)
		if err != nil {
			e.caErr = fmt.Errorf("host_tls: read CA bundle %s: %w", e.cfg.CABundlePath, err)
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			e.caErr = fmt.Errorf("host_tls: no valid certificates in CA bundle %s", e.cfg.CABundlePath)
			return
		}
		e.caPool = pool
	})
	return e.caPool, e.caErr
}

// HostTLSResolver resolves per-host TLS configuration from a map of hostname
// patterns to HostTLSEntry. It supports exact match and wildcard patterns
// (e.g. "*.example.com"). Certificates and CA bundles are loaded lazily on
// first access and cached for the resolver's lifetime.
//
// HostTLSResolver is safe for concurrent use.
type HostTLSResolver struct {
	exact    map[string]*hostTLSEntry
	wildcard map[string]*hostTLSEntry // key = "example.com" for pattern "*.example.com"
}

// NewHostTLSResolver builds a resolver from the config HostTLS map.
// Returns nil if hostTLS is nil or empty (nil resolver is safe to call Resolve on).
func NewHostTLSResolver(hostTLS map[string]*config.HostTLSEntry) *HostTLSResolver {
	if len(hostTLS) == 0 {
		return nil
	}

	r := &HostTLSResolver{
		exact:    make(map[string]*hostTLSEntry),
		wildcard: make(map[string]*hostTLSEntry),
	}

	for pattern, cfg := range hostTLS {
		entry := &hostTLSEntry{cfg: cfg}
		if strings.HasPrefix(pattern, "*.") {
			// "*.example.com" → key "example.com"
			domain := pattern[2:]
			r.wildcard[strings.ToLower(domain)] = entry
		} else {
			r.exact[strings.ToLower(pattern)] = entry
		}
	}

	return r
}

// Resolve looks up per-host TLS overrides for the given target (host:port or host).
// Resolution order: exact hostname match > wildcard (*.domain) > nil (use global).
//
// Resolve is safe to call on a nil receiver (returns nil, nil).
func (r *HostTLSResolver) Resolve(target string) (*ResolvedHostTLS, error) {
	if r == nil {
		return nil, nil
	}

	host := extractHost(target)
	hostLower := strings.ToLower(host)

	entry := r.lookup(hostLower)
	if entry == nil {
		return nil, nil
	}

	result := &ResolvedHostTLS{
		InsecureSkipVerify: entry.cfg.TLSVerify,
	}
	// TLSVerify semantics: config "tls_verify: false" means InsecureSkipVerify=true
	// We need to invert: TLSVerify=false → InsecureSkipVerify=true
	if entry.cfg.TLSVerify != nil {
		inverted := !*entry.cfg.TLSVerify
		result.InsecureSkipVerify = &inverted
	}

	cert, err := entry.loadCert()
	if err != nil {
		return nil, err
	}
	result.ClientCert = cert

	caPool, err := entry.loadCA()
	if err != nil {
		return nil, err
	}
	result.RootCAs = caPool

	return result, nil
}

// lookup finds the best matching entry: exact > wildcard.
func (r *HostTLSResolver) lookup(hostLower string) *hostTLSEntry {
	// Exact match first.
	if entry, ok := r.exact[hostLower]; ok {
		return entry
	}

	// Wildcard: try each parent domain.
	// "sub.example.com" matches "*.example.com" (key "example.com").
	parts := strings.SplitN(hostLower, ".", 2)
	if len(parts) == 2 {
		if entry, ok := r.wildcard[parts[1]]; ok {
			return entry
		}
	}

	return nil
}

// extractHost strips the port from a host:port target, or returns the target
// as-is if no port is present.
func extractHost(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	return host
}

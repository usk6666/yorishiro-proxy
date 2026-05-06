package transport

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// HostTLSConfig holds per-host TLS configuration for upstream connections.
// It supports mTLS client certificates, custom CA bundles, and per-host
// TLS verification control.
type HostTLSConfig struct {
	// ClientCertPath is the path to the PEM-encoded client certificate file.
	ClientCertPath string `json:"client_cert,omitempty"`

	// ClientKeyPath is the path to the PEM-encoded client private key file.
	ClientKeyPath string `json:"client_key,omitempty"`

	// TLSVerify controls TLS certificate verification for this host.
	// nil = use global setting, false = skip verification, true = enforce verification.
	TLSVerify *bool `json:"tls_verify,omitempty"`

	// CABundlePath is the path to a PEM-encoded CA bundle file for custom
	// root certificates. Multiple certificates can be concatenated.
	CABundlePath string `json:"ca_bundle,omitempty"`

	// certOnce guards lazy loading of the client certificate. The parsed
	// result is cached after first load to avoid repeated disk I/O and
	// TOCTOU issues.
	certOnce sync.Once
	certVal  *tls.Certificate
	certErr  error

	// caOnce guards a single read of the CA bundle PEM file. One read
	// populates both caVal (parsed *x509.CertPool used by LoadCABundle)
	// and caHashVal (stable hex digest used by CABundleHash for cache
	// keying), so the file is read at most once per HostTLSConfig
	// instance and the parsed pool can never disagree with the hash.
	caOnce    sync.Once
	caVal     *x509.CertPool
	caHashVal string
	caErr     error
}

// Validate checks that the HostTLSConfig fields are consistent.
// It returns an error if only one of client_cert/client_key is set,
// or if referenced files do not exist.
func (c *HostTLSConfig) Validate() error {
	hasCert := c.ClientCertPath != ""
	hasKey := c.ClientKeyPath != ""
	if hasCert != hasKey {
		if hasCert {
			return fmt.Errorf("client_cert is set but client_key is missing")
		}
		return fmt.Errorf("client_key is set but client_cert is missing")
	}
	if hasCert {
		if _, err := os.Stat(c.ClientCertPath); err != nil {
			return fmt.Errorf("client_cert file %q: not accessible", filepath.Base(c.ClientCertPath))
		}
		if _, err := os.Stat(c.ClientKeyPath); err != nil {
			return fmt.Errorf("client_key file %q: not accessible", filepath.Base(c.ClientKeyPath))
		}
	}
	if c.CABundlePath != "" {
		if _, err := os.Stat(c.CABundlePath); err != nil {
			return fmt.Errorf("ca_bundle file %q: not accessible", filepath.Base(c.CABundlePath))
		}
	}
	return nil
}

// LoadClientCert loads the client certificate and key from the configured paths.
// The result is cached after the first successful load.
// Returns nil, nil if no client certificate is configured.
func (c *HostTLSConfig) LoadClientCert() (*tls.Certificate, error) {
	if c.ClientCertPath == "" || c.ClientKeyPath == "" {
		return nil, nil
	}
	c.certOnce.Do(func() {
		cert, err := tls.LoadX509KeyPair(c.ClientCertPath, c.ClientKeyPath)
		if err != nil {
			c.certErr = fmt.Errorf("load client certificate: %w", err)
			return
		}
		c.certVal = &cert
	})
	return c.certVal, c.certErr
}

// loadCAOnce reads the CA bundle PEM file at most once and populates both
// the parsed *x509.CertPool and a stable hex digest of the raw PEM bytes
// from the same byte slice. A single sync.Once eliminates the inter-read
// TOCTOU window and halves cold-dial I/O compared with parsing the file
// twice (once for LoadCABundle, once for CABundleHash).
//
// No-op when CABundlePath is empty: caVal / caHashVal stay zero-valued
// and caErr stays nil. Both LoadCABundle and CABundleHash short-circuit
// before calling this for the empty-path case.
func (c *HostTLSConfig) loadCAOnce() {
	c.caOnce.Do(func() {
		data, err := os.ReadFile(c.CABundlePath)
		if err != nil {
			c.caErr = fmt.Errorf("read CA bundle: %w", err)
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			c.caErr = fmt.Errorf("CA bundle %q: no valid PEM certificates found", filepath.Base(c.CABundlePath))
			return
		}
		c.caVal = pool
		sum := sha256.Sum256(data)
		c.caHashVal = hex.EncodeToString(sum[:8])
	})
}

// LoadCABundle loads the custom CA bundle from the configured path.
// The result is cached after the first successful load.
// Returns nil if no CA bundle is configured.
func (c *HostTLSConfig) LoadCABundle() (*x509.CertPool, error) {
	if c.CABundlePath == "" {
		return nil, nil
	}
	c.loadCAOnce()
	return c.caVal, c.caErr
}

// CABundleHash returns a stable hex-encoded hash of the configured CA bundle
// file's PEM bytes. The hash is cached after the first successful read.
// Returns an empty string when no CA bundle is configured.
//
// The hash is suitable as a cache-key fragment so that replacing the CA
// bundle at runtime (via HostTLSRegistry.Set / SetGlobal swapping the
// HostTLSConfig pointer for a host) yields a different hash and forces
// downstream caches (e.g. the H2 connection pool) to invalidate.
func (c *HostTLSConfig) CABundleHash() (string, error) {
	if c.CABundlePath == "" {
		return "", nil
	}
	c.loadCAOnce()
	return c.caHashVal, c.caErr
}

// HostTLSRegistry manages per-host TLS configurations and a global default.
// It is safe for concurrent use.
type HostTLSRegistry struct {
	mu     sync.RWMutex
	global *HostTLSConfig
	hosts  map[string]*HostTLSConfig
}

// NewHostTLSRegistry creates a new empty registry.
func NewHostTLSRegistry() *HostTLSRegistry {
	return &HostTLSRegistry{
		hosts: make(map[string]*HostTLSConfig),
	}
}

// SetGlobal sets the global (default) TLS configuration applied when no
// host-specific config matches.
func (r *HostTLSRegistry) SetGlobal(cfg *HostTLSConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.global = cfg
}

// Global returns the global TLS configuration, or nil if not set.
func (r *HostTLSRegistry) Global() *HostTLSConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.global
}

// Set registers a TLS configuration for the given hostname.
// The hostname is stored lowercase for case-insensitive matching.
func (r *HostTLSRegistry) Set(hostname string, cfg *HostTLSConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts[strings.ToLower(hostname)] = cfg
}

// Remove removes the TLS configuration for the given hostname.
func (r *HostTLSRegistry) Remove(hostname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.hosts, strings.ToLower(hostname))
}

// Lookup finds the TLS configuration for the given serverName.
// It first checks for an exact match, then tries wildcard matches
// (e.g., "*.example.com" matches "api.example.com"), and finally
// falls back to the global configuration.
// Returns nil if no configuration matches.
func (r *HostTLSRegistry) Lookup(serverName string) *HostTLSConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()

	name := strings.ToLower(serverName)

	// Exact match.
	if cfg, ok := r.hosts[name]; ok {
		return cfg
	}

	// Wildcard match: check "*.domain.com" patterns.
	if idx := strings.IndexByte(name, '.'); idx >= 0 {
		wildcard := "*" + name[idx:]
		if cfg, ok := r.hosts[wildcard]; ok {
			return cfg
		}
	}

	// Fallback to global.
	return r.global
}

// Hosts returns a copy of all registered host-specific configurations.
func (r *HostTLSRegistry) Hosts() map[string]*HostTLSConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]*HostTLSConfig, len(r.hosts))
	for k, v := range r.hosts {
		result[k] = v
	}
	return result
}

// ApplyToTLSConfig modifies a tls.Config based on the HostTLSConfig for the
// given serverName. It sets client certificates, InsecureSkipVerify, and RootCAs
// as appropriate. The globalInsecure parameter provides the fallback value for
// InsecureSkipVerify when TLSVerify is nil.
func (r *HostTLSRegistry) ApplyToTLSConfig(tlsCfg *tls.Config, serverName string, globalInsecure bool) error {
	cfg := r.Lookup(serverName)
	if cfg == nil {
		slog.Debug("no per-host TLS config found", "server", serverName)
		return nil
	}

	slog.Debug("applying per-host TLS config", "server", serverName)

	// Apply client certificate.
	cert, err := cfg.LoadClientCert()
	if err != nil {
		return fmt.Errorf("host %s: %w", serverName, err)
	}
	if cert != nil {
		tlsCfg.Certificates = []tls.Certificate{*cert}
		slog.Debug("mTLS client certificate applied", "server", serverName)
	}

	// Apply TLS verification setting.
	if cfg.TLSVerify != nil {
		tlsCfg.InsecureSkipVerify = !*cfg.TLSVerify //nolint:gosec // per-host TLS verify control
		slog.Debug("per-host TLS verify override", "server", serverName,
			"tls_verify", *cfg.TLSVerify, "insecure_skip_verify", tlsCfg.InsecureSkipVerify)
	} else {
		tlsCfg.InsecureSkipVerify = globalInsecure //nolint:gosec // proxy requires MITM
	}

	// Apply custom CA bundle.
	pool, err := cfg.LoadCABundle()
	if err != nil {
		return fmt.Errorf("host %s: %w", serverName, err)
	}
	if pool != nil {
		tlsCfg.RootCAs = pool
		slog.Debug("custom CA bundle applied", "server", serverName)
	}

	return nil
}

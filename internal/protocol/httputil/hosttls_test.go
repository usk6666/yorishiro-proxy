package httputil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCertAndKey generates a self-signed certificate and key, writes them
// as PEM files, and returns the paths.
func writeTestCertAndKey(t *testing.T, dir, prefix string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: prefix + " test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPath = filepath.Join(dir, prefix+"-cert.pem")
	keyPath = filepath.Join(dir, prefix+"-key.pem")

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("encode key: %v", err)
	}

	return certPath, keyPath
}

// writeTestCABundle writes a PEM CA bundle file and returns the path.
func writeTestCABundle(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	path := filepath.Join(dir, "ca-bundle.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create CA bundle file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode CA cert: %v", err)
	}

	return path
}

func TestHostTLSConfig_Validate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertAndKey(t, dir, "test")
	caPath := writeTestCABundle(t, dir)

	tests := []struct {
		name    string
		cfg     HostTLSConfig
		wantErr bool
	}{
		{
			name: "empty config is valid",
			cfg:  HostTLSConfig{},
		},
		{
			name: "valid cert and key",
			cfg: HostTLSConfig{
				ClientCertPath: certPath,
				ClientKeyPath:  keyPath,
			},
		},
		{
			name: "cert without key",
			cfg: HostTLSConfig{
				ClientCertPath: certPath,
			},
			wantErr: true,
		},
		{
			name: "key without cert",
			cfg: HostTLSConfig{
				ClientKeyPath: keyPath,
			},
			wantErr: true,
		},
		{
			name: "nonexistent cert file",
			cfg: HostTLSConfig{
				ClientCertPath: "/nonexistent/cert.pem",
				ClientKeyPath:  keyPath,
			},
			wantErr: true,
		},
		{
			name: "nonexistent key file",
			cfg: HostTLSConfig{
				ClientCertPath: certPath,
				ClientKeyPath:  "/nonexistent/key.pem",
			},
			wantErr: true,
		},
		{
			name: "valid ca_bundle",
			cfg: HostTLSConfig{
				CABundlePath: caPath,
			},
		},
		{
			name: "nonexistent ca_bundle",
			cfg: HostTLSConfig{
				CABundlePath: "/nonexistent/ca.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHostTLSConfig_LoadClientCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertAndKey(t, dir, "client")

	t.Run("loads valid cert and key", func(t *testing.T) {
		cfg := &HostTLSConfig{
			ClientCertPath: certPath,
			ClientKeyPath:  keyPath,
		}
		cert, err := cfg.LoadClientCert()
		if err != nil {
			t.Fatalf("LoadClientCert() error = %v", err)
		}
		if cert == nil {
			t.Fatal("LoadClientCert() returned nil")
		}
	})

	t.Run("returns nil for empty paths", func(t *testing.T) {
		cfg := &HostTLSConfig{}
		cert, err := cfg.LoadClientCert()
		if err != nil {
			t.Fatalf("LoadClientCert() error = %v", err)
		}
		if cert != nil {
			t.Error("LoadClientCert() should return nil for empty paths")
		}
	})

	t.Run("returns error for invalid cert", func(t *testing.T) {
		invalidPath := filepath.Join(dir, "invalid.pem")
		if err := os.WriteFile(invalidPath, []byte("not a cert"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := &HostTLSConfig{
			ClientCertPath: invalidPath,
			ClientKeyPath:  keyPath,
		}
		_, err := cfg.LoadClientCert()
		if err == nil {
			t.Error("LoadClientCert() should return error for invalid cert")
		}
	})
}

func TestHostTLSConfig_LoadCABundle(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTestCABundle(t, dir)

	t.Run("loads valid CA bundle", func(t *testing.T) {
		cfg := &HostTLSConfig{CABundlePath: caPath}
		pool, err := cfg.LoadCABundle()
		if err != nil {
			t.Fatalf("LoadCABundle() error = %v", err)
		}
		if pool == nil {
			t.Fatal("LoadCABundle() returned nil")
		}
	})

	t.Run("returns nil for empty path", func(t *testing.T) {
		cfg := &HostTLSConfig{}
		pool, err := cfg.LoadCABundle()
		if err != nil {
			t.Fatalf("LoadCABundle() error = %v", err)
		}
		if pool != nil {
			t.Error("LoadCABundle() should return nil for empty path")
		}
	})

	t.Run("returns error for invalid PEM", func(t *testing.T) {
		invalidPath := filepath.Join(dir, "invalid-ca.pem")
		if err := os.WriteFile(invalidPath, []byte("not a cert"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := &HostTLSConfig{CABundlePath: invalidPath}
		_, err := cfg.LoadCABundle()
		if err == nil {
			t.Error("LoadCABundle() should return error for invalid PEM")
		}
	})
}

func TestHostTLSRegistry_Lookup(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertAndKey(t, dir, "global")
	hostCertPath, hostKeyPath := writeTestCertAndKey(t, dir, "host")

	reg := NewHostTLSRegistry()

	globalCfg := &HostTLSConfig{
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
	}
	reg.SetGlobal(globalCfg)

	hostCfg := &HostTLSConfig{
		ClientCertPath: hostCertPath,
		ClientKeyPath:  hostKeyPath,
	}
	reg.Set("api.example.com", hostCfg)

	wildcardCfg := &HostTLSConfig{
		ClientCertPath: hostCertPath,
		ClientKeyPath:  hostKeyPath,
	}
	reg.Set("*.internal.com", wildcardCfg)

	t.Run("exact match", func(t *testing.T) {
		result := reg.Lookup("api.example.com")
		if result != hostCfg {
			t.Error("expected host-specific config for exact match")
		}
	})

	t.Run("wildcard match", func(t *testing.T) {
		result := reg.Lookup("service.internal.com")
		if result != wildcardCfg {
			t.Error("expected wildcard config")
		}
	})

	t.Run("fallback to global", func(t *testing.T) {
		result := reg.Lookup("other.example.com")
		if result != globalCfg {
			t.Error("expected global config as fallback")
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		result := reg.Lookup("API.EXAMPLE.COM")
		if result != hostCfg {
			t.Error("expected case-insensitive match")
		}
	})
}

func TestHostTLSRegistry_LookupNoGlobal(t *testing.T) {
	reg := NewHostTLSRegistry()
	result := reg.Lookup("any.host.com")
	if result != nil {
		t.Error("expected nil when no global and no match")
	}
}

func TestHostTLSRegistry_Remove(t *testing.T) {
	reg := NewHostTLSRegistry()
	cfg := &HostTLSConfig{}
	reg.Set("test.com", cfg)

	if reg.Lookup("test.com") != cfg {
		t.Fatal("expected config after Set")
	}

	reg.Remove("test.com")
	if reg.Lookup("test.com") != nil {
		t.Error("expected nil after Remove")
	}
}

func TestHostTLSRegistry_Hosts(t *testing.T) {
	reg := NewHostTLSRegistry()
	reg.Set("a.com", &HostTLSConfig{})
	reg.Set("b.com", &HostTLSConfig{})

	hosts := reg.Hosts()
	if len(hosts) != 2 {
		t.Errorf("Hosts() returned %d entries, want 2", len(hosts))
	}
}

func TestHostTLSRegistry_ApplyToTLSConfig(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertAndKey(t, dir, "client")
	caPath := writeTestCABundle(t, dir)

	t.Run("applies client cert and custom CA", func(t *testing.T) {
		reg := NewHostTLSRegistry()
		boolFalse := false
		reg.Set("secure.example.com", &HostTLSConfig{
			ClientCertPath: certPath,
			ClientKeyPath:  keyPath,
			CABundlePath:   caPath,
			TLSVerify:      &boolFalse,
		})

		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if err := reg.ApplyToTLSConfig(tlsCfg, "secure.example.com", false); err != nil {
			t.Fatalf("ApplyToTLSConfig() error = %v", err)
		}

		if len(tlsCfg.Certificates) == 0 {
			t.Error("expected client certificate to be set")
		}
		if !tlsCfg.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify=true when TLSVerify=false")
		}
		if tlsCfg.RootCAs == nil {
			t.Error("expected RootCAs to be set")
		}
	})

	t.Run("TLSVerify nil falls back to global insecure", func(t *testing.T) {
		reg := NewHostTLSRegistry()
		reg.SetGlobal(&HostTLSConfig{})

		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if err := reg.ApplyToTLSConfig(tlsCfg, "any.host.com", true); err != nil {
			t.Fatalf("ApplyToTLSConfig() error = %v", err)
		}
		if !tlsCfg.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify=true from global fallback")
		}
	})

	t.Run("no match does nothing", func(t *testing.T) {
		reg := NewHostTLSRegistry()
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if err := reg.ApplyToTLSConfig(tlsCfg, "unknown.host.com", false); err != nil {
			t.Fatalf("ApplyToTLSConfig() error = %v", err)
		}
		if len(tlsCfg.Certificates) != 0 {
			t.Error("expected no certificates for unmatched host")
		}
	})

	t.Run("TLSVerify true enforces verification", func(t *testing.T) {
		reg := NewHostTLSRegistry()
		boolTrue := true
		reg.Set("verified.example.com", &HostTLSConfig{
			TLSVerify: &boolTrue,
		})

		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if err := reg.ApplyToTLSConfig(tlsCfg, "verified.example.com", true); err != nil {
			t.Fatalf("ApplyToTLSConfig() error = %v", err)
		}
		if tlsCfg.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify=false when TLSVerify=true")
		}
	})
}

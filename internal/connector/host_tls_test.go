package connector

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

func TestNewHostTLSResolver_NilMap(t *testing.T) {
	r := NewHostTLSResolver(nil)
	if r != nil {
		t.Error("expected nil resolver for nil map")
	}
}

func TestNewHostTLSResolver_EmptyMap(t *testing.T) {
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{})
	if r != nil {
		t.Error("expected nil resolver for empty map")
	}
}

func TestHostTLSResolver_Resolve_NilReceiver(t *testing.T) {
	var r *HostTLSResolver
	result, err := r.Resolve("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil result from nil receiver")
	}
}

func TestHostTLSResolver_ExactMatch(t *testing.T) {
	verify := false
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {TLSVerify: &verify},
	})

	result, err := r.Resolve("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for exact match")
	}
	if result.InsecureSkipVerify == nil {
		t.Fatal("expected InsecureSkipVerify to be set")
	}
	// TLSVerify=false → InsecureSkipVerify=true
	if !*result.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true when TLSVerify=false")
	}
}

func TestHostTLSResolver_ExactMatch_CaseInsensitive(t *testing.T) {
	verify := true
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"Example.COM": {TLSVerify: &verify},
	})

	result, err := r.Resolve("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for case-insensitive match")
	}
	// TLSVerify=true → InsecureSkipVerify=false
	if *result.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=false when TLSVerify=true")
	}
}

func TestHostTLSResolver_WildcardMatch(t *testing.T) {
	verify := false
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"*.example.com": {TLSVerify: &verify},
	})

	tests := []struct {
		target string
		match  bool
	}{
		{"sub.example.com:443", true},
		{"api.example.com:8443", true},
		{"example.com:443", false},          // wildcard requires subdomain
		{"deep.sub.example.com:443", false}, // only single level
		{"other.com:443", false},
	}

	for _, tt := range tests {
		result, err := r.Resolve(tt.target)
		if err != nil {
			t.Fatalf("Resolve(%q): unexpected error: %v", tt.target, err)
		}
		if tt.match && result == nil {
			t.Errorf("Resolve(%q): expected match but got nil", tt.target)
		}
		if !tt.match && result != nil {
			t.Errorf("Resolve(%q): expected no match but got result", tt.target)
		}
	}
}

func TestHostTLSResolver_ExactOverWildcard(t *testing.T) {
	verifyExact := true
	verifyWild := false

	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"api.example.com": {TLSVerify: &verifyExact},
		"*.example.com":   {TLSVerify: &verifyWild},
	})

	// Exact match should win
	result, err := r.Resolve("api.example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// Exact entry has TLSVerify=true → InsecureSkipVerify=false
	if *result.InsecureSkipVerify {
		t.Error("expected exact match to win over wildcard")
	}

	// Non-exact subdomain should match wildcard
	result, err = r.Resolve("other.example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected wildcard match")
	}
	// Wildcard entry has TLSVerify=false → InsecureSkipVerify=true
	if !*result.InsecureSkipVerify {
		t.Error("expected wildcard match with InsecureSkipVerify=true")
	}
}

func TestHostTLSResolver_NoMatch(t *testing.T) {
	verify := false
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {TLSVerify: &verify},
	})

	result, err := r.Resolve("other.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil result for non-matching host")
	}
}

func TestHostTLSResolver_TargetWithoutPort(t *testing.T) {
	verify := false
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {TLSVerify: &verify},
	})

	result, err := r.Resolve("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected match for target without port")
	}
}

func TestHostTLSResolver_TLSVerifyNil(t *testing.T) {
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {}, // TLSVerify is nil
	})

	result, err := r.Resolve("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result (entry exists)")
	}
	if result.InsecureSkipVerify != nil {
		t.Error("expected InsecureSkipVerify=nil when TLSVerify is nil (use global)")
	}
}

func TestHostTLSResolver_ClientCert(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateTestCertFiles(t, dir)

	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {
			ClientCertPath: certPath,
			ClientKeyPath:  keyPath,
		},
	})

	result, err := r.Resolve("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.ClientCert == nil {
		t.Error("expected ClientCert to be loaded")
	}

	// Second resolve should return cached cert (same pointer)
	result2, err := r.Resolve("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error on second resolve: %v", err)
	}
	if result2.ClientCert != result.ClientCert {
		t.Error("expected cached cert (same pointer) on second resolve")
	}
}

func TestHostTLSResolver_ClientCert_InvalidPath(t *testing.T) {
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {
			ClientCertPath: "/nonexistent/cert.pem",
			ClientKeyPath:  "/nonexistent/key.pem",
		},
	})

	_, err := r.Resolve("example.com:443")
	if err == nil {
		t.Error("expected error for invalid cert path")
	}
}

func TestHostTLSResolver_CABundle(t *testing.T) {
	dir := t.TempDir()
	caPath := generateTestCAFile(t, dir)

	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {
			CABundlePath: caPath,
		},
	})

	result, err := r.Resolve("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.RootCAs == nil {
		t.Error("expected RootCAs to be loaded")
	}
}

func TestHostTLSResolver_CABundle_InvalidPath(t *testing.T) {
	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {
			CABundlePath: "/nonexistent/ca.pem",
		},
	})

	_, err := r.Resolve("example.com:443")
	if err == nil {
		t.Error("expected error for invalid CA bundle path")
	}
}

func TestHostTLSResolver_CABundle_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	badCA := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a PEM certificate"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {
			CABundlePath: badCA,
		},
	})

	_, err := r.Resolve("example.com:443")
	if err == nil {
		t.Error("expected error for invalid PEM content")
	}
}

func TestHostTLSResolver_FullOverride(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := generateTestCertFiles(t, dir)
	caPath := generateTestCAFile(t, dir)
	verify := false

	r := NewHostTLSResolver(map[string]*config.HostTLSEntry{
		"example.com": {
			ClientCertPath: certPath,
			ClientKeyPath:  keyPath,
			CABundlePath:   caPath,
			TLSVerify:      &verify,
		},
	})

	result, err := r.Resolve("example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.InsecureSkipVerify == nil || !*result.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
	if result.ClientCert == nil {
		t.Error("expected ClientCert")
	}
	if result.RootCAs == nil {
		t.Error("expected RootCAs")
	}
}

// --- Test helpers ---

func generateTestCertFiles(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	keyPath = filepath.Join(dir, "key.pem")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

func generateTestCAFile(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "ca.pem")
	caFile, err := os.Create(caPath)
	if err != nil {
		t.Fatal(err)
	}
	defer caFile.Close()
	if err := pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}); err != nil {
		t.Fatal(err)
	}

	return caPath
}

package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// newTestCA creates a CA for testing. It calls t.Fatal on failure.
func newTestCA(t *testing.T) *CA {
	t.Helper()
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	return ca
}

func TestGetCertificate_HostnameSAN(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	tests := []struct {
		name     string
		hostname string
	}{
		{name: "simple hostname", hostname: "example.com"},
		{name: "subdomain", hostname: "www.example.com"},
		{name: "deeply nested subdomain", hostname: "a.b.c.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := iss.GetCertificate(tt.hostname)
			if err != nil {
				t.Fatalf("GetCertificate(%q): %v", tt.hostname, err)
			}

			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("parse certificate: %v", err)
			}

			// Verify DNS SAN is set.
			if len(x509Cert.DNSNames) != 1 || x509Cert.DNSNames[0] != tt.hostname {
				t.Errorf("DNSNames = %v, want [%s]", x509Cert.DNSNames, tt.hostname)
			}

			// Verify no IP SANs.
			if len(x509Cert.IPAddresses) != 0 {
				t.Errorf("IPAddresses = %v, want empty", x509Cert.IPAddresses)
			}

			// Verify CommonName.
			if x509Cert.Subject.CommonName != tt.hostname {
				t.Errorf("Subject.CommonName = %q, want %q", x509Cert.Subject.CommonName, tt.hostname)
			}
		})
	}
}

func TestGetCertificate_IPAddress(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	tests := []struct {
		name     string
		hostname string
		wantIP   net.IP
	}{
		{name: "IPv4", hostname: "192.168.1.1", wantIP: net.ParseIP("192.168.1.1")},
		{name: "IPv4 loopback", hostname: "127.0.0.1", wantIP: net.ParseIP("127.0.0.1")},
		{name: "IPv6 loopback", hostname: "::1", wantIP: net.ParseIP("::1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := iss.GetCertificate(tt.hostname)
			if err != nil {
				t.Fatalf("GetCertificate(%q): %v", tt.hostname, err)
			}

			x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("parse certificate: %v", err)
			}

			// Verify IP SAN is set.
			if len(x509Cert.IPAddresses) != 1 {
				t.Fatalf("IPAddresses length = %d, want 1", len(x509Cert.IPAddresses))
			}
			if !x509Cert.IPAddresses[0].Equal(tt.wantIP) {
				t.Errorf("IPAddresses[0] = %v, want %v", x509Cert.IPAddresses[0], tt.wantIP)
			}

			// Verify no DNS SANs.
			if len(x509Cert.DNSNames) != 0 {
				t.Errorf("DNSNames = %v, want empty", x509Cert.DNSNames)
			}
		})
	}
}

func TestGetCertificate_CertificateProperties(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	cert, err := iss.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "ECDSA P-256 key",
			check: func(t *testing.T) {
				t.Helper()
				pub, ok := x509Cert.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("PublicKey type = %T, want *ecdsa.PublicKey", x509Cert.PublicKey)
				}
				if pub.Curve != elliptic.P256() {
					t.Errorf("PublicKey curve = %v, want P-256", pub.Curve.Params().Name)
				}
			},
		},
		{
			name: "validity period is 24 hours",
			check: func(t *testing.T) {
				t.Helper()
				duration := x509Cert.NotAfter.Sub(x509Cert.NotBefore)
				tolerance := time.Minute
				if duration < certValidity-tolerance || duration > certValidity+tolerance {
					t.Errorf("validity duration = %v, want ~%v", duration, certValidity)
				}
			},
		},
		{
			name: "signed by CA",
			check: func(t *testing.T) {
				t.Helper()
				if x509Cert.Issuer.CommonName != "yorishiro-proxy CA" {
					t.Errorf("Issuer.CommonName = %q, want %q", x509Cert.Issuer.CommonName, "yorishiro-proxy CA")
				}
			},
		},
		{
			name: "KeyUsage includes DigitalSignature",
			check: func(t *testing.T) {
				t.Helper()
				if x509Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
					t.Error("KeyUsage does not include DigitalSignature")
				}
			},
		},
		{
			name: "ExtKeyUsage includes ServerAuth",
			check: func(t *testing.T) {
				t.Helper()
				found := false
				for _, usage := range x509Cert.ExtKeyUsage {
					if usage == x509.ExtKeyUsageServerAuth {
						found = true
						break
					}
				}
				if !found {
					t.Error("ExtKeyUsage does not include ServerAuth")
				}
			},
		},
		{
			name: "is not a CA certificate",
			check: func(t *testing.T) {
				t.Helper()
				if x509Cert.IsCA {
					t.Error("IsCA = true, want false")
				}
			},
		},
		{
			name: "serial number is positive",
			check: func(t *testing.T) {
				t.Helper()
				if x509Cert.SerialNumber == nil || x509Cert.SerialNumber.Sign() <= 0 {
					t.Errorf("SerialNumber = %v, want positive", x509Cert.SerialNumber)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t)
		})
	}
}

func TestGetCertificate_CAVerification(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	cert, err := iss.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	// Build a cert pool with the CA cert and verify the server cert.
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())

	opts := x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if _, err := x509Cert.Verify(opts); err != nil {
		t.Errorf("certificate verification failed: %v", err)
	}
}

func TestGetCertificate_CacheHit(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	cert1, err := iss.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}

	cert2, err := iss.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("second GetCertificate: %v", err)
	}

	// Both calls should return the exact same pointer.
	if cert1 != cert2 {
		t.Error("second call returned a different certificate object; expected cache hit")
	}
}

func TestGetCertificate_DifferentHostsDifferentCerts(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	cert1, err := iss.GetCertificate("host-a.example.com")
	if err != nil {
		t.Fatalf("GetCertificate(host-a): %v", err)
	}

	cert2, err := iss.GetCertificate("host-b.example.com")
	if err != nil {
		t.Fatalf("GetCertificate(host-b): %v", err)
	}

	// Different hostnames must produce different certificates.
	if cert1 == cert2 {
		t.Error("different hostnames returned the same certificate object")
	}

	// Parse and verify SANs differ.
	x509Cert1, _ := x509.ParseCertificate(cert1.Certificate[0])
	x509Cert2, _ := x509.ParseCertificate(cert2.Certificate[0])

	if x509Cert1.DNSNames[0] == x509Cert2.DNSNames[0] {
		t.Errorf("both certificates have the same SAN: %s", x509Cert1.DNSNames[0])
	}
}

func TestGetCertificate_ConcurrentAccess(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	const goroutines = 50
	hostname := "concurrent.example.com"

	results := make([]*tls.Certificate, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = iss.GetCertificate(hostname)
		}(i)
	}

	wg.Wait()

	// All goroutines should succeed.
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}

	// All goroutines should get the same certificate (via cache or singleflight).
	first := results[0]
	for i := 1; i < goroutines; i++ {
		if results[i] != first {
			t.Errorf("goroutine %d got a different certificate pointer than goroutine 0", i)
		}
	}
}

func TestGetCertificateForClientHello_Compatibility(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	// Simulate a tls.ClientHelloInfo.
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
	}

	cert, err := iss.GetCertificateForClientHello(hello)
	if err != nil {
		t.Fatalf("GetCertificateForClientHello: %v", err)
	}

	if cert == nil {
		t.Fatal("GetCertificateForClientHello returned nil certificate")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	if len(x509Cert.DNSNames) != 1 || x509Cert.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", x509Cert.DNSNames)
	}
}

func TestGetCertificate_CacheConsistencyWithClientHello(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca)

	// Get via GetCertificate.
	cert1, err := iss.GetCertificate("shared.example.com")
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	// Get via GetCertificateForClientHello with the same hostname.
	hello := &tls.ClientHelloInfo{
		ServerName: "shared.example.com",
	}
	cert2, err := iss.GetCertificateForClientHello(hello)
	if err != nil {
		t.Fatalf("GetCertificateForClientHello: %v", err)
	}

	// Should be the same cached certificate.
	if cert1 != cert2 {
		t.Error("GetCertificate and GetCertificateForClientHello returned different certs for same hostname")
	}
}

func TestNewIssuer_WithMaxCacheSize(t *testing.T) {
	ca := newTestCA(t)

	tests := []struct {
		name     string
		size     int
		wantSize int
	}{
		{name: "custom size", size: 256, wantSize: 256},
		{name: "small size", size: 1, wantSize: 1},
		{name: "zero falls back to default", size: 0, wantSize: defaultMaxCacheSize},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iss := NewIssuer(ca, WithMaxCacheSize(tt.size))
			if iss.cache.maxSize != tt.wantSize {
				t.Errorf("cache maxSize = %d, want %d", iss.cache.maxSize, tt.wantSize)
			}
		})
	}
}

func TestGetCertificate_CacheEviction(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca, WithMaxCacheSize(3))

	// Generate certificates for 3 hosts to fill the cache.
	hosts := []string{"a.example.com", "b.example.com", "c.example.com"}
	certs := make(map[string]*tls.Certificate)
	for _, h := range hosts {
		cert, err := iss.GetCertificate(h)
		if err != nil {
			t.Fatalf("GetCertificate(%q): %v", h, err)
		}
		certs[h] = cert
	}

	if iss.CacheLen() != 3 {
		t.Fatalf("CacheLen = %d, want 3", iss.CacheLen())
	}

	// Adding a 4th host should evict the LRU entry ("a.example.com").
	cert4, err := iss.GetCertificate("d.example.com")
	if err != nil {
		t.Fatalf("GetCertificate(d.example.com): %v", err)
	}
	if cert4 == nil {
		t.Fatal("GetCertificate returned nil for new host")
	}

	if iss.CacheLen() != 3 {
		t.Errorf("CacheLen = %d after eviction, want 3", iss.CacheLen())
	}

	// "a.example.com" should have been evicted; requesting it again should
	// produce a new (different) certificate.
	certA2, err := iss.GetCertificate("a.example.com")
	if err != nil {
		t.Fatalf("GetCertificate(a.example.com) after eviction: %v", err)
	}
	if certA2 == certs["a.example.com"] {
		t.Error("expected a new certificate after eviction, got the same pointer")
	}
}

func TestClearCache_RemovesAllEntries(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca, WithMaxCacheSize(10))

	// Populate the cache with some certificates.
	for i := 0; i < 5; i++ {
		hostname := fmt.Sprintf("host-%d.example.com", i)
		if _, err := iss.GetCertificate(hostname); err != nil {
			t.Fatalf("GetCertificate(%q): %v", hostname, err)
		}
	}

	if iss.CacheLen() != 5 {
		t.Fatalf("CacheLen = %d before clear, want 5", iss.CacheLen())
	}

	iss.ClearCache()

	if iss.CacheLen() != 0 {
		t.Errorf("CacheLen = %d after ClearCache, want 0", iss.CacheLen())
	}

	// Verify that getting a previously cached hostname generates a new cert.
	cert1, err := iss.GetCertificate("host-0.example.com")
	if err != nil {
		t.Fatalf("GetCertificate after clear: %v", err)
	}
	if cert1 == nil {
		t.Fatal("GetCertificate returned nil after clear")
	}
	if iss.CacheLen() != 1 {
		t.Errorf("CacheLen = %d after re-generation, want 1", iss.CacheLen())
	}
}

func TestCacheLen_ReflectsCacheState(t *testing.T) {
	ca := newTestCA(t)
	iss := NewIssuer(ca, WithMaxCacheSize(10))

	if iss.CacheLen() != 0 {
		t.Errorf("initial CacheLen = %d, want 0", iss.CacheLen())
	}

	for i := 0; i < 5; i++ {
		hostname := fmt.Sprintf("host-%d.example.com", i)
		if _, err := iss.GetCertificate(hostname); err != nil {
			t.Fatalf("GetCertificate(%q): %v", hostname, err)
		}
	}

	if iss.CacheLen() != 5 {
		t.Errorf("CacheLen = %d after 5 certs, want 5", iss.CacheLen())
	}
}

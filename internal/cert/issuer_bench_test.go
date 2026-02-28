package cert

import (
	"fmt"
	"testing"
)

func BenchmarkIssueServerCert(b *testing.B) {
	b.Run("CacheMiss", func(b *testing.B) {
		ca := &CA{}
		if err := ca.Generate(); err != nil {
			b.Fatalf("CA.Generate: %v", err)
		}
		// Use a large cache so eviction does not interfere.
		iss := NewIssuer(ca, WithMaxCacheSize(b.N+1))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			hostname := fmt.Sprintf("host-%d.example.com", i)
			if _, err := iss.GetCertificate(hostname); err != nil {
				b.Fatalf("GetCertificate(%q): %v", hostname, err)
			}
		}
	})

	b.Run("CacheHit", func(b *testing.B) {
		ca := &CA{}
		if err := ca.Generate(); err != nil {
			b.Fatalf("CA.Generate: %v", err)
		}
		iss := NewIssuer(ca)

		// Pre-populate the cache with a single hostname.
		const hostname = "cached.example.com"
		if _, err := iss.GetCertificate(hostname); err != nil {
			b.Fatalf("pre-populate cache: %v", err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := iss.GetCertificate(hostname); err != nil {
				b.Fatalf("GetCertificate: %v", err)
			}
		}
	})
}

func BenchmarkIssueServerCert_IPAddress(b *testing.B) {
	ca := &CA{}
	if err := ca.Generate(); err != nil {
		b.Fatalf("CA.Generate: %v", err)
	}
	iss := NewIssuer(ca, WithMaxCacheSize(b.N+1))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256)
		if _, err := iss.GetCertificate(ip); err != nil {
			b.Fatalf("GetCertificate(%q): %v", ip, err)
		}
	}
}

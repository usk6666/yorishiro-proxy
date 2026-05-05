package envelope

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

func TestTLSSnapshot_VersionName(t *testing.T) {
	tests := []struct {
		name    string
		snap    *TLSSnapshot
		wantSub string // substring match (allows "unknown (0x...)")
	}{
		{"nil snapshot returns empty", nil, ""},
		{"zero version returns empty", &TLSSnapshot{Version: 0}, ""},
		{"TLS 1.0", &TLSSnapshot{Version: tls.VersionTLS10}, "TLS 1.0"},
		{"TLS 1.1", &TLSSnapshot{Version: tls.VersionTLS11}, "TLS 1.1"},
		{"TLS 1.2", &TLSSnapshot{Version: tls.VersionTLS12}, "TLS 1.2"},
		{"TLS 1.3", &TLSSnapshot{Version: tls.VersionTLS13}, "TLS 1.3"},
		{"unknown version is formatted", &TLSSnapshot{Version: 0x1234}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.snap.VersionName()
			if tt.wantSub == "" && got != "" {
				t.Errorf("VersionName() = %q, want empty", got)
			}
			if tt.wantSub != "" && !strings.Contains(got, tt.wantSub) {
				t.Errorf("VersionName() = %q, want substring %q", got, tt.wantSub)
			}
		})
	}
}

func TestTLSSnapshot_CipherName(t *testing.T) {
	if got := (*TLSSnapshot)(nil).CipherName(); got != "" {
		t.Errorf("nil.CipherName() = %q, want empty", got)
	}
	if got := (&TLSSnapshot{CipherSuite: 0}).CipherName(); got != "" {
		t.Errorf("zero cipher.CipherName() = %q, want empty", got)
	}
	// TLS_AES_128_GCM_SHA256 = 0x1301 (RFC 8446 Appendix B.4)
	snap := &TLSSnapshot{CipherSuite: tls.TLS_AES_128_GCM_SHA256}
	if got := snap.CipherName(); got != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("CipherName() = %q, want TLS_AES_128_GCM_SHA256", got)
	}
}

func TestTLSSnapshot_PeerCertSubject(t *testing.T) {
	if got := (*TLSSnapshot)(nil).PeerCertSubject(); got != "" {
		t.Errorf("nil.PeerCertSubject() = %q, want empty", got)
	}
	if got := (&TLSSnapshot{PeerCertificate: nil}).PeerCertSubject(); got != "" {
		t.Errorf("nil cert.PeerCertSubject() = %q, want empty", got)
	}
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "upstream-tls-marker"},
	}
	snap := &TLSSnapshot{PeerCertificate: cert}
	got := snap.PeerCertSubject()
	if !strings.Contains(got, "upstream-tls-marker") {
		t.Errorf("PeerCertSubject() = %q, want to contain %q", got, "upstream-tls-marker")
	}
}

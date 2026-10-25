package connector

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
)

// USK-1317 T15: the transparent TLS route decision table.
func TestClassifyTransparentTLS(t *testing.T) {
	tests := []struct {
		name string
		peek ClientHelloPeek
		want transparentTLSClass
	}{
		{"h2 offer", ClientHelloPeek{ExtensionsParsed: true, ALPN: []string{"h2"}}, transparentTLSMITM},
		{"http/1.1 offer", ClientHelloPeek{ExtensionsParsed: true, ALPN: []string{"http/1.1"}}, transparentTLSMITM},
		{"browser offer", ClientHelloPeek{ExtensionsParsed: true, ALPN: []string{"h2", "http/1.1"}}, transparentTLSMITM},
		{"http/1.1 after a non-HTTP value", ClientHelloPeek{ExtensionsParsed: true, ALPN: []string{"imap", "http/1.1"}}, transparentTLSMITM},
		{"only non-HTTP values", ClientHelloPeek{ExtensionsParsed: true, ALPN: []string{"imap", "acme-tls/1"}}, transparentTLSPassthrough},
		{"case-variant HTTP value is not HTTP (byte-exact)", ClientHelloPeek{ExtensionsParsed: true, ALPN: []string{"HTTP/1.1", "H2"}}, transparentTLSPassthrough},
		{"http/1.0 is not offered as an HTTP MITM value", ClientHelloPeek{ExtensionsParsed: true, ALPN: []string{"http/1.0"}}, transparentTLSPassthrough},
		{"no ALPN extension", ClientHelloPeek{ExtensionsParsed: true, SNI: "a.example"}, transparentTLSMITMNoALPN},
		{"no ALPN, no SNI", ClientHelloPeek{ExtensionsParsed: true}, transparentTLSMITMNoALPN},
		{"unparsed ClientHello", ClientHelloPeek{}, transparentTLSPassthrough},
		{"unparsed ClientHello with SNI", ClientHelloPeek{SNI: "a.example"}, transparentTLSPassthrough},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyTransparentTLS(tc.peek); got != tc.want {
				t.Errorf("classifyTransparentTLS(%+v) = %d, want %d", tc.peek, got, tc.want)
			}
		})
	}
}

// peekFromBytes feeds raw first-record bytes through a net.Pipe into the
// real peekClientHelloSNIAndALPN.
func peekFromBytes(t *testing.T, rec []byte) ClientHelloPeek {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() { _, _ = b.Write(rec) }()
	return peekClientHelloSNIAndALPN(NewPeekConn(a))
}

// peekFromTLSClient captures the ClientHello a real crypto/tls client
// writes and peeks it.
func peekFromTLSClient(t *testing.T, cfg *tls.Config) ClientHelloPeek {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() {
		c := tls.Client(b, cfg)
		_ = c.HandshakeContext(context.Background())
		_ = c.Close()
	}()
	return peekClientHelloSNIAndALPN(NewPeekConn(a))
}

// USK-1317 T15 (R6): ExtensionsParsed separates "no ALPN offered" from
// "the ClientHello could not be read".
func TestPeekClientHelloSNIAndALPN_ExtensionsParsed(t *testing.T) {
	t.Run("real client with ALPN", func(t *testing.T) {
		p := peekFromTLSClient(t, &tls.Config{ServerName: "a.example", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}) //nolint:gosec // test
		if !p.ExtensionsParsed {
			t.Errorf("ExtensionsParsed = false, want true (peek %+v)", p)
		}
	})
	t.Run("real client without ALPN", func(t *testing.T) {
		p := peekFromTLSClient(t, &tls.Config{ServerName: "a.example", InsecureSkipVerify: true}) //nolint:gosec // test
		if !p.ExtensionsParsed || p.ALPN != nil {
			t.Errorf("ExtensionsParsed = %v, ALPN = %v; want true, nil", p.ExtensionsParsed, p.ALPN)
		}
	})
	t.Run("real client without SNI or ALPN", func(t *testing.T) {
		p := peekFromTLSClient(t, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
		if !p.ExtensionsParsed || p.SNI != "" {
			t.Errorf("ExtensionsParsed = %v, SNI = %q; want true, empty", p.ExtensionsParsed, p.SNI)
		}
	})
	t.Run("synthetic hello with empty ALPN list", func(t *testing.T) {
		p := peekFromBytes(t, buildClientHelloWithExts(t, "a.example", []string{}))
		if !p.ExtensionsParsed || p.ALPN != nil {
			t.Errorf("ExtensionsParsed = %v, ALPN = %v; want true, nil", p.ExtensionsParsed, p.ALPN)
		}
	})
	t.Run("truncated ALPN extension", func(t *testing.T) {
		rec := buildClientHelloWithExts(t, "", []string{"h2"})
		// Same deterministic offset as TestParseClientHelloALPN_TruncatedExtensionData.
		rec[54], rec[55] = 0xff, 0xff
		if p := peekFromBytes(t, rec); p.ExtensionsParsed {
			t.Errorf("ExtensionsParsed = true for a truncated ALPN extension (peek %+v)", p)
		}
	})
	t.Run("not a ClientHello", func(t *testing.T) {
		if p := peekFromBytes(t, []byte("GET / HTTP/1.1\r\n\r\n")); p.ExtensionsParsed {
			t.Error("ExtensionsParsed = true for plaintext bytes")
		}
	})
	t.Run("oversized record", func(t *testing.T) {
		if p := peekFromBytes(t, []byte{tlsContentTypeHandshake, 0x03, 0x01, 0xff, 0xff}); p.ExtensionsParsed {
			t.Error("ExtensionsParsed = true for a record over the peek cap")
		}
	})
}

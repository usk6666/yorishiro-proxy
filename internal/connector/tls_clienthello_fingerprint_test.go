package connector

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
)

// TestPeekClientHelloSNIAndALPN_Fingerprints verifies the sniff-first peek
// computes non-empty JA3/JA4 for a real ClientHello (USK-1015).
func TestPeekClientHelloSNIAndALPN_Fingerprints(t *testing.T) {
	a, b := net.Pipe()
	pc := NewPeekConn(a)

	go func() {
		conn := tls.Client(b, &tls.Config{
			ServerName:         "fp.example.com",
			NextProtos:         []string{"h2", "http/1.1"},
			InsecureSkipVerify: true, //nolint:gosec // test
		})
		_ = conn.HandshakeContext(context.Background())
		_ = conn.Close()
	}()

	peeked := peekClientHelloSNIAndALPN(pc)
	if peeked.ClientJA3 == "" || peeked.ClientJA4 == "" {
		t.Errorf("expected non-empty fingerprints, got ja3=%q ja4=%q", peeked.ClientJA3, peeked.ClientJA4)
	}
	if len(peeked.ClientJA3) != 32 {
		t.Errorf("JA3 = %q, want 32-char md5 hex", peeked.ClientJA3)
	}

	_ = a.Close()
	_ = b.Close()
}

// TestPeekClientHelloSNI_PassthroughFingerprints verifies the passthrough
// SNI peek also computes JA3/JA4 (decision #9 — the ClientHello is on the
// wire in the clear even under passthrough).
func TestPeekClientHelloSNI_PassthroughFingerprints(t *testing.T) {
	a, b := net.Pipe()
	pc := NewPeekConn(a)

	go func() {
		conn := tls.Client(b, &tls.Config{
			ServerName:         "pass.example.com",
			InsecureSkipVerify: true, //nolint:gosec // test
		})
		_ = conn.HandshakeContext(context.Background())
		_ = conn.Close()
	}()

	sni, ja3, ja4 := peekClientHelloSNI(pc)
	if sni != "pass.example.com" {
		t.Errorf("sni = %q, want pass.example.com", sni)
	}
	if ja3 == "" || ja4 == "" {
		t.Errorf("expected non-empty passthrough fingerprints, got ja3=%q ja4=%q", ja3, ja4)
	}

	_ = a.Close()
	_ = b.Close()
}

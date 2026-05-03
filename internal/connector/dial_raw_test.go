package connector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// newSelfSignedTLSConfig generates a self-signed TLS certificate for testing.
func newSelfSignedTLSConfig(hostname string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func TestDialUpstreamRaw_PlainTCP(t *testing.T) {
	// Start a TCP echo server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	ctx := context.Background()
	conn, snap, err := DialUpstreamRaw(ctx, ln.Addr().String(), DialRawOpts{})
	if err != nil {
		t.Fatalf("DialUpstreamRaw: %v", err)
	}
	defer conn.Close()

	if snap != nil {
		t.Error("expected nil TLSSnapshot for plain TCP")
	}

	// Verify the connection works.
	msg := []byte("hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("got %q, want %q", buf, msg)
	}
}

func TestDialUpstreamRaw_TLS(t *testing.T) {
	serverCfg, err := newSelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatal(err)
	}

	// Start a TLS echo server.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	ctx := context.Background()
	conn, snap, err := DialUpstreamRaw(ctx, ln.Addr().String(), DialRawOpts{
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // test
		},
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("DialUpstreamRaw: %v", err)
	}
	defer conn.Close()

	if snap == nil {
		t.Fatal("expected non-nil TLSSnapshot for TLS connection")
	}
	if snap.Version == 0 {
		t.Error("expected non-zero TLS version")
	}

	// Verify the connection works.
	msg := []byte("secure hello")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("got %q, want %q", buf, msg)
	}
}

func TestDialUpstreamRaw_InvalidTarget(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		target string
	}{
		{"empty", ""},
		{"no port", "no-port"},
		// CWE-93 CRLF guards: a target string that smuggles CR/LF must
		// be rejected before any TCP dial is attempted, so the bytes
		// cannot leak into a CONNECT request line on the upstream-proxy
		// path. validateTarget runs first on every DialUpstreamRaw call.
		{"crlf injection", "evil.example.com:443\r\nX-Evil: 1"},
		{"only cr", "evil.example.com:443\r"},
		{"only lf", "evil.example.com:443\n"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := DialUpstreamRaw(ctx, tc.target, DialRawOpts{})
			if err == nil {
				t.Errorf("expected error for target %q", tc.target)
			}
		})
	}
}

func TestDialUpstreamRaw_Timeout(t *testing.T) {
	// Use a non-routable address to trigger a timeout.
	ctx := context.Background()
	_, _, err := DialUpstreamRaw(ctx, "192.0.2.1:443", DialRawOpts{
		DialTimeout: 100 * time.Millisecond,
	})
	if err == nil {
		t.Error("expected timeout error")
	}
}

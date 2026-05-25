// Package testutil provides shared TLS test fixtures for the connector
// package's integration tests.
//
// USK-997: the central fixture is StartRFC7301NonCompliantUpstream, an
// emulation of the demo1.nextcloud.com nginx ssl_alpn_protocol misconfig
// — a TLS server that violates RFC 7301 §3.2 by returning http/1.1
// even for a solo-h2 ClientHello ALPN offer. The sniff-first MITM path
// (buildSniffFirstStack) must transparently propagate the upstream pick
// back to the client; this fixture is the regression target.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// RFC7301NonCompliantUpstream is a TLS listener whose ALPN selection
// callback violates RFC 7301 §3.2: it always picks "http/1.1" regardless
// of what the client offered, including the "client offered solo h2"
// case where a compliant server would either pick h2 or fail with
// no_application_protocol (alert 120).
//
// Use cases:
//
//   - Regression test for the demo1.nextcloud.com USK-995 reproducer.
//   - Smoke test for sniff-first MITM ALPN transparency: the proxy
//     must forward whatever upstream returned, even if it's a spec
//     violation.
//
// Lifecycle: callers receive Addr (listening "host:port" string) and
// must call Close() to release the listener. The ServedConnCount field
// is exposed for tests that need to assert "upstream was actually
// dialled exactly once" — a typical browser-parity sniff-first
// invariant.
type RFC7301NonCompliantUpstream struct {
	// Addr is the listening address ("127.0.0.1:port").
	Addr string

	// ServedConnCount counts accepted (post-handshake) connections.
	// Useful for "did the proxy redial after a fake mismatch?" tests.
	ServedConnCount atomic.Int64

	ln net.Listener
}

// Close releases the listener. Idempotent.
func (s *RFC7301NonCompliantUpstream) Close() error {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

// StartRFC7301NonCompliantUpstream starts a TLS listener bound to
// 127.0.0.1 that responds to every ClientHello with NextProtos =
// ["http/1.1"], regardless of the offered ALPN list. After the
// handshake the listener serves the given handler (typically a minimal
// HTTP/1.x echo). Use this in connector integration tests to assert
// sniff-first MITM transparency against RFC 7301 §3.2 violators.
//
// The returned fixture's Close method MUST be called by the test
// (typically via t.Cleanup) to release the listener.
//
// On listener-start failure, t.Fatal is called.
func StartRFC7301NonCompliantUpstream(t *testing.T, handler func(net.Conn)) *RFC7301NonCompliantUpstream {
	t.Helper()

	cert, err := selfSignedCert("localhost")
	if err != nil {
		t.Fatalf("testutil: self-signed cert: %v", err)
	}

	baseCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// GetConfigForClient is invoked per-ClientHello with a snapshot of
	// what the client offered. We clone the base config and force
	// NextProtos = ["http/1.1"] regardless of chi.SupportedProtos —
	// this is the RFC 7301 §3.2 violation the demo1.nextcloud.com
	// upstream exhibits in the wild.
	baseCfg.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
		clone := baseCfg.Clone()
		clone.NextProtos = []string{"http/1.1"}
		// Clear GetConfigForClient on the clone to avoid recursion.
		clone.GetConfigForClient = nil
		return clone, nil
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", baseCfg)
	if err != nil {
		t.Fatalf("testutil: tls.Listen: %v", err)
	}

	srv := &RFC7301NonCompliantUpstream{
		Addr: ln.Addr().String(),
		ln:   ln,
	}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				// Listener closed → exit accept loop. Any other accept
				// error is also terminal (the listener cannot recover).
				return
			}
			// Force the handshake to settle so the ALPN decision is
			// observable before we count the connection. A failed
			// handshake (e.g. client gave up) is benign — we just
			// don't count it.
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
				if hsErr := tc.Handshake(); hsErr != nil {
					if !errors.Is(hsErr, net.ErrClosed) {
						// Log via t through a goroutine-safe channel is
						// awkward; tests can read ServedConnCount to detect
						// handshake outcomes. Silently drop.
					}
					_ = tc.Close()
					continue
				}
				_ = tc.SetReadDeadline(time.Time{})
			}
			srv.ServedConnCount.Add(1)
			if handler != nil {
				go handler(conn)
			} else {
				_ = conn.Close()
			}
		}
	}()

	return srv
}

// selfSignedCert generates an ECDSA-P256 self-signed certificate valid
// for the given hostname (also added to DNSNames). Mirrors the helper
// in dial_raw_test.go so testutil does not depend on the connector
// package's test internals.
func selfSignedCert(hostname string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ecdsa key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

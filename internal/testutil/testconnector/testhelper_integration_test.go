//go:build e2e

package testconnector_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// rawTLSUpstream is a tiny TLS upstream that records the bytes each client
// writes after handshake and then responds with a fixed 200 OK. It is used
// to verify wire fidelity because net/http's parser cannons headers to the
// canonical form, whereas this helper preserves the exact bytes received.
type rawTLSUpstream struct {
	Listener  net.Listener
	TLSConfig *tls.Config
	Cert      *x509.Certificate

	mu    sync.Mutex
	first string
}

func startRawTLSUpstream(t *testing.T) *rawTLSUpstream {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "rawupstream"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost", "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        cert,
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	ru := &rawTLSUpstream{
		Listener:  ln,
		TLSConfig: tlsCfg,
		Cert:      cert,
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go ru.handle(c)
		}
	}()
	return ru
}

func (r *rawTLSUpstream) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)

	// Read the request line + headers verbatim, stopping at the blank line.
	var buf []byte
	for {
		line, err := br.ReadBytes('\n')
		buf = append(buf, line...)
		if err != nil {
			break
		}
		if len(line) == 2 && line[0] == '\r' && line[1] == '\n' {
			break
		}
		if len(line) == 1 && line[0] == '\n' {
			break
		}
	}

	r.mu.Lock()
	if r.first == "" {
		r.first = string(buf)
	}
	r.mu.Unlock()

	// Minimal response.
	_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
}

// WaitFirst waits until at least one request has been received and returns
// the exact bytes (request line + headers) as they came off the wire.
func (r *rawTLSUpstream) WaitFirst(t *testing.T, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		s := r.first
		r.mu.Unlock()
		if s != "" {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("rawTLSUpstream: no request received within %v", timeout)
	return ""
}

// Close terminates the raw upstream listener.
func (r *rawTLSUpstream) Close() { _ = r.Listener.Close() }

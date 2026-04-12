package tlslayer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCert generates a self-signed certificate for testing.
func selfSignedCert(t *testing.T, san ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     san,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// certPool returns a CertPool containing the leaf certificate of cert.
func certPool(cert tls.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	return pool
}

func TestServer_BasicHandshake(t *testing.T) {
	cert := selfSignedCert(t, "localhost")
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	type serverResult struct {
		conn net.Conn
		snap interface{}
		err  error
	}
	ch := make(chan serverResult, 1)

	go func() {
		conn, snap, err := Server(context.Background(), serverConn, serverCfg)
		ch <- serverResult{conn, snap, err}
	}()

	// Client side
	clientCfg := &tls.Config{
		ServerName: "localhost",
		RootCAs:    certPool(cert),
		NextProtos: []string{"h2"},
	}
	tlsClient := tls.Client(clientConn, clientCfg)
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	result := <-ch
	if result.err != nil {
		t.Fatalf("Server() error: %v", result.err)
	}
	if result.conn == nil {
		t.Fatal("Server() returned nil conn")
	}
	if result.snap == nil {
		t.Fatal("Server() returned nil snapshot")
	}

	// Verify ALPN negotiation
	clientState := tlsClient.ConnectionState()
	if clientState.NegotiatedProtocol != "h2" {
		t.Errorf("client ALPN = %q, want %q", clientState.NegotiatedProtocol, "h2")
	}
}

func TestClient_StandardHandshake(t *testing.T) {
	cert := selfSignedCert(t, "localhost")

	// Start a TLS server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	type serverResult struct {
		alpn string
		err  error
	}
	ch := make(chan serverResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- serverResult{err: err}
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, serverCfg)
		if err := tlsConn.Handshake(); err != nil {
			ch <- serverResult{err: err}
			return
		}
		state := tlsConn.ConnectionState()
		ch <- serverResult{alpn: state.NegotiatedProtocol}
	}()

	// Dial and perform client handshake
	plain, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	opts := ClientOpts{
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    certPool(cert),
		},
		OfferALPN: []string{"http/1.1"},
	}

	tlsConn, snap, err := Client(context.Background(), plain, opts)
	if err != nil {
		t.Fatalf("Client() error: %v", err)
	}
	defer tlsConn.Close()

	if snap.ALPN != "http/1.1" {
		t.Errorf("snap.ALPN = %q, want %q", snap.ALPN, "http/1.1")
	}
	if snap.Version == 0 {
		t.Error("snap.Version should be non-zero")
	}
	if snap.CipherSuite == 0 {
		t.Error("snap.CipherSuite should be non-zero")
	}

	sr := <-ch
	if sr.err != nil {
		t.Fatalf("server error: %v", sr.err)
	}
	if sr.alpn != "http/1.1" {
		t.Errorf("server ALPN = %q, want %q", sr.alpn, "http/1.1")
	}
}

func TestClient_UTLS_Chrome(t *testing.T) {
	cert := selfSignedCert(t, "localhost")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	ch := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- err
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, serverCfg)
		ch <- tlsConn.Handshake()
	}()

	plain, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	opts := ClientOpts{
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    certPool(cert),
		},
		InsecureSkipVerify: true,
		UTLSProfile:        "chrome",
		OfferALPN:          []string{"h2", "http/1.1"},
	}

	tlsConn, snap, err := Client(context.Background(), plain, opts)
	if err != nil {
		t.Fatalf("Client(uTLS chrome) error: %v", err)
	}
	defer tlsConn.Close()

	if snap.ALPN == "" {
		t.Error("snap.ALPN should be non-empty with uTLS chrome profile offering h2/http1.1")
	}

	if serverErr := <-ch; serverErr != nil {
		t.Fatalf("server handshake error: %v", serverErr)
	}
}

func TestClient_InsecureSkipVerify(t *testing.T) {
	cert := selfSignedCert(t, "localhost")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ch := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- err
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, serverCfg)
		ch <- tlsConn.Handshake()
	}()

	plain, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Use InsecureSkipVerify without adding cert to RootCAs
	opts := ClientOpts{
		TLSConfig: &tls.Config{
			ServerName: "localhost",
		},
		InsecureSkipVerify: true,
	}

	tlsConn, snap, err := Client(context.Background(), plain, opts)
	if err != nil {
		t.Fatalf("Client(insecure) error: %v", err)
	}
	defer tlsConn.Close()

	if snap == nil {
		t.Fatal("snap should not be nil")
	}

	if serverErr := <-ch; serverErr != nil {
		t.Fatalf("server handshake error: %v", serverErr)
	}
}

func TestClient_mTLS(t *testing.T) {
	serverCert := selfSignedCert(t, "localhost")
	clientCert := selfSignedCert(t, "client")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(clientCert.Leaf)

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}

	type serverResult struct {
		hasPeerCert bool
		err         error
	}
	ch := make(chan serverResult, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- serverResult{err: err}
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, serverCfg)
		if err := tlsConn.Handshake(); err != nil {
			ch <- serverResult{err: err}
			return
		}
		state := tlsConn.ConnectionState()
		ch <- serverResult{hasPeerCert: len(state.PeerCertificates) > 0}
	}()

	plain, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	opts := ClientOpts{
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    certPool(serverCert),
		},
		ClientCert: &clientCert,
	}

	tlsConn, snap, err := Client(context.Background(), plain, opts)
	if err != nil {
		t.Fatalf("Client(mTLS) error: %v", err)
	}
	defer tlsConn.Close()

	if snap.PeerCertificate == nil {
		t.Error("snap.PeerCertificate should be non-nil (server cert)")
	}

	sr := <-ch
	if sr.err != nil {
		t.Fatalf("server error: %v", sr.err)
	}
	if !sr.hasPeerCert {
		t.Error("server should have received client certificate")
	}
}

func TestClient_NilTLSConfig(t *testing.T) {
	_, _, err := Client(context.Background(), nil, ClientOpts{})
	if err == nil {
		t.Fatal("expected error with nil TLSConfig")
	}
}

func TestClient_UnsupportedUTLSProfile(t *testing.T) {
	plain, server := net.Pipe()
	defer plain.Close()
	defer server.Close()

	opts := ClientOpts{
		TLSConfig:   &tls.Config{ServerName: "test"},
		UTLSProfile: "nonexistent",
	}

	_, _, err := Client(context.Background(), plain, opts)
	if err == nil {
		t.Fatal("expected error with unsupported uTLS profile")
	}
}

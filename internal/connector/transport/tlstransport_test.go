package transport

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

// generateTestCert creates a self-signed TLS certificate for testing.
func generateTestCert(t *testing.T, serverName string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// startTLSServer starts a TLS server on a random port and returns the listener.
// The server accepts one connection, completes the handshake, reads one byte,
// and closes. The nextProtos parameter configures ALPN.
func startTLSServer(t *testing.T, cert tls.Certificate, nextProtos []string) net.Listener {
	t.Helper()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Complete the handshake and keep connection open briefly.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	}()

	return ln
}

func TestBrowserProfile_String(t *testing.T) {
	tests := []struct {
		profile BrowserProfile
		want    string
	}{
		{ProfileChrome, "chrome"},
		{ProfileFirefox, "firefox"},
		{ProfileSafari, "safari"},
		{ProfileEdge, "edge"},
		{ProfileRandom, "random"},
		{BrowserProfile(99), "BrowserProfile(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.profile.String()
			if got != tt.want {
				t.Errorf("BrowserProfile(%d).String() = %q, want %q", int(tt.profile), got, tt.want)
			}
		})
	}
}

func TestParseBrowserProfile(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    BrowserProfile
		wantErr bool
	}{
		{name: "chrome lowercase", input: "chrome", want: ProfileChrome},
		{name: "chrome uppercase", input: "CHROME", want: ProfileChrome},
		{name: "chrome mixed case", input: "Chrome", want: ProfileChrome},
		{name: "firefox", input: "firefox", want: ProfileFirefox},
		{name: "safari", input: "safari", want: ProfileSafari},
		{name: "edge", input: "edge", want: ProfileEdge},
		{name: "random", input: "random", want: ProfileRandom},
		{name: "with whitespace", input: "  chrome  ", want: ProfileChrome},
		{name: "unknown profile", input: "opera", wantErr: true},
		{name: "empty string", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBrowserProfile(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseBrowserProfile(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseBrowserProfile(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestStandardTransport_TLSConnect(t *testing.T) {
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"h2", "http/1.1"})
	defer ln.Close()

	transport := &StandardTransport{InsecureSkipVerify: true}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, proto, err := transport.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	if proto != "h2" {
		t.Errorf("negotiated protocol = %q, want %q", proto, "h2")
	}
}

func TestStandardTransport_TLSConnect_HTTP11Only(t *testing.T) {
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"http/1.1"})
	defer ln.Close()

	transport := &StandardTransport{InsecureSkipVerify: true}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, proto, err := transport.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	if proto != "http/1.1" {
		t.Errorf("negotiated protocol = %q, want %q", proto, "http/1.1")
	}
}

func TestStandardTransport_TLSConnect_CustomNextProtos(t *testing.T) {
	// Server supports both h2 and http/1.1, but client only offers http/1.1.
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"h2", "http/1.1"})
	defer ln.Close()

	transport := &StandardTransport{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, proto, err := transport.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	if proto != "http/1.1" {
		t.Errorf("negotiated protocol = %q, want %q (NextProtos should force http/1.1)", proto, "http/1.1")
	}
}

func TestStandardTransport_TLSConnect_HandshakeFailure(t *testing.T) {
	// Create a plain TCP server (no TLS) to cause handshake failure.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	transport := &StandardTransport{InsecureSkipVerify: true}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err = transport.TLSConnect(ctx, rawConn, "localhost")
	if err == nil {
		t.Fatal("expected handshake error, got nil")
	}
}

func TestUTLSTransport_TLSConnect(t *testing.T) {
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"h2", "http/1.1"})
	defer ln.Close()

	transport := &UTLSTransport{
		Profile:            ProfileChrome,
		InsecureSkipVerify: true,
	}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, proto, err := transport.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	// Chrome profile should negotiate h2 when server supports it.
	if proto != "h2" {
		t.Errorf("negotiated protocol = %q, want %q", proto, "h2")
	}
}

func TestUTLSTransport_TLSConnect_DefaultProfile(t *testing.T) {
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"h2", "http/1.1"})
	defer ln.Close()

	// Zero profile should default to Chrome.
	transport := &UTLSTransport{
		InsecureSkipVerify: true,
	}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, _, err := transport.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect with default profile: %v", err)
	}
	defer tlsConn.Close()
}

func TestUTLSTransport_TLSConnect_Firefox(t *testing.T) {
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"h2", "http/1.1"})
	defer ln.Close()

	transport := &UTLSTransport{
		Profile:            ProfileFirefox,
		InsecureSkipVerify: true,
	}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, _, err := transport.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect with Firefox profile: %v", err)
	}
	defer tlsConn.Close()
}

func TestUTLSTransport_TLSConnect_HandshakeFailure(t *testing.T) {
	// Create a plain TCP server (no TLS) to cause handshake failure.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	transport := &UTLSTransport{
		Profile:            ProfileChrome,
		InsecureSkipVerify: true,
	}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err = transport.TLSConnect(ctx, rawConn, "localhost")
	if err == nil {
		t.Fatal("expected handshake error, got nil")
	}
}

// Compile-time check that both types implement TLSTransport.
var (
	_ TLSTransport = (*StandardTransport)(nil)
	_ TLSTransport = (*UTLSTransport)(nil)
)

func TestUTLSTransport_AllProfiles(t *testing.T) {
	cert := generateTestCert(t, "localhost")

	profiles := []BrowserProfile{
		ProfileChrome,
		ProfileFirefox,
		ProfileSafari,
		ProfileEdge,
	}

	for _, profile := range profiles {
		t.Run(profile.String(), func(t *testing.T) {
			ln := startTLSServer(t, cert, []string{"h2", "http/1.1"})
			defer ln.Close()

			transport := &UTLSTransport{
				Profile:            profile,
				InsecureSkipVerify: true,
			}

			rawConn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer rawConn.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			tlsConn, _, err := transport.TLSConnect(ctx, rawConn, "localhost")
			if err != nil {
				t.Fatalf("TLSConnect with %s profile: %v", profile, err)
			}
			defer tlsConn.Close()
		})
	}
}

func TestTLSConnectionState_StandardTLS(t *testing.T) {
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"http/1.1"})
	defer ln.Close()

	transport := &StandardTransport{InsecureSkipVerify: true}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, _, err := transport.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	state, ok := TLSConnectionState(tlsConn)
	if !ok {
		t.Fatal("TLSConnectionState should return true for *tls.Conn")
	}
	if state.Version == 0 {
		t.Error("TLS version should be non-zero")
	}
}

func TestTLSConnectionState_UTLSConn(t *testing.T) {
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"http/1.1"})
	defer ln.Close()

	transport := &UTLSTransport{
		Profile:            ProfileChrome,
		InsecureSkipVerify: true,
	}

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsConn, _, err := transport.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	state, ok := TLSConnectionState(tlsConn)
	if !ok {
		t.Fatal("TLSConnectionState should return true for *utls.UConn")
	}
	if state.Version == 0 {
		t.Error("TLS version should be non-zero")
	}
}

func TestTLSConnectionState_PlainConn(t *testing.T) {
	// A plain net.Conn should not have TLS state.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	_, ok := TLSConnectionState(client)
	if ok {
		t.Error("TLSConnectionState should return false for plain net.Conn")
	}
}

// TestWithNextProtos_ClonesStandardTransport asserts that overriding ALPN
// on a StandardTransport returns a fresh copy without mutating the source.
// This is the property the resend MCP tools rely on (USK-717).
func TestWithNextProtos_ClonesStandardTransport(t *testing.T) {
	src := &StandardTransport{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	got := WithNextProtos(src, []string{"http/1.1"})

	st, ok := got.(*StandardTransport)
	if !ok {
		t.Fatalf("WithNextProtos returned %T, want *StandardTransport", got)
	}
	if st == src {
		t.Fatal("WithNextProtos returned the same pointer; expected a clone")
	}
	if !st.InsecureSkipVerify {
		t.Error("clone lost InsecureSkipVerify")
	}
	if len(st.NextProtos) != 1 || st.NextProtos[0] != "http/1.1" {
		t.Errorf("clone NextProtos = %v, want [http/1.1]", st.NextProtos)
	}
	if len(src.NextProtos) != 2 {
		t.Errorf("source NextProtos mutated: got %v, want [h2 http/1.1]", src.NextProtos)
	}
}

// TestWithNextProtos_ClonesUTLSTransport asserts the same clone-and-override
// semantics for UTLSTransport — uTLS Chrome is the production default and
// must not have its ALPN extension mutated by per-call overrides.
func TestWithNextProtos_ClonesUTLSTransport(t *testing.T) {
	src := &UTLSTransport{
		Profile:            ProfileChrome,
		InsecureSkipVerify: true,
	}
	got := WithNextProtos(src, []string{"http/1.1"})

	ut, ok := got.(*UTLSTransport)
	if !ok {
		t.Fatalf("WithNextProtos returned %T, want *UTLSTransport", got)
	}
	if ut == src {
		t.Fatal("WithNextProtos returned the same pointer; expected a clone")
	}
	if ut.Profile != ProfileChrome {
		t.Errorf("clone Profile = %v, want ProfileChrome", ut.Profile)
	}
	if len(ut.NextProtos) != 1 || ut.NextProtos[0] != "http/1.1" {
		t.Errorf("clone NextProtos = %v, want [http/1.1]", ut.NextProtos)
	}
	if len(src.NextProtos) != 0 {
		t.Errorf("source NextProtos mutated: got %v, want nil", src.NextProtos)
	}
}

// TestWithInsecureSkipVerify_ClonesTransports asserts the per-call
// InsecureSkipVerify override is independent of the shared transport's
// setting (USK-718, exercised by resend_raw's per-call schema flag).
func TestWithInsecureSkipVerify_ClonesTransports(t *testing.T) {
	std := &StandardTransport{InsecureSkipVerify: false}
	clone := WithInsecureSkipVerify(std, true)
	st, ok := clone.(*StandardTransport)
	if !ok {
		t.Fatalf("WithInsecureSkipVerify returned %T, want *StandardTransport", clone)
	}
	if st == std {
		t.Fatal("returned the same pointer; expected a clone")
	}
	if !st.InsecureSkipVerify {
		t.Error("clone InsecureSkipVerify = false, want true")
	}
	if std.InsecureSkipVerify {
		t.Error("source InsecureSkipVerify mutated")
	}

	utls := &UTLSTransport{Profile: ProfileChrome, InsecureSkipVerify: false}
	uclone := WithInsecureSkipVerify(utls, true)
	ut, ok := uclone.(*UTLSTransport)
	if !ok {
		t.Fatalf("WithInsecureSkipVerify returned %T, want *UTLSTransport", uclone)
	}
	if !ut.InsecureSkipVerify {
		t.Error("UTLS clone InsecureSkipVerify = false, want true")
	}
	if utls.InsecureSkipVerify {
		t.Error("UTLS source InsecureSkipVerify mutated")
	}
}

// TestWithNextProtos_UTLSChromeNegotiatesHTTP11 verifies the end-to-end
// invariant the resend MCP tools depend on: cloning a UTLSTransport with
// NextProtos=["http/1.1"] makes the actual handshake commit to HTTP/1.1
// even when the server offers both h2 and http/1.1. Pre-USK-717 the resend
// path skipped this clone and silently negotiated h2 with modern servers,
// breaking the http1.New Layer wrapping the post-handshake conn.
func TestWithNextProtos_UTLSChromeNegotiatesHTTP11(t *testing.T) {
	cert := generateTestCert(t, "localhost")
	ln := startTLSServer(t, cert, []string{"h2", "http/1.1"})
	defer ln.Close()

	src := &UTLSTransport{Profile: ProfileChrome, InsecureSkipVerify: true}
	pinned := WithNextProtos(src, []string{"http/1.1"})

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tlsConn, proto, err := pinned.TLSConnect(ctx, rawConn, "localhost")
	if err != nil {
		t.Fatalf("TLSConnect: %v", err)
	}
	defer tlsConn.Close()

	if proto != "http/1.1" {
		t.Errorf("negotiated ALPN = %q, want http/1.1", proto)
	}
}

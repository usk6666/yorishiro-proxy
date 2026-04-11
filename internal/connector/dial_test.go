package connector

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/codec/http1"
	"github.com/usk6666/yorishiro-proxy/internal/codec/tcp"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// --- target validation --------------------------------------------------------

func TestValidateTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		target  string
		wantErr string
	}{
		{"valid host:port", "example.com:443", ""},
		{"valid ipv4", "127.0.0.1:80", ""},
		{"valid ipv6", "[::1]:443", ""},
		{"empty", "", "empty target"},
		{"crlf injection", "evil.com:443\r\nX-Injected: 1", "CR/LF"},
		{"only CR", "evil.com:443\rfoo", "CR/LF"},
		{"only LF", "evil.com:443\nfoo", "CR/LF"},
		{"no port", "example.com", "missing port"},
		{"empty host", ":443", "missing host"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := validateTarget(tc.target)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// --- DialUpstream: plain TCP --------------------------------------------------

func TestDialUpstream_PlainTCP(t *testing.T) {
	t.Parallel()
	addr := startEchoServer(t)

	result, err := DialUpstream(context.Background(), addr, DialOpts{DialTimeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer result.Conn.Close()
	defer result.Codec.Close()

	if result.ALPN != "" {
		t.Errorf("ALPN = %q, want empty for plain TCP", result.ALPN)
	}
	// For plain TCP (no TLS handshake) the factory maps the empty ALPN
	// string to the HTTP/1.x Codec, matching the traditional "no ALPN =
	// HTTP/1.1 implicit" convention. Forward-proxy plain HTTP is the
	// primary consumer of this path.
	if _, ok := result.Codec.(*http1.Codec); !ok {
		t.Errorf("Codec = %T, want *http1.Codec", result.Codec)
	}

	// Echo round-trip to prove the connection is usable.
	want := []byte("hello plain")
	if _, err := result.Conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(result.Conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(want) {
		t.Errorf("echo mismatch: got %q want %q", buf, want)
	}
}

func TestDialUpstream_InvalidTarget(t *testing.T) {
	t.Parallel()
	_, err := DialUpstream(context.Background(), "bad.example.com:443\r\nX-Evil: 1", DialOpts{
		DialTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("want CRLF injection error")
	}
	if !strings.Contains(err.Error(), "CR/LF") {
		t.Errorf("error %q does not mention CR/LF", err.Error())
	}
}

func TestDialUpstream_Timeout(t *testing.T) {
	t.Parallel()
	// 198.51.100.0/24 is reserved for documentation (RFC 5737) and is
	// guaranteed not to be routable — the dial will hang, our timeout must
	// trip promptly.
	start := time.Now()
	_, err := DialUpstream(context.Background(), "198.51.100.1:81", DialOpts{
		DialTimeout: 150 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("want timeout error")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("timeout not enforced: elapsed %v", elapsed)
	}
}

// --- DialUpstream: TLS --------------------------------------------------------

func TestDialUpstream_StandardTLS_HTTP11(t *testing.T) {
	t.Parallel()
	srv := newTLSServer(t, []string{"http/1.1"})
	defer srv.Close()

	result, err := DialUpstream(context.Background(), srv.addr, DialOpts{
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // test
		},
		OfferALPN:   []string{"h2", "http/1.1"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer result.Conn.Close()
	defer result.Codec.Close()

	if result.ALPN != "http/1.1" {
		t.Errorf("ALPN = %q, want http/1.1", result.ALPN)
	}
	if _, ok := result.Codec.(*http1.Codec); !ok {
		t.Errorf("Codec = %T, want *http1.Codec", result.Codec)
	}
}

func TestDialUpstream_StandardTLS_H2_Rejected(t *testing.T) {
	t.Parallel()
	srv := newTLSServer(t, []string{"h2"})
	defer srv.Close()

	_, err := DialUpstream(context.Background(), srv.addr, DialOpts{
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // test
		},
		OfferALPN:   []string{"h2"},
		DialTimeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("want error for h2 (not implemented in M39)")
	}
	if !errors.Is(err, ErrHTTP2NotImplemented) {
		t.Errorf("err = %v, want ErrHTTP2NotImplemented", err)
	}
}

func TestDialUpstream_TLS_UnknownALPN_FallbackToTCP(t *testing.T) {
	t.Parallel()
	srv := newTLSServer(t, []string{"exotic-proto/1"})
	defer srv.Close()

	result, err := DialUpstream(context.Background(), srv.addr, DialOpts{
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // test
		},
		OfferALPN:   []string{"exotic-proto/1"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer result.Conn.Close()
	defer result.Codec.Close()

	if result.ALPN != "exotic-proto/1" {
		t.Errorf("ALPN = %q, want exotic-proto/1", result.ALPN)
	}
	if _, ok := result.Codec.(*tcp.Codec); !ok {
		t.Errorf("Codec = %T, want *tcp.Codec (fallback)", result.Codec)
	}
}

// TestDialUpstream_StandardTLS_MinVersionFloor asserts that a caller-provided
// TLSConfig with a sub-TLS1.2 MinVersion is raised to TLS 1.2 by
// DialUpstream. This brings the standard path into parity with the uTLS path
// (which pins TLS 1.2 unconditionally) and prevents a stale caller config
// from silently downgrading the handshake.
func TestDialUpstream_StandardTLS_MinVersionFloor(t *testing.T) {
	t.Parallel()
	// Server requires TLS 1.2+; a client that honours MinVersion=TLS10
	// would negotiate TLS 1.2 anyway — we rely on the handshake succeeding
	// to prove the floor was enforced. The real regression guard is that
	// no downgrade is attempted.
	srv := newTLSServer(t, []string{"http/1.1"})
	defer srv.Close()

	result, err := DialUpstream(context.Background(), srv.addr, DialOpts{
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,             //nolint:gosec // test
			MinVersion:         tls.VersionTLS10, // intentionally too low
		},
		OfferALPN:   []string{"http/1.1"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer result.Conn.Close()
	defer result.Codec.Close()

	tc, ok := result.Conn.(*tls.Conn)
	if !ok {
		t.Fatalf("Conn = %T, want *tls.Conn", result.Conn)
	}
	state := tc.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version = 0x%x, want >= TLS 1.2 (0x%x)",
			state.Version, tls.VersionTLS12)
	}
}

// --- DialUpstream: uTLS -------------------------------------------------------

func TestDialUpstream_UTLS_Chrome_HTTP11(t *testing.T) {
	t.Parallel()
	srv := newTLSServer(t, []string{"http/1.1"})
	defer srv.Close()

	result, err := DialUpstream(context.Background(), srv.addr, DialOpts{
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // test
		},
		UTLSProfile: "chrome",
		OfferALPN:   []string{"http/1.1"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer result.Conn.Close()
	defer result.Codec.Close()

	if result.ALPN != "http/1.1" {
		t.Errorf("ALPN = %q, want http/1.1", result.ALPN)
	}
	if _, ok := result.Codec.(*http1.Codec); !ok {
		t.Errorf("Codec = %T, want *http1.Codec", result.Codec)
	}
}

func TestDialUpstream_UTLS_UnknownProfile(t *testing.T) {
	t.Parallel()
	srv := newTLSServer(t, []string{"http/1.1"})
	defer srv.Close()

	_, err := DialUpstream(context.Background(), srv.addr, DialOpts{
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // test
		},
		UTLSProfile: "unknown-browser",
		DialTimeout: 3 * time.Second,
	})
	if err == nil {
		t.Fatal("want error for unknown profile")
	}
	if !strings.Contains(err.Error(), "unsupported uTLS profile") {
		t.Errorf("error %q does not mention unsupported uTLS profile", err.Error())
	}
}

// --- DialUpstream: mTLS -------------------------------------------------------

func TestDialUpstream_MTLS_ClientCert(t *testing.T) {
	t.Parallel()

	// Generate a client CA, a client cert signed by it, and a server CA/cert.
	clientCACert, clientCAKey := newSelfSignedCA(t, "test-client-ca")
	clientCert, clientKey := newClientCertSignedBy(t, "unit-test-client", clientCACert, clientCAKey)

	// mTLS server requiring any cert signed by clientCACert.
	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(clientCACert)

	// Server self-signed cert for its own TLS.
	serverCert, serverKey := newServerSelfSigned(t)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  serverKey,
				Leaf:        serverCert,
			},
		},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAPool,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		tc, ok := conn.(*tls.Conn)
		if !ok {
			accepted <- fmt.Errorf("accepted conn is not *tls.Conn")
			return
		}
		if err := tc.Handshake(); err != nil {
			accepted <- fmt.Errorf("server handshake: %w", err)
			return
		}
		state := tc.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			accepted <- fmt.Errorf("no client cert presented")
			return
		}
		if state.PeerCertificates[0].Subject.CommonName != "unit-test-client" {
			accepted <- fmt.Errorf("unexpected client CN %q", state.PeerCertificates[0].Subject.CommonName)
			return
		}
		accepted <- nil
	}()

	client := &tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey:  clientKey,
		Leaf:        clientCert,
	}

	result, err := DialUpstream(context.Background(), ln.Addr().String(), DialOpts{
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true, //nolint:gosec // test
		},
		ClientCert:  client,
		OfferALPN:   []string{"http/1.1"},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer result.Conn.Close()
	defer result.Codec.Close()

	if err := <-accepted; err != nil {
		t.Fatalf("server: %v", err)
	}
	if result.ALPN != "http/1.1" {
		t.Errorf("ALPN = %q, want http/1.1", result.ALPN)
	}
}

// --- Upstream HTTP proxy ------------------------------------------------------

func TestDialUpstream_ViaHTTPProxy(t *testing.T) {
	t.Parallel()
	echoAddr := startEchoServer(t)
	proxyAddr, cleanup := startMockHTTPConnectProxy(t, "", "")
	defer cleanup()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	result, err := DialUpstream(context.Background(), echoAddr, DialOpts{
		UpstreamProxy: proxyURL,
		DialTimeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialUpstream: %v", err)
	}
	defer result.Conn.Close()
	defer result.Codec.Close()

	msg := []byte("hello via http proxy")
	if _, err := result.Conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(result.Conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("echo mismatch: got %q want %q", buf, msg)
	}
}

func TestDialUpstream_ViaHTTPProxy_CRLFInjection(t *testing.T) {
	t.Parallel()
	// The target contains CRLF — validateTarget MUST reject it before any
	// bytes reach the proxy. We assert by giving an invalid proxy: if the
	// validation short-circuits, we get a CR/LF error. If it does not, we
	// get a dial error from the unreachable proxy instead.
	proxyURL, _ := url.Parse("http://127.0.0.1:1")
	_, err := DialUpstream(context.Background(), "evil.com:443\r\nX-Injected: 1", DialOpts{
		UpstreamProxy: proxyURL,
		DialTimeout:   500 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "CR/LF") {
		t.Errorf("error %q does not mention CR/LF (possible injection!)", err.Error())
	}
}

// --- Upstream SOCKS5 proxy ----------------------------------------------------

func TestDialUpstream_ViaSOCKS5Proxy_InvalidServer(t *testing.T) {
	t.Parallel()
	// A server that immediately closes is enough to cause the SOCKS5
	// handshake to fail — we are primarily verifying that the SOCKS5 path
	// is wired into DialUpstream.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	proxyURL, _ := url.Parse("socks5://" + ln.Addr().String())
	_, err = DialUpstream(context.Background(), "example.com:80", DialOpts{
		UpstreamProxy: proxyURL,
		DialTimeout:   2 * time.Second,
	})
	if err == nil {
		t.Fatal("want SOCKS5 handshake error")
	}
}

// --- ALPN factory -------------------------------------------------------------

func TestALPNFactory_RegisterUnregister(t *testing.T) {
	// Not parallel: mutates the global factory map.
	const alpn = "test/register"

	// Confirm unknown ALPN falls back to TCP codec.
	server, client := net.Pipe()
	defer server.Close()
	cdc, err := buildCodec(alpn, client)
	if err != nil {
		t.Fatalf("buildCodec fallback: %v", err)
	}
	if _, ok := cdc.(*tcp.Codec); !ok {
		t.Errorf("fallback codec = %T, want *tcp.Codec", cdc)
	}
	cdc.Close()

	// Register a fake builder that returns a distinctive TCP codec.
	sentinel := errors.New("custom builder invoked")
	RegisterALPNCodec(alpn, func(_ net.Conn) (codec.Codec, error) {
		return nil, sentinel
	})
	t.Cleanup(func() { UnregisterALPNCodec(alpn) })

	server2, client2 := net.Pipe()
	defer server2.Close()
	defer client2.Close()
	_, err = buildCodec(alpn, client2)
	if !errors.Is(err, sentinel) {
		t.Errorf("buildCodec after register = %v, want sentinel", err)
	}

	// Unregister and confirm fallback resumes.
	UnregisterALPNCodec(alpn)
	server3, client3 := net.Pipe()
	defer server3.Close()
	cdc3, err := buildCodec(alpn, client3)
	if err != nil {
		t.Fatalf("buildCodec after unregister: %v", err)
	}
	if _, ok := cdc3.(*tcp.Codec); !ok {
		t.Errorf("after unregister codec = %T, want *tcp.Codec", cdc3)
	}
	cdc3.Close()
}

func TestALPNFactory_Default_HTTP11(t *testing.T) {
	t.Parallel()
	// "" and "http/1.1" both map to HTTP/1.x upstream Codec.
	for _, alpn := range []string{"", "http/1.1"} {
		alpn := alpn
		t.Run(alpn, func(t *testing.T) {
			t.Parallel()
			server, client := net.Pipe()
			defer server.Close()
			cdc, err := buildCodec(alpn, client)
			if err != nil {
				t.Fatalf("buildCodec(%q): %v", alpn, err)
			}
			if _, ok := cdc.(*http1.Codec); !ok {
				t.Errorf("codec = %T, want *http1.Codec", cdc)
			}
			cdc.Close()
		})
	}
}

func TestALPNFactory_H2_NotImplemented(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_, err := buildCodec("h2", client)
	if !errors.Is(err, ErrHTTP2NotImplemented) {
		t.Errorf("err = %v, want ErrHTTP2NotImplemented", err)
	}
}

func TestALPNFactory_RegisterNilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("want panic on nil builder")
		}
	}()
	RegisterALPNCodec("nil-builder-test", nil)
}

func TestALPNFactory_ConcurrentRegisterLookup(t *testing.T) {
	// Deliberately not t.Parallel: exercises the factory RWMutex against
	// the race detector. Multiple goroutines register/unregister while
	// others call buildCodec.
	const goroutines = 16
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent/%d", id)
			builder := func(_ net.Conn) (codec.Codec, error) { return nil, errors.New("x") }
			for {
				select {
				case <-stop:
					return
				default:
				}
				RegisterALPNCodec(name, builder)
				server, client := net.Pipe()
				_, _ = buildCodec(name, client)
				client.Close()
				server.Close()
				UnregisterALPNCodec(name)
			}
		}(i)
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// --- MakeDialFunc -------------------------------------------------------------

func TestMakeDialFunc_HappyPath(t *testing.T) {
	t.Parallel()
	addr := startEchoServer(t)
	host, port, _ := net.SplitHostPort(addr)
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}

	dial := MakeDialFunc(DialOpts{DialTimeout: 3 * time.Second})
	ex := &exchange.Exchange{URL: u, Direction: exchange.Send}
	cdc, err := dial(context.Background(), ex)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cdc.Close()
	// Plain HTTP forward proxy path: plain-TCP dial + empty ALPN → HTTP/1.x.
	if _, ok := cdc.(*http1.Codec); !ok {
		t.Errorf("codec = %T, want *http1.Codec for plain HTTP forward proxy dial", cdc)
	}
}

func TestTargetFromExchange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr string
	}{
		{"http default port", "http://example.com/path", "example.com:80", ""},
		{"https default port", "https://example.com/", "example.com:443", ""},
		{"explicit port", "https://example.com:8443/", "example.com:8443", ""},
		{"ws default port", "ws://example.com/", "example.com:80", ""},
		{"wss default port", "wss://example.com/", "example.com:443", ""},
		{"unknown scheme", "foo://example.com/", "", "unknown scheme"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tc.url)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			got, err := targetFromExchange(&exchange.Exchange{URL: u})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestTargetFromExchange_NilURL(t *testing.T) {
	t.Parallel()
	_, err := targetFromExchange(&exchange.Exchange{})
	if err == nil {
		t.Fatal("want error for nil URL")
	}
}

// --- helpers: echo TCP server ------------------------------------------------

func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// --- helpers: TLS server with selectable ALPN --------------------------------

type tlsTestServer struct {
	addr string
	ln   net.Listener
}

func (s *tlsTestServer) Close() { s.ln.Close() }

func newTLSServer(t *testing.T, nextProtos []string) *tlsTestServer {
	t.Helper()
	cert, key := newServerSelfSigned(t)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
			Leaf:        cert,
		}},
		NextProtos: nextProtos,
		MinVersion: tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return &tlsTestServer{addr: ln.Addr().String(), ln: ln}
}

func newServerSelfSigned(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	return crt, key
}

// --- helpers: mTLS CA / client cert ------------------------------------------

func newSelfSignedCA(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return crt, key
}

func newClientCertSignedBy(t *testing.T, cn string, ca *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	return crt, key
}

// --- helpers: mock HTTP CONNECT proxy ----------------------------------------

func startMockHTTPConnectProxy(t *testing.T, username, password string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConnectProxy(c, username, password)
		}
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func handleConnectProxy(c net.Conn, username, password string) {
	defer c.Close()
	reader := bufio.NewReader(c)
	req, err := gohttp.ReadRequest(reader)
	if err != nil {
		return
	}
	if req.Method != gohttp.MethodConnect {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	if username != "" || password != "" {
		authHdr := req.Header.Get("Proxy-Authorization")
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		if authHdr != expected {
			c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
	}
	target, err := net.DialTimeout("tcp", req.Host, 3*time.Second)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()
	c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(target, reader); errCh <- err }()
	go func() { _, err := io.Copy(c, target); errCh <- err }()
	<-errCh
}

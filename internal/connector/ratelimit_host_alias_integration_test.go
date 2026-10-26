//go:build e2e && !e2e_smoke

package connector_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1263: the per-host RateLimiter and the PassthroughList compare the
// destination host in its canonical form, so respelling the host
// (trailing dot, case, IPv4-mapped IPv6, IPv6 text forms, zone, legacy
// IPv4 for the limiter) does not yield a fresh rate-limit bucket or skip
// a passthrough pattern. The CONNECT authority, the dial target and the
// recorded data are unchanged.

const rateLimitAliasDenyBody = "yorishiro-proxy: target blocked by rate limit"

// newDrainedPerHostLimiter returns a per-host limiter (one token, no
// refill within the test) whose buckets for drained are already empty.
func newDrainedPerHostLimiter(t *testing.T, drained ...string) *connector.RateLimiter {
	t.Helper()
	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerHostPerSecond: 0.001})
	for _, h := range drained {
		if d := rl.Check(h); d != nil {
			t.Fatalf("drain Check(%q) denied: %+v", h, d)
		}
	}
	return rl
}

// T1: a CONNECT to another spelling of an already rate-limited host is
// refused with 429, with an open scope and with an allow-list scope.
func TestFullListener_RateLimitHostAliases_CONNECT(t *testing.T) {
	aliases := []string{
		"localhost.", "LOCALHOST.",
		"[::ffff:127.0.0.1]", "[0:0::ffff:7f00:1]",
		"[0:0::1]", "[::1%25lo]", "[::1%lo]",
	}
	scopes := map[string]func() *connector.TargetScope{
		"open scope": func() *connector.TargetScope { return nil },
		"allow localhost/127.0.0.1/::1": func() *connector.TargetScope {
			s := connector.NewTargetScope()
			s.SetPolicyRules([]connector.TargetRule{
				{Hostname: "localhost"}, {Hostname: "127.0.0.1"}, {Hostname: "::1"},
			}, nil)
			return s
		},
	}
	// Each alias gets its own limiter and listener: an alias that slipped
	// past the limiter would otherwise create a bucket that a later alias
	// (e.g. "LOCALHOST." after "localhost.") then hits for the wrong reason.
	for name, mkScope := range scopes {
		t.Run(name, func(t *testing.T) {
			for _, host := range aliases {
				t.Run(host, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()

					rl := newDrainedPerHostLimiter(t, "localhost", "127.0.0.1", "::1")
					var onStackCalls atomic.Int32
					proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{
						rateLimiter:      rl,
						scope:            mkScope(),
						innerPeekTimeout: deniedCONNECTInnerPeek,
						onStack: func(_ context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
							defer stack.Close()
							onStackCalls.Add(1)
						},
					})

					assertCONNECTClosedPromptly(t, proxyAddr, host+":9999",
						"HTTP/1.1 429 Too Many Requests", rateLimitAliasDenyBody)
					if n := onStackCalls.Load(); n != 0 {
						t.Errorf("OnStack called %d times, want 0 (alias is rate limited)", n)
					}
				})
			}
		})
	}
}

// T3: in open mode a legacy IPv4 spelling of a rate-limited address shares
// its bucket; the limiter runs before any dial.
func TestFullListener_RateLimitHostAliases_LegacyIPv4OpenMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rl := newDrainedPerHostLimiter(t, "127.0.0.1")
	proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{
		rateLimiter:      rl,
		innerPeekTimeout: deniedCONNECTInnerPeek,
		onStack: func(_ context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			stack.Close()
		},
	})
	for _, host := range []string{"0x7f.0.0.1", "2130706433", "127.1", "127.0.0.1."} {
		t.Run(host, func(t *testing.T) {
			assertCONNECTClosedPromptly(t, proxyAddr, host+":9999",
				"HTTP/1.1 429 Too Many Requests", rateLimitAliasDenyBody)
		})
	}
}

// T2: a plain-HTTP forward request to another spelling of a rate-limited
// host is refused with 429 before the upstream dial.
func TestFullListener_RateLimitHostAliases_HTTPForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A real upstream so a request that slips past the limiter is dialed
	// and reaches OnStack.
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(upstream.Addr().String())

	for _, host := range []string{"localhost.", "LOCALHOST.", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]"} {
		t.Run(host, func(t *testing.T) {
			// A fresh limiter and listener per alias (see the CONNECT test).
			rl := newDrainedPerHostLimiter(t, "localhost", "127.0.0.1")
			var onStackCalls atomic.Int32
			fl := connector.NewFullListener(connector.FullListenerConfig{
				Name: "test-forward",
				Addr: "127.0.0.1:0",
				OnHTTP1: connector.NewHTTP1ForwardHandler(connector.HTTP1ForwardHandlerConfig{
					BuildCfg:    &connector.BuildConfig{ProxyConfig: &config.ProxyConfig{}},
					RateLimiter: rl,
					OnStack: func(_ context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
						defer stack.Close()
						onStackCalls.Add(1)
					},
				}),
			})
			go fl.Start(ctx)
			select {
			case <-fl.Ready():
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for FullListener to be ready")
			}

			authority := host + ":" + port
			conn, err := net.DialTimeout("tcp", fl.Addr(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()
			req := fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority)
			if _, err := conn.Write([]byte(req)); err != nil {
				t.Fatalf("write request: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			got, _ := io.ReadAll(conn)
			if !strings.HasPrefix(string(got), "HTTP/1.1 429 Too Many Requests\r\n") {
				t.Errorf("forward reply = %q, want 429 Too Many Requests", got)
			}
			if n := onStackCalls.Load(); n != 0 {
				t.Errorf("OnStack called %d times, want 0 (alias is rate limited)", n)
			}
		})
	}
}

// newPassthroughUpstream starts a TLS echo upstream on 127.0.0.1 with its
// own self-signed certificate (CN "passthrough-alias-upstream"), and
// returns its port and a pool trusting that certificate.
func newPassthroughUpstream(t *testing.T) (port string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1263),
		Subject:               pkix.Name{CommonName: "passthrough-alias-upstream"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	roots = x509.NewCertPool()
	roots.AddCert(leaf)
	return port, roots
}

// T8: a CONNECT whose authority respells a passthrough-listed host is
// relayed without MITM: the client handshakes with the upstream's own
// certificate.
func TestFullListener_PassthroughHostAliases(t *testing.T) {
	tests := []struct {
		pattern, connectHost, serverName string
	}{
		{"localhost", "localhost.", "localhost"},
		{"localhost", "LOCALHOST.", "localhost"},
		{"127.0.0.1", "[::ffff:127.0.0.1]", "127.0.0.1"},
		{"*.localhost", "pinned.localhost.", "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.connectHost, func(t *testing.T) {
			if tt.connectHost == "pinned.localhost." {
				if _, err := net.LookupHost("pinned.localhost"); err != nil {
					t.Skipf("resolver does not map *.localhost to loopback: %v", err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			port, roots := newPassthroughUpstream(t)
			pl := connector.NewPassthroughList()
			pl.Add(tt.pattern)

			var onStackCalls atomic.Int32
			proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{
				passthroughList: pl,
				onStack: func(_ context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
					defer stack.Close()
					onStackCalls.Add(1)
				},
			})

			conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()
			target := tt.connectHost + ":" + port
			if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
				t.Fatalf("write CONNECT: %v", err)
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read CONNECT response: %v", err)
			}
			if got := string(buf[:n]); got != "HTTP/1.1 200 Connection Established\r\n\r\n" {
				t.Fatalf("CONNECT response = %q", got)
			}

			tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: tt.serverName})
			if err := tlsConn.Handshake(); err != nil {
				t.Fatalf("TLS handshake: %v (a MITM leaf means the passthrough pattern %q did not match %q)", err, tt.pattern, tt.connectHost)
			}
			defer tlsConn.Close()
			if cn := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "passthrough-alias-upstream" {
				t.Errorf("peer cert CN = %q, want passthrough-alias-upstream", cn)
			}
			data := []byte("passthrough-alias")
			if _, err := tlsConn.Write(data); err != nil {
				t.Fatalf("write: %v", err)
			}
			echo := make([]byte, len(data))
			if _, err := io.ReadFull(tlsConn, echo); err != nil {
				t.Fatalf("read echo: %v", err)
			}
			if !bytes.Equal(echo, data) {
				t.Errorf("echo = %q, want %q", echo, data)
			}
			if n := onStackCalls.Load(); n != 0 {
				t.Errorf("OnStack called %d times, want 0 (passthrough bypasses MITM)", n)
			}
		})
	}
}

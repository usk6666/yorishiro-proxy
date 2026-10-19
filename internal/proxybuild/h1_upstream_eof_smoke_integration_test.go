//go:build e2e

package proxybuild_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1229: an upstream that reads a keep-alive HTTP/1.1 request and closes
// without a (complete) response must not leave the client hanging. The
// proxy mirrors the upstream's FIN: the client connection is ended
// promptly, as it would be talking to the origin directly.
//
// Shared helpers live here (plain //go:build e2e) so the smoke test and the
// exhaustive h1_upstream_eof_integration_test.go both compile them.

// usk1229Handler serves one accepted upstream connection. idx is 1-based.
type usk1229Handler func(idx int, c net.Conn, br *bufio.Reader)

// usk1229Upstream is a TCP (optionally TLS) upstream that counts accepted
// connections and runs handler on each.
type usk1229Upstream struct {
	ln      net.Listener
	handler usk1229Handler

	mu    sync.Mutex
	count int
	wg    sync.WaitGroup
}

func startUSK1229Upstream(t *testing.T, useTLS bool, handler usk1229Handler) *usk1229Upstream {
	t.Helper()
	var ln net.Listener
	var err error
	if useTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{usk1229SelfSignedCert(t)},
			NextProtos:   []string{"http/1.1"},
		})
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	u := &usk1229Upstream{ln: ln, handler: handler}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.mu.Lock()
			u.count++
			idx := u.count
			u.mu.Unlock()
			u.wg.Add(1)
			go func() {
				defer u.wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				u.handler(idx, c, bufio.NewReader(c))
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		done := make(chan struct{})
		go func() { u.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	return u
}

func (u *usk1229Upstream) Addr() string { return u.ln.Addr().String() }

// ConnCount returns the number of accepted upstream connections.
func (u *usk1229Upstream) ConnCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.count
}

// usk1229ReadHead reads one request line and header section (the tests
// send only bodiless requests) and returns the request-target.
func usk1229ReadHead(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", fmt.Errorf("bad request line %q", line)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		if h == "\r\n" || h == "\n" {
			return parts[1], nil
		}
	}
}

// usk1229CloseAfterRequest reads one request, waits delay, and closes the
// connection without writing a byte.
func usk1229CloseAfterRequest(delay time.Duration) usk1229Handler {
	return func(_ int, _ net.Conn, br *bufio.Reader) {
		if _, err := usk1229ReadHead(br); err != nil {
			return
		}
		time.Sleep(delay)
	}
}

// usk1229ReplyThenClose reads one request, writes reply verbatim, and
// closes the connection.
func usk1229ReplyThenClose(reply string) usk1229Handler {
	return func(_ int, c net.Conn, br *bufio.Reader) {
		if _, err := usk1229ReadHead(br); err != nil {
			return
		}
		_, _ = c.Write([]byte(reply))
		time.Sleep(50 * time.Millisecond)
	}
}

// startUSK1229MITM boots a BuildLiveStack listener (CONNECT MITM and plain
// forward-proxy paths) recording into a state-tracking flow store.
func startUSK1229MITM(t *testing.T, ctx context.Context, engine *pluginv2.Engine) (*flowStoreForH2Pool, string) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	store := &flowStoreForH2Pool{}
	stack, err := proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-1229",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
		PluginV2Engine: engine,
	})
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}
	return store, stack.Listener.Addr()
}

// usk1229DialMITM opens a CONNECT tunnel to upAddr through the proxy and
// completes a client TLS handshake (http/1.1) over it.
func usk1229DialMITM(t *testing.T, proxyAddr, upAddr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	raw, err := connectTunnelDialerForPoolTest(proxyAddr, upAddr)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // test
	t.Cleanup(func() { _ = tc.Close() })
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	return tc, bufio.NewReader(tc)
}

// usk1229ReadUntilClose reads from br until the peer closes the connection
// and returns every byte received. It fails the test if the connection is
// still open after limit, or if the close took longer than within.
func usk1229ReadUntilClose(t *testing.T, c net.Conn, br *bufio.Reader, start time.Time, within, limit time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(start.Add(limit))
	got, err := io.ReadAll(br)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("client connection still open %v after the request (received %d bytes %q); want the proxy to end it when the upstream closed",
			time.Since(start).Round(time.Millisecond), len(got), got)
	}
	if el := time.Since(start); el > within {
		t.Errorf("client connection closed after %v; want under %v", el.Round(time.Millisecond), within)
	}
	return got
}

// usk1229WaitStream polls store until a Stream reaches a terminal state
// (complete / error) and returns a snapshot of it.
func usk1229WaitStream(store *flowStoreForH2Pool, within time.Duration) *flow.Stream {
	end := time.Now().Add(within)
	for time.Now().Before(end) {
		for _, st := range store.Streams() {
			if st.State == "complete" || st.State == "error" {
				return st
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// usk1229ErrorTag returns the tags["error"] value appended to stream id.
func usk1229ErrorTag(store *flowStoreForH2Pool, id string) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, upd := range store.updates[id] {
		if v, ok := upd.AppendTags["error"]; ok {
			return v
		}
		if v, ok := upd.Tags["error"]; ok {
			return v
		}
	}
	return ""
}

func usk1229SelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1229),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestProxybuild_MITM_H1UpstreamClosesBeforeResponse_ClientEOF_Smoke is
// the USK-1229 merge-gate repro (Test Plan #1): a keep-alive HTTPS client
// through CONNECT MITM whose upstream reads the request and closes 200ms
// later receives EOF with zero bytes in well under a second, instead of
// waiting for its own timeout or the 120s keep-alive idle bound.
func TestProxybuild_MITM_H1UpstreamClosesBeforeResponse_ClientEOF_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startUSK1229Upstream(t, true, usk1229CloseAfterRequest(200*time.Millisecond))
	_, proxyAddr := startUSK1229MITM(t, ctx, nil)
	c, br := usk1229DialMITM(t, proxyAddr, up.Addr())

	start := time.Now()
	if _, err := c.Write([]byte("GET /hang HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if got := usk1229ReadUntilClose(t, c, br, start, time.Second, 3*time.Second); len(got) != 0 {
		t.Errorf("client received %q; want no bytes (the upstream sent none)", got)
	}
}

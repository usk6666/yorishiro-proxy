package proxybuild

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-1315 wiring tests: the OnStack (h1) and OnHTTP2Stack (h2) handlers
// built by proxybuild must redial with the dial target / TLS authority split
// the ConnectionStack was built for, not the callback's single target. Each
// test builds the stack through connector.BuildConnectionStack with
// UpstreamTarget{Dial: 127.0.0.1:P, TLS: a.example:P}, runs the production
// handler on it, provokes a redial, and asserts that the redial's ClientHello
// also carried SNI a.example. The callback target is the dial target, so a
// handler that redialed SameUpstreamTarget(target) would send no SNI (Go
// omits an IP-literal ServerName) and fail the assertion.

// newWiringTestBuildConfig returns a BuildConfig that MITMs with a fresh CA
// and skips upstream verification of the self-signed test upstream.
func newWiringTestBuildConfig(t *testing.T) *connector.BuildConfig {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	return &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
}

// buildSplitStack runs connector.BuildConnectionStack for ut on the proxy
// side of a local TCP connection while a TLS client offering clientALPN
// (SNI = the TLS authority's host) handshakes on the other side. When
// clientALPN is [h2], the client also starts a ClientRole http2.Layer so the
// proxy's ServerRole preface exchange completes; it is returned as clientH2.
func buildSplitStack(t *testing.T, ut connector.UpstreamTarget, cfg *connector.BuildConfig, clientALPN []string) (stack *connector.ConnectionStack, clientTLS *tls.Conn, clientH2 *http2.Layer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		stack *connector.ConnectionStack
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		sc, aerr := ln.Accept()
		if aerr != nil {
			resCh <- result{err: aerr}
			return
		}
		s, _, _, berr := connector.BuildConnectionStack(context.Background(), sc, ut, cfg, connector.ClientHelloPeek{})
		if berr != nil {
			_ = sc.Close()
		}
		resCh <- result{stack: s, err: berr}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	tlsHost, _, _ := net.SplitHostPort(ut.TLS)
	clientTLS = tls.Client(cc, &tls.Config{
		ServerName:         tlsHost,
		NextProtos:         clientALPN,
		InsecureSkipVerify: true, //nolint:gosec // test: the MITM cert is not under test
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if slices.Equal(clientALPN, []string{"h2"}) {
		clientH2, err = http2.New(clientTLS, "test-client", http2.ClientRole, http2.WithScheme("https"))
		if err != nil {
			t.Fatalf("test-client http2.New: %v", err)
		}
		t.Cleanup(func() { _ = clientH2.Close() })
	}

	var res result
	select {
	case res = <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("BuildConnectionStack timed out")
	}
	if res.err != nil {
		t.Fatalf("BuildConnectionStack(%+v): %v", ut, res.err)
	}
	t.Cleanup(func() { _ = res.stack.Close() })
	return res.stack, clientTLS, clientH2
}

// runHandlerAsync runs fn on its own goroutine under a cancellable ctx and
// registers a cleanup that cancels it and waits for fn to return.
func runHandlerAsync(t *testing.T, fn func(ctx context.Context)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("handler did not return after ctx cancel")
		}
	})
}

// readH1Response reads one Content-Length-framed HTTP/1.1 response from br
// and returns its status line and body.
func readH1Response(t *testing.T, br *bufio.Reader, bodyLen int) (status, body string) {
	t.Helper()
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	for {
		line, lerr := br.ReadString('\n')
		if lerr != nil {
			t.Fatalf("read header: %v", lerr)
		}
		if line == "\r\n" {
			break
		}
	}
	buf := make([]byte, bodyLen)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return strings.TrimRight(status, "\r\n"), string(buf)
}

// TestBuildOnStack_H1Redial_UsesStackUpstreamTarget drives the h1 OnStack
// handler (buildOnStack → runHTTP1ExchangeLoop → h1Chain): the upstream
// closes its first connection after one response, so the second request
// redials. The redial must dial the stack's dial target with SNI a.example.
func TestBuildOnStack_H1Redial_UsesStackUpstreamTarget(t *testing.T) {
	firstClosed := make(chan struct{})
	addr, snis := startSNIRecordingTLSServer(t, []string{"http/1.1"}, func(idx int, c *tls.Conn) {
		if c.Handshake() != nil {
			return
		}
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
		if idx == 0 {
			// Keep-alive expiry on the upstream side: the next exchange
			// must redial.
			_ = c.Close()
			close(firstClosed)
		}
	})
	_, port, _ := net.SplitHostPort(addr)
	ut := connector.UpstreamTarget{Dial: addr, TLS: net.JoinHostPort("a.example", port)}
	cfg := newWiringTestBuildConfig(t)

	stack, clientTLS, _ := buildSplitStack(t, ut, cfg, []string{"http/1.1"})
	onStack := buildOnStack(pipeline.New(), Deps{BuildConfig: cfg}, nil, discardLogger())
	runHandlerAsync(t, func(ctx context.Context) { onStack(ctx, stack, nil, nil, ut.Dial) })

	_ = clientTLS.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(clientTLS)
	req := "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"

	if _, err := io.WriteString(clientTLS, req); err != nil {
		t.Fatalf("write request 1: %v", err)
	}
	if status, body := readH1Response(t, br, 2); status != "HTTP/1.1 200 OK" || body != "OK" {
		t.Fatalf("response 1 = %q %q, want 200 OK", status, body)
	}
	select {
	case <-firstClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not close its first connection")
	}

	if _, err := io.WriteString(clientTLS, req); err != nil {
		t.Fatalf("write request 2: %v", err)
	}
	if status, body := readH1Response(t, br, 2); status != "HTTP/1.1 200 OK" || body != "OK" {
		t.Fatalf("response 2 = %q %q, want 200 OK over the redialed upstream", status, body)
	}

	if got := snis(); !slices.Equal(got, []string{"a.example", "a.example"}) {
		t.Errorf("upstream SNIs = %q, want [\"a.example\" \"a.example\"] (the redial must use the stack's TLS authority)", got)
	}
}

// TestBuildOnHTTP2Stack_GoAwayRedial_UsesStackUpstreamTarget drives the h2
// OnHTTP2Stack handler: the upstream sends GOAWAY on the stack's pooled
// upstream connection, which wakes the pre-warm worker into the handler's
// mint closure (connector.RedialUpstreamH2). The redial must dial the
// stack's dial target with SNI a.example.
func TestBuildOnHTTP2Stack_GoAwayRedial_UsesStackUpstreamTarget(t *testing.T) {
	sendGoAway := make(chan struct{})
	addr, snis := startSNIRecordingTLSServer(t, []string{"h2"}, func(idx int, c *tls.Conn) {
		if c.Handshake() != nil {
			return
		}
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
			return
		}
		wr := frame.NewWriter(c)
		if err := wr.WriteSettings(nil); err != nil {
			return
		}
		if idx == 0 {
			go func() {
				<-sendGoAway
				_ = wr.WriteGoAway(0, 0, nil) // NO_ERROR
			}()
		}
		_, _ = io.Copy(io.Discard, c) // drain until the test closes the conn
	})
	_, port, _ := net.SplitHostPort(addr)
	ut := connector.UpstreamTarget{Dial: addr, TLS: net.JoinHostPort("a.example", port)}
	cfg := newWiringTestBuildConfig(t)

	stack, _, _ := buildSplitStack(t, ut, cfg, []string{"h2"})
	upstreamH2 := stack.UpstreamH2Layer()
	if upstreamH2 == nil {
		t.Fatal("UpstreamH2Layer is nil")
	}
	t.Cleanup(func() { _ = upstreamH2.Close() }) // no pool owns it (cfg.HTTP2Pool == nil)

	onH2 := buildOnHTTP2Stack(pipeline.New(), Deps{BuildConfig: cfg}, discardLogger())
	runHandlerAsync(t, func(ctx context.Context) { onH2(ctx, stack, upstreamH2, nil, nil, ut.Dial) })

	close(sendGoAway)

	deadline := time.Now().Add(10 * time.Second)
	for len(snis()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := snis(); !slices.Equal(got, []string{"a.example", "a.example"}) {
		t.Errorf("upstream SNIs = %q, want [\"a.example\" \"a.example\"] (the GOAWAY redial must use the stack's TLS authority)", got)
	}
}

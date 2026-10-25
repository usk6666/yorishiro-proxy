package connector

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// startTestCONNECTProxy runs a minimal HTTP CONNECT proxy on loopback that
// tunnels every accepted CONNECT to the requested target. It returns the
// proxy's listen address.
func startTestCONNECTProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveTestCONNECT(c)
			}()
		}
	}()
	return ln.Addr().String()
}

func serveTestCONNECT(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if l == "\r\n" {
			break
		}
	}
	up, err := net.DialTimeout("tcp", fields[1], 5*time.Second)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// startTestTCPSink accepts connections and holds them open until cleanup.
func startTestTCPSink(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen sink: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

func TestWithUpstreamPeer_DirectDial(t *testing.T) {
	target := startTestTCPSink(t)
	conn, _, err := DialUpstreamRaw(context.Background(), target, DialRawOpts{DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("DialUpstreamRaw: %v", err)
	}
	defer conn.Close()

	base := envelope.EnvelopeContext{ConnID: "c1", TargetHost: target}
	got := WithUpstreamPeer(base, conn)
	if got.ServerAddr == nil || got.ServerAddr.String() != target {
		t.Errorf("ServerAddr = %v, want %s", got.ServerAddr, target)
	}
	if got.UpstreamProxy != "" {
		t.Errorf("UpstreamProxy = %q, want empty for a direct dial", got.UpstreamProxy)
	}
	if got.ConnID != "c1" || got.TargetHost != target {
		t.Errorf("WithUpstreamPeer clobbered base fields: %+v", got)
	}
}

func TestWithUpstreamPeer_ViaHTTPProxy_RedactsCredentials(t *testing.T) {
	target := startTestTCPSink(t)
	proxyAddr := startTestCONNECTProxy(t)

	tests := []struct {
		name     string
		proxyURL string
	}{
		{name: "user and password", proxyURL: "http://alice:s3cret-pass@" + proxyAddr},
		{name: "single token userinfo", proxyURL: "http://tok3n-only@" + proxyAddr},
		{name: "no userinfo", proxyURL: "http://" + proxyAddr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.proxyURL)
			if err != nil {
				t.Fatalf("parse proxy URL: %v", err)
			}
			conn, _, err := DialUpstreamRaw(context.Background(), target, DialRawOpts{
				UpstreamProxy: u,
				DialTimeout:   5 * time.Second,
			})
			if err != nil {
				t.Fatalf("DialUpstreamRaw via proxy: %v", err)
			}
			defer conn.Close()

			want := "http://" + proxyAddr
			if got := UpstreamProxyOf(conn); got != want {
				t.Errorf("UpstreamProxyOf = %q, want %q", got, want)
			}
			got := WithUpstreamPeer(envelope.EnvelopeContext{}, conn)
			if got.ServerAddr == nil || got.ServerAddr.String() != proxyAddr {
				t.Errorf("ServerAddr = %v, want proxy address %s (socket peer, not final target)", got.ServerAddr, proxyAddr)
			}
			if got.UpstreamProxy != want {
				t.Errorf("UpstreamProxy = %q, want %q", got.UpstreamProxy, want)
			}
			for _, secret := range []string{"alice", "s3cret", "tok3n", "@", "xxxxx"} {
				if strings.Contains(got.UpstreamProxy, secret) {
					t.Errorf("UpstreamProxy %q leaks userinfo fragment %q", got.UpstreamProxy, secret)
				}
			}
		})
	}
}

func TestWithUpstreamPeer_ViaHTTPProxy_TLSUpstream(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)
	target := srv.Listener.Addr().String()
	proxyAddr := startTestCONNECTProxy(t)
	u, _ := url.Parse("http://user:pw@" + proxyAddr)

	conn, snap, err := DialUpstreamRaw(context.Background(), target, DialRawOpts{
		TLSConfig:          &tls.Config{ServerName: "127.0.0.1"},
		InsecureSkipVerify: true,
		OfferALPN:          []string{"http/1.1"},
		UpstreamProxy:      u,
		DialTimeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialUpstreamRaw TLS via proxy: %v", err)
	}
	defer conn.Close()
	if snap == nil {
		t.Fatal("expected TLS snapshot")
	}

	got := WithUpstreamPeer(envelope.EnvelopeContext{TLS: snap}, conn)
	if got.ServerAddr == nil || got.ServerAddr.String() != proxyAddr {
		t.Errorf("ServerAddr = %v, want proxy address %s", got.ServerAddr, proxyAddr)
	}
	if want := "http://" + proxyAddr; got.UpstreamProxy != want {
		t.Errorf("UpstreamProxy = %q, want %q (must survive the TLS wrap)", got.UpstreamProxy, want)
	}
	if got.TLS != snap {
		t.Error("WithUpstreamPeer dropped the TLS snapshot")
	}
}

func TestWithUpstreamPeer_NilConn(t *testing.T) {
	base := envelope.EnvelopeContext{ConnID: "c1"}
	got := WithUpstreamPeer(base, nil)
	if got.ServerAddr != nil || got.UpstreamProxy != "" || got.ConnID != "c1" {
		t.Errorf("WithUpstreamPeer(nil conn) = %+v, want base unchanged", got)
	}
}

// TestRedialUpstreamH1_RefreshesServerAddr pins that an HTTP/1.x redial
// replaces the stale socket's peer in the copied EnvelopeContext template
// with the fresh socket's peer.
func TestRedialUpstreamH1_RefreshesServerAddr(t *testing.T) {
	staleAddr := startTestTCPSink(t)
	freshAddr := startTestTCPSink(t)

	staleConn, err := net.Dial("tcp", staleAddr)
	if err != nil {
		t.Fatalf("dial stale: %v", err)
	}
	stale := http1.New(staleConn, "c1/upstream", envelope.Receive,
		http1.WithScheme("http"),
		http1.WithEnvelopeContext(WithUpstreamPeer(envelope.EnvelopeContext{
			ConnID:        "c1",
			TargetHost:    freshAddr,
			ServerAddr:    staleConn.RemoteAddr(),
			UpstreamProxy: "http://stale-proxy.invalid:1",
		}, staleConn)),
	)
	defer stale.Close()

	fresh, err := RedialUpstreamH1(context.Background(), SameUpstreamTarget(freshAddr), UpstreamTLSProfiled, stale, &BuildConfig{}, 1)
	if err != nil {
		t.Fatalf("RedialUpstreamH1: %v", err)
	}
	defer fresh.Close()

	tmpl := fresh.EnvelopeContextTemplate()
	if tmpl.ServerAddr == nil || tmpl.ServerAddr.String() != freshAddr {
		t.Errorf("fresh ServerAddr = %v, want %s", tmpl.ServerAddr, freshAddr)
	}
	if tmpl.UpstreamProxy != "" {
		t.Errorf("fresh UpstreamProxy = %q, want empty (direct redial)", tmpl.UpstreamProxy)
	}
}

// TestRedialUpstreamH2_RefreshesServerAddr is the HTTP/2 sibling of
// TestRedialUpstreamH1_RefreshesServerAddr.
func TestRedialUpstreamH2_RefreshesServerAddr(t *testing.T) {
	newH2Server := func() *httptest.Server {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		s.EnableHTTP2 = true
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	staleSrv := newH2Server()
	freshSrv := newH2Server()
	staleAddr := staleSrv.Listener.Addr().String()
	freshAddr := freshSrv.Listener.Addr().String()

	cfg := &BuildConfig{InsecureSkipVerify: true}
	staleConn, _, err := DialUpstreamRaw(context.Background(), staleAddr, DialRawOpts{
		TLSConfig:          &tls.Config{ServerName: "127.0.0.1"},
		InsecureSkipVerify: true,
		OfferALPN:          []string{"h2"},
		DialTimeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial stale: %v", err)
	}
	stale, err := http2.New(staleConn, "c1/upstream", http2.ClientRole,
		http2.WithScheme("https"),
		http2.WithEnvelopeContext(envelope.EnvelopeContext{
			ConnID:        "c1",
			TargetHost:    freshAddr,
			ServerAddr:    staleConn.RemoteAddr(),
			UpstreamProxy: "http://stale-proxy.invalid:1",
		}),
	)
	if err != nil {
		t.Fatalf("http2.New stale: %v", err)
	}
	defer stale.Close()

	fresh, err := RedialUpstreamH2(context.Background(), SameUpstreamTarget(freshAddr), stale, cfg, 1, nil)
	if err != nil {
		t.Fatalf("RedialUpstreamH2: %v", err)
	}
	defer fresh.Close()

	tmpl := fresh.EnvelopeContextTemplate()
	if tmpl.ServerAddr == nil || tmpl.ServerAddr.String() != freshAddr {
		t.Errorf("fresh ServerAddr = %v, want %s", tmpl.ServerAddr, freshAddr)
	}
	if tmpl.UpstreamProxy != "" {
		t.Errorf("fresh UpstreamProxy = %q, want empty (direct redial)", tmpl.UpstreamProxy)
	}
}

//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1117 through BuildLiveStack (the production listener wiring): the
// explicit plain-HTTP forward proxy sends origin-form without
// Proxy-Connection / Proxy-Authorization, also through an upstream proxy
// and after a stale-upstream redial; plaintext inside a CONNECT or SOCKS5
// tunnel is the client's own choice and stays verbatim.

// fwdHeads is a TCP upstream that records every request head byte-for-byte
// and answers 200 (keep-alive). closeAfter closes each connection after
// that many responses (0 = never), so the proxy's pooled upstream goes
// stale.
type fwdHeads struct {
	ln         net.Listener
	closeAfter int
	mu         sync.Mutex
	heads      []string
	conns      int
	got        chan struct{}
}

func startFwdHeads(t *testing.T, closeAfter int) *fwdHeads {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &fwdHeads{ln: ln, closeAfter: closeAfter, got: make(chan struct{}, 16)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.mu.Lock()
			u.conns++
			u.mu.Unlock()
			go u.serve(c)
		}
	}()
	return u
}

func (u *fwdHeads) addr() string { return u.ln.Addr().String() }

func (u *fwdHeads) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)
	for served := 0; ; {
		var head bytes.Buffer
		for {
			line, err := br.ReadBytes('\n')
			head.Write(line)
			if err != nil {
				return
			}
			if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
				break
			}
		}
		u.mu.Lock()
		u.heads = append(u.heads, head.String())
		u.mu.Unlock()
		u.got <- struct{}{}
		if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
			return
		}
		served++
		if u.closeAfter > 0 && served >= u.closeAfter {
			return
		}
	}
}

func (u *fwdHeads) waitHead(t *testing.T, n int) string {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		u.mu.Lock()
		if len(u.heads) >= n {
			h := u.heads[n-1]
			u.mu.Unlock()
			return h
		}
		u.mu.Unlock()
		select {
		case <-u.got:
		case <-deadline:
			t.Fatalf("upstream did not receive request %d within 10s", n)
		}
	}
}

func (u *fwdHeads) connCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conns
}

// fwdReq is the curl 8.14.1 forward-proxy request shape (absolute-form +
// Proxy-Connection) plus a Proxy-Authorization, with mixed casing and OWS
// interleaved so header order and byte fidelity are observable.
func fwdReq(upAddr, path, connection string) string {
	return "GET http://" + upAddr + path + " HTTP/1.1\r\n" +
		"X-A:  1 \r\n" +
		"host: " + upAddr + "\r\n" +
		"proxy-authorization: Basic dXNlcjpwYXNz\r\n" +
		"User-Agent: curl/8.14.1\r\n" +
		"Accept: */*\r\n" +
		"Proxy-Connection: Keep-Alive\r\n" +
		"Connection: " + connection + "\r\n" +
		"\r\n"
}

func fwdWant(upAddr, path, connection string) string {
	return "GET " + path + " HTTP/1.1\r\n" +
		"X-A:  1 \r\n" +
		"host: " + upAddr + "\r\n" +
		"User-Agent: curl/8.14.1\r\n" +
		"Accept: */*\r\n" +
		"Connection: " + connection + "\r\n" +
		"\r\n"
}

func startFwdOriginFormStack(t *testing.T, mutate func(*connector.BuildConfig)) (*flowStoreForH2Pool, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	if mutate != nil {
		mutate(buildCfg)
	}
	store := &flowStoreForH2Pool{}
	stack, err := proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-1117",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig:  buildCfg,
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

// readFwdResponse reads one Content-Length response off br.
func readFwdResponse(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	n := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(k, "Content-Length") {
			n, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if _, err := io.CopyN(io.Discard, br, int64(n)); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return strings.TrimRight(status, "\r\n")
}

func fwdDial(t *testing.T, proxyAddr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	return c, bufio.NewReader(c)
}

// TestProxybuild_ForwardOriginForm_StripsAndRecords is T1 + T2: the
// upstream receives origin-form without Proxy-*, every other header in
// order with its casing and OWS, Host as sent; the Send flow is the
// client bytes and no modified variant is recorded.
func TestProxybuild_ForwardOriginForm_StripsAndRecords(t *testing.T) {
	up := startFwdHeads(t, 0)
	store, proxyAddr := startFwdOriginFormStack(t, nil)

	req := fwdReq(up.addr(), "/echo?y2=1", "close")
	c, br := fwdDial(t, proxyAddr)
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if status := readFwdResponse(t, br); !strings.Contains(status, " 200 ") {
		t.Fatalf("status = %q, want 200", status)
	}
	if got, want := up.waitHead(t, 1), fwdWant(up.addr(), "/echo?y2=1", "close"); got != want {
		t.Errorf("upstream head:\n got %q\nwant %q", got, want)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		var sends []string
		var variants []string
		for _, f := range store.Flows() {
			if f.Direction == "send" {
				sends = append(sends, string(f.RawBytes))
				variants = append(variants, f.Metadata["variant"])
			}
		}
		if len(sends) > 0 || time.Now().After(deadline) {
			if len(sends) != 1 || sends[0] != req {
				t.Errorf("send flows raw = %q, want exactly one with the client bytes %q", sends, req)
			}
			for _, v := range variants {
				if v == "modified" {
					t.Errorf("a modified variant was recorded for the proxy-form removal")
				}
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fwdConnectProxy is an upstream HTTP CONNECT proxy that records each
// CONNECT head and relays the tunnel.
type fwdConnectProxy struct {
	ln       net.Listener
	mu       sync.Mutex
	connects []string
}

func startFwdConnectProxy(t *testing.T) *fwdConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &fwdConnectProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *fwdConnectProxy) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)
	var head bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		head.Write(line)
		if err != nil {
			return
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	p.mu.Lock()
	p.connects = append(p.connects, head.String())
	p.mu.Unlock()
	fields := strings.Fields(strings.SplitN(head.String(), "\r\n", 2)[0])
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return
	}
	up, err := net.DialTimeout("tcp", fields[1], 5*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func (p *fwdConnectProxy) connectHeads() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...)
}

// TestProxybuild_ForwardOriginForm_ThroughUpstreamProxy is T4: through an
// upstream CONNECT proxy the tunnelled request is origin-form without
// Proxy-*; the CONNECT itself is unaffected.
func TestProxybuild_ForwardOriginForm_ThroughUpstreamProxy(t *testing.T) {
	up := startFwdHeads(t, 0)
	chain := startFwdConnectProxy(t)
	_, proxyAddr := startFwdOriginFormStack(t, func(c *connector.BuildConfig) {
		c.SetUpstreamProxy(&url.URL{Scheme: "http", Host: chain.ln.Addr().String()})
	})

	c, br := fwdDial(t, proxyAddr)
	if _, err := c.Write([]byte(fwdReq(up.addr(), "/via-proxy", "close"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	if status := readFwdResponse(t, br); !strings.Contains(status, " 200 ") {
		t.Fatalf("status = %q, want 200", status)
	}
	if got, want := up.waitHead(t, 1), fwdWant(up.addr(), "/via-proxy", "close"); got != want {
		t.Errorf("upstream head:\n got %q\nwant %q", got, want)
	}
	heads := chain.connectHeads()
	if len(heads) != 1 || !strings.HasPrefix(heads[0], "CONNECT "+up.addr()+" HTTP/1.1\r\n") {
		t.Errorf("upstream proxy saw %q, want one CONNECT %s", heads, up.addr())
	}
}

// TestProxybuild_ForwardOriginForm_RedialKeepsTransform is T11: the
// upstream FINs after each response, so the second request on the same
// client connection goes out on a redialed upstream — still origin-form
// without Proxy-*.
func TestProxybuild_ForwardOriginForm_RedialKeepsTransform(t *testing.T) {
	up := startFwdHeads(t, 1)
	_, proxyAddr := startFwdOriginFormStack(t, nil)

	c, br := fwdDial(t, proxyAddr)
	if _, err := c.Write([]byte(fwdReq(up.addr(), "/first", "keep-alive"))); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if status := readFwdResponse(t, br); !strings.Contains(status, " 200 ") {
		t.Fatalf("status 1 = %q, want 200", status)
	}
	if got, want := up.waitHead(t, 1), fwdWant(up.addr(), "/first", "keep-alive"); got != want {
		t.Errorf("upstream head 1:\n got %q\nwant %q", got, want)
	}
	// Let the upstream FIN reach the proxy so the pooled conn is stale.
	time.Sleep(200 * time.Millisecond)
	if _, err := c.Write([]byte(fwdReq(up.addr(), "/second", "keep-alive"))); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if status := readFwdResponse(t, br); !strings.Contains(status, " 200 ") {
		t.Fatalf("status 2 = %q, want 200", status)
	}
	if got, want := up.waitHead(t, 2), fwdWant(up.addr(), "/second", "keep-alive"); got != want {
		t.Errorf("upstream head 2 (redialed):\n got %q\nwant %q", got, want)
	}
	if n := up.connCount(); n != 2 {
		t.Errorf("upstream connections = %d, want 2 (the second request must be redialed)", n)
	}
}

// TestProxybuild_ForwardOriginForm_TunnelPlaintextVerbatim is T12: plain
// HTTP inside a CONNECT or SOCKS5 tunnel is the client's own choice of
// form; absolute-form and Proxy-* reach the upstream as sent.
func TestProxybuild_ForwardOriginForm_TunnelPlaintextVerbatim(t *testing.T) {
	t.Run("CONNECT", func(t *testing.T) {
		up := startFwdHeads(t, 0)
		_, proxyAddr := startFwdOriginFormStack(t, nil)
		c, br := fwdDial(t, proxyAddr)
		if _, err := c.Write([]byte("CONNECT " + up.addr() + " HTTP/1.1\r\nHost: " + up.addr() + "\r\n\r\n")); err != nil {
			t.Fatalf("write CONNECT: %v", err)
		}
		if status := readFwdResponse(t, br); !strings.Contains(status, " 200") {
			t.Fatalf("CONNECT status = %q, want 200", status)
		}
		req := fwdReq(up.addr(), "/in-tunnel", "close")
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if status := readFwdResponse(t, br); !strings.Contains(status, " 200 ") {
			t.Fatalf("status = %q, want 200", status)
		}
		if got := up.waitHead(t, 1); got != req {
			t.Errorf("upstream head = %q, want verbatim %q", got, req)
		}
	})
	t.Run("SOCKS5", func(t *testing.T) {
		up := startFwdHeads(t, 0)
		_, proxyAddr := startFwdOriginFormStack(t, nil)
		c, br := fwdDial(t, proxyAddr)
		_, portStr, _ := net.SplitHostPort(up.addr())
		port, _ := strconv.Atoi(portStr)
		hello := []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
		hello = binary.BigEndian.AppendUint16(hello, uint16(port))
		if _, err := c.Write(hello); err != nil {
			t.Fatalf("write SOCKS5: %v", err)
		}
		reply := make([]byte, 12)
		if _, err := io.ReadFull(br, reply); err != nil || reply[0] != 0x05 || reply[1] != 0x00 || reply[3] != 0x00 {
			t.Fatalf("SOCKS5 reply = %x, err %v; want success", reply, err)
		}
		req := fwdReq(up.addr(), "/in-socks", "close")
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if status := readFwdResponse(t, br); !strings.Contains(status, " 200 ") {
			t.Fatalf("status = %q, want 200", status)
		}
		if got := up.waitHead(t, 1); got != req {
			t.Errorf("upstream head = %q, want verbatim %q", got, req)
		}
	})
}

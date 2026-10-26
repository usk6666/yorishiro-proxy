//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// USK-1185: request_timeout_ms: 0 disables every client-side receive
// deadline it governs, and client_idle_timeout_ms sets the HTTP/1.x
// keep-alive wait. Each listener boots at a short 200ms bound first, so a
// "disabled" that silently falls back to the static value or a package
// default is caught.

const usk1185Boot = 200 * time.Millisecond

// usk1185Trickle is how long each trickled head takes: well past the boot
// bound.
const usk1185Gap = 25 * time.Millisecond

// startUSK1185Proxy starts a listener whose Manager booted at the 200ms
// bound and then had mutate applied (as MCP configure would).
func startUSK1185Proxy(t *testing.T, ctx context.Context, store flow.Writer, mutate func(*proxybuild.Manager)) (*proxybuild.Manager, string) {
	t.Helper()
	mgr := newUSK1162Manager(t, store, usk1185Boot)
	if mutate != nil {
		mutate(mgr)
	}
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	running, addr := mgr.Status()
	if !running || addr == "" {
		t.Fatal("no listener address")
	}
	return mgr, addr
}

func usk1185Disable(m *proxybuild.Manager) { m.DisableRequestTimeout() }

// usk1185TrickleAll writes b one byte per gap and returns once done.
func usk1185TrickleAll(t *testing.T, w io.Writer, b []byte, gap time.Duration) {
	t.Helper()
	for i := range b {
		time.Sleep(gap)
		if _, err := w.Write(b[i : i+1]); err != nil {
			t.Fatalf("trickle byte %d: %v", i, err)
		}
	}
}

// usk1185SlowFinishConn passes the first Write (the ClientHello) through and
// delays the second (the client's Finished) by delay, so the proxy's
// client-side handshake spans more than the boot bound.
type usk1185SlowFinishConn struct {
	net.Conn
	delay time.Duration
	mu    sync.Mutex
	n     int
}

func (c *usk1185SlowFinishConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.n++
	n := c.n
	c.mu.Unlock()
	if n == 2 {
		time.Sleep(c.delay)
	}
	return c.Conn.Write(b)
}

// T7: plain HTTP with request_timeout_ms disabled — a head trickled far
// past the 200ms boot bound is answered and recorded complete.
func TestProxybuild_PlainHTTP_RequestTimeoutDisabled_TrickledHeadAnswered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	store := &flowStoreCapture{}
	_, proxyAddr := startUSK1185Proxy(t, ctx, store, usk1185Disable)

	conn, br := usk1162Dial(t, proxyAddr)
	start := time.Now()
	usk1185TrickleAll(t, conn, []byte(usk1162Get(host, "/slow")), usk1185Gap)
	if el := time.Since(start); el < 4*usk1185Boot {
		t.Fatalf("trickle took only %v; the test would not exceed the boot bound", el)
	}
	if code, body := usk1162ReadResponse(t, conn, br); code != 200 || body != "path=/slow body=" {
		t.Fatalf("trickled request = %d %q, want 200", code, body)
	}
	usk1162AwaitSingleComplete(t, store, 5*time.Second)
}

// T8: CONNECT + TLS MITM with request_timeout_ms disabled — a trickled
// CONNECT, a 6s pause before the first inner byte (past the 5s inner-peek
// default), a slow client handshake, and a trickled inner head all go
// through.
func TestProxybuild_CONNECT_MITM_RequestTimeoutDisabled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		fmt.Fprintf(w, "tls path=%s", r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	target := strings.TrimPrefix(upstream.URL, "https://")
	_, proxyAddr := startUSK1185Proxy(t, ctx, &flowStoreCapture{}, usk1185Disable)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\n"); err != nil {
		t.Fatalf("write CONNECT line: %v", err)
	}
	usk1185TrickleAll(t, conn, []byte("Host: "+target+"\r\n\r\n"), usk1185Gap)
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT response = %q, err = %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("CONNECT response headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	time.Sleep(6 * time.Second) // > connector.DefaultInnerPeekTimeout (5s)

	tc := tls.Client(&usk1185SlowFinishConn{Conn: conn, delay: 4 * usk1185Boot}, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test against the MITM CA
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"http/1.1"},
		MaxVersion:         tls.VersionTLS13,
	})
	t.Cleanup(func() { _ = tc.Close() })
	hsCtx, hsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer hsCancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		t.Fatalf("client TLS handshake through the tunnel: %v", err)
	}
	usk1185TrickleAll(t, tc, []byte("GET /mitm HTTP/1.1\r\nHost: "+target+"\r\n\r\n"), usk1185Gap)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := gohttp.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read MITM response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "tls path=/mitm" {
		t.Fatalf("MITM response = %d %q", resp.StatusCode, body)
	}
}

// T9: SOCKS5 with request_timeout_ms disabled — a 6s pause after the
// SOCKS5 reply (past the 5s inner-peek default) before the inner request.
func TestProxybuild_SOCKS5_RequestTimeoutDisabled_InnerPeekNotBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	_, proxyAddr := startUSK1185Proxy(t, ctx, &flowStoreCapture{}, usk1185Disable)

	conn, rep := socks5Connect(t, proxyAddr, host, port)
	if rep != 0x00 {
		t.Fatalf("SOCKS5 REP = %#x, want 0x00", rep)
	}
	// socks5Connect read VER REP RSV ATYP; drain BND.ADDR + BND.PORT.
	// The proxy replies with an IPv4 bound address.
	if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
		t.Fatalf("drain SOCKS5 reply: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})

	time.Sleep(6 * time.Second) // > connector.DefaultInnerPeekTimeout (5s)

	br := bufio.NewReader(conn)
	code, body := usk1162RoundTrip(t, conn, br, "GET /socks HTTP/1.1\r\nHost: "+host+":"+portStr+"\r\n\r\n")
	if code != 200 || body != "path=/socks body=" {
		t.Fatalf("SOCKS5 inner request = %d %q", code, body)
	}
}

// T10: client_idle_timeout_ms sets the keep-alive wait; 0 disables it.
func TestProxybuild_PlainHTTP_ClientIdleTimeout(t *testing.T) {
	t.Run("300ms closes a silent keep-alive connection", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		upstream := startUSK1162Upstream(t)
		host := strings.TrimPrefix(upstream.URL, "http://")
		_, proxyAddr := startUSK1185Proxy(t, ctx, &flowStoreCapture{}, func(m *proxybuild.Manager) {
			m.SetClientIdleTimeout(300 * time.Millisecond)
		})

		conn, br := usk1162Dial(t, proxyAddr)
		if code, _ := usk1162RoundTrip(t, conn, br, usk1162Get(host, "/one")); code != 200 {
			t.Fatalf("request 1 = %d", code)
		}
		start := time.Now()
		if got := usk1162AwaitClose(t, br, conn, 3*time.Second); got != "" {
			t.Errorf("proxy wrote %q to an idle keep-alive connection", got)
		}
		if el := time.Since(start); el < 200*time.Millisecond {
			t.Errorf("idle connection closed after %v, want ~300ms", el)
		}
	})
	t.Run("disabled keeps a silent keep-alive connection open", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		upstream := startUSK1162Upstream(t)
		host := strings.TrimPrefix(upstream.URL, "http://")
		_, proxyAddr := startUSK1185Proxy(t, ctx, &flowStoreCapture{}, func(m *proxybuild.Manager) {
			m.SetClientIdleTimeout(300 * time.Millisecond)
			m.DisableClientIdleTimeout()
		})

		conn, br := usk1162Dial(t, proxyAddr)
		if code, _ := usk1162RoundTrip(t, conn, br, usk1162Get(host, "/one")); code != 200 {
			t.Fatalf("request 1 = %d", code)
		}
		time.Sleep(1500 * time.Millisecond)
		if code, body := usk1162RoundTrip(t, conn, br, usk1162Get(host, "/two")); code != 200 || body != "path=/two body=" {
			t.Fatalf("request 2 after 1.5s idle = %d %q", code, body)
		}
	})
}

// T11: tcp_forwards tls:true with request_timeout_ms disabled — a client
// handshake slower than the boot bound completes.
func TestProxybuild_TCPForward_TLS_RequestTimeoutDisabled_SlowHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	mgr, _ := startUSK1185Proxy(t, ctx, &flowStoreCapture{}, usk1185Disable)
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: host, Protocol: "http", TLS: true},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]
	if fwdAddr == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}

	raw, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	tc := tls.Client(&usk1185SlowFinishConn{Conn: raw, delay: 4 * usk1185Boot}, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test against the MITM CA
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"http/1.1"},
		MaxVersion:         tls.VersionTLS13,
	})
	hsCtx, hsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer hsCancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(tc, "GET /fwd HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := gohttp.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "path=/fwd body=" {
		t.Fatalf("forward response = %d %q", resp.StatusCode, body)
	}
}

// T14: the transparent plain-HTTP route reads the first request head
// before the dial when a Host name must admit the connection. That read is
// bounded by a fixed 30s; with request_timeout_ms disabled it is not
// bounded. The bound is seeded short (200ms) through the test hook.
func TestTransparent_HTTPNameAdmit_RequestTimeoutDisabled_TrickledHead(t *testing.T) {
	restore := connector.SetTransparentHeadTimeoutForTest(usk1185Boot)
	t.Cleanup(restore)
	scope := func() *connector.TargetScope {
		return policyScope([]connector.TargetRule{{Hostname: "allowed.example"}}, nil)
	}
	// The request line goes out in one write so the transparent peek
	// classifies the connection as HTTP; the header section is trickled.
	const reqLine = "GET /t HTTP/1.1\r\n"
	const headers = "Host: allowed.example\r\nConnection: close\r\n\r\n"

	run := func(t *testing.T, disable bool) *gohttp.Response {
		t.Helper()
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) {
			d.Scope = scope()
			d.NameResolver = newFakeNameResolver(map[string][]netip.Addr{"allowed.example": {netip.MustParseAddr("127.0.0.1")}})
			if disable {
				d.BuildConfig.DisableRequestHeaderTimeout()
			}
		})
		c := p.dial(t)
		if _, err := io.WriteString(c, reqLine); err != nil {
			t.Fatalf("write request line: %v", err)
		}
		// A refusal closes the connection mid-trickle; stop writing then
		// and read the response.
		for i := 0; i < len(headers); i++ {
			time.Sleep(usk1185Gap)
			if _, err := io.WriteString(c, headers[i:i+1]); err != nil {
				break
			}
		}
		resp, err := gohttp.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp
	}

	t.Run("enabled: the seeded bound refuses the trickled head", func(t *testing.T) {
		if resp := run(t, false); resp.StatusCode == 200 {
			t.Fatalf("trickled head admitted with the seeded 200ms bound; the hook did not engage")
		}
	})
	t.Run("disabled: the trickled head is admitted", func(t *testing.T) {
		if resp := run(t, true); resp.StatusCode != 200 {
			t.Fatalf("status %d, want 200 (the head read must not be bounded with request_timeout_ms disabled)", resp.StatusCode)
		}
	})
}

// T10b: client_idle_timeout_ms also bounds the keep-alive wait on the
// CONNECT + TLS MITM HTTP/1.x path.
func TestProxybuild_CONNECT_MITM_ClientIdleTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		fmt.Fprintf(w, "tls path=%s", r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	target := strings.TrimPrefix(upstream.URL, "https://")
	_, proxyAddr := startUSK1185Proxy(t, ctx, &flowStoreCapture{}, func(m *proxybuild.Manager) {
		m.SetClientIdleTimeout(300 * time.Millisecond)
	})

	conn, br := usk1162Dial(t, proxyAddr)
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	// Parse as a CONNECT response: a 2xx to CONNECT has no body.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	connectResp, err := gohttp.ReadResponse(br, &gohttp.Request{Method: gohttp.MethodConnect})
	if err != nil || connectResp.StatusCode != 200 {
		t.Fatalf("CONNECT response = %v, err = %v", connectResp, err)
	}
	if br.Buffered() != 0 {
		t.Fatalf("%d unexpected bytes after the CONNECT response", br.Buffered())
	}
	_ = conn.SetReadDeadline(time.Time{})
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test against the MITM CA
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"http/1.1"},
	})
	t.Cleanup(func() { _ = tc.Close() })
	hsCtx, hsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer hsCancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		t.Fatalf("client TLS handshake through the tunnel: %v", err)
	}
	tbr := bufio.NewReader(tc)
	if code, body := usk1162RoundTrip(t, tc, tbr, "GET /one HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); code != 200 || body != "tls path=/one" {
		t.Fatalf("MITM request 1 = %d %q", code, body)
	}
	start := time.Now()
	if got := usk1162AwaitClose(t, tbr, conn, 3*time.Second); got != "" {
		t.Errorf("proxy wrote %q to an idle MITM keep-alive connection", got)
	}
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Errorf("idle MITM connection closed after %v, want ~300ms", el)
	}
}

// T10c: client_idle_timeout_ms also bounds the keep-alive wait on the
// target-override HTTP/1.x path (tcp_forwards protocol "http").
func TestProxybuild_TCPForward_HTTP_ClientIdleTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	mgr, _ := startUSK1185Proxy(t, ctx, &flowStoreCapture{}, func(m *proxybuild.Manager) {
		m.SetClientIdleTimeout(300 * time.Millisecond)
	})
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: host, Protocol: "http"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]
	if fwdAddr == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}

	conn, br := usk1162Dial(t, fwdAddr)
	if code, body := usk1162RoundTrip(t, conn, br, "GET /fwd HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); code != 200 || body != "path=/fwd body=" {
		t.Fatalf("forward request 1 = %d %q", code, body)
	}
	start := time.Now()
	if got := usk1162AwaitClose(t, br, conn, 3*time.Second); got != "" {
		t.Errorf("proxy wrote %q to an idle forward keep-alive connection", got)
	}
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Errorf("idle forward connection closed after %v, want ~300ms", el)
	}
}

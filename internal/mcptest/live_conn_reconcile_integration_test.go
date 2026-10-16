//go:build e2e && !e2e_smoke

// USK-1160 exhaustive tier: the other routes and triggers of live-connection
// reconciliation. Helpers live in live_conn_reconcile_smoke_integration_test.go.
package mcptest_test

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // RFC 6455 Sec-WebSocket-Accept is defined over SHA-1
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// bootReloadHarness boots the harness with a policy file allowing
// 127.0.0.1 and returns it with the policy path.
func bootReloadHarness(t *testing.T) (*mcptest.Harness, string) {
	t.Helper()
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	writePolicyFile(t, policyPath, `{"allows":[{"hostname":"127.0.0.1"}]}`)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-target-policy-file", policyPath},
	})
	return h, policyPath
}

func reloadDenyLoopback(t *testing.T, h *mcptest.Harness, policyPath string) {
	t.Helper()
	writePolicyFile(t, policyPath, `{"denies":[{"hostname":"127.0.0.1"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy: %v", err)
	}
}

func splitHostPortInt(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// TestE2E_LiveConnReconcile_SOCKS5PassthroughCutOnReload is T2 /
// acceptance criterion 2 (SOCKS5 passthrough).
func TestE2E_LiveConnReconcile_SOCKS5PassthroughCutOnReload(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	target := upstream.Listener.Addr().String()
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithPassthrough(t, h, "127.0.0.1")

	host, port := splitHostPortInt(t, target)
	raw := socks5DialNoAuth(t, proxyAddr, host, port)
	c := clientTLSOver(t, raw)
	assertPassthrough(t, c, upstream.Certificate().Raw)
	if got := keepAliveGet(t, c, target, "/before"); got != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("before reload: status=%d hits=%d, want 200 and 1", got, hits.Load())
	}

	reloadDenyLoopback(t, h, policyPath)
	assertConnClosedWithin(t, c.br, c.SetReadDeadline, 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after reload = %d, want 1", got)
	}
}

// echoUpstream is a TCP echo server counting the bytes it received.
func echoUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var received atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						received.Add(int64(n))
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), &received
}

// TestE2E_LiveConnReconcile_BytechunkCutOnReload is T3 / acceptance
// criterion 2 (bytechunk): a CONNECT tunnel carrying bytes that are
// neither TLS nor HTTP — whose envelopes carry no TargetHost, so
// HostScopeStep never re-checks them — is closed by the reload.
func TestE2E_LiveConnReconcile_BytechunkCutOnReload(t *testing.T) {
	target, received := echoUpstream(t)
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithPassthrough(t, h)

	c, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	msg := []byte{0x00, 0x01, 'r', 'a', 'w', '-', '1'}
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(c, echo); err != nil || string(echo) != string(msg) {
		t.Fatalf("echo = %q, %v; want %q", echo, err, msg)
	}

	reloadDenyLoopback(t, h, policyPath)
	assertConnClosedWithin(t, c, c.SetReadDeadline, 5*time.Second)
	before := received.Load()
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte{0x00, 0x02, 'r', 'a', 'w', '-', '2'})
	time.Sleep(200 * time.Millisecond)
	if got := received.Load(); got != before {
		t.Errorf("echo upstream received %d bytes after the cut, want 0", got-before)
	}
}

// TestE2E_LiveConnReconcile_WideningReloadCutsNothing is T4 / acceptance
// criterion 3: an unchanged or widening reload leaves a live tunnel alone.
func TestE2E_LiveConnReconcile_WideningReloadCutsNothing(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	target := upstream.Listener.Addr().String()
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithPassthrough(t, h, "127.0.0.1")

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)
	if got := keepAliveGet(t, c, target, "/1"); got != http.StatusOK {
		t.Fatalf("GET /1 status = %d", got)
	}

	if err := h.ReloadPolicy(t); err != nil { // unchanged
		t.Fatalf("ReloadPolicy (unchanged): %v", err)
	}
	if got := keepAliveGet(t, c, target, "/2"); got != http.StatusOK {
		t.Fatalf("GET /2 after unchanged reload status = %d", got)
	}
	writePolicyFile(t, policyPath, `{"allows":[{"hostname":"127.0.0.1"},{"hostname":"other.test"}],"denies":[{"hostname":"127.0.0.1","path_prefix":"/admin"}]}`)
	if err := h.ReloadPolicy(t); err != nil {
		t.Fatalf("ReloadPolicy (widen): %v", err)
	}
	if got := keepAliveGet(t, c, target, "/3"); got != http.StatusOK {
		t.Fatalf("GET /3 after widening reload status = %d", got)
	}
	if got := hits.Load(); got != 3 {
		t.Errorf("upstream hits = %d, want 3 on the one tunnel", got)
	}
}

// TestE2E_LiveConnReconcile_AgentDenyCutsPassthrough is T14 / acceptance
// criterion 5: an agent-layer deny added through the security tool closes
// a live passthrough tunnel too.
func TestE2E_LiveConnReconcile_AgentDenyCutsPassthrough(t *testing.T) {
	upstream, hits := reloadTestUpstream(t)
	target := upstream.Listener.Addr().String()
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxyAddr := startProxyWithPassthrough(t, h, "127.0.0.1")

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)
	assertPassthrough(t, c, upstream.Certificate().Raw)
	if got := keepAliveGet(t, c, target, "/before"); got != http.StatusOK {
		t.Fatalf("GET /before status = %d", got)
	}

	h.MustOK(t, "security", map[string]any{
		"action": "update_target_scope",
		"params": map[string]any{"add_denies": []map[string]any{{"hostname": "127.0.0.1"}}},
	})
	assertConnClosedWithin(t, c.br, c.SetReadDeadline, 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits after agent deny = %d, want 1", got)
	}
}

// wsPushUpstream is an HTTPS WebSocket server that, after the handshake,
// pushes a text frame every 50ms until a write fails. pushes counts the
// frames written.
func wsPushUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var pushes atomic.Int64
	stop := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
		if err := brw.Flush(); err != nil {
			return
		}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			payload := []byte(fmt.Sprintf("push-%d", i))
			frame := append([]byte{0x81, byte(len(payload))}, payload...)
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err := conn.Write(frame); err != nil {
				return
			}
			pushes.Add(1)
			time.Sleep(50 * time.Millisecond)
		}
	}))
	t.Cleanup(func() {
		close(stop)
		srv.Close()
	})
	return srv, &pushes
}

// TestE2E_LiveConnReconcile_MITMWebSocketPushStops is T7 / acceptance
// criterion 4: the server→client stream of a MITM'd WebSocket — which no
// per-envelope Send check ever stops — ends when the reload denies the
// host: the client connection closes and the upstream stops being read.
func TestE2E_LiveConnReconcile_MITMWebSocketPushStops(t *testing.T) {
	upstream, pushes := wsPushUpstream(t)
	target := upstream.Listener.Addr().String()
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithPassthrough(t, h)

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	c := clientTLSOver(t, raw)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: "+target+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade response = %v, %v; want 101", resp, err)
	}
	// The client speaks first (one masked text frame): the pushes are only
	// relayed to the client once the client→server direction has carried
	// a frame (pre-existing behavior, not what this test is about).
	if _, err := c.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}); err != nil {
		t.Fatalf("write client frame: %v", err)
	}
	readFrame := func() string {
		t.Helper()
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c.br, hdr); err != nil {
			t.Fatalf("read frame header: %v", err)
		}
		payload := make([]byte, hdr[1]&0x7f)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			t.Fatalf("read frame payload: %v", err)
		}
		return string(payload)
	}
	for i := 0; i < 2; i++ {
		if got := readFrame(); !strings.HasPrefix(got, "push-") {
			t.Fatalf("frame %d = %q, want a pushed frame", i, got)
		}
	}
	_ = c.SetDeadline(time.Time{})

	reloadDenyLoopback(t, h, policyPath)
	assertConnClosedWithin(t, c.br, c.SetReadDeadline, 5*time.Second)

	// The upstream leg is closed too: the server's pushes stop.
	deadline := time.Now().Add(5 * time.Second)
	for {
		before := pushes.Load()
		time.Sleep(300 * time.Millisecond)
		if pushes.Load() == before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upstream kept pushing frames after the cut (%d pushes)", pushes.Load())
		}
	}
}

// sseUpstream is a plain-HTTP server streaming one SSE event every 50ms
// until the client goes away. events counts the events flushed.
func sseUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var events atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		fl.Flush()
		for i := 0; ; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			if _, err := fmt.Fprintf(w, "data: event-%d\n\n", i); err != nil {
				return
			}
			fl.Flush()
			events.Add(1)
			time.Sleep(50 * time.Millisecond)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), &events
}

// TestE2E_LiveConnReconcile_PlainForwardStreamCutOnReload: a plain-HTTP
// forward connection admitted by the forward gate ("http" scheme) — here a
// long-lived SSE response — is closed by the reload, and the upstream stops
// streaming into it.
func TestE2E_LiveConnReconcile_PlainForwardStreamCutOnReload(t *testing.T) {
	target, events := sseUpstream(t)
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithPassthrough(t, h)

	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, "GET http://"+target+"/stream HTTP/1.1\r\nHost: "+target+"\r\nAccept: text/event-stream\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("forward response = %v, %v; want 200", resp, err)
	}
	sawEvent := false
	for i := 0; i < 20 && !sawEvent; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read stream: %v", err)
		}
		sawEvent = strings.Contains(line, "event-")
	}
	if !sawEvent {
		t.Fatal("no SSE event arrived through the forward proxy")
	}
	_ = c.SetDeadline(time.Time{})

	reloadDenyLoopback(t, h, policyPath)
	assertConnClosedWithin(t, br, c.SetReadDeadline, 5*time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for {
		before := events.Load()
		time.Sleep(300 * time.Millisecond)
		if events.Load() == before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("upstream kept streaming after the cut (%d events)", events.Load())
		}
	}
}

//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// USK-1392: RFC-001 §9.3 http.on_response RESPOND-replace. The plugin's
// response supersedes the upstream response: the client receives the
// plugin's response instead of the upstream's, the exchange ends normally
// (HTTP/1.x keep-alive kept, HTTP/2 per stream), and the Receive flow is
// recorded as a variant pair (original = upstream bytes, modified = the
// bytes the client got). The harness helpers live in
// plugin_raw_wins_http1_integration_test.go / plugin_raw_wins_h2_integration_test.go.

const replaceOnResponseScript = `
def replace(msg, ctx):
    if msg["body"] == b"path=/q conn=1":
        return None
    return action.RESPOND(status_code=418, headers=[("Content-Type", "text/plain")], body=b"plugin-body")

register_hook("http", "on_response", replace)
`

// TestPluginReceiveRespond_HTTP1_ReplacesResponse covers Test Plan #1 and #3.
func TestPluginReceiveRespond_HTTP1_ReplacesResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startRawCaptureUpstream(t, true, nil)
	h, fwd := startRawWinsForward(t, ctx, replaceOnResponseScript, up.Addr(), "http", nil)

	const req1 = "GET /p HTTP/1.1\r\nHost: example.test\r\n\r\n"
	c, br := dialForward(t, fwd)
	if _, err := c.Write([]byte(req1)); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, body, err := readOneResponse(br)
	if err != nil {
		t.Fatalf("read response: %v (got %q)", err, raw)
	}
	if !strings.HasPrefix(string(raw), "HTTP/1.1 418 ") || body != "plugin-body" {
		t.Fatalf("client got %q, want the plugin's 418 \"plugin-body\"", raw)
	}
	if got := up.waitBytes(1, len(req1)); string(got) != req1 {
		t.Errorf("upstream received %q, want the client request %q", got, req1)
	}

	// Test Plan #3: the replaced exchange ended normally, so the client
	// connection carries the next request, and the upstream's answer to it
	// (on the same upstream connection) reaches the client unchanged.
	const req2 = "GET /q HTTP/1.1\r\nHost: example.test\r\n\r\n"
	if _, err := c.Write([]byte(req2)); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	raw2, body2, err := readOneResponse(br)
	if err != nil {
		t.Fatalf("read second response: %v (got %q; the client connection must survive a replaced response)", err, raw2)
	}
	if !strings.HasPrefix(string(raw2), "HTTP/1.1 200 OK\r\n") || body2 != "path=/q conn=1" {
		t.Errorf("second response = %q, want the upstream's 200 \"path=/q conn=1\"", raw2)
	}

	_ = c.Close()
	_ = h.mgr.StopAll(context.Background())
	orig := waitFlow(h.store, "receive", "original", func(b []byte) bool {
		return bytes.Contains(b, []byte("path=/p conn=1"))
	})
	if orig == nil || !strings.HasPrefix(string(orig.RawBytes), "HTTP/1.1 200 OK\r\n") {
		t.Errorf("no original receive variant carrying the upstream response; flows:%s", describeFlows(h.store))
	}
	mod := waitFlow(h.store, "receive", "modified", nil)
	if mod == nil || !bytes.Equal(mod.RawBytes, raw) {
		t.Errorf("modified receive variant must equal the bytes the client read %q; flows:%s", raw, describeFlows(h.store))
	}
}

// TestPluginReceiveRespond_H2_ReplacesResponse covers Test Plan #2.
func TestPluginReceiveRespond_H2_ReplacesResponse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, seen := startCapturingH2CUpstream(t)
	h, fwd := startRawWinsForwardDeps(t, ctx, replaceOnResponseScript, upAddr, "http2", nil)

	status, body := doH2C(t, ctx, fwd, "GET", "/p", nil)
	if status != 418 || body != "plugin-body" {
		t.Errorf("client got %d %q, want the plugin's 418 \"plugin-body\"", status, body)
	}
	if path, _, _ := seen.snapshot(); path != "/p" {
		t.Errorf("upstream saw path %q, want /p", path)
	}
	waitAnyFlow(t, h.store, "receive")
	if f := waitFlow(h.store, "receive", "original", func(b []byte) bool {
		return bytes.Contains(b, []byte("upstream:/p"))
	}); f == nil {
		t.Errorf("no original receive variant carrying the upstream response; flows:%s", describeFlows(h.store))
	}
	if f := waitFlow(h.store, "receive", "modified", func(b []byte) bool {
		return bytes.Contains(b, []byte("plugin-body"))
	}); f == nil {
		t.Errorf("no modified receive variant carrying the plugin response; flows:%s", describeFlows(h.store))
	}
}

// startInformationalUpstream answers every request with a 103 Early Hints
// followed by a 200 final response, in one write.
func startInformationalUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				br := bufio.NewReader(c)
				for {
					if _, err := readUpstreamRequest(br); err != nil {
						return
					}
					if _, err := c.Write([]byte("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n" +
						"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nupstream")); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestPluginReceiveRespond_HTTP1_InformationalNotReplaced covers Test Plan
// #4: a blanket http.on_response RESPOND also fires on the upstream's 103.
// RESPOND on an informational response is refused (the final response
// follows on the same exchange), so the client gets the 103 once and then
// exactly one final response: the plugin's replacement of the 200.
func TestPluginReceiveRespond_HTTP1_InformationalNotReplaced(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr := startInformationalUpstream(t)
	_, fwd := startRawWinsForward(t, ctx, `
def replace(msg, ctx):
    return action.RESPOND(status_code=418, body=b"plugin-body")

register_hook("http", "on_response", replace)
`, upAddr, "http", nil)

	c, br := dialForward(t, fwd)
	if _, err := c.Write([]byte("GET /p HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, _, err := readOneResponse(br)
	if err != nil {
		t.Fatalf("read first response: %v (got %q)", err, info)
	}
	if !strings.HasPrefix(string(info), "HTTP/1.1 103 ") {
		t.Fatalf("first response = %q, want the upstream's 103 relayed unchanged", info)
	}
	final, body, err := readOneResponse(br)
	if err != nil {
		t.Fatalf("read final response: %v (got %q)", err, final)
	}
	if !strings.HasPrefix(string(final), "HTTP/1.1 418 ") || body != "plugin-body" {
		t.Errorf("final response = %q, want the plugin's 418 \"plugin-body\"", final)
	}
	// Nothing else may follow: a second final response would be taken as
	// the answer to the client's next request.
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	extra, err := br.ReadByte()
	var ne net.Error
	if err == nil || !(errors.As(err, &ne) && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded)) {
		t.Errorf("read after the final response = (%q, %v), want a read timeout (no further response bytes)", extra, err)
	}
}

const wsHandshakeReq = "GET /ws HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

// TestPluginReceiveRespond_WSUpgrade101 covers Test Plan #10: ws.on_upgrade
// also fires on the upstream's 101. RESPOND there replaces the 101, so the
// client gets the plugin's response and no upgrade happens; DROP ends the
// exchange with no response bytes and the client connection is closed.
func TestPluginReceiveRespond_WSUpgrade101(t *testing.T) {
	t.Run("respond", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		up := startWSCaptureUpstream(t, "", nil)
		_, fwd := startRawWinsForward(t, ctx, `
def on_upgrade(msg, ctx):
    if msg["status"] != 101:
        return None
    return action.RESPOND(status_code=403, headers=[("Content-Type", "text/plain")], body=b"no websocket")

register_hook("ws", "on_upgrade", on_upgrade)
`, up.Addr(), "websocket", nil)

		c, br := dialForward(t, fwd)
		if _, err := c.Write([]byte(wsHandshakeReq)); err != nil {
			t.Fatalf("write handshake: %v", err)
		}
		raw, body, err := readOneResponse(br)
		if err != nil {
			t.Fatalf("read response: %v (got %q)", err, raw)
		}
		if !strings.HasPrefix(string(raw), "HTTP/1.1 403 ") || body != "no websocket" {
			t.Errorf("client got %q, want the plugin's 403 \"no websocket\" instead of the 101", raw)
		}
	})

	t.Run("drop", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		up := startWSCaptureUpstream(t, "", nil)
		_, fwd := startRawWinsForward(t, ctx, `
def on_upgrade(msg, ctx):
    if msg["status"] != 101:
        return None
    return action.DROP

register_hook("ws", "on_upgrade", on_upgrade)
`, up.Addr(), "websocket", nil)

		c, br := dialForward(t, fwd)
		if _, err := c.Write([]byte(wsHandshakeReq)); err != nil {
			t.Fatalf("write handshake: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := br.ReadByte()
		if err == nil {
			rest, _ := br.Peek(br.Buffered())
			t.Fatalf("client read %q, want the connection closed with no response bytes", append([]byte{got}, rest...))
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("client connection still open after 5s; want it closed after the dropped 101")
		}
	})
}

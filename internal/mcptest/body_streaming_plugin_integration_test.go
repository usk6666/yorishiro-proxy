//go:build e2e && !e2e_smoke

// USK-1409 T13: with an http.on_response plugin hook loaded, a response
// body within plugin_max_body_size still reaches the hook whole (buffered),
// while a larger one is forwarded as it arrives without calling the hook.
// Driven through the production wiring (config JSON → mcpserver init →
// proxybuild body-mode predicate → HTTP/1.x upstream Layer).
package mcptest_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startGatedPlainUpstream serves GET /size/<n>: the head plus the first
// half of an n-byte body, then the rest once release is closed.
func startGatedPlainUpstream(t *testing.T, release <-chan struct{}) string {
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
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					parts := strings.Fields(line)
					for {
						h, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if h == "\r\n" {
							break
						}
					}
					if len(parts) < 2 {
						return
					}
					n, _ := strconv.Atoi(strings.TrimPrefix(parts[1], "/size/"))
					body := bytes.Repeat([]byte("R"), n)
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n", n)
					_, _ = c.Write(body[:n/2])
					select {
					case <-release:
					case <-time.After(15 * time.Second):
						return
					}
					_, _ = c.Write(body[n/2:])
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestE2E_BodyStreaming_PluginMaxBodySize(t *testing.T) {
	const pluginCap = 2048
	scriptPath := writePluginScript(t, "response_stamp.star", pluginScriptResponseStamp)
	release := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(release) }) }
	defer open()
	upstream := startGatedPlainUpstream(t, release)
	_, proxyAddr := startBodyLimitProxy(t, bodyLimitConfigJSON(t, map[string]any{
		"plugin_max_body_size": pluginCap,
		"plugins": []map[string]any{
			{"name": "response_stamp", "path": scriptPath},
		},
	}))

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	readHead := func() string {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var b strings.Builder
		for {
			line, err := br.ReadString('\n')
			b.WriteString(line)
			if err != nil {
				t.Fatalf("read head (so far %q): %v", b.String(), err)
			}
			if line == "\r\n" {
				return b.String()
			}
		}
	}
	readN := func(n int) []byte {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			t.Fatalf("read %d body bytes: %v", n, err)
		}
		return b
	}

	// 4 KiB (over the plugin cap): the first half arrives before the
	// upstream sends the rest, and the hook never saw the response.
	fmt.Fprintf(conn, "GET http://%s/size/4096 HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream)
	head := readHead()
	if strings.Contains(strings.ToLower(head), "x-plugin-saw") {
		t.Errorf("hook ran on a body over plugin_max_body_size: %q", head)
	}
	readN(2048)
	open()
	readN(2048)

	// 1 KiB (within the cap): buffered, the hook saw the whole body.
	fmt.Fprintf(conn, "GET http://%s/size/1024 HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream)
	head = readHead()
	if !strings.Contains(head, "X-Plugin-Saw: 1024\r\n") {
		t.Errorf("head = %q, want X-Plugin-Saw: 1024 (hook sees a body within the cap whole)", head)
	}
	readN(1024)
}

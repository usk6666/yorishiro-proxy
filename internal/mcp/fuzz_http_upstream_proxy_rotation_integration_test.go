//go:build e2e && !e2e_smoke

package mcp

// fuzz_http_upstream_proxy_rotation_integration_test.go — verifies that
// fuzz_http's per-variant upstream_proxy.url_template expansion drives
// each variant through a distinct upstream proxy URL. The §__nonce§
// reserved variable produces a fresh UUID per variant, so a single
// upstream proxy observing the variants records a distinct
// Proxy-Authorization header (Basic auth derived from the URL userinfo)
// for each iteration. This is the residential-proxy IP rotation
// acceptance gate.

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// startCONNECTProxy stands up an HTTP CONNECT proxy that records each
// connection's Proxy-Authorization header and tunnels the rest of the
// stream to the requested target. Used to validate per-variant upstream
// proxy auth rotation in fuzz_http.
func startCONNECTProxy(t *testing.T) (addr string, observedAuth func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var seen []string

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleCONNECT(conn, &mu, &seen)
		}
	}()

	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(seen))
		copy(out, seen)
		return out
	}
}

// handleCONNECT processes a single client connection: parse CONNECT,
// record Proxy-Authorization, reply 200, then bridge bytes.
func handleCONNECT(client net.Conn, mu *sync.Mutex, seen *[]string) {
	defer client.Close()
	br := bufio.NewReader(client)

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		return
	}

	auth := req.Header.Get("Proxy-Authorization")
	mu.Lock()
	*seen = append(*seen, auth)
	mu.Unlock()

	upstream, err := net.Dial("tcp", req.Host)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		return
	}

	// br may hold buffered bytes that arrived after the CONNECT headers —
	// drain them into the upstream before starting the bidirectional copy
	// so we don't lose the TLS ClientHello (not relevant here since the
	// inner protocol is plaintext, but defensive for parity with real
	// CONNECT proxies).
	if n := br.Buffered(); n > 0 {
		buf, _ := br.Peek(n)
		_, _ = upstream.Write(buf)
		_, _ = br.Discard(n)
	}

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
}

// TestFuzzHTTP_UpstreamProxyRotation_PerVariantDistinctNonce verifies
// that each fuzz_http variant tunnels through the upstream proxy with a
// distinct Proxy-Authorization header. The url_template substitutes
// §__nonce§ into the userinfo so each variant's basic-auth pair is
// unique. The proxy records the headers; the test asserts both
// "header present on every variant" and "headers all distinct".
func TestFuzzHTTP_UpstreamProxyRotation_PerVariantDistinctNonce(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	echo, getCaptured := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")
	proxyAddr, observedAuth := startCONNECTProxy(t)

	payloads := []string{"/a", "/b", "/c"}
	template := fmt.Sprintf("http://session-§__nonce§:secret@%s", proxyAddr)
	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": payloads},
		},
		"upstream_proxy": map[string]any{
			"url_template": template,
		},
		"timeout_ms": 5000,
	})

	if result.CompletedVariants != len(payloads) {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}

	// Every variant reached the echo target — sanity check that the
	// tunnel did not drop bytes.
	if len(getCaptured()) != len(payloads) {
		t.Errorf("target observed %d hits, want %d", len(getCaptured()), len(payloads))
	}

	// The CONNECT proxy must have observed exactly one tunnel per variant,
	// each with a Proxy-Authorization header.
	auths := observedAuth()
	if len(auths) != len(payloads) {
		t.Fatalf("CONNECT proxy saw %d tunnels, want %d", len(auths), len(payloads))
	}

	seenUsers := make(map[string]struct{}, len(auths))
	for i, a := range auths {
		if !strings.HasPrefix(a, "Basic ") {
			t.Errorf("variant %d: Proxy-Authorization = %q, want Basic prefix", i, a)
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a, "Basic "))
		if err != nil {
			t.Errorf("variant %d: base64 decode: %v", i, err)
			continue
		}
		userPass := string(decoded)
		colon := strings.IndexByte(userPass, ':')
		if colon < 0 {
			t.Errorf("variant %d: userinfo missing ':' (got %q)", i, userPass)
			continue
		}
		user := userPass[:colon]
		if !strings.HasPrefix(user, "session-") {
			t.Errorf("variant %d: username = %q, want session-<nonce>", i, user)
		}
		if _, dup := seenUsers[user]; dup {
			t.Errorf("variant %d: duplicate nonce %q (rotation failed)", i, user)
		}
		seenUsers[user] = struct{}{}
	}
	if len(seenUsers) != len(payloads) {
		t.Errorf("distinct nonce count = %d, want %d", len(seenUsers), len(payloads))
	}
}

// TestFuzzHTTP_UpstreamProxyRotation_IterationCounter verifies the
// §__iteration§ reserved variable substitutes the zero-based variant
// index, so a template like "http://var-§__iteration§:pass@..."
// produces predictable usernames var-0, var-1, var-2.
func TestFuzzHTTP_UpstreamProxyRotation_IterationCounter(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	echo, _ := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")
	proxyAddr, observedAuth := startCONNECTProxy(t)

	payloads := []string{"/a", "/b", "/c"}
	template := fmt.Sprintf("http://var-§__iteration§:pass@%s", proxyAddr)
	_ = callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": payloads},
		},
		"upstream_proxy": map[string]any{
			"url_template": template,
		},
		"timeout_ms": 5000,
	})

	auths := observedAuth()
	if len(auths) != len(payloads) {
		t.Fatalf("CONNECT proxy saw %d tunnels, want %d", len(auths), len(payloads))
	}
	for i, a := range auths {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(a, "Basic "))
		if err != nil {
			t.Fatalf("variant %d: base64 decode: %v", i, err)
		}
		userPass := string(decoded)
		colon := strings.IndexByte(userPass, ':')
		user := userPass[:colon]
		want := fmt.Sprintf("var-%d", i)
		if user != want {
			t.Errorf("variant %d: username = %q, want %q", i, user, want)
		}
	}
}

// TestFuzzHTTP_UpstreamProxyRotation_MalformedTemplateNonFatal verifies
// that a template producing an unparseable URL is reported per-variant
// rather than aborting the whole run. This mirrors how SafetyFilter
// violations are surfaced in fuzz_http.
func TestFuzzHTTP_UpstreamProxyRotation_MalformedTemplateNonFatal(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	echo, _ := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	// Scheme not in {http, socks5} — ParseUpstreamProxy rejects.
	payloads := []string{"/a", "/b"}
	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": payloads},
		},
		"upstream_proxy": map[string]any{
			"url_template": "ftp://nope.example:21",
		},
		"timeout_ms": 5000,
	})

	if result.CompletedVariants != len(payloads) {
		t.Errorf("CompletedVariants = %d, want %d (errors should not abort)", result.CompletedVariants, len(payloads))
	}
	for i, v := range result.Variants {
		if !strings.Contains(v.Error, "upstream_proxy.url_template") {
			t.Errorf("variant %d: Error = %q, want upstream_proxy.url_template prefix", i, v.Error)
		}
	}
}

// To keep go vet happy when building this file standalone.
var _ = httptest.NewServer
var _ = atomic.AddInt32
var _ = context.Background

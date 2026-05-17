//go:build e2e

// Package mcptest_test holds USK-917's smoke coverage for the L7 TCP
// forward feature: proxy_start tcp_forwards with Protocol="http" across
// all four (TLS × UpstreamTLS) cells.
//
// internal/proxybuild/tcp_forward_tls_integration_test.go and
// tcp_forward_upstream_tls_integration_test.go cover the proxybuild
// manager directly at the nightly (exhaustive) tier. This file is the
// merge-gate smoke that proves the full proxy_start → MCP handoff still
// honors the four (TLS, UpstreamTLS) combinations on the user-facing
// path (USK-911 schema + USK-915/916 wiring + USK-917 docs/UI wrap-up).
package mcptest_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_TCPForward_L7_TLSMatrix exercises the four TLS×UpstreamTLS
// cells with Protocol="http". Each cell drives a real HTTP/1.1
// request → response round-trip and confirms a flow lands in the
// recorder visible via query(flows).
//
// Cells (TLS = client-side terminate, UpstreamTLS = upstream-dial encrypt):
//   - (false, false): plaintext client → plaintext upstream.
//   - (true,  false): TLS client (proxy MITM cert)   → plaintext upstream.
//   - (false, true):  plaintext client → TLS upstream (HTTP→HTTPS bridge).
//   - (true,  true):  TLS client → TLS upstream (full MITM).
//
// We construct two upstream flavors. The TLS upstreams reuse the
// canonical httptest.NewTLSServer self-signed pattern with NextProtos=[http/1.1];
// the proxy's -insecure flag (set by HarnessOptions default) is what makes
// the upstream-side TLS verification accept the leaf.
func TestE2E_TCPForward_L7_TLSMatrix(t *testing.T) {
	// Spin one harness up front and reuse across cells — each cell
	// uses its own listener Name and a unique forward port, so they
	// do not interfere. This keeps the smoke fast while still
	// exercising the full JSON-RPC / MCP wiring per cell.
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	// Capture the proxy's CA cert so the test client can verify the
	// dynamically-issued forward-listener cert under fc.TLS=true.
	rootPool := fetchProxyCAPool(t, h)

	plainUpstream := startPlainHTTPEcho(t)
	tlsUpstream := startTLSHTTPEcho(t)

	type cell struct {
		name        string
		tls         bool
		upstreamTLS bool
		upstream    string // host:port (plaintext or TLS)
	}
	cases := []cell{
		{name: "plaintext_to_plaintext", tls: false, upstreamTLS: false, upstream: plainUpstream},
		{name: "tls_terminate_to_plaintext", tls: true, upstreamTLS: false, upstream: plainUpstream},
		{name: "plaintext_to_upstream_tls", tls: false, upstreamTLS: true, upstream: tlsUpstream},
		{name: "tls_terminate_to_upstream_tls", tls: true, upstreamTLS: true, upstream: tlsUpstream},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forwardPort := pickFreePort(t)
			listenerName := fmt.Sprintf("forward-l7-%d", i)
			path := "/usk917-" + tc.name

			startArgs := map[string]any{
				"name":        listenerName,
				"listen_addr": "127.0.0.1:0",
				"tcp_forwards": map[string]any{
					strconv.Itoa(forwardPort): map[string]any{
						"target":       tc.upstream,
						"protocol":     "http",
						"tls":          tc.tls,
						"upstream_tls": tc.upstreamTLS,
					},
				},
			}

			res := h.MustOK(t, "proxy_start", startArgs)
			if _, ok := res.Decoded["tcp_forwards"]; !ok {
				t.Fatalf("proxy_start did not echo tcp_forwards (decoded=%v text=%s)", res.Decoded, res.Text)
			}

			body := driveHTTPThroughForward(t, forwardPort, path, tc.tls, rootPool, 5*time.Second)
			if !strings.Contains(body, "Echo-Path: "+path) {
				t.Errorf("response missing Echo-Path header for %q; got body=%q", path, body)
			}

			if !waitForFlowWithPath(t, h, path, 3*time.Second) {
				t.Errorf("no recorded flow with url containing %q after forward round-trip (cell %q)", path, tc.name)
			}

			// Stop the listener to free the listener name for the
			// next cell. Errors are non-fatal — t.Cleanup on the
			// harness tears down regardless.
			_ = h.CallTool(t, "proxy_stop", map[string]any{"name": listenerName})
		})
	}
}

// driveHTTPThroughForward sends a single HTTP/1.1 GET request to
// 127.0.0.1:port (plaintext or TLS depending on useTLS) and returns the
// full raw response (status line + headers + body) so callers can
// assert on the Echo-Path header. Per-step deadlines keep a hung
// proxy from stalling the test indefinitely.
func driveHTTPThroughForward(t *testing.T, port int, path string, useTLS bool, rootPool *x509.CertPool, timeout time.Duration) string {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	var conn net.Conn
	var err error
	if useTLS {
		tlsCfg := &tls.Config{
			RootCAs:    rootPool,
			ServerName: "forward.usk917.test",
			NextProtos: []string{"http/1.1"},
			MinVersion: tls.VersionTLS12,
		}
		dialer := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		t.Fatalf("dial forward port %s (tls=%v): %v", addr, useTLS, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Use a host header that matches the SNI for fc.TLS=true so the
	// proxy's per-host cert issuance is exercised end-to-end. For
	// plaintext cells the Host is informational only.
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: forward.usk917.test\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(raw)
}

// startPlainHTTPEcho binds a hand-rolled HTTP/1.1 echo on
// 127.0.0.1:ephemeral and returns its host:port. The handler accepts
// one request per connection and writes a 200 response carrying an
// Echo-Path header so downstream assertions can pin the route.
//
// We hand-roll the listener rather than reusing
// HarnessOptions.UpstreamProto="http/1.1" because the harness's
// upstream is always wrapped by httptest.StartTLS — the (false,false)
// and (true,false) cells need a *plaintext* upstream.
func startPlainHTTPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("plain echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				path := readHTTP1RequestPath(br)
				if path == "" {
					return
				}
				// Drain the rest of the headers so the request
				// is fully consumed before we respond.
				for {
					line, rerr := br.ReadString('\n')
					if rerr != nil {
						return
					}
					if line == "\r\n" || line == "\n" {
						break
					}
				}
				resp := "HTTP/1.1 200 OK\r\n" +
					"Content-Type: text/plain\r\n" +
					"Echo-Path: " + path + "\r\n" +
					"Content-Length: 0\r\n" +
					"Connection: close\r\n" +
					"\r\n"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startTLSHTTPEcho stands up a TLS HTTP/1.1 server via httptest.StartTLS
// with NextProtos=[http/1.1]. The harness's -insecure flag (default)
// allows the proxy's upstream-side dial to accept the self-signed leaf.
func startTLSHTTPEcho(t *testing.T) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Echo-Path", r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "tls-echo:%s", r.URL.Path)
	}))
	srv.TLS = &tls.Config{NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

// readHTTP1RequestPath reads the first request line of an HTTP/1.x
// request and returns the URL path. Returns "" if the line is
// malformed or read fails.
func readHTTP1RequestPath(br *bufio.Reader) string {
	line, err := br.ReadString('\n')
	if err != nil {
		return ""
	}
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// fetchProxyCAPool queries the proxy's CA cert via the MCP query tool
// and returns a CertPool the test client can use as RootCAs. The proxy
// MITMs the forward listener with a dynamically-issued leaf chained
// off this CA when fc.TLS=true.
func fetchProxyCAPool(t *testing.T, h *mcptest.Harness) *x509.CertPool {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "ca_cert"})
	pemStr, _ := res.Decoded["pem"].(string)
	if pemStr == "" {
		t.Fatalf("query(ca_cert) returned empty PEM: decoded=%v text=%s", res.Decoded, res.Text)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemStr)) {
		t.Fatalf("append proxy CA PEM into pool failed; PEM=%q", pemStr)
	}
	return pool
}

// waitForFlowWithPath polls query(resource=flows) until at least one
// flow's URL contains the given path substring. Returns true when
// observed within deadline. The recording side runs after the wire
// round-trip completes, so a brief poll is appropriate.
func waitForFlowWithPath(t *testing.T, h *mcptest.Harness, path string, deadline time.Duration) bool {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
		})
		// Re-decode from Text since the harness's Decoded view of
		// flow URL fields can vary by transport — we only need a
		// substring match.
		var payload struct {
			Flows []struct {
				URL string `json:"url"`
			} `json:"flows"`
		}
		if err := json.Unmarshal([]byte(res.Text), &payload); err == nil {
			for _, f := range payload.Flows {
				if strings.Contains(f.URL, path) {
					return true
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

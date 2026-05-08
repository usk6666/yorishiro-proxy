//go:build e2e

// Package mcptest_test holds USK-766's smoke coverage for CONNECT-tunnel
// inner-protocol polymorphism.
//
// Pre-USK-766 the only CONNECT scenario covered by the smoke tier was
// `CONNECT + TLS MITM + HTTP/2` (full_listener_integration_test.go's
// TestFullListener_CONNECT_HTTPS_MITM). The three failure modes
// reported by users —
//
//   - plain HTTP over a CONNECT tunnel (curl --proxytunnel http://...)
//   - h2c (HTTP/2 cleartext) over a CONNECT tunnel
//   - wss over h2 extended CONNECT (RFC 8441) — full tier, sibling file
//
// — therefore walked past the merge gate even after USK-762 (CONNECT
// inner peek + dispatch) and USK-764+USK-765 (extended-CONNECT WS swap)
// landed the fixes. This file lays down the wiring proof so a
// regression in connect_inner_dispatch.go (the inner-byte peek) or the
// JSON-RPC harness path to it surfaces in per-PR CI rather than
// nightly.
//
// The two scenarios in this file (plain-HTTP and h2c) target the smoke
// tier (`//go:build e2e`, no `&& !e2e_smoke`). The wss-over-h2 scenario
// lives in connect_modes_full_integration_test.go gated as exhaustive-
// only because real Chrome only offers ALPN=[http/1.1] for wss:// today
// — the wire shape we test there is achievable but not the dominant
// production case.
package mcptest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ConnectModes_PlainHTTP_Smoke proves the USK-762 wiring path
// (CONNECT 200 → peek inner bytes → dispatch to plain-HTTP-over-CONNECT
// stack) works end-to-end through the production JSON-RPC MCP server.
//
// Wire shape: client sends `CONNECT host:port HTTP/1.1`, reads 200,
// then sends `GET / HTTP/1.1` over the SAME socket WITHOUT a TLS
// handshake. This is the exact wire shape produced by
// `curl --proxytunnel http://target/` — a known regression class
// because Go's net/http transport only sends CONNECT for https://
// URLs by default.
//
// Verifies (e2e Subsystem Verification Checklist):
//   - Communication: 200 OK + body returned to the client.
//   - Stream/Flow recording: query("flows") surfaces a stream with
//     protocol="http", scheme="http" (NOT "https" — the MITM principle
//     is "do not synthesize TLS state"), state reaches "complete".
//   - Raw bytes recording: query("flow") returns a non-empty
//     raw_request (base64-encoded original wire bytes).
//   - MCP query tool integration: the flow is retrievable via the
//     query tool, end-to-end.
func TestE2E_ConnectModes_PlainHTTP_Smoke(t *testing.T) {
	upstreamLn, getUpstreamReqs := startSmokeUpstreamPlainHTTP(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nplain-http!")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	// Drive: CONNECT, 200, plain HTTP/1.1 GET — no TLS in between.
	rawReq := fmt.Sprintf("GET /smoke HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp := connectAndSendPlainHTTPSmoke(t, proxyAddr, target, rawReq)

	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}
	if !strings.HasSuffix(resp, "plain-http!") {
		t.Errorf("response body unexpected: %q", resp)
	}

	// Upstream sanity: the request actually reached it.
	upstreamReqs := getUpstreamReqs()
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	if !bytes.Contains(upstreamReqs[0], []byte("GET /smoke HTTP/1.1")) {
		t.Errorf("upstream did not receive GET /smoke: %q", upstreamReqs[0])
	}

	// MCP query tool integration: retrieve the flow record.
	flowEntry := waitForConnectModeFlow(t, h, "/smoke", "http", 5*time.Second)
	if flowEntry.Scheme != "http" {
		t.Errorf("flow.scheme = %q, want %q (MITM principle: do not synthesize TLS)",
			flowEntry.Scheme, "http")
	}
	if flowEntry.State != "complete" {
		t.Errorf("flow.state = %q, want %q", flowEntry.State, "complete")
	}

	// Raw bytes recording (L4-capable principle): query the per-flow
	// detail and confirm raw_request is present (base64-encoded).
	assertFlowRawRequestNonEmpty(t, h, flowEntry.ID)
}

// TestE2E_ConnectModes_H2C_Smoke proves the USK-762 wiring path for the
// h2c-over-CONNECT inner case: client establishes CONNECT, reads 200,
// then sends the HTTP/2 cleartext client preface (`PRI * HTTP/2.0...`)
// directly on the same socket. The proxy's inner-byte peek must
// classify it as InnerH2C and dispatch through BuildPlainH2CStack.
//
// The driver uses x/net/http2.Transport with AllowHTTP=true and a
// custom DialTLS that returns the post-CONNECT raw conn — so the h2
// handshake (preface + SETTINGS) speaks cleartext over the tunnel.
//
// Verifies the same checklist as the plain-HTTP variant: protocol=http,
// scheme=http, state=complete, raw_request non-empty.
func TestE2E_ConnectModes_H2C_Smoke(t *testing.T) {
	// Upstream is an h2c (cleartext HTTP/2) server.
	upstreamAddr, shutdown := startSmokeH2CUpstream(t)
	defer shutdown()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	// Build an h2c client that tunnels through the proxy via CONNECT.
	client := newH2CClientThroughProxy(proxyAddr, upstreamAddr)

	// Use h2c.example.test as the URL host; the proxy strips the
	// authority during MITM but x/net/http2.Transport sets :authority
	// from the URL host. The DialTLS hook directs the actual TCP
	// connection to the proxy (via CONNECT). The upstream itself is the
	// h2c server.
	url := fmt.Sprintf("http://%s/smoke-h2c", upstreamAddr)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("h2c-over-CONNECT GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "h2c-ok") {
		t.Errorf("body = %q, want contains %q", string(body), "h2c-ok")
	}

	// MCP query tool integration: protocol="http", scheme="http".
	flowEntry := waitForConnectModeFlow(t, h, "/smoke-h2c", "http", 5*time.Second)
	if flowEntry.Scheme != "http" {
		t.Errorf("flow.scheme = %q, want %q (h2c is cleartext)",
			flowEntry.Scheme, "http")
	}
	if flowEntry.State != "complete" {
		t.Errorf("flow.state = %q, want %q", flowEntry.State, "complete")
	}

	assertFlowRawRequestNonEmpty(t, h, flowEntry.ID)
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

// connectModeFlow is the subset of query("flows") entry we read for
// CONNECT-mode assertions. Defined locally so the test stays self-
// contained — query_tool.queryFlowsEntry is unexported.
type connectModeFlow struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Scheme   string `json:"scheme"`
	State    string `json:"state"`
	URL      string `json:"url"`
}

// waitForConnectModeFlow polls query("flows") until a flow whose URL
// contains pathSubstring AND whose protocol matches wantProtocol
// appears, or the timeout elapses. t.Fatal's on timeout. The combined
// match (path + protocol) lets the same harness drive multiple
// scenarios in one test process without cross-pollution.
func waitForConnectModeFlow(t *testing.T, h *mcptest.Harness, pathSubstring, wantProtocol string, timeout time.Duration) connectModeFlow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	const pollInterval = 30 * time.Millisecond
	for {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
		})
		var parsed struct {
			Flows []connectModeFlow `json:"flows"`
		}
		if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
			t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
		}
		for _, f := range parsed.Flows {
			if f.Protocol != wantProtocol {
				continue
			}
			if strings.Contains(f.URL, pathSubstring) && f.State == "complete" {
				return f
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no completed %q flow with URL containing %q within %v; flows=%+v",
				wantProtocol, pathSubstring, timeout, parsed.Flows)
		}
		time.Sleep(pollInterval)
	}
}

// assertFlowRawRequestNonEmpty calls query("flow", id) and asserts the
// raw_request field decodes to non-empty bytes. The raw_request is
// always base64-encoded original wire bytes — non-empty proves the
// L4-capable recording principle held end-to-end through the MCP
// boundary.
func assertFlowRawRequestNonEmpty(t *testing.T, h *mcptest.Harness, flowID string) {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})
	rawReqB64, _ := res.Decoded["raw_request"].(string)
	if rawReqB64 == "" {
		t.Errorf("flow %s raw_request is empty (L4-capable principle violated); response=%s",
			flowID, res.Text)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(rawReqB64)
	if err != nil {
		t.Errorf("flow %s raw_request is not valid base64: %v", flowID, err)
		return
	}
	if len(decoded) == 0 {
		t.Errorf("flow %s raw_request decoded to zero bytes (L4-capable principle violated)", flowID)
	}
}

// connectAndSendPlainHTTPSmoke performs CONNECT, reads 200, then sends
// a plain HTTP/1.x request over the tunnel WITHOUT a TLS handshake.
// This is the exact wire shape produced by `curl --proxytunnel http://...`
// — the failure mode USK-762 closes.
//
// Locally re-implemented (rather than imported from
// internal/connector/full_listener_integration_test.go) because that
// helper lives in a separate package and the connector tests still
// need it. Duplicate lines beat coupling test packages here.
func connectAndSendPlainHTTPSmoke(t *testing.T, proxyAddr, target, rawRequest string) string {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	// Read the CONNECT response line-by-line. A single conn.Read may
	// not return the entire status line + empty trailer in one call
	// (TCP doesn't guarantee atomic reads), so use bufio.Reader to
	// read the response status + headers up to the blank line.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status line: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("unexpected CONNECT status: %q", statusLine)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT header: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if br.Buffered() > 0 {
		t.Fatalf("unexpected buffered bytes after CONNECT response")
	}
	_ = conn.SetReadDeadline(time.Time{})

	if _, err := conn.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write plain HTTP request through CONNECT tunnel: %v", err)
	}

	return readSmokeHTTPResponse(t, conn)
}

// readSmokeHTTPResponse reads a complete HTTP response from a
// connection. Locally scoped duplicate of readHTTPResponse in
// internal/connector — same rationale as connectAndSendPlainHTTPSmoke.
func readSmokeHTTPResponse(t *testing.T, conn net.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// Read to EOF — the upstream sends `Connection: close` so the
	// connection drains and Read returns io.EOF (or another error)
	// once the body completes. Returning the accumulated bytes covers
	// the canonical close-delimited response shape this test exercises.
	var respBuf bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			respBuf.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return respBuf.String()
}

// startSmokeUpstreamPlainHTTP starts a plain TCP server that reads
// HTTP requests and sends responses via the handler. Mirrors
// startUpstreamPlainHTTP in internal/connector but locally scoped so
// this test file compiles independently of that package.
func startSmokeUpstreamPlainHTTP(
	t *testing.T,
	handler func(reqBytes []byte) []byte,
) (net.Listener, func() [][]byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	captured := make(chan [][]byte, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		var allReqs [][]byte
		for {
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			reqBytes, err := readSmokeHTTPRequest(br)
			if err != nil {
				break
			}
			reqCopy := make([]byte, len(reqBytes))
			copy(reqCopy, reqBytes)
			allReqs = append(allReqs, reqCopy)

			resp := handler(reqBytes)
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(resp); err != nil {
				break
			}
			if bytes.Contains(bytes.ToLower(resp), []byte("connection: close")) {
				break
			}
		}
		captured <- allReqs
	}()

	return ln, func() [][]byte {
		select {
		case b := <-captured:
			return b
		case <-time.After(15 * time.Second):
			t.Fatal("timeout waiting for plain upstream captured bytes")
			return nil
		}
	}
}

// readSmokeHTTPRequest reads a complete HTTP/1.x request including
// any Content-Length-bounded body. Locally scoped duplicate of
// readHTTPRequest in internal/connector.
func readSmokeHTTPRequest(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	headerBytes := buf.Bytes()
	const maxContentLength = 1 * 1024 * 1024 // 1 MB safety cap

	contentLength := 0
	for _, line := range bytes.Split(headerBytes, []byte("\r\n")) {
		lower := bytes.ToLower(line)
		if bytes.HasPrefix(lower, []byte("content-length:")) {
			val := strings.TrimSpace(string(line[len("content-length:"):]))
			var n int
			if _, err := fmt.Sscanf(val, "%d", &n); err == nil && n >= 0 && n <= maxContentLength {
				contentLength = n
				break
			}
		}
	}
	if contentLength > 0 {
		body := make([]byte, contentLength)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, err
		}
		buf.Write(body)
	}
	return buf.Bytes(), nil
}

// ----------------------------------------------------------------------
// h2c helpers
// ----------------------------------------------------------------------

// startSmokeH2CUpstream binds an h2c (cleartext HTTP/2) upstream that
// answers any request with `h2c-ok` body. Returns the upstream addr
// and a shutdown function. Used by the h2c-over-CONNECT smoke.
func startSmokeH2CUpstream(t *testing.T) (string, func()) {
	t.Helper()
	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		_, _ = io.WriteString(w, "h2c-ok")
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("h2c upstream listen: %v", err)
	}

	srv := &gohttp.Server{Handler: handler}
	h2s := &http2.Server{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h2s.ServeConn(conn, &http2.ServeConnOpts{
				Handler:    handler,
				BaseConfig: srv,
			})
		}
	}()

	return ln.Addr().String(), func() {
		_ = ln.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

// newH2CClientThroughProxy builds an http.Client that:
//
//   - opens a CONNECT tunnel to the proxy for the given target,
//   - reads the 200 response,
//   - starts speaking HTTP/2 cleartext (h2c) on the SAME socket — no
//     TLS handshake.
//
// The proxy's inner-byte peek classifies the post-CONNECT bytes as
// InnerH2C (the HTTP/2 client preface starts with "PRI * HTTP/2.0..."
// — see internal/connector/detect.go) and dispatches through
// BuildPlainH2CStack.
func newH2CClientThroughProxy(proxyAddr, target string) *gohttp.Client {
	tr := &http2.Transport{
		// AllowHTTP enables the h2c code path (cleartext HTTP/2).
		AllowHTTP: true,
		// The DialTLS hook is the only seam x/net/http2.Transport gives
		// us for swapping the underlying connection. We tunnel through
		// CONNECT and return the raw conn — the http2.Transport then
		// sends the cleartext h2 preface directly on it because
		// AllowHTTP is true and the URL is http://.
		DialTLS: func(_, _ string, _ *tls.Config) (net.Conn, error) {
			return dialCONNECTTunnel(proxyAddr, target)
		},
	}
	return &gohttp.Client{Transport: tr, Timeout: 30 * time.Second}
}

// dialCONNECTTunnel opens a CONNECT tunnel to proxyAddr for target and
// returns the post-200 raw connection. Caller writes whatever inner
// protocol bytes they want next (TLS handshake, plain HTTP, h2 preface
// — the proxy peeks and dispatches accordingly).
func dialCONNECTTunnel(proxyAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := c.Write([]byte(req)); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if !strings.Contains(line, "200") {
		_ = c.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	if br.Buffered() > 0 {
		_ = c.Close()
		return nil, fmt.Errorf("unexpected buffered bytes after CONNECT")
	}
	return c, nil
}

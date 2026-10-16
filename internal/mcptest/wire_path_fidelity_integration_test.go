//go:build e2e && !e2e_smoke

package mcptest_test

import (
	"bufio"
	"bytes"
	"crypto/sha1" //nolint:gosec // RFC 6455 §4.2.2 Sec-WebSocket-Accept is defined over SHA-1
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1139 wire-path fidelity e2e. The reported request path (GitHub
// issue 137, an ad cookie-sync URL) carries percent-encoded ':' '/' '?'
// '=' inside one path segment. Before the fix HTTP/1.x recorded the
// decoded path (and resend split it at the decoded '?'), and HTTP/2
// recorded it double-escaped (%253A).
const (
	usk1139WirePath   = "/check_uuid/https%3A%2F%2Fsync.example%2Fsetuid%3Fa%3D1"
	usk1139RawQuery   = "q=x%3Ay"
	usk1139WireTarget = usk1139WirePath + "?" + usk1139RawQuery
)

// wirePathFlow is the subset of query("flows") the tests read.
type wirePathFlow struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	URL      string `json:"url"`
}

// waitForWirePathFlow polls query("flows") for a complete flow whose URL
// contains substr and was not already seen (exclude), returning it.
func waitForWirePathFlow(t *testing.T, h *mcptest.Harness, substr string, exclude map[string]bool, timeout time.Duration) wirePathFlow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows"})
		var parsed struct {
			Flows []wirePathFlow `json:"flows"`
		}
		if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
			t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
		}
		for _, f := range parsed.Flows {
			if exclude[f.ID] || f.State != "complete" {
				continue
			}
			if strings.Contains(f.URL, substr) {
				return f
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no complete flow with URL containing %q within %v; flows=%+v", substr, timeout, parsed.Flows)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// rawProxyRoundTrip writes rawRequest to the proxy listener over a plain
// TCP connection (no net/http, so the request-target bytes are exactly
// what the test wrote) and returns the response status line.
func rawProxyRoundTrip(t *testing.T, proxyAddr, rawRequest string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	_, _ = io.Copy(io.Discard, br)
	return strings.TrimRight(status, "\r\n")
}

// TestE2E_WirePath_HTTP1_AbsoluteForm_RecordAndResend is Test Plan row 1:
// the reported path, over a raw absolute-form HTTP/1.1 request, must reach
// the upstream byte-exact, be recorded byte-exact, and be resent byte-exact.
func TestE2E_WirePath_HTTP1_AbsoluteForm_RecordAndResend(t *testing.T) {
	upstream := startRawHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}

	status := rawProxyRoundTrip(t, proxyAddr, fmt.Sprintf(
		"GET http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.addr(), usk1139WireTarget, upstream.addr()))
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("proxied status line = %q, want 200", status)
	}

	// (1) Live forward is wire-exact (it already was before the fix): the
	// opaque HTTP/1.x send path relays the absolute-form target verbatim.
	liveTarget := "http://" + upstream.addr() + usk1139WireTarget
	if got := upstream.waitForRequest(t, 5*time.Second).path; got != liveTarget {
		t.Errorf("upstream request-target = %q, want %q", got, liveTarget)
	}

	// (2) The recorded URL carries the wire bytes.
	fl := waitForWirePathFlow(t, h, "/check_uuid/", nil, 5*time.Second)
	if !strings.HasSuffix(fl.URL, usk1139WireTarget) {
		t.Errorf("recorded url = %q, want suffix %q", fl.URL, usk1139WireTarget)
	}

	// (3) resend_http {flow_id} sends the same path and query (resend
	// synthesizes an origin-form request line).
	h.MustOK(t, "resend_http", map[string]any{"flow_id": fl.ID})
	if got := upstream.waitForRequest(t, 5*time.Second).path; got != usk1139WireTarget {
		t.Errorf("resend request-target = %q, want %q", got, usk1139WireTarget)
	}
}

// h2URIUpstream is a TLS HTTP/2 server recording each request's
// RequestURI (the :path pseudo-header verbatim).
type h2URIUpstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	uris []string
	got  chan struct{}
}

func startH2URIUpstream(t *testing.T) *h2URIUpstream {
	t.Helper()
	u := &h2URIUpstream{got: make(chan struct{}, 8)}
	u.srv = httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		u.mu.Lock()
		u.uris = append(u.uris, r.RequestURI)
		u.mu.Unlock()
		select {
		case u.got <- struct{}{}:
		default:
		}
		w.WriteHeader(gohttp.StatusOK)
		_, _ = io.WriteString(w, "h2-ok")
	}))
	u.srv.EnableHTTP2 = true
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

func (u *h2URIUpstream) waitURI(t *testing.T, n int, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		u.mu.Lock()
		if len(u.uris) >= n {
			got := u.uris[n-1]
			u.mu.Unlock()
			return got
		}
		u.mu.Unlock()
		select {
		case <-u.got:
		case <-deadline:
			t.Fatalf("upstream saw fewer than %d requests within %v", n, timeout)
		}
	}
}

// h2RawGET opens a CONNECT tunnel through the proxy, completes TLS with
// ALPN h2 against the MITM leaf, and sends one GET whose :path is written
// verbatim with x/net's Framer + HPACK encoder (net/http would re-derive
// the path from a *url.URL). Returns the response :status.
func h2RawGET(t *testing.T, proxyAddr, target, wirePathWithQuery string) string {
	t.Helper()
	raw, err := fpDialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT tunnel: %v", err)
	}
	host, _, _ := net.SplitHostPort(target)
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true, //nolint:gosec // test client trusts the proxy MITM leaf
	})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("client leg ALPN = %q, want h2", got)
	}

	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: target},
		{Name: ":path", Value: wirePathWithQuery},
	} {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("hpack encode: %v", err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	status := ""
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			status = f.Value
		}
	})
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read frame (status so far %q): %v", status, err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			if f.StreamID == 1 {
				if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
					t.Fatalf("hpack decode: %v", err)
				}
				if f.StreamEnded() {
					return status
				}
			}
		case *http2.DataFrame:
			if f.StreamID == 1 && f.StreamEnded() {
				return status
			}
		case *http2.RSTStreamFrame:
			t.Fatalf("stream reset: %v", f.ErrCode)
		case *http2.GoAwayFrame:
			t.Fatalf("goaway: %v", f.ErrCode)
		}
	}
}

// TestE2E_WirePath_HTTP2_RecordAndResend is Test Plan row 2: the HTTP/2
// sibling over TLS MITM. Before the fix the recorded URL was %253A-doubled.
func TestE2E_WirePath_HTTP2_RecordAndResend(t *testing.T) {
	upstream := startH2URIUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{TLSFingerprint: "none"})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}
	_, port, _ := net.SplitHostPort(upstream.srv.Listener.Addr().String())
	target := net.JoinHostPort("localhost", port)

	if status := h2RawGET(t, proxyAddr, target, usk1139WireTarget); status != "200" {
		t.Fatalf("h2 :status = %q, want 200", status)
	}
	if got := upstream.waitURI(t, 1, 5*time.Second); got != usk1139WireTarget {
		t.Errorf("upstream :path = %q, want %q", got, usk1139WireTarget)
	}

	fl := waitForWirePathFlow(t, h, "/check_uuid/", nil, 5*time.Second)
	if !strings.HasSuffix(fl.URL, usk1139WireTarget) {
		t.Errorf("recorded url = %q, want suffix %q", fl.URL, usk1139WireTarget)
	}

	h.MustOK(t, "resend_http", map[string]any{"flow_id": fl.ID})
	if got := upstream.waitURI(t, 2, 10*time.Second); got != usk1139WireTarget {
		t.Errorf("resend :path = %q, want %q", got, usk1139WireTarget)
	}
}

// TestE2E_Intercept_HTTP1_ModifyHeaderKeepsWirePath is Test Plan row 4: a
// header-only modify_and_forward re-synthesizes the HTTP/1.x request line
// from HTTPMessage.Path. With a decoded Path, "/a%3Fb%20c" went out as
// "GET /a?b c HTTP/1.1". Path shape invented for the test.
func TestE2E_Intercept_HTTP1_ModifyHeaderKeepsWirePath(t *testing.T) {
	const wireTarget = "/a%3Fb%20c"
	upstream := startRawHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxyAddr := startProxyWithRules(t, h, []map[string]any{{
		"id":        "match-all",
		"enabled":   true,
		"protocol":  "http",
		"direction": "request",
		"http":      map[string]any{"path_pattern": ".*"},
	}}, nil)

	done := make(chan string, 1)
	go func() {
		defer close(done)
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		_, _ = fmt.Fprintf(conn, "GET http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
			upstream.addr(), wireTarget, upstream.addr())
		line, _ := bufio.NewReader(conn).ReadString('\n')
		done <- line
	}()

	entry := waitForHeldEntry(t, h, 5*time.Second)
	h.MustOK(t, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{"intercept_id": entry["id"]},
		"http": map[string]any{
			"headers": []map[string]any{
				{"name": "Host", "value": upstream.addr()},
				{"name": "X-Modified", "value": "1"},
				{"name": "Connection", "value": "close"},
			},
		},
	})

	got := upstream.waitForRequest(t, 5*time.Second)
	if got.path != wireTarget {
		t.Errorf("upstream request-target = %q, want %q (request line %q %q %q)",
			got.path, wireTarget, got.method, got.path, got.httpVersion)
	}
	if v := findHeaderValue(got.headerLines(), "X-Modified"); v != "1" {
		t.Errorf("upstream X-Modified = %q, want 1 (the modify did not apply)", v)
	}
	<-done
}

// parseHTTP1Response reads a response status line and headers (no body).
func parseHTTP1Response(br *bufio.Reader) (string, error) {
	status, err := br.ReadString('\n')
	if err != nil {
		return status, err
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return status, err
		}
		if line == "\r\n" || line == "\n" {
			return strings.TrimRight(status, "\r\n"), nil
		}
	}
}

// wsCaptureUpstream is a raw-TCP WebSocket upstream: it records each
// upgrade request-target, answers 101, then echoes one frame back.
type wsCaptureUpstream struct {
	ln      net.Listener
	mu      sync.Mutex
	targets []string
	got     chan struct{}
}

func startWSCaptureUpstream(t *testing.T) *wsCaptureUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &wsCaptureUpstream{ln: ln, got: make(chan struct{}, 8)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go u.handle(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return u
}

func (u *wsCaptureUpstream) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	req, err := parseHTTP1Request(br)
	if err != nil {
		return
	}
	u.mu.Lock()
	u.targets = append(u.targets, req.path)
	u.mu.Unlock()
	select {
	case u.got <- struct{}{}:
	default:
	}
	key := findHeaderValue(req.headerLines(), "Sec-WebSocket-Key")
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // RFC 6455
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(sum[:]))
	f, err := ws.ReadFrame(br)
	if err != nil {
		return
	}
	_ = ws.WriteFrame(conn, &ws.Frame{Fin: true, Opcode: f.Opcode, Payload: f.Payload})
}

func (u *wsCaptureUpstream) waitTarget(t *testing.T, n int, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		u.mu.Lock()
		if len(u.targets) >= n {
			got := u.targets[n-1]
			u.mu.Unlock()
			return got
		}
		u.mu.Unlock()
		select {
		case <-u.got:
		case <-deadline:
			t.Fatalf("WS upstream saw fewer than %d upgrades within %v", n, timeout)
		}
	}
}

// TestE2E_ResendWS_FlowID_EncodedUpgradePathWireExact is Test Plan row 11:
// a WebSocket upgrade recorded over HTTP/1.x with an encoded request path
// is replayed by resend_ws {flow_id} with the same request-target. Path
// shape invented for the test.
func TestE2E_ResendWS_FlowID_EncodedUpgradePathWireExact(t *testing.T) {
	const wireTarget = "/ws%3Fa%2Fb%20c?k=v%3D1"
	upstream := startWSCaptureUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}
	addr := upstream.ln.Addr().String()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = fmt.Fprintf(conn, "GET http://%s%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", addr, wireTarget, addr)
	br := bufio.NewReader(conn)
	resp, err := parseHTTP1Response(br)
	if err != nil || !strings.Contains(resp, " 101 ") {
		t.Fatalf("upgrade status = %q, err %v; want 101", resp, err)
	}
	// One masked text frame and its echo, so the upstream finishes the
	// exchange and closes; the stream then completes.
	if err := ws.WriteFrame(conn, &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Masked: true,
		MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("live")}); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}
	if _, err := ws.ReadFrame(br); err != nil {
		t.Fatalf("read ws echo: %v", err)
	}
	_ = conn.Close()

	// The live leg relays the absolute-form target verbatim.
	if got, want := upstream.waitTarget(t, 1, 5*time.Second), "http://"+addr+wireTarget; got != want {
		t.Errorf("live upgrade request-target = %q, want %q", got, want)
	}
	fl := waitForWirePathFlow(t, h, "/ws", nil, 10*time.Second)
	if !strings.HasSuffix(fl.URL, wireTarget) {
		t.Errorf("recorded upgrade url = %q, want suffix %q", fl.URL, wireTarget)
	}

	h.MustOK(t, "resend_ws", map[string]any{
		"flow_id":    fl.ID,
		"opcode":     "text",
		"payload":    "hello",
		"timeout_ms": 5000,
	})
	if got := upstream.waitTarget(t, 2, 5*time.Second); got != wireTarget {
		t.Errorf("resend_ws upgrade request-target = %q, want %q", got, wireTarget)
	}
}

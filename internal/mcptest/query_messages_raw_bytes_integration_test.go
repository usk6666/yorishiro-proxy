//go:build e2e && !e2e_smoke

// USK-1344: query resource=messages must not surface a bodyless HTTP
// message's raw wire bytes (the HTTP/1.1 request head, the HTTP/2 HPACK
// HEADERS block) as its L7 `body`. The wire bytes come back in `raw_bytes`
// (base64) instead. Drives real traffic through the live proxy.
package mcptest_test

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

type rawBytesMessageEntry struct {
	ID               string `json:"id"`
	Direction        string `json:"direction"`
	Method           string `json:"method"`
	Body             string `json:"body"`
	BodyOriginalSize int    `json:"body_original_size"`
	RawBytes         string `json:"raw_bytes"`
	RawBytesEncoding string `json:"raw_bytes_encoding"`
	RawBytesSize     int    `json:"raw_bytes_size"`
}

// waitForSendMessage polls query(messages) until the send entry of flowID
// is recorded, or fails the test after timeout.
func waitForSendMessage(t *testing.T, h *mcptest.Harness, flowID string, timeout time.Duration) rawBytesMessageEntry {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "messages", "id": flowID})
		var parsed struct {
			Messages []rawBytesMessageEntry `json:"messages"`
		}
		if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
			t.Fatalf("decode query(messages): %v (text=%q)", err, res.Text)
		}
		for _, m := range parsed.Messages {
			if m.Direction == "send" {
				return m
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no send message recorded for flow %s within %s (text=%s)", flowID, timeout, res.Text)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// assertBodylessSendEntry checks the USK-1344 contract on a bodyless GET:
// empty body, no body_original_size, raw bytes in raw_bytes (base64).
func assertBodylessSendEntry(t *testing.T, e rawBytesMessageEntry) []byte {
	t.Helper()
	if e.Body != "" {
		t.Errorf("send body = %q, want empty (bodyless GET; raw wire bytes must not appear as body)", e.Body)
	}
	if e.BodyOriginalSize != 0 {
		t.Errorf("send body_original_size = %d, want 0", e.BodyOriginalSize)
	}
	if e.RawBytesEncoding != "base64" {
		t.Errorf("send raw_bytes_encoding = %q, want base64", e.RawBytesEncoding)
	}
	raw, err := base64.StdEncoding.DecodeString(e.RawBytes)
	if err != nil {
		t.Fatalf("send raw_bytes is not base64: %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("send raw_bytes is empty; want the recorded wire bytes")
	}
	if e.RawBytesSize != len(raw) {
		t.Errorf("send raw_bytes_size = %d, want %d", e.RawBytesSize, len(raw))
	}
	return raw
}

// TestE2E_QueryMessages_BodylessGET_RawBytes_HTTP1 sends a plain forward
// HTTP/1.1 GET through the proxy.
func TestE2E_QueryMessages_BodylessGET_RawBytes_HTTP1(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "h1-ok")
	}))
	defer upstream.Close()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &gohttp.Client{
		Transport: &gohttp.Transport{Proxy: gohttp.ProxyURL(proxyURL)},
		Timeout:   15 * time.Second,
	}

	resp, err := client.Get(upstream.URL + "/usk1344-h1")
	if err != nil {
		t.Fatalf("h1 GET through proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	f := waitForConnectModeFlow(t, h, "usk1344-h1", "http", 5*time.Second)
	raw := assertBodylessSendEntry(t, waitForSendMessage(t, h, f.ID, 5*time.Second))
	if !bytes.HasPrefix(raw, []byte("GET ")) {
		t.Errorf("send raw_bytes = %q, want the HTTP/1.1 request head starting with \"GET \"", raw)
	}
}

// TestE2E_QueryMessages_BodylessGET_RawBytes_HTTP2 sends an HTTP/2 GET over
// CONNECT + TLS(h2) through the proxy.
func TestE2E_QueryMessages_BodylessGET_RawBytes_HTTP2(t *testing.T) {
	upstream := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "h2-ok")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
			NextProtos:         []string{"h2"},
		},
		DialTLS: func(_, _ string, cfg *tls.Config) (net.Conn, error) {
			raw, err := dialCONNECTTunnel(proxyAddr, upstreamAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, cfg)
			if err := tlsConn.Handshake(); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	defer tr.CloseIdleConnections()
	client := &gohttp.Client{Transport: tr, Timeout: 15 * time.Second}

	resp, err := client.Get(fmt.Sprintf("https://%s/usk1344-h2", upstreamAddr))
	if err != nil {
		t.Fatalf("h2 GET through proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("status=%d proto=%s, want 200 over HTTP/2", resp.StatusCode, resp.Proto)
	}

	f := waitForConnectModeFlow(t, h, "usk1344-h2", "http", 5*time.Second)
	raw := assertBodylessSendEntry(t, waitForSendMessage(t, h, f.ID, 5*time.Second))
	if bytes.HasPrefix(raw, []byte("GET ")) {
		t.Errorf("h2 send raw_bytes looks like an HTTP/1.1 head (%q); want HPACK-encoded HEADERS", raw)
	}
}

//go:build e2e

// USK-1197 smoke coverage: an HTTP/2 request WITH a body must record the
// Stream scheme. On the aggregator h2 path the first DATA frame's
// wire_level=h2-frame overlay reaches RecordStep before the semantic
// HTTPMessage and wins the USK-908 first-write-wins createStream; the
// overlay carries no Message, so the Stream was created with Scheme="".
// The semantic envelope must backfill it.
package mcptest_test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_H2BodyStreamScheme_TLS_Smoke drives a body-bearing POST and a
// body-less GET over CONNECT + TLS(h2) and asserts both Streams record
// scheme=https, that filter.scheme=https returns the POST, and that the
// h2-frame overlay rows are still recorded (MITM Principle 3).
func TestE2E_H2BodyStreamScheme_TLS_Smoke(t *testing.T) {
	upstream := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
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

	postResp, err := client.Post(fmt.Sprintf("https://%s/usk1197?case=post", upstreamAddr),
		"application/x-www-form-urlencoded", strings.NewReader("a=1"))
	if err != nil {
		t.Fatalf("h2 POST through proxy: %v", err)
	}
	_, _ = io.ReadAll(postResp.Body)
	postResp.Body.Close()
	if postResp.StatusCode != gohttp.StatusOK || postResp.ProtoMajor != 2 {
		t.Fatalf("POST status=%d proto=%s, want 200 over HTTP/2", postResp.StatusCode, postResp.Proto)
	}

	getResp, err := client.Get(fmt.Sprintf("https://%s/usk1197?case=get", upstreamAddr))
	if err != nil {
		t.Fatalf("h2 GET through proxy: %v", err)
	}
	_, _ = io.ReadAll(getResp.Body)
	getResp.Body.Close()

	postFlow := waitForConnectModeFlow(t, h, "case=post", "http", 5*time.Second)
	if postFlow.Scheme != "https" {
		t.Errorf("POST-with-body flow.scheme = %q, want %q", postFlow.Scheme, "https")
	}
	getFlow := waitForConnectModeFlow(t, h, "case=get", "http", 5*time.Second)
	if getFlow.Scheme != "https" {
		t.Errorf("body-less GET flow.scheme = %q, want %q", getFlow.Scheme, "https")
	}

	// filter.scheme=https must return the body-bearing h2 flow.
	if !queryFlowsContainsID(t, h, map[string]any{"scheme": "https", "url_pattern": "usk1197"}, postFlow.ID) {
		t.Errorf("query(flows, filter.scheme=https) did not return the POST-with-body flow %s", postFlow.ID)
	}

	// MITM Principle 3: the h2-frame overlay rows are still recorded.
	msgRes := h.MustOK(t, "query", map[string]any{
		"resource": "messages",
		"id":       postFlow.ID,
		"filter":   map[string]any{"wire_level": "h2-frame"},
	})
	var msgs struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(msgRes.Text), &msgs); err != nil {
		t.Fatalf("decode query(messages): %v (text=%q)", err, msgRes.Text)
	}
	if len(msgs.Messages) == 0 {
		t.Errorf("query(messages, wire_level=h2-frame) returned no overlay rows for flow %s", postFlow.ID)
	}
}

// TestE2E_H2BodyStreamScheme_H2C_Smoke drives a body-bearing POST over
// CONNECT + h2c and asserts the Stream records scheme=http.
func TestE2E_H2BodyStreamScheme_H2C_Smoke(t *testing.T) {
	upstreamAddr, shutdown := startSmokeH2CUpstream(t)
	defer shutdown()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	client := newH2CClientThroughProxy(proxyAddr, upstreamAddr)
	resp, err := client.Post(fmt.Sprintf("http://%s/usk1197-h2c?case=post", upstreamAddr),
		"application/x-www-form-urlencoded", strings.NewReader("a=1"))
	if err != nil {
		t.Fatalf("h2c POST through proxy: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	f := waitForConnectModeFlow(t, h, "usk1197-h2c", "http", 5*time.Second)
	if f.Scheme != "http" {
		t.Errorf("h2c POST-with-body flow.scheme = %q, want %q", f.Scheme, "http")
	}
}

// queryFlowsContainsID runs query(flows) with the given filter and
// reports whether the result includes flowID.
func queryFlowsContainsID(t *testing.T, h *mcptest.Harness, filter map[string]any, flowID string) bool {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{
		"resource": "flows",
		"filter":   filter,
	})
	var parsed struct {
		Flows []connectModeFlow `json:"flows"`
	}
	if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
		t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
	}
	for _, f := range parsed.Flows {
		if f.ID == flowID {
			return true
		}
	}
	return false
}

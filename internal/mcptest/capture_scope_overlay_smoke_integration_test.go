//go:build e2e

// USK-1199 smoke coverage: capture_scope method / url_prefix rules must
// decide recording for body-bearing HTTP/2 and gRPC-Web streams.
//
// On the aggregator h2 path the first DATA frame's wire_level=h2-frame
// overlay (Message=nil) reaches RecordStep before the semantic
// HTTPMessage, and RecordStep caches the per-stream capture_scope
// decision on that first Send envelope. Before the fix the overlay
// exposed no method / path, so an include rule cached "do not record"
// (the whole stream, semantic flow included, vanished) and an exclude
// rule never fired.
//
// Every case drives the real production stack through the JSON-RPC
// harness: proxy_start(capture_scope) → CONNECT + TLS(h2) → aggregator →
// RecordStep → SQLite → query.
package mcptest_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// captureScopeFlow is the query(flows) row shape these tests read.
type captureScopeFlow struct {
	ID           string `json:"id"`
	Protocol     string `json:"protocol"`
	Scheme       string `json:"scheme"`
	State        string `json:"state"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	MessageCount int    `json:"message_count"`
}

// listCaptureScopeFlows runs query(flows) with filter (nil = none) and
// returns every row that is not a tls-handshake observation stream.
func listCaptureScopeFlows(t *testing.T, h *mcptest.Harness, filter map[string]any) []captureScopeFlow {
	t.Helper()
	args := map[string]any{"resource": "flows"}
	if filter != nil {
		args["filter"] = filter
	}
	res := h.MustOK(t, "query", args)
	var parsed struct {
		Flows []captureScopeFlow `json:"flows"`
	}
	if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
		t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
	}
	out := parsed.Flows[:0]
	for _, f := range parsed.Flows {
		if f.Protocol == "tls-handshake" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// waitForCaptureScopeFlows polls query(flows) until pred accepts the
// rows or timeout elapses (t.Fatal on timeout).
func waitForCaptureScopeFlows(t *testing.T, h *mcptest.Harness, what string, timeout time.Duration, pred func([]captureScopeFlow) bool) []captureScopeFlow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		flows := listCaptureScopeFlows(t, h, nil)
		if pred(flows) {
			return flows
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s; flows=%+v", timeout, what, flows)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

func findCompleteFlow(flows []captureScopeFlow, urlSubstring string) (captureScopeFlow, bool) {
	for _, f := range flows {
		if strings.Contains(f.URL, urlSubstring) && f.State == "complete" {
			return f, true
		}
	}
	return captureScopeFlow{}, false
}

// startCaptureScopeHarness boots the harness and starts a proxy listener
// with the given capture_scope payload. Returns the harness and the
// proxy address.
func startCaptureScopeHarness(t *testing.T, opts mcptest.HarnessOptions, scope map[string]any) (*mcptest.Harness, string) {
	t.Helper()
	h := mcptest.StartHarness(t, opts)
	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":   "127.0.0.1:0",
		"capture_scope": scope,
	})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	return h, proxyAddr
}

// startH2TLSUpstream starts an httptest TLS upstream speaking HTTP/2.
func startH2TLSUpstream(t *testing.T) string {
	t.Helper()
	upstream := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "h2-ok")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	return upstream.Listener.Addr().String()
}

// startH1TLSUpstream starts an httptest TLS upstream speaking HTTP/1.1
// only.
func startH1TLSUpstream(t *testing.T) string {
	t.Helper()
	upstream := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "h1-ok")
	}))
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	return upstream.Listener.Addr().String()
}

// newH2TLSClientThroughProxy returns an HTTP/2 client that reaches
// upstreamAddr through a CONNECT tunnel + TLS(h2) to the proxy.
func newH2TLSClientThroughProxy(t *testing.T, proxyAddr, upstreamAddr string) *gohttp.Client {
	t.Helper()
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
	t.Cleanup(tr.CloseIdleConnections)
	return &gohttp.Client{Transport: tr, Timeout: 15 * time.Second}
}

// newH1TLSClientThroughProxy returns an HTTP/1.1-only client that uses
// the proxy via CONNECT for https URLs.
func newH1TLSClientThroughProxy(t *testing.T, proxyAddr string) *gohttp.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	tr := &gohttp.Transport{
		Proxy: gohttp.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
			NextProtos:         []string{"http/1.1"},
		},
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(string, *tls.Conn) gohttp.RoundTripper{},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &gohttp.Client{Transport: tr, Timeout: 15 * time.Second}
}

// doCaptureScopeRequest issues method to rawURL (body for POST) and
// asserts a 200 response with the wanted protocol major version.
func doCaptureScopeRequest(t *testing.T, client *gohttp.Client, method, rawURL string, wantProtoMajor int) {
	t.Helper()
	var body io.Reader
	if method == gohttp.MethodPost {
		body = strings.NewReader("a=1")
	}
	req, err := gohttp.NewRequest(method, rawURL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s through proxy: %v", method, rawURL, err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK || resp.ProtoMajor != wantProtoMajor {
		t.Fatalf("%s %s: status=%d proto=%s, want 200 over HTTP/%d", method, rawURL, resp.StatusCode, resp.Proto, wantProtoMajor)
	}
}

// assertH2FrameRows asserts the h2-frame overlay rows of flowID are
// still recorded (MITM Principle 3).
func assertH2FrameRows(t *testing.T, h *mcptest.Harness, flowID string) {
	t.Helper()
	msgRes := h.MustOK(t, "query", map[string]any{
		"resource": "messages",
		"id":       flowID,
		"filter":   map[string]any{"wire_level": "h2-frame"},
	})
	var msgs struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(msgRes.Text), &msgs); err != nil {
		t.Fatalf("decode query(messages): %v (text=%q)", err, msgRes.Text)
	}
	if len(msgs.Messages) == 0 {
		t.Errorf("query(messages, wire_level=h2-frame) returned no overlay rows for flow %s", flowID)
	}
}

// TestE2E_CaptureScopeOverlay_H2Include_Smoke: under an include rule
// that matches a body-bearing HTTP/2 POST (by method, or by url_prefix),
// the POST's semantic flow is recorded with its h2-frame overlay rows,
// and a GET that the rule does not match is not recorded.
func TestE2E_CaptureScopeOverlay_H2Include_Smoke(t *testing.T) {
	cases := []struct {
		name    string
		rule    map[string]any
		postURL string
		getURL  string
	}{
		{name: "method_POST", rule: map[string]any{"method": "POST"}, postURL: "/api/usk1199?case=post", getURL: "/api/usk1199?case=get"},
		{name: "url_prefix_api", rule: map[string]any{"url_prefix": "/api/"}, postURL: "/api/usk1199?case=post", getURL: "/other/usk1199?case=get"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamAddr := startH2TLSUpstream(t)
			h, proxyAddr := startCaptureScopeHarness(t, mcptest.HarnessOptions{},
				map[string]any{"includes": []any{tc.rule}})
			client := newH2TLSClientThroughProxy(t, proxyAddr, upstreamAddr)

			doCaptureScopeRequest(t, client, gohttp.MethodGet, "https://"+upstreamAddr+tc.getURL, 2)
			doCaptureScopeRequest(t, client, gohttp.MethodPost, "https://"+upstreamAddr+tc.postURL, 2)

			flows := waitForCaptureScopeFlows(t, h, "the body-bearing h2 POST flow", 5*time.Second, func(fs []captureScopeFlow) bool {
				_, ok := findCompleteFlow(fs, "case=post")
				return ok
			})
			post, _ := findCompleteFlow(flows, "case=post")
			if post.Method != "POST" {
				t.Errorf("POST flow method = %q, want POST (semantic HTTPMessage must be recorded)", post.Method)
			}
			if post.MessageCount < 2 {
				t.Errorf("POST flow message_count = %d, want >= 2 semantic messages", post.MessageCount)
			}
			assertH2FrameRows(t, h, post.ID)

			// The GET's Send envelope passed RecordStep before its
			// response reached the client, so its absence is settled.
			for _, f := range listCaptureScopeFlows(t, h, map[string]any{"wire_level": "all"}) {
				if strings.Contains(f.URL, "case=get") {
					t.Errorf("GET flow %s recorded although include %v does not match it", f.ID, tc.rule)
				}
			}
		})
	}
}

// TestE2E_CaptureScopeOverlay_H2ExcludeMethod_Smoke: under exclude
// method=POST, a body-bearing HTTP/2 POST leaves no Stream at all (not
// even overlay rows), while a GET is recorded.
func TestE2E_CaptureScopeOverlay_H2ExcludeMethod_Smoke(t *testing.T) {
	upstreamAddr := startH2TLSUpstream(t)
	h, proxyAddr := startCaptureScopeHarness(t, mcptest.HarnessOptions{},
		map[string]any{"excludes": []any{map[string]any{"method": "POST"}}})
	client := newH2TLSClientThroughProxy(t, proxyAddr, upstreamAddr)

	doCaptureScopeRequest(t, client, gohttp.MethodPost, "https://"+upstreamAddr+"/api/usk1199?case=post", 2)
	doCaptureScopeRequest(t, client, gohttp.MethodGet, "https://"+upstreamAddr+"/api/usk1199?case=get", 2)

	waitForCaptureScopeFlows(t, h, "the GET flow", 5*time.Second, func(fs []captureScopeFlow) bool {
		_, ok := findCompleteFlow(fs, "case=get")
		return ok
	})
	for _, filter := range []map[string]any{nil, {"wire_level": "all"}} {
		flows := listCaptureScopeFlows(t, h, filter)
		for _, f := range flows {
			if !strings.Contains(f.URL, "case=get") {
				t.Errorf("filter %v: flow %+v recorded although exclude method=POST matches the POST stream", filter, f)
			}
		}
	}
}

// TestE2E_CaptureScopeOverlay_Controls_Smoke pins decisions that were
// already correct (semantic envelope first) under include method=POST:
// a bodyless HTTP/2 GET is not recorded and an HTTP/1.1 POST with a body
// is recorded.
func TestE2E_CaptureScopeOverlay_Controls_Smoke(t *testing.T) {
	h2Addr := startH2TLSUpstream(t)
	h1Addr := startH1TLSUpstream(t)
	h, proxyAddr := startCaptureScopeHarness(t, mcptest.HarnessOptions{},
		map[string]any{"includes": []any{map[string]any{"method": "POST"}}})

	h2Client := newH2TLSClientThroughProxy(t, proxyAddr, h2Addr)
	doCaptureScopeRequest(t, h2Client, gohttp.MethodGet, "https://"+h2Addr+"/ctl?case=h2get", 2)
	h1Client := newH1TLSClientThroughProxy(t, proxyAddr)
	doCaptureScopeRequest(t, h1Client, gohttp.MethodPost, "https://"+h1Addr+"/ctl?case=h1post", 1)

	waitForCaptureScopeFlows(t, h, "the HTTP/1.1 POST flow", 5*time.Second, func(fs []captureScopeFlow) bool {
		_, ok := findCompleteFlow(fs, "case=h1post")
		return ok
	})
	for _, f := range listCaptureScopeFlows(t, h, map[string]any{"wire_level": "all"}) {
		if strings.Contains(f.URL, "case=h2get") {
			t.Errorf("bodyless h2 GET flow %s recorded under include method=POST", f.ID)
		}
	}
}

// TestE2E_CaptureScopeOverlay_NativeGRPC_Smoke pins the native gRPC
// decision (GRPCStart is semantic-first) under include url_prefix.
func TestE2E_CaptureScopeOverlay_NativeGRPC_Smoke(t *testing.T) {
	h, proxyAddr := startCaptureScopeHarness(t, mcptest.HarnessOptions{UpstreamProto: "grpc"},
		map[string]any{"includes": []any{map[string]any{"url_prefix": "/" + mcptest.GRPCSafetyServiceName + "/"}}})

	cc := dialGRPCThroughProxy(t, proxyAddr, grpcUpstreamHostPort(t, h.UpstreamTLS.URL))
	defer cc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req := []byte("usk1199 native grpc")
	var resp []byte
	if err := cc.Invoke(ctx, mcptest.GRPCSafetyEchoMethod, &req, &resp, grpc.ForceCodec(grpcRegressionRawCodec{})); err != nil {
		t.Fatalf("gRPC Invoke through proxy: %v", err)
	}

	waitForCaptureScopeFlows(t, h, "the native gRPC flow", 5*time.Second, func(fs []captureScopeFlow) bool {
		for _, f := range fs {
			if f.Protocol == "grpc" {
				return true
			}
		}
		return false
	})
}

// TestE2E_CaptureScopeOverlay_GRPCWebH2_Smoke: gRPC-Web over h2 (binary
// and base64/text). The request body's h2-frame overlay arrives before
// the GRPCStart envelope. An include url_prefix on the service records
// both RPCs; an exclude method=POST records neither.
func TestE2E_CaptureScopeOverlay_GRPCWebH2_Smoke(t *testing.T) {
	variants := []struct {
		name        string
		base64Wire  bool
		contentType string
	}{
		{"binary_proto", false, "application/grpc-web+proto"},
		{"text_base64_proto", true, "application/grpc-web-text+proto"},
	}
	modes := []struct {
		name       string
		scope      map[string]any
		wantRecord bool
	}{
		{
			name:       "include_url_prefix",
			scope:      map[string]any{"includes": []any{map[string]any{"url_prefix": "/" + mcptest.GRPCWebSafetyServiceName + "/"}}},
			wantRecord: true,
		},
		{
			name:       "exclude_method_POST",
			scope:      map[string]any{"excludes": []any{map[string]any{"method": "POST"}}},
			wantRecord: false,
		},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			h, proxyAddr := startCaptureScopeHarness(t, mcptest.HarnessOptions{UpstreamProto: "grpc-web"}, mode.scope)
			upstreamHostPort := grpcWebUpstreamHostPort(t, h.UpstreamTLS.URL)

			for i, v := range variants {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				payload := []byte(fmt.Sprintf("usk1199 grpc-web %s", v.name))
				got, err := sendGRPCWebRequestThroughProxy(ctx, proxyAddr, upstreamHostPort,
					mcptest.GRPCWebSafetyEchoMethod, payload, v.base64Wire, v.contentType)
				cancel()
				if err != nil {
					t.Fatalf("%s: gRPC-Web round-trip: %v", v.name, err)
				}
				if string(got) != string(payload) {
					t.Fatalf("%s: echo mismatch: got %q want %q", v.name, got, payload)
				}
				if hits := h.GRPCWebObservedHits.Total(); hits != int64(i+1) {
					t.Fatalf("%s: upstream hits = %d, want %d", v.name, hits, i+1)
				}
			}

			if mode.wantRecord {
				waitForCaptureScopeFlows(t, h, "two grpc-web flows", 5*time.Second, func(fs []captureScopeFlow) bool {
					n := 0
					for _, f := range fs {
						if f.Protocol == "grpc-web" && f.State != "error" {
							n++
						}
					}
					return n == len(variants)
				})
				return
			}
			for _, filter := range []map[string]any{nil, {"wire_level": "all"}} {
				if flows := listCaptureScopeFlows(t, h, filter); len(flows) != 0 {
					t.Errorf("filter %v: %d flows recorded under exclude method=POST, want 0: %+v", filter, len(flows), flows)
				}
			}
		})
	}
}

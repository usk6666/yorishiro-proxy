//go:build e2e

// USK-1125 smoke coverage: proxy_start accepts a wildcard listen_addr
// (0.0.0.0) and the resulting listener proxies and records traffic.
//
// Exhaustive companions (dial via a discovered non-loopback IP, specific-IP
// bind, config-file listen_addr, tcp_forwards host inheritance) live in
// proxy_start_non_loopback_integration_test.go.
package mcptest_test

import (
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

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// listenFlow is the query(flows) row subset the listen-address tests read.
type listenFlow struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Scheme   string `json:"scheme"`
	State    string `json:"state"`
	URL      string `json:"url"`
}

// startPlainHTTPUpstream starts a loopback HTTP/1.1 upstream that answers
// every request with "ok:<path>".
func startPlainHTTPUpstream(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "ok:"+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// getViaProxy issues an absolute-form GET for http://upstreamAddr+path via
// the forward proxy at proxyAddr and returns the response body. It fails
// the test on a transport error or non-200 status.
func getViaProxy(t *testing.T, proxyAddr, upstreamAddr, path string) string {
	t.Helper()
	pURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	tr := &gohttp.Transport{Proxy: gohttp.ProxyURL(pURL), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &gohttp.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := client.Get("http://" + upstreamAddr + path)
	if err != nil {
		t.Fatalf("GET via proxy %s: %v", proxyAddr, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("GET via proxy %s: status %d body %q", proxyAddr, resp.StatusCode, body)
	}
	return string(body)
}

// waitForListenFlow polls query(flows) until a complete flow whose URL
// contains pathSubstring appears, and returns it.
func waitForListenFlow(t *testing.T, h *mcptest.Harness, pathSubstring string) listenFlow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows"})
		var parsed struct {
			Flows []listenFlow `json:"flows"`
		}
		if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
			t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
		}
		for _, f := range parsed.Flows {
			if strings.Contains(f.URL, pathSubstring) && f.State == "complete" {
				return f
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no complete flow for %q recorded; flows=%+v", pathSubstring, parsed.Flows)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// assertListenFlowRecorded checks the Subsystem Checklist recording
// outcomes for a plain-HTTP request: protocol http, scheme http, complete.
func assertListenFlowRecorded(t *testing.T, h *mcptest.Harness, pathSubstring string) {
	t.Helper()
	f := waitForListenFlow(t, h, pathSubstring)
	if f.Protocol != "http" {
		t.Errorf("flow.protocol = %q, want http", f.Protocol)
	}
	if f.Scheme != "http" {
		t.Errorf("flow.scheme = %q, want http", f.Scheme)
	}
}

// listenAddrPort returns the port of a proxy_start result's listen_addr and
// asserts its host equals wantHost.
func listenAddrPort(t *testing.T, res mcptest.ToolResult, wantHost string) string {
	t.Helper()
	addr, _ := res.Decoded["listen_addr"].(string)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("proxy_start listen_addr %q: %v (result=%s)", addr, err, res.Text)
	}
	if host != wantHost {
		t.Fatalf("proxy_start bound host = %q, want %q", host, wantHost)
	}
	return port
}

// TestE2E_ProxyStart_WildcardListenRecordsTraffic proves a listener bound
// to 0.0.0.0 accepts a client on the loopback interface, relays the
// request, and records the flow.
func TestE2E_ProxyStart_WildcardListenRecordsTraffic(t *testing.T) {
	if ln, err := net.Listen("tcp", "0.0.0.0:0"); err != nil {
		t.Skipf("cannot bind 0.0.0.0 in this environment: %v", err)
	} else {
		_ = ln.Close()
	}
	upstream := startPlainHTTPUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	res := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "0.0.0.0:0"})
	port := listenAddrPort(t, res, "0.0.0.0")

	const path = "/usk1125-wildcard-smoke"
	body := getViaProxy(t, net.JoinHostPort("127.0.0.1", port), upstream, path)
	if want := fmt.Sprintf("ok:%s", path); body != want {
		t.Errorf("response body = %q, want %q", body, want)
	}
	assertListenFlowRecorded(t, h, path)
}

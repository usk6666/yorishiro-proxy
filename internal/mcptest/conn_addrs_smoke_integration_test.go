//go:build e2e

// Package mcptest_test holds the smoke-tier wiring proof that live
// streams record where they came from and where they went: conn_info
// client_addr (the accepted client socket's peer), server_addr (the
// upstream socket's peer) and listener_name (the operator-configured
// listener name). Exhaustive per-entry-path coverage lives in
// conn_addrs_integration_test.go.
package mcptest_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ConnAddrs_NamedListenerCONNECTHTTPS_Smoke drives one HTTPS
// request through a CONNECT tunnel on a named listener and asserts the
// recorded stream carries the test client's local address, the test
// upstream's address and the listener name.
func TestE2E_ConnAddrs_NamedListenerCONNECTHTTPS_Smoke(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: "http/1.1"})
	proxyAddr := startNamedListener(t, h, "worker-a", nil)
	upstreamAddr := h.UpstreamTLS.Listener.Addr().String()

	client, localAddrs := connAddrsHTTPClient(t, "http://"+proxyAddr, false)
	resp, err := client.Get(h.UpstreamTLS.URL + "/conn-addrs-smoke")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	detail := waitConnAddrsStream(t, h, nil, func(e connAddrsEntry) bool {
		return strings.Contains(e.URL, "/conn-addrs-smoke")
	})
	assertConnAddrs(t, detail, localAddrs.only(t), upstreamAddr, "worker-a")
	if detail.ConnInfo.UpstreamProxy != "" {
		t.Errorf("conn_info.upstream_proxy = %q, want empty for a direct dial", detail.ConnInfo.UpstreamProxy)
	}
}

// ----------------------------------------------------------------------
// Shared helpers (also used by the exhaustive tier)
// ----------------------------------------------------------------------

// startNamedListener starts a proxy listener with the given name and any
// extra proxy_start arguments, returning its listen address.
func startNamedListener(t *testing.T, h *mcptest.Harness, name string, extra map[string]any) string {
	t.Helper()
	args := map[string]any{"name": name, "listen_addr": "127.0.0.1:0"}
	for k, v := range extra {
		args[k] = v
	}
	res := h.MustOK(t, "proxy_start", args)
	addr, _ := res.Decoded["listen_addr"].(string)
	if addr == "" {
		t.Fatalf("proxy_start(%s): missing listen_addr: %s", name, res.Text)
	}
	return addr
}

// localAddrSet records the local addresses of the client sockets a test
// opened toward the proxy.
type localAddrSet struct {
	addrs chan string
}

// only returns the single recorded local address, failing the test when
// the client opened none or more than one connection.
func (s *localAddrSet) only(t *testing.T) string {
	t.Helper()
	var got []string
	for {
		select {
		case a := <-s.addrs:
			got = append(got, a)
			continue
		default:
		}
		break
	}
	if len(got) != 1 {
		t.Fatalf("client opened %d proxy connections (%v), want exactly 1", len(got), got)
	}
	return got[0]
}

// connAddrsHTTPClient returns an HTTP client that reaches its targets via
// the proxy URL (http:// for CONNECT / absolute-form, socks5:// for
// SOCKS5) and records the local address of every socket it dials to the
// proxy. h2 selects ALPN h2 inside CONNECT tunnels.
func connAddrsHTTPClient(t *testing.T, proxyURL string, h2 bool) (*gohttp.Client, *localAddrSet) {
	t.Helper()
	pURL, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	set := &localAddrSet{addrs: make(chan string, 16)}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &gohttp.Transport{
		Proxy: gohttp.ProxyURL(pURL),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				set.addrs <- c.LocalAddr().String()
			}
			return c, err
		},
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
		},
		ForceAttemptHTTP2: h2,
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) gohttp.RoundTripper{}
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &gohttp.Client{Transport: tr, Timeout: 15 * time.Second}, set
}

// connAddrsEntry is the subset of a query("flows") entry these tests read.
type connAddrsEntry struct {
	ID           string `json:"id"`
	Protocol     string `json:"protocol"`
	State        string `json:"state"`
	URL          string `json:"url"`
	ListenerName string `json:"listener_name"`
}

// connAddrsDetail is the subset of a query("flow") result these tests read.
type connAddrsDetail struct {
	ID           string `json:"id"`
	Protocol     string `json:"protocol"`
	ListenerName string `json:"listener_name"`
	ConnInfo     struct {
		ClientAddr    string `json:"client_addr"`
		ServerAddr    string `json:"server_addr"`
		UpstreamProxy string `json:"upstream_proxy"`
	} `json:"conn_info"`
}

// waitConnAddrsStream polls query("flows") (with the optional filter)
// until a completed entry satisfies match AND its detail carries a
// server_addr (written once the stream reaches an upstream socket), then returns
// the query("flow") detail. Fails the test on timeout.
func waitConnAddrsStream(t *testing.T, h *mcptest.Harness, filter map[string]any, match func(connAddrsEntry) bool) connAddrsDetail {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last []connAddrsEntry
	var lastDetail connAddrsDetail
	for {
		args := map[string]any{"resource": "flows", "limit": 200}
		if filter != nil {
			args["filter"] = filter
		}
		res := h.MustOK(t, "query", args)
		var parsed struct {
			Flows []connAddrsEntry `json:"flows"`
		}
		if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
			t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
		}
		last = parsed.Flows
		for _, e := range parsed.Flows {
			if e.State != "complete" || !match(e) {
				continue
			}
			d := queryConnAddrsDetail(t, h, e.ID)
			lastDetail = d
			if d.ConnInfo.ServerAddr != "" {
				return d
			}
		}
		if time.Now().After(deadline) {
			if lastDetail.ID != "" {
				// A matching stream exists but never gained a
				// server_addr; hand it back so the caller's field
				// assertions report exactly what is missing.
				return lastDetail
			}
			t.Fatalf("no completed matching stream within deadline; flows=%+v", last)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func queryConnAddrsDetail(t *testing.T, h *mcptest.Harness, id string) connAddrsDetail {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
	var d connAddrsDetail
	if err := json.Unmarshal([]byte(res.Text), &d); err != nil {
		t.Fatalf("decode query(flow %s): %v (text=%q)", id, err, res.Text)
	}
	return d
}

func assertConnAddrs(t *testing.T, d connAddrsDetail, wantClient, wantServer, wantListener string) {
	t.Helper()
	if d.ConnInfo.ClientAddr != wantClient {
		t.Errorf("stream %s conn_info.client_addr = %q, want %q", d.ID, d.ConnInfo.ClientAddr, wantClient)
	}
	if d.ConnInfo.ServerAddr != wantServer {
		t.Errorf("stream %s conn_info.server_addr = %q, want %q", d.ID, d.ConnInfo.ServerAddr, wantServer)
	}
	if d.ListenerName != wantListener {
		t.Errorf("stream %s listener_name = %q, want %q", d.ID, d.ListenerName, wantListener)
	}
}

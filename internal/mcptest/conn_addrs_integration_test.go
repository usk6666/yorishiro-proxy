//go:build e2e && !e2e_smoke

// Package mcptest_test holds the exhaustive-tier coverage for live
// stream connection metadata: client_addr / server_addr / listener_name
// on every entry path (plain-HTTP forward, CONNECT h1 / h2, WebSocket
// upgrade, SOCKS5, tcp_forwards), the listener_name query filter, the
// JSONL export, and the upstream-proxy representation (server_addr =
// the proxy socket peer, upstream_proxy = the redacted proxy URL).
package mcptest_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func newConnAddrsH1TLSUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(s.Close)
	return s
}

// newConnAddrsH2TLSUpstream starts an h2 TLS upstream and returns a
// counter of the TCP connections it has accepted, so a test can tell a
// pooled upstream connection from a fresh dial (both share RemoteAddr).
func newConnAddrsH2TLSUpstream(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var accepted atomic.Int64
	s := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "ok-h2")
	}))
	s.Config.ConnState = func(_ net.Conn, st gohttp.ConnState) {
		if st == gohttp.StateNew {
			accepted.Add(1)
		}
	}
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	return s, &accepted
}

func newConnAddrsPlainUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "ok-plain")
	}))
	t.Cleanup(s.Close)
	return s
}

func connAddrsGet(t *testing.T, client *gohttp.Client, rawURL string) {
	t.Helper()
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s via proxy: %v", rawURL, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("GET %s via proxy: status %d", rawURL, resp.StatusCode)
	}
}

// TestE2E_ConnAddrs_EntryPaths_Full covers every live entry path on a
// named listener and the listener_name filter + JSONL export on top.
func TestE2E_ConnAddrs_EntryPaths_Full(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: "ws"})
	proxyA := startNamedListener(t, h, "worker-a", nil)
	proxyB := startNamedListener(t, h, "worker-b", nil)

	h1Up := newConnAddrsH1TLSUpstream(t)
	h2Up, h2Accepted := newConnAddrsH2TLSUpstream(t)
	plainUp := newConnAddrsPlainUpstream(t)

	var plainStreamID string

	t.Run("plain_http_forward", func(t *testing.T) {
		client, locals := connAddrsHTTPClient(t, "http://"+proxyA, false)
		connAddrsGet(t, client, plainUp.URL+"/ca-plain-forward")
		d := waitConnAddrsStream(t, h, nil, urlPathMatch("/ca-plain-forward"))
		assertConnAddrs(t, d, locals.only(t), plainUp.Listener.Addr().String(), "worker-a")
		plainStreamID = d.ID
	})

	t.Run("connect_h1", func(t *testing.T) {
		client, locals := connAddrsHTTPClient(t, "http://"+proxyA, false)
		connAddrsGet(t, client, h1Up.URL+"/ca-connect-h1")
		d := waitConnAddrsStream(t, h, nil, urlPathMatch("/ca-connect-h1"))
		assertConnAddrs(t, d, locals.only(t), h1Up.Listener.Addr().String(), "worker-a")
	})

	// Two sequential CONNECT h2 clients to the same upstream: the second
	// rides the pooled upstream connection (asserted via the upstream's
	// accepted-connection count, since a pooled socket and a fresh dial
	// share RemoteAddr), yet each stream must carry its own client_addr
	// and the pooled upstream socket's peer.
	t.Run("connect_h2_pool", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			path := "/ca-connect-h2-" + strconv.Itoa(i)
			client, locals := connAddrsHTTPClient(t, "http://"+proxyA, true)
			connAddrsGet(t, client, h2Up.URL+path)
			d := waitConnAddrsStream(t, h, nil, urlPathMatch(path))
			assertConnAddrs(t, d, locals.only(t), h2Up.Listener.Addr().String(), "worker-a")
		}
		if n := h2Accepted.Load(); n != 1 {
			t.Errorf("h2 upstream accepted %d connections, want 1 (second CONNECT must hit the h2 pool)", n)
		}
	})

	t.Run("socks5", func(t *testing.T) {
		client, locals := connAddrsHTTPClient(t, "socks5://"+proxyA, false)
		connAddrsGet(t, client, h1Up.URL+"/ca-socks5")
		d := waitConnAddrsStream(t, h, nil, urlPathMatch("/ca-socks5"))
		assertConnAddrs(t, d, locals.only(t), h1Up.Listener.Addr().String(), "worker-a")
	})

	t.Run("websocket", func(t *testing.T) {
		wsUp := wsUpstreamHostPort(t, h.UpstreamTLS.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err := dialWSThroughProxy(ctx, t, proxyA, wsUp)
		if err != nil {
			t.Fatalf("dial WS through proxy: %v", err)
		}
		local := conn.LocalAddr().String()
		if err := writeMaskedClientFrame(conn, ws.OpcodeText, []byte("hello-conn-addrs")); err != nil {
			t.Fatalf("write WS frame: %v", err)
		}
		if _, err := readServerFrameWithDeadline(conn, 5*time.Second); err != nil {
			t.Fatalf("read WS echo: %v", err)
		}
		_ = conn.Close()
		d := waitConnAddrsStream(t, h, nil, func(e connAddrsEntry) bool { return e.Protocol == "ws" })
		assertConnAddrs(t, d, local, h.UpstreamTLS.Listener.Addr().String(), "worker-a")
	})

	t.Run("tcp_forwards_inherit_parent_name", func(t *testing.T) {
		echoAddr := startTCPEchoServer(t)
		fwdPort := pickFreePort(t)
		startNamedListener(t, h, "worker-tcp", map[string]any{
			"tcp_forwards": map[string]any{strconv.Itoa(fwdPort): echoAddr},
		})
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fwdPort)), 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward port: %v", err)
		}
		local := conn.LocalAddr().String()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "conn-addrs-raw\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		_ = conn.Close()
		d := waitConnAddrsStream(t, h, map[string]any{"listener_name": "worker-tcp"},
			func(e connAddrsEntry) bool { return e.Protocol == "raw" })
		assertConnAddrs(t, d, local, echoAddr, "worker-tcp")
	})

	t.Run("listener_name_filter", func(t *testing.T) {
		client, _ := connAddrsHTTPClient(t, "http://"+proxyB, false)
		connAddrsGet(t, client, plainUp.URL+"/ca-worker-b")
		waitConnAddrsStream(t, h, map[string]any{"listener_name": "worker-b"}, urlPathMatch("/ca-worker-b"))

		for _, name := range []string{"worker-a", "worker-b"} {
			res := h.MustOK(t, "query", map[string]any{
				"resource": "flows",
				"limit":    200,
				"filter":   map[string]any{"listener_name": name},
			})
			var parsed struct {
				Flows []connAddrsEntry `json:"flows"`
			}
			if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
				t.Fatalf("decode query(flows): %v", err)
			}
			if len(parsed.Flows) == 0 {
				t.Errorf("filter listener_name=%s returned no flows", name)
			}
			sawWorkerB := false
			for _, e := range parsed.Flows {
				if e.ListenerName != name {
					t.Errorf("filter listener_name=%s returned stream %s with listener_name %q", name, e.ID, e.ListenerName)
				}
				if strings.Contains(e.URL, "/ca-worker-b") {
					sawWorkerB = true
				}
			}
			if wantB := name == "worker-b"; sawWorkerB != wantB {
				t.Errorf("filter listener_name=%s: worker-b stream present = %v, want %v", name, sawWorkerB, wantB)
			}
		}
	})

	t.Run("jsonl_export", func(t *testing.T) {
		if plainStreamID == "" {
			t.Skip("plain_http_forward did not record a stream")
		}
		const outName = "conn-addrs-export.jsonl"
		h.MustOK(t, "manage", map[string]any{
			"action": "export_flows",
			"params": map[string]any{"format": "jsonl", "output_path": outName},
		})
		raw, err := os.ReadFile(filepath.Join(h.ExportDir, outName))
		if err != nil {
			t.Fatalf("read export: %v", err)
		}
		found := false
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			var rec struct {
				Stream struct {
					ID           string `json:"id"`
					ListenerName string `json:"listener_name"`
					ConnInfo     struct {
						ClientAddr string `json:"client_addr"`
						ServerAddr string `json:"server_addr"`
					} `json:"conn_info"`
				} `json:"stream"`
			}
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("decode JSONL line: %v", err)
			}
			if rec.Stream.ID != plainStreamID {
				continue
			}
			found = true
			if rec.Stream.ListenerName != "worker-a" {
				t.Errorf("exported listener_name = %q, want worker-a", rec.Stream.ListenerName)
			}
			if rec.Stream.ConnInfo.ClientAddr == "" {
				t.Error("exported conn_info.client_addr is empty")
			}
			if rec.Stream.ConnInfo.ServerAddr != plainUp.Listener.Addr().String() {
				t.Errorf("exported conn_info.server_addr = %q, want %q", rec.Stream.ConnInfo.ServerAddr, plainUp.Listener.Addr().String())
			}
		}
		if !found {
			t.Errorf("stream %s not found in JSONL export", plainStreamID)
		}
	})
}

// TestE2E_ConnAddrs_UpstreamProxyChain_Full chains two listeners: the
// "chained" listener reaches its upstream through the "outer" listener
// configured as its upstream proxy (with credentials in the URL). The
// chained stream must record the proxy socket as server_addr and the
// credential-free proxy URL as upstream_proxy; the outer stream sees the
// chained listener's outbound socket as its client.
func TestE2E_ConnAddrs_UpstreamProxyChain_Full(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	upstream := newConnAddrsH1TLSUpstream(t)
	outerAddr := startNamedListener(t, h, "outer", nil)
	chainedAddr := startNamedListener(t, h, "chained", map[string]any{
		"upstream_proxy": "http://chainuser:chain-s3cret@" + outerAddr,
	})

	client, locals := connAddrsHTTPClient(t, "http://"+chainedAddr, false)
	connAddrsGet(t, client, upstream.URL+"/ca-chain")
	clientLocal := locals.only(t)

	chained := waitConnAddrsStream(t, h, map[string]any{"listener_name": "chained"}, urlPathMatch("/ca-chain"))
	assertConnAddrs(t, chained, clientLocal, outerAddr, "chained")
	if want := "http://" + outerAddr; chained.ConnInfo.UpstreamProxy != want {
		t.Errorf("chained conn_info.upstream_proxy = %q, want %q", chained.ConnInfo.UpstreamProxy, want)
	}

	outer := waitConnAddrsStream(t, h, map[string]any{"listener_name": "outer"}, urlPathMatch("/ca-chain"))
	if outer.ListenerName != "outer" {
		t.Errorf("outer listener_name = %q, want outer", outer.ListenerName)
	}
	if outer.ConnInfo.ServerAddr != upstream.Listener.Addr().String() {
		t.Errorf("outer conn_info.server_addr = %q, want %q", outer.ConnInfo.ServerAddr, upstream.Listener.Addr().String())
	}
	if outer.ConnInfo.UpstreamProxy != "" {
		t.Errorf("outer conn_info.upstream_proxy = %q, want empty (direct dial)", outer.ConnInfo.UpstreamProxy)
	}
	if outer.ConnInfo.ClientAddr == "" || outer.ConnInfo.ClientAddr == clientLocal {
		t.Errorf("outer conn_info.client_addr = %q, want the chained listener's outbound socket (not the test client %q)",
			outer.ConnInfo.ClientAddr, clientLocal)
	}

	// The credential must never reach any recorded / returned surface.
	for _, id := range []string{chained.ID, outer.ID} {
		res := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
		for _, secret := range []string{"chain-s3cret", "chainuser"} {
			if strings.Contains(res.Text, secret) {
				t.Errorf("query(flow %s) leaks proxy credential fragment %q", id, secret)
			}
		}
	}
}

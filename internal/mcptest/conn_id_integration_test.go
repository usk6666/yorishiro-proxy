//go:build e2e && !e2e_smoke

// Package mcptest_test holds the exhaustive-tier coverage that one client
// connection has one conn_id: the conn_id on its normal Streams, on its
// audit Streams (blocked / passthrough) and on the proxy's own log
// records are the same value, on every entry path (plain-HTTP forward,
// CONNECT, SOCKS5, tcp_forwards L7 and raw). The CONNECT HTTPS case is
// also in the smoke tier (conn_addrs_smoke_integration_test.go).
package mcptest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// waitConnIDStream polls query("flows") (with the optional filter) until
// an entry satisfies match, in any state, and returns its detail.
func waitConnIDStream(t *testing.T, h *mcptest.Harness, filter map[string]any, match func(connAddrsEntry) bool) connAddrsDetail {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
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
		for _, e := range parsed.Flows {
			if match(e) {
				return queryConnAddrsDetail(t, h, e.ID)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching stream within deadline (filter=%v); flows=%+v", filter, parsed.Flows)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func anyEntry(connAddrsEntry) bool { return true }

// TestE2E_ConnID_EntryPaths_StreamMatchesLog_Full: for plain-HTTP
// forward, CONNECT HTTPS and SOCKS5, the normal Stream's conn_id is the
// conn_id FullListener logged for the same client connection.
func TestE2E_ConnID_EntryPaths_StreamMatchesLog_Full(t *testing.T) {
	h, logPath := startConnIDHarness(t, mcptest.HarnessOptions{})
	proxyAddr := startNamedListener(t, h, "conn-id", nil)
	h1Up := newConnAddrsH1TLSUpstream(t)
	plainUp := newConnAddrsPlainUpstream(t)

	cases := []struct {
		name     string
		proxyURL string
		target   string
	}{
		{"plain_http_forward", "http://" + proxyAddr, plainUp.URL + "/ci-plain"},
		{"connect_https", "http://" + proxyAddr, h1Up.URL + "/ci-connect"},
		{"socks5", "socks5://" + proxyAddr, h1Up.URL + "/ci-socks5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, locals := connAddrsHTTPClient(t, tc.proxyURL, false)
			connAddrsGet(t, client, tc.target)
			u, _ := url.Parse(tc.target)
			d := waitConnAddrsStream(t, h, nil, urlPathMatch(u.Path))
			logID := waitLogConnID(t, logPath, "connection closed", locals.only(t))
			assertConnIDJoin(t, d.ID, d.ConnID, logID)
		})
	}
}

// TestE2E_ConnID_TCPForwards_StreamMatchesLog_Full: for tcp_forwards
// (L7 http, L7 http2 and raw) the Stream's conn_id is the conn_id the
// forward handler logged for the same client connection. The raw arm
// already stamped the ctx conn ID on its bytechunk Layers, so it is a
// control for the L7 arms (its red is only the uuid format).
func TestE2E_ConnID_TCPForwards_StreamMatchesLog_Full(t *testing.T) {
	h, logPath := startConnIDHarness(t, mcptest.HarnessOptions{})
	plainUp := newConnAddrsPlainUpstream(t)
	h2cUp, shutdownH2C := startSmokeH2CUpstream(t)
	t.Cleanup(shutdownH2C)
	echoAddr := startTCPEchoServer(t)

	httpPort, h2Port, rawPort := pickFreePort(t), pickFreePort(t), pickFreePort(t)
	startNamedListener(t, h, "conn-id-fwd", map[string]any{
		"tcp_forwards": map[string]any{
			strconv.Itoa(httpPort): map[string]any{"target": plainUp.Listener.Addr().String(), "protocol": "http"},
			strconv.Itoa(h2Port):   map[string]any{"target": h2cUp, "protocol": "http2"},
			strconv.Itoa(rawPort):  map[string]any{"target": echoAddr, "protocol": "raw"},
		},
	})
	fwdAddr := func(port int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) }

	t.Run("http", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fwdAddr(httpPort), 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward: %v", err)
		}
		local := conn.LocalAddr().String()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(conn, "GET /ci-fwd-http HTTP/1.1\r\nHost: fwd.test\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := io.ReadAll(conn); err != nil {
			t.Fatalf("read: %v", err)
		}
		_ = conn.Close()
		d := waitConnIDStream(t, h, nil, func(e connAddrsEntry) bool { return urlPathMatch("/ci-fwd-http")(e) && e.State == "complete" })
		assertConnIDJoin(t, d.ID, d.ConnID, waitLogConnID(t, logPath, "tcp forward connection closed", local))
	})

	t.Run("http2", func(t *testing.T) {
		locals := make(chan string, 4)
		tr := &http2.Transport{
			AllowHTTP: true,
			DialTLS: func(_, _ string, _ *tls.Config) (net.Conn, error) {
				c, err := net.DialTimeout("tcp", fwdAddr(h2Port), 5*time.Second)
				if err == nil {
					locals <- c.LocalAddr().String()
				}
				return c, err
			},
		}
		client := &gohttp.Client{Transport: tr, Timeout: 15 * time.Second}
		resp, err := client.Get("http://" + fwdAddr(h2Port) + "/ci-fwd-h2")
		if err != nil {
			t.Fatalf("h2 GET: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		tr.CloseIdleConnections()
		local := <-locals
		d := waitConnIDStream(t, h, nil, func(e connAddrsEntry) bool { return urlPathMatch("/ci-fwd-h2")(e) && e.State == "complete" })
		assertConnIDJoin(t, d.ID, d.ConnID, waitLogConnID(t, logPath, "tcp forward connection closed", local))
	})

	t.Run("raw", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fwdAddr(rawPort), 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward: %v", err)
		}
		local := conn.LocalAddr().String()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "conn-id-raw\n"); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		_ = conn.Close()
		d := waitConnIDStream(t, h, map[string]any{"listener_name": "conn-id-fwd"},
			func(e connAddrsEntry) bool { return e.Protocol == "raw" })
		assertConnIDJoin(t, d.ID, d.ConnID, waitLogConnID(t, logPath, "tcp forward connection closed", local))
	})
}

// TestE2E_ConnID_KeepAliveNormalAndBlockedShareLogConnID: on one
// plain-HTTP keep-alive connection, request 1 is relayed (normal Stream)
// and request 2 is blocked by the SafetyFilter (blocked audit Stream).
// Both Streams carry the conn_id the proxy logged for that connection.
func TestE2E_ConnID_KeepAliveNormalAndBlockedShareLogConnID(t *testing.T) {
	upstreamAddr, _ := startObservedUpstream(t)
	h, logPath := startConnIDHarness(t, mcptest.HarnessOptions{ConfigJSON: safetyFilterDestructiveSQLConfig})
	proxyAddr := startNamedListener(t, h, "conn-id-ka", nil)

	pURL, _ := url.Parse("http://" + proxyAddr)
	locals := make(chan string, 4)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &gohttp.Transport{
		Proxy:           gohttp.ProxyURL(pURL),
		MaxConnsPerHost: 1,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err == nil {
				locals <- c.LocalAddr().String()
			}
			return c, err
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	client := &gohttp.Client{Transport: tr, Timeout: 15 * time.Second}

	resp, err := client.Post("http://"+upstreamAddr+"/ci-ka-allowed", "text/plain", bytes.NewBufferString("SELECT 1"))
	if err != nil {
		t.Fatalf("benign POST: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("benign POST status %d", resp.StatusCode)
	}
	if resp, err := client.Post("http://"+upstreamAddr+"/ci-ka-blocked", "text/plain", bytes.NewBufferString("DROP TABLE users")); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	tr.CloseIdleConnections()

	if n := len(locals); n != 1 {
		t.Fatalf("client opened %d proxy connections, want 1 (keep-alive reuse)", n)
	}
	local := <-locals

	normal := waitConnIDStream(t, h, nil, func(e connAddrsEntry) bool { return urlPathMatch("/ci-ka-allowed")(e) && e.State == "complete" })
	blocked := waitConnIDStream(t, h, map[string]any{"blocked_by": "safety_filter"}, anyEntry)
	logID := waitLogConnID(t, logPath, "connection closed", local)
	assertConnIDJoin(t, normal.ID, normal.ConnID, logID)
	assertConnIDJoin(t, blocked.ID, blocked.ConnID, logID)
}

// TestE2E_ConnID_TLSPassthroughAuditMatchesLog: the tls_passthrough audit
// Stream (conn ID read from ctx) carries the logged conn_id, in uuid form.
func TestE2E_ConnID_TLSPassthroughAuditMatchesLog(t *testing.T) {
	h, logPath := startConnIDHarness(t, mcptest.HarnessOptions{})
	upstream := newConnAddrsH1TLSUpstream(t)
	proxyAddr := startNamedListener(t, h, "conn-id-pt", map[string]any{"tls_passthrough": []string{"127.0.0.1"}})

	client, locals := connAddrsHTTPClient(t, "http://"+proxyAddr, false)
	connAddrsGet(t, client, upstream.URL+"/ci-passthrough")
	local := locals.only(t)

	d := waitConnIDStream(t, h, nil, func(e connAddrsEntry) bool { return e.Protocol == "tls-handshake" && e.State == "complete" })
	assertConnIDJoin(t, d.ID, d.ConnID, waitLogConnID(t, logPath, "connection closed", local))
}

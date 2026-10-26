//go:build e2e && !e2e_smoke

// USK-1302 exhaustive tier: a Stream whose upstream socket existed but
// never delivered anything (upstream aborted / hung before responding,
// raw upstream closed silently) still records conn_info.server_addr and
// upstream_proxy, while a Stream whose upstream dial failed keeps both
// empty (the proxy never connected anywhere).
package mcptest_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// abortHandler reads the request and aborts without a response: HTTP/1.x
// closes the connection, HTTP/2 resets the stream.
func abortHandler(w gohttp.ResponseWriter, r *gohttp.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	panic(gohttp.ErrAbortHandler)
}

// waitNoReceiveStream polls until a stream matching match exists and
// done reports true for it, returning the last observed entry + detail at
// the deadline so the caller's assertions report what is missing.
func waitNoReceiveStream(
	t *testing.T, h *mcptest.Harness, filter map[string]any,
	match func(connAddrsEntry) bool, done func(connAddrsEntry, connAddrsDetail) bool,
) (connAddrsEntry, connAddrsDetail) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var lastE connAddrsEntry
	var lastD connAddrsDetail
	for {
		for _, e := range queryConnAddrsEntries(t, h, filter) {
			if !match(e) {
				continue
			}
			d := queryConnAddrsDetail(t, h, e.ID)
			lastE, lastD = e, d
			if done(e, d) {
				return e, d
			}
		}
		if time.Now().After(deadline) {
			if lastE.ID == "" {
				t.Fatalf("no matching stream within deadline")
			}
			return lastE, lastD
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func queryConnAddrsEntries(t *testing.T, h *mcptest.Harness, filter map[string]any) []connAddrsEntry {
	t.Helper()
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
	return parsed.Flows
}

// settledWithAddr: the stream reached a terminal state and carries a
// server_addr.
func settledWithAddr(e connAddrsEntry, d connAddrsDetail) bool {
	return e.State != "active" && d.ConnInfo.ServerAddr != ""
}

// queryFlowRaw returns the query("flow") result as a generic map, for
// fields (failure_reason, tags) the typed connAddrsDetail does not carry.
func queryFlowRaw(t *testing.T, h *mcptest.Harness, id string) map[string]any {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
	var m map[string]any
	if err := json.Unmarshal([]byte(res.Text), &m); err != nil {
		t.Fatalf("decode query(flow %s): %v (text=%q)", id, err, res.Text)
	}
	return m
}

func assertNoReceiveStream(t *testing.T, e connAddrsEntry, d connAddrsDetail, wantState, wantServer, wantProxy string) {
	t.Helper()
	if e.State != wantState {
		t.Errorf("stream %s state = %q, want %q", e.ID, e.State, wantState)
	}
	if d.ConnInfo.ServerAddr != wantServer {
		t.Errorf("stream %s conn_info.server_addr = %q, want %q", e.ID, d.ConnInfo.ServerAddr, wantServer)
	}
	if d.ConnInfo.UpstreamProxy != wantProxy {
		t.Errorf("stream %s conn_info.upstream_proxy = %q, want %q", e.ID, d.ConnInfo.UpstreamProxy, wantProxy)
	}
}

// TestE2E_ConnAddrs_NoReceive_UpstreamAborts_Full covers HTTP/1.x
// (CONNECT and plain forward) and HTTP/2 (CONNECT, multiplexed on one
// pooled upstream socket) where the upstream aborts before responding.
func TestE2E_ConnAddrs_NoReceive_UpstreamAborts_Full(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxy := startNamedListener(t, h, "nr-abort", nil)

	t.Run("connect_h1", func(t *testing.T) {
		up := httptest.NewTLSServer(gohttp.HandlerFunc(abortHandler))
		t.Cleanup(up.Close)
		client, _ := connAddrsHTTPClient(t, "http://"+proxy, false)
		if resp, err := client.Get(up.URL + "/nr-connect-h1"); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("GET succeeded with status %d, want an aborted exchange", resp.StatusCode)
		}
		e, d := waitNoReceiveStream(t, h, nil, urlPathMatch("/nr-connect-h1"), settledWithAddr)
		assertNoReceiveStream(t, e, d, "error", up.Listener.Addr().String(), "")
	})

	t.Run("plain_http_forward", func(t *testing.T) {
		up := httptest.NewServer(gohttp.HandlerFunc(abortHandler))
		t.Cleanup(up.Close)
		client, _ := connAddrsHTTPClient(t, "http://"+proxy, false)
		if resp, err := client.Get(up.URL + "/nr-plain-forward"); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("GET succeeded with status %d, want an aborted exchange", resp.StatusCode)
		}
		e, d := waitNoReceiveStream(t, h, nil, urlPathMatch("/nr-plain-forward"), settledWithAddr)
		assertNoReceiveStream(t, e, d, "error", up.Listener.Addr().String(), "")
	})

	t.Run("connect_h2_multiplexed", func(t *testing.T) {
		var accepted atomic.Int64
		up := httptest.NewUnstartedServer(gohttp.HandlerFunc(abortHandler))
		up.Config.ConnState = func(_ net.Conn, st gohttp.ConnState) {
			if st == gohttp.StateNew {
				accepted.Add(1)
			}
		}
		up.EnableHTTP2 = true
		up.StartTLS()
		t.Cleanup(up.Close)

		client, _ := connAddrsHTTPClient(t, "http://"+proxy, true)
		client.Transport.(*gohttp.Transport).DisableKeepAlives = false
		for i := 0; i < 2; i++ {
			if resp, err := client.Get(up.URL + "/nr-connect-h2-" + strconv.Itoa(i)); err == nil {
				_ = resp.Body.Close()
				t.Fatalf("GET %d succeeded with status %d, want a reset stream", i, resp.StatusCode)
			}
		}
		for i := 0; i < 2; i++ {
			e, d := waitNoReceiveStream(t, h, nil, urlPathMatch("/nr-connect-h2-"+strconv.Itoa(i)), settledWithAddr)
			assertNoReceiveStream(t, e, d, "error", up.Listener.Addr().String(), "")
		}
		if n := accepted.Load(); n != 1 {
			t.Errorf("h2 upstream accepted %d connections, want 1 (both streams on one pooled socket)", n)
		}
	})
}

// TestE2E_ConnAddrs_NoReceive_ClientGivesUp_Full: the upstream accepts
// the request and never answers; the client times out. The stream must
// already show where it went.
func TestE2E_ConnAddrs_NoReceive_ClientGivesUp_Full(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxy := startNamedListener(t, h, "nr-hang", nil)

	release := make(chan struct{})
	up := httptest.NewServer(gohttp.HandlerFunc(func(_ gohttp.ResponseWriter, r *gohttp.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(up.Close)
	t.Cleanup(func() { close(release) }) // runs before up.Close (LIFO)

	client, _ := connAddrsHTTPClient(t, "http://"+proxy, false)
	client.Timeout = 500 * time.Millisecond
	if resp, err := client.Get(up.URL + "/nr-client-gives-up"); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("GET succeeded with status %d, want a client timeout", resp.StatusCode)
	}
	e, d := waitNoReceiveStream(t, h, nil, urlPathMatch("/nr-client-gives-up"),
		func(_ connAddrsEntry, d connAddrsDetail) bool { return d.ConnInfo.ServerAddr != "" })
	if d.ConnInfo.ServerAddr != up.Listener.Addr().String() {
		t.Errorf("stream %s (state %s) conn_info.server_addr = %q, want %q",
			e.ID, e.State, d.ConnInfo.ServerAddr, up.Listener.Addr().String())
	}
}

// TestE2E_ConnAddrs_NoReceive_ViaUpstreamProxy_Full: the chained listener
// reaches the upstream through the outer listener; the final upstream
// aborts, so neither leg receives anything. The chained stream records
// the proxy socket + credential-free proxy URL, the outer stream the
// final upstream.
func TestE2E_ConnAddrs_NoReceive_ViaUpstreamProxy_Full(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	up := httptest.NewTLSServer(gohttp.HandlerFunc(abortHandler))
	t.Cleanup(up.Close)
	outerAddr := startNamedListener(t, h, "nr-outer", nil)
	chainedAddr := startNamedListener(t, h, "nr-chained", map[string]any{
		"upstream_proxy": "http://nruser:nr-s3cret@" + outerAddr,
	})

	client, _ := connAddrsHTTPClient(t, "http://"+chainedAddr, false)
	if resp, err := client.Get(up.URL + "/nr-chain"); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("GET succeeded with status %d, want an aborted exchange", resp.StatusCode)
	}

	ce, cd := waitNoReceiveStream(t, h, map[string]any{"listener_name": "nr-chained"}, urlPathMatch("/nr-chain"), settledWithAddr)
	assertNoReceiveStream(t, ce, cd, "error", outerAddr, "http://"+outerAddr)

	oe, od := waitNoReceiveStream(t, h, map[string]any{"listener_name": "nr-outer"}, urlPathMatch("/nr-chain"), settledWithAddr)
	assertNoReceiveStream(t, oe, od, "error", up.Listener.Addr().String(), "")
}

// TestE2E_ConnAddrs_NoReceive_RawUpstreamSilent_Full: a tcp_forwards raw
// relay whose upstream reads the client's bytes and closes without
// sending anything still records the upstream peer.
func TestE2E_ConnAddrs_NoReceive_RawUpstreamSilent_Full(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = bufio.NewReader(c).ReadString('\n')
			}(c)
		}
	}()

	fwdPort := pickFreePort(t)
	startNamedListener(t, h, "nr-raw", map[string]any{
		"tcp_forwards": map[string]any{strconv.Itoa(fwdPort): ln.Addr().String()},
	})
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(fwdPort)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward port: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "nr-raw-silent\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b, _ := io.ReadAll(conn); len(b) != 0 {
		t.Fatalf("upstream sent %q, want nothing", b)
	}
	_ = conn.Close()

	e, d := waitNoReceiveStream(t, h, map[string]any{"listener_name": "nr-raw"},
		func(e connAddrsEntry) bool { return e.Protocol == "raw" }, settledWithAddr)
	if e.State == "active" {
		t.Errorf("raw stream %s state = active, want terminal", e.ID)
	}
	if d.ConnInfo.ServerAddr != ln.Addr().String() {
		t.Errorf("raw stream %s conn_info.server_addr = %q, want %q", e.ID, d.ConnInfo.ServerAddr, ln.Addr().String())
	}
}

// TestE2E_ConnAddrs_NoReceive_H1RedialFails_KeepsEmpty: exchange 1
// succeeds; the upstream then closes its socket and stops listening, so
// exchange 2's redial (keep-alive on the same CONNECT tunnel) is refused.
// Stream 2 never had an upstream socket and must keep server_addr empty;
// stream 1 keeps the socket it used.
func TestE2E_ConnAddrs_NoReceive_H1RedialFails_KeepsEmpty(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxy := startNamedListener(t, h, "nr-h1-redial", nil)
	up := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	upAddr := up.Listener.Addr().String()

	tconn, br := dialCONNECTTLS(t, proxy, upAddr, []string{"http/1.1"})
	writeH1Get(t, tconn, upAddr, "/nr-redial-one")
	resp, err := gohttp.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response 1: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("response 1 status = %d, want 200", resp.StatusCode)
	}

	_ = up.Listener.Close()
	up.CloseClientConnections()
	time.Sleep(200 * time.Millisecond)

	writeH1Get(t, tconn, upAddr, "/nr-redial-two")
	_ = tconn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, err := gohttp.ReadResponse(br, nil); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("response 2 status = %d, want no response (redial refused)", resp.StatusCode)
	}

	e2, d2 := waitNoReceiveStream(t, h, nil, urlPathMatch("/nr-redial-two"),
		func(e connAddrsEntry, _ connAddrsDetail) bool { return e.State != "active" })
	time.Sleep(200 * time.Millisecond)
	d2 = queryConnAddrsDetail(t, h, e2.ID)
	assertNoReceiveStream(t, e2, d2, "error", "", "")

	e1, d1 := waitNoReceiveStream(t, h, nil, urlPathMatch("/nr-redial-one"), settledWithAddr)
	assertNoReceiveStream(t, e1, d1, "complete", upAddr, "")
}

// TestE2E_ConnAddrs_NoReceive_H2RedialFails_KeepsEmpty: the h2 upstream
// answers stream 1, then sends GOAWAY and stops listening; the next
// stream's redial is refused, so it keeps server_addr empty.
func TestE2E_ConnAddrs_NoReceive_H2RedialFails_KeepsEmpty(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxy := startNamedListener(t, h, "nr-h2-redial", nil)
	up := httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "ok-h2")
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	upAddr := up.Listener.Addr().String()

	client, _ := connAddrsHTTPClient(t, "http://"+proxy, true)
	client.Transport.(*gohttp.Transport).DisableKeepAlives = false
	connAddrsGet(t, client, up.URL+"/nr-h2-redial-one")

	// GOAWAY the pooled upstream connection and stop listening.
	_ = up.Listener.Close()
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = up.Config.Shutdown(sctx)
	cancel()
	time.Sleep(200 * time.Millisecond)

	// USK-1404: a failed redial is a proxy-local failure, so the client
	// stream is reset with CANCEL (not the retryable REFUSED_STREAM) and
	// the request fails promptly — well before Go's h2 transport's first
	// 1 s retry backoff and far before the client timeout.
	client.Timeout = 10 * time.Second
	start := time.Now()
	resp, err := client.Get(up.URL + "/nr-h2-redial-two")
	elapsed := time.Since(start)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("GET 2 returned status %d, want the client stream reset after the failed redial", resp.StatusCode)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Errorf("GET 2 err = %v after %v, want a stream reset, not a client timeout", err, elapsed)
	}
	if elapsed >= 800*time.Millisecond {
		t.Errorf("GET 2 took %v (err=%v), want < 800ms (no REFUSED_STREAM retry loop)", elapsed, err)
	}

	var seen int
	deadline := time.Now().Add(8 * time.Second)
	for {
		seen = 0
		settled := true
		for _, e := range queryConnAddrsEntries(t, h, nil) {
			if !strings.Contains(e.URL, "/nr-h2-redial-two") {
				continue
			}
			seen++
			if e.State == "active" {
				settled = false
			}
		}
		if (seen > 0 && settled) || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if seen == 0 {
		t.Fatal("no stream recorded for the request whose redial failed")
	}
	time.Sleep(200 * time.Millisecond)
	seen = 0
	for _, e := range queryConnAddrsEntries(t, h, nil) {
		if !strings.Contains(e.URL, "/nr-h2-redial-two") {
			continue
		}
		seen++
		d := queryConnAddrsDetail(t, h, e.ID)
		assertNoReceiveStream(t, e, d, "error", "", "")
		raw := queryFlowRaw(t, h, e.ID)
		if fr, _ := raw["failure_reason"].(string); fr != "" {
			t.Errorf("stream %s failure_reason = %q, want \"\" (proxy-local redial failure, not an upstream refusal)", e.ID, fr)
		}
		tags, _ := raw["tags"].(map[string]any)
		if te, _ := tags["error"].(string); !strings.Contains(te, "redial") {
			t.Errorf("stream %s tags.error = %q, want the redial failure", e.ID, te)
		}
	}
	if seen != 1 {
		t.Errorf("recorded %d streams for /nr-h2-redial-two, want exactly 1 (no client retry loop)", seen)
	}

	e1, d1 := waitNoReceiveStream(t, h, nil, urlPathMatch("/nr-h2-redial-one"), settledWithAddr)
	assertNoReceiveStream(t, e1, d1, "complete", upAddr, "")
}

// dialCONNECTTLS opens a CONNECT tunnel to target through proxy and runs
// a TLS client handshake (accepting the MITM certificate) inside it.
func dialCONNECTTLS(t *testing.T, proxy, target string, alpn []string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	cbr := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(cbr, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	host, _, _ := net.SplitHostPort(target)
	tconn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		NextProtos:         alpn,
		InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
	})
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through tunnel: %v", err)
	}
	return tconn, bufio.NewReader(tconn)
}

func writeH1Get(t *testing.T, w io.Writer, host, path string) {
	t.Helper()
	if _, err := io.WriteString(w, "GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatalf("write GET %s: %v", path, err)
	}
}

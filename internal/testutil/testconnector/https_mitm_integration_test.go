//go:build e2e

package testconnector_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil/testconnector"
)

// ---------- HTTPS MITM basic scenarios ----------

func TestHTTPSGetE2E(t *testing.T) {
	h := testconnector.Start(t, testconnector.WithUpstreamHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Upstream", "yes")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello-https")
		})))

	client := httpsClientViaProxy(t, h)
	resp, err := client.Get(h.UpstreamServer.URL + "/path")
	if err != nil {
		t.Fatalf("GET via MITM: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if string(body) != "hello-https" {
		t.Fatalf("body=%q want %q", body, "hello-https")
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("header X-Upstream=%q", resp.Header.Get("X-Upstream"))
	}

	// Stream + Flow recording verification.
	waitForFlows(t, h.Store, "HTTP/1.x", 2, 3*time.Second)
	assertRecordedStream(t, h)
}

func TestHTTPSPostBodyRoundTripE2E(t *testing.T) {
	h := testconnector.Start(t, testconnector.WithUpstreamHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		})))

	client := httpsClientViaProxy(t, h)
	reqBody := bytes.Repeat([]byte("abcd"), 64) // 256 bytes
	resp, err := client.Post(h.UpstreamServer.URL+"/echo", "application/octet-stream", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST via MITM: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, reqBody) {
		t.Fatalf("echo mismatch: got %d bytes, want %d", len(body), len(reqBody))
	}
	waitForFlows(t, h.Store, "HTTP/1.x", 2, 3*time.Second)
}

func TestHTTPSKeepAliveE2E(t *testing.T) {
	var hits int
	h := testconnector.Start(t, testconnector.WithUpstreamHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			hits++
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "req-%d", hits)
		})))

	// Make two GETs on the same client Transport, reusing the CONNECT tunnel.
	client := httpsClientViaProxy(t, h)
	for i := 0; i < 2; i++ {
		resp, err := client.Get(h.UpstreamServer.URL + "/k")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	// HTTP/1.x Codec assigns a fresh StreamID per request-response pair, so
	// we expect at least 2 streams after keep-alive.
	waitForStreams(t, h.Store, "HTTP/1.x", 2, 3*time.Second)
}

// TestHTTPSHeaderWireFidelityE2E verifies that mixed-case and duplicate
// headers sent inside the TLS tunnel are preserved in the RecordStep output.
// It uses a raw bufio-driven upstream so the upstream side can also observe
// the wire bytes (rather than the canonicalized form net/http would give us).
func TestHTTPSHeaderWireFidelityE2E(t *testing.T) {
	rawUp := startRawTLSUpstream(t)
	defer rawUp.Close()

	h := testconnector.Start(t, testconnector.WithRawUpstream(rawUp.Listener.Addr(), rawUp.Cert))

	// Send a manually-crafted HTTP/1.1 request via the connector's CONNECT
	// MITM. Two headers use unusual casing and one is duplicated.
	request := "GET /headers HTTP/1.1\r\n" +
		"Host: " + rawUp.Listener.Addr().String() + "\r\n" +
		"X-Custom-Header: CustomValue\r\n" +
		"x-another: AnotherValue\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	_ = connectAndSendThroughMITM(t, h, rawUp.Listener.Addr().String(), request)

	// Wait until the raw upstream has recorded the received bytes.
	raw := rawUp.WaitFirst(t, 3*time.Second)
	if !strings.Contains(raw, "X-Custom-Header: CustomValue") {
		t.Fatalf("upstream did not observe mixed-case header: %q", raw)
	}
	if !strings.Contains(raw, "x-another: AnotherValue") {
		t.Fatalf("upstream did not observe lowercase duplicate header: %q", raw)
	}

	// Also verify the Store preserved the casing in RawBytes on the send
	// flow.
	waitForFlows(t, h.Store, "HTTP/1.x", 1, 3*time.Second)
	ctx := context.Background()
	streams, _ := h.Store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTP/1.x"})
	if len(streams) == 0 {
		t.Fatal("no HTTP/1.x stream recorded")
	}
	flows, _ := h.Store.GetFlows(ctx, streams[0].ID, flow.FlowListOptions{Direction: "send"})
	if len(flows) == 0 {
		t.Fatal("no send flow recorded")
	}
	rb := string(flows[0].RawBytes)
	if !strings.Contains(rb, "X-Custom-Header: CustomValue") {
		t.Fatalf("raw bytes lost mixed-case header: %q", rb)
	}
	if !strings.Contains(rb, "x-another: AnotherValue") {
		t.Fatalf("raw bytes lost lowercase header: %q", rb)
	}
}

// ---------- Helpers ----------

// httpsClientViaProxy builds an http.Client that tunnels all traffic through
// the connector at h.ClientAddr and trusts both the MITM CA and the upstream
// CA (for situations where the client has to verify the MITM leaf, which is
// signed by the harness's CA).
func httpsClientViaProxy(t *testing.T, h *testconnector.Harness) *http.Client {
	t.Helper()
	proxyURL, _ := url.Parse("http://" + h.ClientAddr)
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			TLSClientConfig:       &tls.Config{RootCAs: h.CAPool},
			ForceAttemptHTTP2:     false,
			TLSHandshakeTimeout:   3 * time.Second,
			ResponseHeaderTimeout: 3 * time.Second,
			IdleConnTimeout:       500 * time.Millisecond,
		},
		Timeout: 10 * time.Second,
	}
}

// connectAndSendThroughMITM performs a CONNECT handshake against the connector,
// completes a TLS handshake against the MITM cert, and writes raw request
// bytes through the tunnel. Returns the full response bytes.
func connectAndSendThroughMITM(t *testing.T, h *testconnector.Harness, target, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	// Read CONNECT 200 line.
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		conn.Close()
		t.Fatalf("CONNECT response not 200: %q", statusLine)
	}
	// Drain to end of CONNECT headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			t.Fatalf("read CONNECT header line: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// We cannot reuse br for the TLS client because tls.Client operates on
	// the raw net.Conn — any bytes buffered in br would be lost. Since we
	// only read up to the CRLF after headers, bufio may have consumed
	// additional bytes from the socket. Drain them into a prefix reader.
	buffered, _ := br.Peek(br.Buffered())
	wrapped := &peekReadConn{Conn: conn, remaining: append([]byte(nil), buffered...)}

	host, _, _ := net.SplitHostPort(target)
	tlsConn := tls.Client(wrapped, &tls.Config{
		ServerName: host,
		RootCAs:    h.CAPool,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake to MITM: %v", err)
	}
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, _ := io.ReadAll(tlsConn)
	return string(resp)
}

// peekReadConn is a tiny net.Conn adapter that replays a prefix buffer before
// reading from the underlying connection. Used when bufio buffered some
// post-CONNECT bytes we need to preserve.
type peekReadConn struct {
	net.Conn
	remaining []byte
}

func (p *peekReadConn) Read(b []byte) (int, error) {
	if len(p.remaining) > 0 {
		n := copy(b, p.remaining)
		p.remaining = p.remaining[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// waitForFlows polls the store until at least minFlows rows exist for the
// given protocol, or fails after timeout.
func waitForFlows(t *testing.T, store *flow.SQLiteStore, protocol string, minFlows int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ctx := context.Background()
	for time.Now().Before(deadline) {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: protocol})
		if err == nil && len(streams) > 0 {
			total := 0
			for _, st := range streams {
				cnt, _ := store.CountFlows(ctx, st.ID)
				total += cnt
			}
			if total >= minFlows {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d flows in %s streams", minFlows, protocol)
}

// waitForStreams polls the store until at least minStreams exist.
func waitForStreams(t *testing.T, store *flow.SQLiteStore, protocol string, minStreams int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ctx := context.Background()
	for time.Now().Before(deadline) {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: protocol})
		if err == nil && len(streams) >= minStreams {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d %s streams", minStreams, protocol)
}

// assertRecordedStream verifies that at least one HTTP/1.x stream exists and
// has both a send and a receive flow with populated RawBytes.
func assertRecordedStream(t *testing.T, h *testconnector.Harness) {
	t.Helper()
	ctx := context.Background()
	streams, err := h.Store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTP/1.x"})
	if err != nil {
		t.Fatalf("list streams: %v", err)
	}
	if len(streams) == 0 {
		t.Fatal("no HTTP/1.x streams recorded")
	}
	st := streams[0]
	if st.State != "complete" {
		t.Logf("stream state=%q (may still be active; polling up to 1s)", st.State)
		deadline := time.Now().Add(1 * time.Second)
		for time.Now().Before(deadline) {
			got, _ := h.Store.GetStream(ctx, st.ID)
			if got != nil && got.State == "complete" {
				st = got
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	flows, err := h.Store.GetFlows(ctx, st.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("get flows: %v", err)
	}
	if len(flows) < 2 {
		t.Fatalf("expected >=2 flows, got %d", len(flows))
	}
	var hasSend, hasRecv bool
	for _, f := range flows {
		if f.Direction == "send" {
			hasSend = true
			if f.RawBytes == nil {
				t.Fatal("send flow missing RawBytes (L4-capable)")
			}
		}
		if f.Direction == "receive" {
			hasRecv = true
			if f.RawBytes == nil {
				t.Fatal("receive flow missing RawBytes (L4-capable)")
			}
		}
	}
	if !hasSend || !hasRecv {
		t.Fatalf("expected both send and receive flows, got hasSend=%v hasRecv=%v", hasSend, hasRecv)
	}
}

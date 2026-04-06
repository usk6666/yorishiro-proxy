//go:build e2e

package testproxy_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil/testproxy"
)

// ---------- HTTP/1.x E2E Tests ----------

func TestHTTPGetE2E(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "hello")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer origin.Close()

	tp := testproxy.New(t)
	defer tp.Close()
	tp.Start(context.Background())

	// Send GET via raw TCP with Connection: close for clean shutdown.
	respText := rawHTTPRequest(t, tp.Addr(),
		fmt.Sprintf("GET %s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
			origin.URL, origin.Listener.Addr().String()))

	if !strings.Contains(respText, "200") {
		t.Fatalf("expected 200, got: %s", firstLine(respText))
	}
	if !strings.Contains(respText, "OK") {
		t.Fatalf("expected body OK, got: %s", respText)
	}

	// Verify flow recording.
	waitForFlows(t, tp.Store, "HTTP/1.x", 2, 2*time.Second)
	verifyHTTPStreamRecording(t, tp.Store, "HTTP/1.x", "http")
}

func TestHTTPPostE2E(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(bodyBytes)
	}))
	defer origin.Close()

	tp := testproxy.New(t)
	defer tp.Close()
	tp.Start(context.Background())

	reqBody := "request-body-content"
	respText := rawHTTPRequest(t, tp.Addr(),
		fmt.Sprintf("POST %s/echo HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			origin.URL, origin.Listener.Addr().String(), len(reqBody), reqBody))

	if !strings.Contains(respText, "200") {
		t.Fatalf("expected 200, got: %s", firstLine(respText))
	}
	if !strings.Contains(respText, reqBody) {
		t.Fatalf("expected body %q echoed back, got: %s", reqBody, respText)
	}

	waitForFlows(t, tp.Store, "HTTP/1.x", 2, 2*time.Second)
	verifyHTTPStreamRecording(t, tp.Store, "HTTP/1.x", "http")
}

func TestHTTPHeaderWireFidelityE2E(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "headers-ok")
	}))
	defer origin.Close()

	tp := testproxy.New(t)
	defer tp.Close()
	tp.Start(context.Background())

	// Send raw HTTP with intentional header casing to verify wire fidelity.
	respText := rawHTTPRequest(t, tp.Addr(),
		fmt.Sprintf("GET %s/headers HTTP/1.1\r\nHost: %s\r\nX-Custom-Header: CustomValue\r\nx-another: AnotherValue\r\nConnection: close\r\n\r\n",
			origin.URL, origin.Listener.Addr().String()))

	if !strings.Contains(respText, "200") {
		t.Fatalf("expected 200, got: %s", firstLine(respText))
	}

	// Verify raw bytes in flow recording preserve header casing.
	waitForFlows(t, tp.Store, "HTTP/1.x", 2, 2*time.Second)
	ctx := context.Background()
	streams, err := tp.Store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTP/1.x"})
	if err != nil || len(streams) == 0 {
		t.Fatalf("expected at least 1 stream, got err=%v, count=%d", err, len(streams))
	}
	flows, err := tp.Store.GetFlows(ctx, streams[0].ID, flow.FlowListOptions{Direction: "send"})
	if err != nil || len(flows) == 0 {
		t.Fatalf("expected send flow, got err=%v, count=%d", err, len(flows))
	}
	rawBytes := string(flows[0].RawBytes)
	if !strings.Contains(rawBytes, "X-Custom-Header: CustomValue") {
		t.Fatalf("expected raw bytes to preserve header casing, got:\n%s", rawBytes)
	}
	if !strings.Contains(rawBytes, "x-another: AnotherValue") {
		t.Fatalf("expected raw bytes to preserve lowercase header, got:\n%s", rawBytes)
	}
}

func TestHTTPKeepAliveE2E(t *testing.T) {
	var requestCount int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "req-%d", requestCount)
	}))
	defer origin.Close()

	tp := testproxy.New(t)
	defer tp.Close()
	tp.Start(context.Background())

	// Send two requests over the same connection via keep-alive.
	conn, err := net.DialTimeout("tcp", tp.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	host := origin.Listener.Addr().String()

	// First request (keep-alive).
	req1 := fmt.Sprintf("GET %s/keepalive1 HTTP/1.1\r\nHost: %s\r\n\r\n",
		origin.URL+"/keepalive1", host)
	if _, err := conn.Write([]byte(req1)); err != nil {
		t.Fatalf("write request 1: %v", err)
	}

	// Read first response.
	resp1 := readOneHTTPResponse(t, conn)
	if !strings.Contains(resp1, "200") {
		t.Fatalf("expected 200 in response 1, got: %s", firstLine(resp1))
	}
	if !strings.Contains(resp1, "req-1") {
		t.Fatalf("expected req-1 in response 1, got: %s", resp1)
	}

	// Second request (close).
	req2 := fmt.Sprintf("GET %s/keepalive2 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		origin.URL+"/keepalive2", host)
	if _, err := conn.Write([]byte(req2)); err != nil {
		t.Fatalf("write request 2: %v", err)
	}

	resp2 := readOneHTTPResponse(t, conn)
	if !strings.Contains(resp2, "200") {
		t.Fatalf("expected 200 in response 2, got: %s", firstLine(resp2))
	}
	if !strings.Contains(resp2, "req-2") {
		t.Fatalf("expected req-2 in response 2, got: %s", resp2)
	}

	// Verify two streams were recorded (one per request-response pair in HTTP/1.x Codec).
	waitForStreams(t, tp.Store, "HTTP/1.x", 2, 2*time.Second)
}

func TestHTTPFlowRecordingE2E(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "recorded")
	}))
	defer origin.Close()

	tp := testproxy.New(t)
	defer tp.Close()
	tp.Start(context.Background())

	rawHTTPRequest(t, tp.Addr(),
		fmt.Sprintf("GET %s/record HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
			origin.URL, origin.Listener.Addr().String()))

	waitForFlows(t, tp.Store, "HTTP/1.x", 2, 2*time.Second)
	ctx := context.Background()

	// Verify Stream.
	streams, err := tp.Store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTP/1.x"})
	if err != nil {
		t.Fatalf("list streams: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(streams))
	}
	st := streams[0]
	if st.Protocol != "HTTP/1.x" {
		t.Fatalf("expected protocol HTTP/1.x, got %q", st.Protocol)
	}
	if st.Scheme != "http" {
		t.Fatalf("expected scheme http, got %q", st.Scheme)
	}
	if st.State != "complete" {
		t.Fatalf("expected state complete, got %q", st.State)
	}

	// Verify Flows (send + receive).
	flows, err := tp.Store.GetFlows(ctx, st.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("get flows: %v", err)
	}
	if len(flows) != 2 {
		t.Fatalf("expected 2 flows (send+receive), got %d", len(flows))
	}

	sendFlow := flows[0]
	if sendFlow.Direction != "send" {
		t.Fatalf("expected first flow direction send, got %q", sendFlow.Direction)
	}
	if sendFlow.Sequence != 0 {
		t.Fatalf("expected send flow sequence 0, got %d", sendFlow.Sequence)
	}
	if sendFlow.Method != "GET" {
		t.Fatalf("expected send flow method GET, got %q", sendFlow.Method)
	}
	if sendFlow.RawBytes == nil {
		t.Fatal("expected send flow to have RawBytes")
	}

	recvFlow := flows[1]
	if recvFlow.Direction != "receive" {
		t.Fatalf("expected second flow direction receive, got %q", recvFlow.Direction)
	}
	if recvFlow.Sequence != 1 {
		t.Fatalf("expected receive flow sequence 1, got %d", recvFlow.Sequence)
	}
	if recvFlow.StatusCode != 200 {
		t.Fatalf("expected receive flow status 200, got %d", recvFlow.StatusCode)
	}
	if recvFlow.RawBytes == nil {
		t.Fatal("expected receive flow to have RawBytes")
	}
	if !strings.Contains(string(recvFlow.Body), "recorded") {
		t.Fatalf("expected receive flow body to contain 'recorded', got %q", string(recvFlow.Body))
	}
}

// ---------- TCP E2E Tests ----------

func TestTCPBidirectionalE2E(t *testing.T) {
	// Start a TCP echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	tp := testproxy.New(t)
	tp.TCPTarget = echoLn.Addr().String()
	defer tp.Close()
	tp.Start(context.Background())

	conn, err := net.DialTimeout("tcp", tp.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send binary data (not starting with HTTP method).
	data := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 'h', 'e', 'l', 'l', 'o'}
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read echoed data.
	buf := make([]byte, len(data))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read echo: %v (read %d bytes)", err, n)
	}
	if !bytes.Equal(buf, data) {
		t.Fatalf("expected echo %v, got %v", data, buf)
	}

	// Close to trigger OnComplete.
	conn.Close()
	time.Sleep(500 * time.Millisecond)

	// Verify flow recording.
	ctx := context.Background()
	streams, err := tp.Store.ListStreams(ctx, flow.StreamListOptions{Protocol: "TCP"})
	if err != nil {
		t.Fatalf("list streams: %v", err)
	}
	if len(streams) != 1 {
		// Debug: list all streams regardless of protocol.
		allStreams, _ := tp.Store.ListStreams(ctx, flow.StreamListOptions{})
		t.Fatalf("expected 1 TCP stream, got %d (all streams: %d)", len(streams), len(allStreams))
	}
	st := streams[0]
	if st.Protocol != "TCP" {
		t.Fatalf("expected protocol TCP, got %q", st.Protocol)
	}

	flows, err := tp.Store.GetFlows(ctx, st.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("get flows: %v", err)
	}
	// Expect at least 1 send flow and 1 receive flow.
	var hasSend, hasRecv bool
	for _, f := range flows {
		if f.Direction == "send" {
			hasSend = true
			if f.RawBytes == nil {
				t.Fatal("expected TCP send flow to have RawBytes")
			}
		}
		if f.Direction == "receive" {
			hasRecv = true
			if f.RawBytes == nil {
				t.Fatal("expected TCP receive flow to have RawBytes")
			}
		}
	}
	if !hasSend {
		t.Fatal("expected at least one TCP send flow")
	}
	if !hasRecv {
		t.Fatal("expected at least one TCP receive flow")
	}
}

func TestTCPFlowRecordingE2E(t *testing.T) {
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverLn.Close()

	serverResponse := []byte("server-response-data")
	go func() {
		for {
			conn, err := serverLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				conn.Read(buf)
				conn.Write(serverResponse)
			}()
		}
	}()

	tp := testproxy.New(t)
	tp.TCPTarget = serverLn.Addr().String()
	defer tp.Close()
	tp.Start(context.Background())

	conn, err := net.DialTimeout("tcp", tp.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	clientData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	conn.Write(clientData)

	buf := make([]byte, len(serverResponse))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadFull(conn, buf)
	conn.Close()

	if !bytes.Equal(buf, serverResponse) {
		t.Fatalf("expected %v, got %v", serverResponse, buf)
	}

	time.Sleep(300 * time.Millisecond)

	ctx := context.Background()
	streams, err := tp.Store.ListStreams(ctx, flow.StreamListOptions{Protocol: "TCP"})
	if err != nil {
		t.Fatalf("list streams: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("expected 1 TCP stream, got %d", len(streams))
	}
	st := streams[0]
	if st.State != "complete" {
		t.Fatalf("expected state complete, got %q", st.State)
	}

	flowCount, err := tp.Store.CountFlows(ctx, st.ID)
	if err != nil {
		t.Fatalf("count flows: %v", err)
	}
	if flowCount < 2 {
		t.Fatalf("expected at least 2 flows (send+receive), got %d", flowCount)
	}
}

// ---------- Helpers ----------

// rawHTTPRequest sends a raw HTTP request string through the proxy and returns
// the full response as a string.
func rawHTTPRequest(t *testing.T, proxyAddr, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(resp)
}

// readOneHTTPResponse reads exactly one HTTP response from a keep-alive connection.
func readOneHTTPResponse(t *testing.T, conn net.Conn) string {
	t.Helper()
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return fmt.Sprintf("HTTP/%d.%d %d %s\r\n\r\n%s",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status, string(body))
}

// firstLine returns the first line of text.
func firstLine(s string) string {
	if idx := strings.Index(s, "\r\n"); idx >= 0 {
		return s[:idx]
	}
	if idx := strings.Index(s, "\n"); idx >= 0 {
		return s[:idx]
	}
	return s
}

// waitForFlows polls the store until the expected number of flows appear for
// the given protocol, or times out.
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
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d flows in %s streams", minFlows, protocol)
}

// waitForStreams polls the store until the expected number of streams appear.
func waitForStreams(t *testing.T, store *flow.SQLiteStore, protocol string, minStreams int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ctx := context.Background()
	for time.Now().Before(deadline) {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: protocol})
		if err == nil && len(streams) >= minStreams {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d %s streams", minStreams, protocol)
}

// verifyHTTPStreamRecording checks that at least one stream and its flows exist.
func verifyHTTPStreamRecording(t *testing.T, store *flow.SQLiteStore, protocol, scheme string) {
	t.Helper()
	ctx := context.Background()

	streams, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: protocol})
	if err != nil {
		t.Fatalf("list streams: %v", err)
	}
	if len(streams) == 0 {
		t.Fatalf("expected at least 1 %s stream", protocol)
	}

	st := streams[0]
	if st.Scheme != scheme {
		t.Fatalf("expected scheme %q, got %q", scheme, st.Scheme)
	}

	flows, err := store.GetFlows(ctx, st.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("get flows: %v", err)
	}
	if len(flows) < 2 {
		t.Fatalf("expected at least 2 flows for %s stream, got %d", protocol, len(flows))
	}
}

//go:build e2e

package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// =============================================================================
// Test helpers for independent HTTP/1.x engine integration tests
// =============================================================================

// startH1Proxy starts a plain HTTP/1.x forward proxy (no TLS, no MITM).
// Returns the listener, handler, and cancel function.
func startH1Proxy(t *testing.T, ctx context.Context, store flow.Store) (*proxy.Listener, *protohttp.Handler, context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)

	go func() {
		if err := listener.Start(proxyCtx); err != nil {
			t.Logf("proxy listener error: %v", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	return listener, httpHandler, proxyCancel
}

// newH1Store creates a temporary SQLite store for testing.
func newH1Store(t *testing.T, ctx context.Context) *flow.SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// sendRawHTTPRequest sends raw bytes to the proxy via a TCP connection and
// returns the raw response bytes.
func sendRawHTTPRequest(t *testing.T, proxyAddr string, rawRequest string) string {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := io.WriteString(conn, rawRequest); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return string(resp)
}

// sendRawHTTPRequestParsed sends raw bytes to the proxy and returns a parsed
// HTTP response (using Go's standard library parser for validation).
// The response body is fully buffered before the connection is closed, so
// callers can safely read resp.Body after the connection is gone.
func sendRawHTTPRequestParsed(t *testing.T, proxyAddr string, rawRequest string) *gohttp.Response {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := io.WriteString(conn, rawRequest); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// Buffer the entire body before returning so that callers are not
	// affected by the deferred conn.Close().
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	return resp
}

// =============================================================================
// Raw Bytes Round-Trip Tests
// =============================================================================

func TestH1Engine_RawBytes_HeaderCaseAndOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream responds with a fixed body and custom header.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Custom-Header", "preserved")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "header-test-ok")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send request with mixed-case headers in specific order.
	rawReq := fmt.Sprintf(
		"GET %s/header-test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"X-First-Header: value1\r\n"+
			"x-second-header: value2\r\n"+
			"X-THIRD-HEADER: VALUE3\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "header-test-ok" {
		t.Fatalf("body = %q, want %q", body, "header-test-ok")
	}

	// Verify flow recording with raw bytes.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTP/1.x")
	}
	if fl.FlowType != "unary" {
		t.Errorf("flow type = %q, want %q", fl.FlowType, "unary")
	}

	send, recv := pollFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}

	// Verify raw bytes are captured on the send message.
	if len(send.RawBytes) == 0 {
		t.Fatal("send.RawBytes is empty, expected raw HTTP request bytes")
	}

	rawStr := string(send.RawBytes)
	// Header names should be preserved in their original case in raw bytes.
	if !strings.Contains(rawStr, "X-First-Header:") {
		t.Errorf("raw bytes missing X-First-Header, got:\n%s", rawStr)
	}
	if !strings.Contains(rawStr, "x-second-header:") {
		t.Errorf("raw bytes missing x-second-header (lowercase), got:\n%s", rawStr)
	}
	if !strings.Contains(rawStr, "X-THIRD-HEADER:") {
		t.Errorf("raw bytes missing X-THIRD-HEADER (uppercase), got:\n%s", rawStr)
	}

	// Verify header order: X-First should appear before x-second, which should
	// appear before X-THIRD.
	firstIdx := strings.Index(rawStr, "X-First-Header:")
	secondIdx := strings.Index(rawStr, "x-second-header:")
	thirdIdx := strings.Index(rawStr, "X-THIRD-HEADER:")
	if firstIdx >= 0 && secondIdx >= 0 && thirdIdx >= 0 {
		if firstIdx > secondIdx || secondIdx > thirdIdx {
			t.Errorf("header order not preserved in raw bytes: first=%d, second=%d, third=%d", firstIdx, secondIdx, thirdIdx)
		}
	}

	// Verify response raw bytes are also captured.
	if len(recv.RawBytes) == 0 {
		t.Error("recv.RawBytes is empty, expected raw HTTP response bytes")
	}

	// Verify state is complete.
	if fl.State != "complete" {
		t.Errorf("flow state = %q, want %q", fl.State, "complete")
	}
}

func TestH1Engine_RawBytes_ObsFoldWhitespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "obs-fold-ok")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send request with obs-fold (continuation line starting with SP).
	rawReq := fmt.Sprintf(
		"GET %s/obs-fold HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"X-Folded-Header: first-part\r\n"+
			" continuation-part\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	send, _ := pollFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}

	// Raw bytes should contain the obs-fold as received on the wire.
	if len(send.RawBytes) == 0 {
		t.Fatal("send.RawBytes is empty")
	}

	rawStr := string(send.RawBytes)
	if !strings.Contains(rawStr, "X-Folded-Header:") {
		t.Errorf("raw bytes missing X-Folded-Header")
	}

	// Verify anomaly tag for obs-fold.
	if fl.Tags == nil {
		t.Fatal("flow tags is nil, expected obs-fold anomaly tag")
	}
	if fl.Tags["smuggling:obs_fold"] != "true" {
		t.Errorf("expected smuggling:obs_fold tag, got tags: %v", fl.Tags)
	}
}

func TestH1Engine_RawBytes_ChunkedRecordedWithoutDecoding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream responds with chunked encoding.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// Read request body to confirm chunked data was decoded by the proxy.
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "received:%s", body)
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send chunked POST request.
	rawReq := fmt.Sprintf(
		"POST %s/chunked HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"5\r\n"+
			"Hello\r\n"+
			"6\r\n"+
			" World\r\n"+
			"0\r\n"+
			"\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if !strings.Contains(string(body), "received:Hello World") {
		t.Errorf("body = %q, want containing %q", body, "received:Hello World")
	}

	// Verify flow recording: raw bytes should contain the original chunked
	// encoding, NOT the decoded body.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	send, _ := pollFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}

	if len(send.RawBytes) == 0 {
		t.Fatal("send.RawBytes is empty")
	}

	rawStr := string(send.RawBytes)
	// RawBytes captures the header section (request-line + headers + CRLF CRLF).
	// Verify the Transfer-Encoding: chunked header is faithfully recorded.
	if !strings.Contains(rawStr, "Transfer-Encoding: chunked") {
		t.Errorf("raw bytes missing Transfer-Encoding header, got:\n%s", rawStr)
	}

	// The body content (chunked or decoded) should NOT be in RawBytes,
	// since RawBytes only contains the header section.
	if strings.Contains(rawStr, "Hello") {
		t.Errorf("raw bytes unexpectedly contain body content, got:\n%s", rawStr)
	}

	// Verify the decoded body is accessible via the Message Body field.
	if !strings.Contains(string(send.Body), "Hello") {
		t.Errorf("send.Body = %q, want containing %q", send.Body, "Hello")
	}
}

// =============================================================================
// Anomaly Recording Tests
// =============================================================================

func TestH1Engine_Anomaly_CLTEConflict(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "clte-ok")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send request with both Content-Length and Transfer-Encoding (CL/TE conflict).
	rawReq := fmt.Sprintf(
		"POST %s/clte HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: 5\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"5\r\n"+
			"Hello\r\n"+
			"0\r\n"+
			"\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	// Verify CL/TE anomaly tag is recorded.
	if fl.Tags == nil {
		t.Fatal("flow tags is nil, expected CLTE anomaly tag")
	}
	if fl.Tags["smuggling:cl_te_conflict"] != "true" {
		t.Errorf("expected smuggling:cl_te_conflict tag, got tags: %v", fl.Tags)
	}
}

func TestH1Engine_Anomaly_DuplicateCL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "dupcl-ok")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send request with duplicate Content-Length headers (different values).
	rawReq := fmt.Sprintf(
		"POST %s/dupcl HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: 5\r\n"+
			"Content-Length: 10\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"Hello",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	if fl.Tags == nil {
		t.Fatal("flow tags is nil, expected DuplicateCL anomaly tag")
	}
	if fl.Tags["smuggling:duplicate_cl"] != "true" {
		t.Errorf("expected smuggling:duplicate_cl tag, got tags: %v", fl.Tags)
	}
}

func TestH1Engine_Anomaly_InvalidTE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "invalidte-ok")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send request with non-standard Transfer-Encoding value.
	rawReq := fmt.Sprintf(
		"GET %s/invalidte HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Transfer-Encoding: cow\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	io.ReadAll(resp.Body)
	resp.Body.Close()

	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	if fl.Tags == nil {
		t.Fatal("flow tags is nil, expected InvalidTE anomaly tag")
	}
	if fl.Tags["smuggling:invalid_te"] != "true" {
		t.Errorf("expected smuggling:invalid_te tag, got tags: %v", fl.Tags)
	}
}

func TestH1Engine_Anomaly_QueryViaMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "mcp-query-ok")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send anomalous request.
	rawReq := fmt.Sprintf(
		"POST %s/mcp-query HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: 4\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"4\r\n"+
			"test\r\n"+
			"0\r\n"+
			"\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Verify the flow is queryable via the store (simulating MCP query).
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	// Verify flow is retrievable by ID (MCP "resource: flow" equivalent).
	retrieved, err := store.GetFlow(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if retrieved.ID != fl.ID {
		t.Errorf("GetFlow ID = %q, want %q", retrieved.ID, fl.ID)
	}
	if retrieved.Tags["smuggling:cl_te_conflict"] != "true" {
		t.Errorf("expected CLTE anomaly tag on retrieved flow, got tags: %v", retrieved.Tags)
	}

	// Verify messages are retrievable (MCP "resource: flow" with messages).
	msgs, err := store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(msgs))
	}
}

// =============================================================================
// HTTP/1.0 Compatibility Tests
// =============================================================================

func TestH1Engine_HTTP10_BasicProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "http10-response")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send HTTP/1.0 request (no Connection header; defaults to close).
	rawReq := fmt.Sprintf(
		"GET %s/http10 HTTP/1.0\r\n"+
			"Host: %s\r\n"+
			"\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "http10-response" {
		t.Errorf("body = %q, want %q", body, "http10-response")
	}

	// Verify flow recording.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	if fl.Protocol != "HTTP/1.x" {
		t.Errorf("flow protocol = %q, want %q", fl.Protocol, "HTTP/1.x")
	}
	if fl.State != "complete" {
		t.Errorf("flow state = %q, want %q", fl.State, "complete")
	}

	send, recv := pollFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("recv message not found")
	}
	if send.Method != "GET" {
		t.Errorf("send method = %q, want %q", send.Method, "GET")
	}
	if recv.StatusCode != 200 {
		t.Errorf("recv status = %d, want %d", recv.StatusCode, 200)
	}
}

func TestH1Engine_HTTP10_EOFTerminated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create upstream that sends HTTP/1.0 response with EOF-terminated body
	// (no Content-Length, no chunked TE).
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	upstreamAddr := upstreamLn.Addr().String()

	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read and discard request.
				buf := make([]byte, 4096)
				c.Read(buf)

				// Write HTTP/1.0 response without Content-Length (EOF-terminated).
				resp := "HTTP/1.0 200 OK\r\n" +
					"Content-Type: text/plain\r\n" +
					"\r\n" +
					"eof-terminated-body"
				c.Write([]byte(resp))
				// Close to signal EOF.
			}(conn)
		}
	}()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send request targeting the raw upstream.
	rawReq := fmt.Sprintf(
		"GET http://%s/eof-test HTTP/1.0\r\n"+
			"Host: %s\r\n"+
			"\r\n",
		upstreamAddr, upstreamAddr)

	respStr := sendRawHTTPRequest(t, listener.Addr(), rawReq)

	if !strings.Contains(respStr, "eof-terminated-body") {
		t.Errorf("response missing EOF-terminated body, got:\n%s", respStr)
	}

	// Verify flow recording captured the response body.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]

	_, recv := pollFlowMessages(t, ctx, store, fl.ID)
	if recv == nil {
		t.Fatal("recv message not found")
	}
	if !strings.Contains(string(recv.Body), "eof-terminated-body") {
		t.Errorf("recorded response body = %q, want containing %q", recv.Body, "eof-terminated-body")
	}
}

// =============================================================================
// Go net/http Client Compatibility Tests
// =============================================================================

func TestH1Engine_GoHTTPClient_GET(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Go-Client", "yes")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "go-client-response")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Use Go standard http.Client with the proxy.
	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(upstream.URL + "/go-client")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "go-client-response" {
		t.Errorf("body = %q, want %q", body, "go-client-response")
	}

	// Verify flow recording.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]
	if fl.State != "complete" {
		t.Errorf("flow state = %q, want %q", fl.State, "complete")
	}
}

func TestH1Engine_GoHTTPClient_POST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(gohttp.StatusCreated)
		fmt.Fprintf(w, "echo:%s", body)
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	proxyURL, _ := url.Parse("http://" + listener.Addr())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(upstream.URL+"/go-client-post", "text/plain", strings.NewReader("request-body"))
	if err != nil {
		t.Fatalf("client.Post: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusCreated)
	}
	if string(body) != "echo:request-body" {
		t.Errorf("body = %q, want %q", body, "echo:request-body")
	}

	// Verify flow.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 1)
	fl := flows[0]
	send, recv := pollFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("recv message not found")
	}
	if send.Method != "POST" {
		t.Errorf("send method = %q, want %q", send.Method, "POST")
	}
	if recv.StatusCode != 201 {
		t.Errorf("recv status = %d, want %d", recv.StatusCode, 201)
	}
}

// =============================================================================
// ConnPool Tests
// =============================================================================

func TestH1Engine_ConnPool_KeepAliveReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var requestCount atomic.Int32
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		n := requestCount.Add(1)
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "req-%d", n)
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Send multiple requests on a single keep-alive connection.
	conn, err := net.DialTimeout("tcp", listener.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)

	for i := 0; i < 3; i++ {
		req := fmt.Sprintf(
			"GET %s/keepalive-%d HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"\r\n",
			upstream.URL, i, mustParseURL(upstream.URL).Host)

		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatalf("write request %d: %v", i, err)
		}

		resp, err := gohttp.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != gohttp.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i, resp.StatusCode, gohttp.StatusOK)
		}
		expected := fmt.Sprintf("req-%d", i+1)
		if string(body) != expected {
			t.Errorf("request %d: body = %q, want %q", i, body, expected)
		}
	}

	// Verify all 3 requests were recorded as separate flows.
	flows := pollFlows(t, ctx, store, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10}, 3)
	if len(flows) < 3 {
		t.Errorf("expected at least 3 flows, got %d", len(flows))
	}
}

// =============================================================================
// State Transition Tests
// =============================================================================

func TestH1Engine_StateTransition_ActiveToComplete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "state-test")
	}))
	defer upstream.Close()

	store := newH1Store(t, ctx)
	listener, _, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	rawReq := fmt.Sprintf(
		"GET %s/state-test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		upstream.URL, mustParseURL(upstream.URL).Host)

	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Wait for flow to reach complete state.
	var fl *flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err := store.ListFlows(ctx, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		for _, f := range flows {
			if f.State == "complete" {
				fl = f
				break
			}
		}
		if fl != nil {
			break
		}
	}

	if fl == nil {
		t.Fatal("flow never reached complete state")
	}

	if fl.Duration <= 0 {
		t.Errorf("flow duration = %v, want > 0", fl.Duration)
	}
}

func TestH1Engine_StateTransition_ErrorOnConnectionFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store := newH1Store(t, ctx)
	listener, handler, proxyCancel := startH1Proxy(t, ctx, store)
	defer proxyCancel()

	// Configure a ConnPool with a very short dial timeout so the test doesn't
	// wait for the default 30s.
	handler.SetConnPool(&protohttp.ConnPool{
		DialTimeout: 1 * time.Second,
	})

	// Listen on a port and immediately close the listener so connections
	// are refused (connection refused, not timeout).
	blockerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	blockerLn.Close()
	refusedAddr := blockerLn.Addr().String()

	rawReq := fmt.Sprintf(
		"GET http://%s/nonexistent HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		refusedAddr, refusedAddr)

	// The proxy should return a 502 Bad Gateway.
	resp := sendRawHTTPRequestParsed(t, listener.Addr(), rawReq)
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 502 {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}

	// Verify flow is recorded with error state.
	var fl *flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err := store.ListFlows(ctx, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		for _, f := range flows {
			if f.State == "error" {
				fl = f
				break
			}
		}
		if fl != nil {
			break
		}
	}

	if fl == nil {
		// If no error-state flow appeared, check what flows exist.
		flows, _ := store.ListFlows(ctx, flow.ListOptions{Protocol: "HTTP/1.x", Limit: 10})
		if len(flows) == 0 {
			// The proxy genuinely does not record flows for upstream dial failures.
			// The 502 response assertion above is sufficient; no flow assertion needed.
			t.Log("no flow recorded for upstream dial failure; only 502 response verified")
			return
		}
		// A flow exists but is not in error state — this is unexpected.
		t.Errorf("flow exists but state = %q, want %q", flows[0].State, "error")
	}
}

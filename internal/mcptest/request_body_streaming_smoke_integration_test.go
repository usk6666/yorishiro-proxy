//go:build e2e

// USK-1414: HTTP/1.x request body streaming through the production wiring
// (config JSON → mcpserver init → proxybuild body-mode predicate →
// client-facing HTTP/1.x Layer of the plain forward proxy), observed on the
// wire and through the MCP query tool.
package mcptest_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// startUploadUpstream starts a plain HTTP/1.1 upstream that runs serve on
// every accepted connection; accepts counts them.
func startUploadUpstream(t *testing.T, serve func(c net.Conn, br *bufio.Reader)) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepts := &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(60 * time.Second))
				serve(c, bufio.NewReader(c))
			}()
		}
	}()
	return ln.Addr().String(), accepts
}

// readUploadHead reads a header section (through the blank line) from br
// as it arrived and returns it with its Content-Length (-1 when absent).
func readUploadHead(br *bufio.Reader) (string, int64, error) {
	var head strings.Builder
	cl := int64(-1)
	for {
		line, err := br.ReadString('\n')
		head.WriteString(line)
		if err != nil {
			return head.String(), cl, err
		}
		if line == "\r\n" {
			return head.String(), cl, nil
		}
		if name, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			if n, perr := strconv.ParseInt(strings.TrimSpace(v), 10, 64); perr == nil {
				cl = n
			}
		}
	}
}

// dialUploadProxy dials the proxy listener.
func dialUploadProxy(t *testing.T, proxyAddr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// queryUploadMessages returns the recorded messages of streamID with
// direction dir.
func queryUploadMessages(t *testing.T, h *mcptest.Harness, streamID, dir string) []map[string]any {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "messages", "id": streamID})
	msgs, _ := res.Decoded["messages"].([]any)
	var out []map[string]any
	for _, m := range msgs {
		e, _ := m.(map[string]any)
		if d, _ := e["direction"].(string); d == dir {
			out = append(out, e)
		}
	}
	return out
}

// TestSmoke_RequestBodyStreaming_OverMaxBodySizeReachesUpstream (USK-1414
// T4): with no rule needing the body, a request body larger than
// max_body_size is streamed — the upstream receives every byte — while the
// recorded copy is cut at max_record_body_size and marked truncated.
func TestSmoke_RequestBodyStreaming_OverMaxBodySizeReachesUpstream(t *testing.T) {
	const maxBody = 10 << 20 // the smallest max_body_size the default spill threshold allows
	const recordCap = 64 << 10
	body := bytes.Repeat([]byte("U"), maxBody+512<<10)
	want := sha256.Sum256(body)

	upstream, _ := startUploadUpstream(t, func(c net.Conn, br *bufio.Reader) {
		_, cl, err := readUploadHead(br)
		if err != nil || cl < 0 {
			return
		}
		hsh := sha256.New()
		n, _ := io.CopyN(hsh, br, cl)
		sum := hex.EncodeToString(hsh.Sum(nil))
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Received: %d\r\nConnection: close\r\n\r\n%s", len(sum), n, sum)
	})
	h, proxyAddr := startBodyLimitProxy(t, bodyLimitConfigJSON(t, map[string]any{
		"max_body_size":        maxBody,
		"max_record_body_size": recordCap,
	}))

	c := dialUploadProxy(t, proxyAddr)
	go func() {
		fmt.Fprintf(c, "POST http://%s/upload-big HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", upstream, upstream, len(body))
		_, _ = c.Write(body)
	}()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response (a body over max_body_size must still be forwarded): %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("upstream answer = %d %q (received %s bytes), want 200 and the sha256 of the whole %d-byte body",
			resp.StatusCode, got, resp.Header.Get("X-Received"), len(body))
	}

	streamID := waitRecordCapStream(t, h, "/upload-big")
	send := queryUploadMessages(t, h, streamID, "send")
	if len(send) != 1 {
		t.Fatalf("send messages = %d, want 1", len(send))
	}
	if b, _ := send[0]["body"].(string); len(b) != recordCap || b != strings.Repeat("U", recordCap) {
		t.Errorf("recorded request body len = %d, want the leading %d bytes", len(b), recordCap)
	}
	if tr, _ := send[0]["body_truncated"].(bool); !tr {
		t.Errorf("body_truncated = %v, want true", send[0]["body_truncated"])
	}
	md, _ := send[0]["metadata"].(map[string]any)
	if _, ok := md["http_anomaly_raw_body_truncated"]; !ok {
		t.Errorf("metadata http_anomaly_raw_body_truncated absent; metadata=%v", md)
	}
}

// TestSmoke_RequestBodyStreaming_ForwardScopeDenyClosesConnection
// (USK-1414 T8, plain forward proxy): a streamed request refused by the
// path scope is answered 403 without waiting for its body and the
// connection then closes; a request carried inside the unsent body is
// never parsed — the upstream reads no byte and one Stream is recorded.
func TestSmoke_RequestBodyStreaming_ForwardScopeDenyClosesConnection(t *testing.T) {
	upBytes := make(chan int64, 4)
	upstream, accepts := startUploadUpstream(t, func(c net.Conn, _ *bufio.Reader) {
		n, _ := io.Copy(io.Discard, c)
		upBytes <- n
	})
	h, proxyAddr := startBodyLimitProxy(t,
		`{"target_scope_policy":{"allows":[{"hostname":"127.0.0.1","path_prefix":"/api/"}]}}`)

	c := dialUploadProxy(t, proxyAddr)
	smuggled := fmt.Sprintf("GET http://%s/api/smuggled HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream)
	fmt.Fprintf(c, "POST http://%s/other HTTP/1.1\r\nHost: %s\r\nContent-Length: 100000\r\n\r\n%s", upstream, upstream, smuggled)

	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	head, _, err := readUploadHead(br)
	if err != nil {
		t.Fatalf("read 403 within 10s (the proxy waited for the whole body?): got %q: %v", head, err)
	}
	if !strings.HasPrefix(head, "HTTP/1.1 403") || !strings.Contains(head, "Connection: close\r\n") {
		t.Fatalf("response head = %q, want 403 with Connection: close", head)
	}
	_, err = io.Copy(io.Discard, br)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection still open after the 403: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	var flows []map[string]any
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": map[string]any{"protocol": "http"}})
		raw, _ := res.Decoded["flows"].([]any)
		flows = flows[:0]
		for _, r := range raw {
			if m, ok := r.(map[string]any); ok {
				flows = append(flows, m)
			}
		}
		if len(flows) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if len(flows) != 1 {
		t.Errorf("recorded http Streams = %d, want 1 (the request inside the unsent body must never be parsed)", len(flows))
	}
	for i := int32(0); i < accepts.Load(); i++ {
		select {
		case n := <-upBytes:
			if n != 0 {
				t.Errorf("upstream read %d bytes, want 0", n)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("upstream connection was not closed")
		}
	}
}

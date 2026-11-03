//go:build e2e && !e2e_smoke

// USK-1415: an upstream that answers 413 and resets the connection while
// the proxy is still writing the request body, through the production
// plain-HTTP forward wiring (HTTP/1.x stale-connection retry wrapper,
// production OnComplete). Helpers live in
// request_body_streaming_smoke_integration_test.go and
// request_body_streaming_integration_test.go.
package mcptest_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestE2E_EarlyResponse_UpstreamResetMidBody (T2): the client receives the
// 413, and `query` shows the Stream complete with the 413 recorded.
func TestE2E_EarlyResponse_UpstreamResetMidBody(t *testing.T) {
	body := bytes.Repeat([]byte("E"), 16<<20)
	upstream, _ := startUploadUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, _, err := readUploadHead(br); err != nil {
			return
		}
		if _, err := io.ReadFull(br, make([]byte, 64<<10)); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 9\r\nConnection: close\r\n\r\ntoo large")
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
	})
	h, proxyAddr := startBodyLimitProxy(t, "")

	c := dialUploadProxy(t, proxyAddr)
	go func() {
		_, _ = fmt.Fprintf(c, "POST http://%s/early-413 HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", upstream, upstream, len(body))
		_, _ = c.Write(body)
	}()
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	resp, _ := io.ReadAll(bufio.NewReader(c))
	if !strings.HasPrefix(string(resp), "HTTP/1.1 413 ") || !strings.HasSuffix(string(resp), "too large") {
		t.Fatalf("client response = %q, want the upstream's 413", resp)
	}

	st := waitUploadStream(t, h, "/early-413", "")
	id, _ := st["id"].(string)
	deadline := time.Now().Add(10 * time.Second)
	for st["state"] != "complete" && time.Now().Before(deadline) {
		if s, _ := st["state"].(string); s == "error" {
			break
		}
		time.Sleep(25 * time.Millisecond)
		st = waitUploadStream(t, h, "/early-413", "")
	}
	if s, _ := st["state"].(string); s != "complete" {
		t.Errorf("Stream state = %q, want complete (the response arrived)", s)
	}
	recv := queryUploadMessages(t, h, id, "receive")
	if len(recv) != 1 {
		t.Fatalf("receive messages = %d, want 1", len(recv))
	}
	if code, _ := recv[0]["status_code"].(float64); code != 413 {
		t.Errorf("recorded status_code = %v, want 413", recv[0]["status_code"])
	}
}

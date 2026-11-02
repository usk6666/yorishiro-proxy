//go:build e2e && !e2e_smoke

// USK-1414 exhaustive tier: recording, a client cut mid-body and the plugin
// on_request cap for streamed HTTP/1.x request bodies, through the
// production wiring. Helpers live in
// request_body_streaming_smoke_integration_test.go.
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

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// waitUploadStream polls `query flows` until one Stream matches urlPattern
// (any http Stream when "") in state (any state when ""), returning it.
// A Stream whose request body is still uploading has no send message yet,
// and url_pattern matches the recorded request, so such a Stream is found
// with urlPattern "" (each test runs its own harness).
func waitUploadStream(t *testing.T, h *mcptest.Harness, urlPattern, state string) map[string]any {
	t.Helper()
	filter := map[string]any{"protocol": "http"}
	if urlPattern != "" {
		filter["url_pattern"] = urlPattern
	}
	if state != "" {
		filter["state"] = state
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows", "filter": filter})
		flows, _ := res.Decoded["flows"].([]any)
		if len(flows) == 1 {
			st, _ := flows[0].(map[string]any)
			return st
		}
		if len(flows) > 1 {
			t.Fatalf("%d Streams match %q, want 1", len(flows), urlPattern)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Stream matching %q in state %q within 10s", urlPattern, state)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestE2E_RequestBodyStreaming_RecordingLifecycle (T3): while the request
// body is still being uploaded the Stream is active and no send message is
// recorded; after the body ended the Stream completes and the send message
// carries the whole body.
func TestE2E_RequestBodyStreaming_RecordingLifecycle(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789"), 800)
	half := len(body) / 2
	got1 := make(chan struct{})
	upstream, _ := startUploadUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, _, err := readUploadHead(br); err != nil {
			return
		}
		if _, err := io.ReadFull(br, make([]byte, half)); err != nil {
			return
		}
		close(got1)
		if _, err := io.ReadFull(br, make([]byte, len(body)-half)); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	h, proxyAddr := startBodyLimitProxy(t, "")

	c := dialUploadProxy(t, proxyAddr)
	fmt.Fprintf(c, "POST http://%s/rec-upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", upstream, upstream, len(body))
	_, _ = c.Write(body[:half])
	select {
	case <-got1:
	case <-time.After(15 * time.Second):
		t.Fatal("the upstream did not receive the first body fragment before the client sent the rest (request body buffered)")
	}

	st := waitUploadStream(t, h, "", "")
	if s, _ := st["state"].(string); s != "active" {
		t.Errorf("Stream state while the body is uploading = %q, want active", s)
	}
	id, _ := st["id"].(string)
	if send := queryUploadMessages(t, h, id, "send"); len(send) != 0 {
		t.Errorf("send messages while the body is uploading = %d, want 0 (saved at body end)", len(send))
	}

	_, _ = c.Write(body[half:])
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(resp), "HTTP/1.1 200 OK") {
		t.Fatalf("client response = %q, want 200", resp)
	}
	waitUploadStream(t, h, "/rec-upload", "complete")
	send := queryUploadMessages(t, h, id, "send")
	if len(send) != 1 {
		t.Fatalf("send messages = %d, want 1", len(send))
	}
	if b, _ := send[0]["body"].(string); b != string(body) {
		t.Errorf("recorded request body = %d bytes, want the whole %d-byte body", len(b), len(body))
	}
	if tr, _ := send[0]["body_truncated"].(bool); tr {
		t.Error("body_truncated = true for a complete body")
	}
}

// TestE2E_RequestBodyStreaming_ClientCutMidBody (T11): the client closes
// mid-body. The upstream receives the bytes sent and then EOF (the proxy
// mirrors the FIN); with no final response the Stream ends in error, and
// the send message keeps the partial body marked truncated.
func TestE2E_RequestBodyStreaming_ClientCutMidBody(t *testing.T) {
	const sent = 100
	upEOF := make(chan int, 1)
	upstream, _ := startUploadUpstream(t, func(_ net.Conn, br *bufio.Reader) {
		if _, _, err := readUploadHead(br); err != nil {
			return
		}
		b, err := io.ReadAll(br)
		if err == nil {
			upEOF <- len(b)
		}
	})
	h, proxyAddr := startBodyLimitProxy(t, "")

	c := dialUploadProxy(t, proxyAddr)
	fmt.Fprintf(c, "POST http://%s/cut-upload HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\n%s", upstream, upstream, strings.Repeat("c", sent))
	st := waitUploadStream(t, h, "", "")
	_ = c.Close()

	select {
	case n := <-upEOF:
		if n != sent {
			t.Errorf("upstream read %d body bytes before EOF, want %d", n, sent)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream did not observe EOF after the client cut mid-body")
	}
	id, _ := st["id"].(string)
	waitUploadStream(t, h, "/cut-upload", "error")
	send := queryUploadMessages(t, h, id, "send")
	if len(send) != 1 {
		t.Fatalf("send messages = %d, want 1", len(send))
	}
	if b, _ := send[0]["body"].(string); b != strings.Repeat("c", sent) {
		t.Errorf("recorded partial body = %q, want the %d bytes received", b, sent)
	}
	md, _ := send[0]["metadata"].(map[string]any)
	if _, ok := md["http_anomaly_truncated_body"]; !ok {
		t.Errorf("metadata http_anomaly_truncated_body absent; metadata=%v", md)
	}
}

// pluginScriptRequestStamp stamps the request body length it saw.
const pluginScriptRequestStamp = `
def on_request(msg, ctx):
    msg["headers"].append("X-Plugin-Saw", str(len(msg["body"])))

register_hook("http", "on_request", on_request, phase="pre_pipeline")
`

// TestE2E_RequestBodyStreaming_PluginMaxBodySize (T15): with an http
// on_request hook loaded, a request body within plugin_max_body_size still
// reaches the hook whole; a larger one is streamed past the hook — its
// first fragment reaches the upstream before the client sends the rest,
// and the upstream receives the whole body.
func TestE2E_RequestBodyStreaming_PluginMaxBodySize(t *testing.T) {
	const pluginCap = 2048
	scriptPath := writePluginScript(t, "request_stamp.star", pluginScriptRequestStamp)
	type upReq struct {
		head string
		body []byte
	}
	reqs := make(chan upReq, 2)
	got1 := make(chan struct{}, 2)
	upstream, _ := startUploadUpstream(t, func(c net.Conn, br *bufio.Reader) {
		head, cl, err := readUploadHead(br)
		if err != nil || cl < 0 {
			return
		}
		b := make([]byte, cl)
		first := cl
		if cl > pluginCap {
			first = cl / 2
		}
		if _, err := io.ReadFull(br, b[:first]); err != nil {
			return
		}
		got1 <- struct{}{}
		if _, err := io.ReadFull(br, b[first:]); err != nil {
			return
		}
		reqs <- upReq{head, b}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	_, proxyAddr := startBodyLimitProxy(t, bodyLimitConfigJSON(t, map[string]any{
		"plugin_max_body_size": pluginCap,
		"plugins":              []map[string]any{{"name": "request_stamp", "path": scriptPath}},
	}))

	send := func(n int, gated bool) upReq {
		t.Helper()
		body := bytes.Repeat([]byte("p"), n)
		c := dialUploadProxy(t, proxyAddr)
		fmt.Fprintf(c, "POST http://%s/plugin-upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", upstream, upstream, n)
		if gated {
			_, _ = c.Write(body[:n/2])
			select {
			case <-got1:
			case <-time.After(15 * time.Second):
				t.Fatal("the upstream did not receive the first fragment of a body over plugin_max_body_size before the client sent the rest")
			}
			_, _ = c.Write(body[n/2:])
		} else {
			_, _ = c.Write(body)
		}
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		resp, _ := io.ReadAll(c)
		if !strings.HasPrefix(string(resp), "HTTP/1.1 200 OK") {
			t.Fatalf("client response = %q, want 200", resp)
		}
		select {
		case r := <-reqs:
			if !bytes.Equal(r.body, body) {
				t.Errorf("upstream body = %d bytes, want the whole %d-byte body", len(r.body), n)
			}
			if !gated {
				<-got1
			}
			return r
		case <-time.After(10 * time.Second):
			t.Fatal("upstream saw no request")
			return upReq{}
		}
	}

	if r := send(1024, false); !strings.Contains(r.head, "X-Plugin-Saw: 1024\r\n") {
		t.Errorf("upstream head = %q, want X-Plugin-Saw: 1024 (the hook sees a body within the cap whole)", r.head)
	}
	if r := send(4096, true); strings.Contains(strings.ToLower(r.head), "x-plugin-saw") {
		t.Errorf("upstream head = %q: the hook ran on a body over plugin_max_body_size", r.head)
	}
}

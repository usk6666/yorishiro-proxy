//go:build e2e && !e2e_smoke

package mcptest_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1117: the explicit plain-HTTP forward proxy sends the upstream an
// origin-form request without Proxy-Connection / Proxy-Authorization
// (default on); the recording stays the bytes the client sent;
// forward_as_received: true restores the verbatim relay.

// fwdHeadUpstream is a TCP upstream that records each request head
// (request line through the blank line) byte-for-byte and answers 200.
// Requests carry no body.
type fwdHeadUpstream struct {
	ln    net.Listener
	mu    sync.Mutex
	heads []string
	got   chan struct{}
}

func startFwdHeadUpstream(t *testing.T) *fwdHeadUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &fwdHeadUpstream{ln: ln, got: make(chan struct{}, 16)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(c)
		}
	}()
	return u
}

func (u *fwdHeadUpstream) addr() string { return u.ln.Addr().String() }

func (u *fwdHeadUpstream) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)
	for {
		var head bytes.Buffer
		for {
			line, err := br.ReadBytes('\n')
			head.Write(line)
			if err != nil {
				return
			}
			if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
				break
			}
		}
		u.mu.Lock()
		u.heads = append(u.heads, head.String())
		u.mu.Unlock()
		u.got <- struct{}{}
		if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
			return
		}
	}
}

// waitHead waits for the n-th (1-based) captured head.
func (u *fwdHeadUpstream) waitHead(t *testing.T, n int) string {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		u.mu.Lock()
		if len(u.heads) >= n {
			h := u.heads[n-1]
			u.mu.Unlock()
			return h
		}
		u.mu.Unlock()
		select {
		case <-u.got:
		case <-deadline:
			t.Fatalf("upstream did not receive request %d within 10s", n)
		}
	}
}

// fwdClientRequest is the curl 8.14.1 forward-proxy request shape
// (absolute-form + Proxy-Connection) with a Proxy-Authorization and mixed
// casing / OWS interleaved so order and byte fidelity are observable.
func fwdClientRequest(upAddr, path string) string {
	return "GET http://" + upAddr + path + " HTTP/1.1\r\n" +
		"X-A:  1 \r\n" +
		"host: " + upAddr + "\r\n" +
		"proxy-authorization: Basic dXNlcjpwYXNz\r\n" +
		"User-Agent: curl/8.14.1\r\n" +
		"Accept: */*\r\n" +
		"Proxy-Connection: Keep-Alive\r\n" +
		"Connection: close\r\n" +
		"\r\n"
}

func fwdUpstreamExpect(upAddr, path string) string {
	return "GET " + path + " HTTP/1.1\r\n" +
		"X-A:  1 \r\n" +
		"host: " + upAddr + "\r\n" +
		"User-Agent: curl/8.14.1\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n" +
		"\r\n"
}

// fwdRoundTrip writes req to the proxy over raw TCP and returns the
// response status line.
func fwdRoundTrip(t *testing.T, proxyAddr, req string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	_, _ = io.Copy(io.Discard, br)
	return strings.TrimRight(status, "\r\n")
}

func fwdStartProxy(t *testing.T, h *mcptest.Harness, extra map[string]any) string {
	t.Helper()
	args := map[string]any{"listen_addr": "127.0.0.1:0"}
	for k, v := range extra {
		args[k] = v
	}
	res := h.MustOK(t, "proxy_start", args)
	addr, _ := res.Decoded["listen_addr"].(string)
	if addr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", res.Text)
	}
	return addr
}

// fwdSendRawBytes returns the raw_bytes of every send-direction message
// of flow id (query resource "messages"), in order.
func fwdSendRawBytes(t *testing.T, h *mcptest.Harness, id string) []string {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "messages", "id": id})
	var parsed struct {
		Messages []struct {
			Direction string `json:"direction"`
			RawBytes  string `json:"raw_bytes"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
		t.Fatalf("decode messages: %v (%s)", err, res.Text)
	}
	var out []string
	for _, m := range parsed.Messages {
		if m.Direction != "send" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(m.RawBytes)
		if err != nil {
			t.Fatalf("decode raw_bytes: %v", err)
		}
		out = append(out, string(b))
	}
	return out
}

// TestE2E_ForwardOriginForm_DefaultStripsAndRecordsAsReceived is Test
// Plan T1 + T2 through the JSON-RPC harness: the upstream receives
// origin-form without Proxy-*, the recording is the client bytes, and no
// modified variant is recorded for the proxy-form removal.
func TestE2E_ForwardOriginForm_DefaultStripsAndRecordsAsReceived(t *testing.T) {
	up := startFwdHeadUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxyAddr := fwdStartProxy(t, h, nil)

	const path = "/echo?y2=1"
	req := fwdClientRequest(up.addr(), path)
	if status := fwdRoundTrip(t, proxyAddr, req); !strings.Contains(status, " 200 ") {
		t.Fatalf("status = %q, want 200", status)
	}
	if got, want := up.waitHead(t, 1), fwdUpstreamExpect(up.addr(), path); got != want {
		t.Errorf("upstream head:\n got %q\nwant %q", got, want)
	}

	fl := waitForWirePathFlow(t, h, "/echo", nil, 10*time.Second)
	detail := pollFlowDetail(t, h, fl.ID, "raw_request")
	if got := decodeB64Field(t, detail.Decoded, "raw_request"); got != req {
		t.Errorf("recorded raw_request = %q, want the client bytes %q", got, req)
	}
	if _, ok := detail.Decoded["original_request"]; ok {
		t.Errorf("original_request present: the proxy-form removal recorded a variant")
	}
	sends := fwdSendRawBytes(t, h, fl.ID)
	if len(sends) != 1 || sends[0] != req {
		t.Errorf("send messages raw = %q, want exactly one row with the client bytes", sends)
	}
}

// TestE2E_ForwardOriginForm_ForwardAsReceivedConfig is T3 (config file):
// forward_as_received: true in the config file restores the verbatim relay.
func TestE2E_ForwardOriginForm_ForwardAsReceivedConfig(t *testing.T) {
	up := startFwdHeadUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"forward_as_received": true}`})
	proxyAddr := fwdStartProxy(t, h, nil)

	req := fwdClientRequest(up.addr(), "/cfg")
	if status := fwdRoundTrip(t, proxyAddr, req); !strings.Contains(status, " 200 ") {
		t.Fatalf("status = %q, want 200", status)
	}
	if got := up.waitHead(t, 1); got != req {
		t.Errorf("upstream head = %q, want verbatim %q", got, req)
	}
}

// TestE2E_ForwardOriginForm_ForwardAsReceivedProxyStart is T3 (proxy_start):
// the per-listener parameter restores the verbatim relay, and an explicit
// false overrides a config-file true.
func TestE2E_ForwardOriginForm_ForwardAsReceivedProxyStart(t *testing.T) {
	t.Run("true is verbatim", func(t *testing.T) {
		up := startFwdHeadUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
		proxyAddr := fwdStartProxy(t, h, map[string]any{"forward_as_received": true})
		req := fwdClientRequest(up.addr(), "/ps")
		if status := fwdRoundTrip(t, proxyAddr, req); !strings.Contains(status, " 200 ") {
			t.Fatalf("status = %q, want 200", status)
		}
		if got := up.waitHead(t, 1); got != req {
			t.Errorf("upstream head = %q, want verbatim %q", got, req)
		}
	})
	t.Run("explicit false overrides config true", func(t *testing.T) {
		up := startFwdHeadUpstream(t)
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"forward_as_received": true}`})
		proxyAddr := fwdStartProxy(t, h, map[string]any{"forward_as_received": false})
		req := fwdClientRequest(up.addr(), "/ps2")
		if status := fwdRoundTrip(t, proxyAddr, req); !strings.Contains(status, " 200 ") {
			t.Fatalf("status = %q, want 200", status)
		}
		if got, want := up.waitHead(t, 1), fwdUpstreamExpect(up.addr(), "/ps2"); got != want {
			t.Errorf("upstream head:\n got %q\nwant %q", got, want)
		}
	})
}

// TestE2E_ForwardOriginForm_InterceptModify is T8: an intercept header
// edit on a forward request still goes out origin-form without Proxy-*,
// the modified variant's raw equals what the upstream received, and the
// original variant keeps the client bytes.
func TestE2E_ForwardOriginForm_InterceptModify(t *testing.T) {
	up := startFwdHeadUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	proxyAddr := startProxyWithRules(t, h, []map[string]any{{
		"id":        "match-all",
		"enabled":   true,
		"protocol":  "http",
		"direction": "request",
		"http":      map[string]any{"path_pattern": ".*"},
	}}, nil)

	req := fwdClientRequest(up.addr(), "/held")
	done := make(chan string, 1)
	go func() {
		defer close(done)
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		_, _ = conn.Write([]byte(req))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		done <- line
	}()

	entry := waitForHeldEntry(t, h, 5*time.Second)
	h.MustOK(t, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{"intercept_id": entry["id"]},
		"http": map[string]any{
			"headers": []map[string]any{
				{"name": "X-A", "value": "1"},
				{"name": "host", "value": up.addr()},
				{"name": "proxy-authorization", "value": "Basic dXNlcjpwYXNz"},
				{"name": "X-Modified", "value": "1"},
				{"name": "Connection", "value": "close"},
			},
		},
	})

	got := up.waitHead(t, 1)
	if !strings.HasPrefix(got, "GET /held HTTP/1.1\r\n") {
		t.Errorf("upstream request line: %q, want origin-form", got)
	}
	if strings.Contains(strings.ToLower(got), "proxy-") {
		t.Errorf("upstream head carries a Proxy-* header: %q", got)
	}
	if !strings.Contains(got, "X-Modified: 1\r\n") {
		t.Errorf("upstream head = %q, want X-Modified (the modify did not apply)", got)
	}
	if line := <-done; !strings.Contains(line, " 200 ") {
		t.Errorf("client status = %q, want 200", line)
	}

	fl := waitForWirePathFlow(t, h, "/held", nil, 10*time.Second)
	detail := pollFlowDetail(t, h, fl.ID, "raw_request")
	if raw := decodeB64Field(t, detail.Decoded, "raw_request"); raw != got {
		t.Errorf("modified variant raw = %q, want the bytes the upstream received %q", raw, got)
	}
	sends := fwdSendRawBytes(t, h, fl.ID)
	foundOrig := false
	for _, s := range sends {
		if s == req {
			foundOrig = true
		}
	}
	if len(sends) != 2 || !foundOrig {
		t.Errorf("send messages raw = %q, want the original (client bytes) and the modified variant", sends)
	}
}

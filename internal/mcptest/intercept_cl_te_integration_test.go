//go:build e2e && !e2e_smoke

package mcptest_test

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_Intercept_HTTP1_ContentLengthTransferEncoding_ViaJSONRPC pins the
// Content-Length / Transfer-Encoding framing an HTTP/1.x upstream receives
// after an intercept modify_and_forward (USK-1258). The intercept tool has
// no knob over this framing, so the documented behaviour is the contract:
//
//   - A body change drops Transfer-Encoding and sets Content-Length to the
//     new body length, whether the held request was chunked or
//     Content-Length framed.
//   - A header-only change sends the agent's header list as given, so an
//     agent-supplied Content-Length + Transfer-Encoding: chunked pair reaches
//     the wire together with the held chunked body bytes — the documented
//     way to build a CL.TE pair from intercept.
//
// The client side writes raw request bytes so the held request's framing is
// exactly the one under test; the upstream parses the request by hand.
func TestE2E_Intercept_HTTP1_ContentLengthTransferEncoding_ViaJSONRPC(t *testing.T) {
	const chunkedBody = "4\r\nabcd\r\n0\r\n\r\n"

	tests := []struct {
		name string
		// framing is the original request's framing header line plus the
		// body bytes that follow the header section.
		framing  string
		origBody string
		modify   func(upstreamAddr string) map[string]any
		wantTE   []string
		wantCL   []string
		wantBody string
	}{
		{
			name:     "body_change_on_chunked_request",
			framing:  "Transfer-Encoding: chunked",
			origBody: chunkedBody,
			modify: func(string) map[string]any {
				return map[string]any{"body": "new-body-bytes"}
			},
			wantTE:   nil,
			wantCL:   []string{strconv.Itoa(len("new-body-bytes"))},
			wantBody: "new-body-bytes",
		},
		{
			name:     "body_change_on_content_length_request",
			framing:  "Content-Length: 4",
			origBody: "abcd",
			modify: func(string) map[string]any {
				return map[string]any{"body": "a-longer-replacement"}
			},
			wantTE:   nil,
			wantCL:   []string{strconv.Itoa(len("a-longer-replacement"))},
			wantBody: "a-longer-replacement",
		},
		{
			name:     "header_only_change_keeps_agent_cl_te_pair",
			framing:  "Transfer-Encoding: chunked",
			origBody: chunkedBody,
			modify: func(upstreamAddr string) map[string]any {
				return map[string]any{"headers": []map[string]any{
					{"name": "Host", "value": upstreamAddr},
					{"name": "Content-Length", "value": strconv.Itoa(len(chunkedBody))},
					{"name": "Transfer-Encoding", "value": "chunked"},
					{"name": "Connection", "value": "close"},
				}}
			},
			wantTE: []string{"chunked"},
			wantCL: []string{strconv.Itoa(len(chunkedBody))},
			// The test upstream frames by Content-Length, so it reads the
			// held chunked bytes verbatim as the body.
			wantBody: chunkedBody,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := startRawHTTPUpstream(t)
			h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
			proxyAddr := startProxyWithRules(t, h, []map[string]any{{
				"id":        "match-all",
				"enabled":   true,
				"protocol":  "http",
				"direction": "request",
				"http":      map[string]any{"path_pattern": ".*"},
			}}, nil)

			req := "POST http://" + upstream.addr() + "/cl-te HTTP/1.1\r\n" +
				"Host: " + upstream.addr() + "\r\n" +
				tc.framing + "\r\n" +
				"Connection: close\r\n" +
				"\r\n" + tc.origBody
			statusCh := sendRawProxyRequest(t, proxyAddr, req)

			entry := waitForHeldEntry(t, h, 5*time.Second)
			h.MustOK(t, "intercept", map[string]any{
				"action": "modify_and_forward",
				"params": map[string]any{"intercept_id": entry["id"]},
				"http":   tc.modify(upstream.addr()),
			})

			wire := upstream.waitForRequest(t, 5*time.Second)
			observed := wire.headerLines()
			if got := findAllHeaderValuesFold(observed, "Transfer-Encoding"); !equalStrings(got, tc.wantTE) {
				t.Errorf("upstream Transfer-Encoding = %q, want %q (headers %v)", got, tc.wantTE, observed)
			}
			if got := findAllHeaderValuesFold(observed, "Content-Length"); !equalStrings(got, tc.wantCL) {
				t.Errorf("upstream Content-Length = %q, want %q (headers %v)", got, tc.wantCL, observed)
			}
			if string(wire.body) != tc.wantBody {
				t.Errorf("upstream body = %q, want %q", wire.body, tc.wantBody)
			}

			select {
			case status := <-statusCh:
				if !strings.Contains(status, " 200 ") {
					t.Errorf("client status line = %q, want 200", status)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the proxied response")
			}
		})
	}
}

// sendRawProxyRequest writes req to the proxy over a fresh TCP connection and
// returns a channel that receives the response status line ("" on error).
func sendRawProxyRequest(t *testing.T, proxyAddr, req string) chan string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	out := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(conn).ReadString('\n')
		out <- strings.TrimRight(line, "\r\n")
	}()
	return out
}

// findAllHeaderValuesFold returns every value of the header name, matched
// case-insensitively, in wire order.
func findAllHeaderValuesFold(lines []rawHeaderLine, name string) []string {
	var out []string
	for _, l := range lines {
		if strings.EqualFold(l.name, name) {
			out = append(out, l.value)
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// USK-1148: RFC-001 §9.3 item 2 on the HTTP/1.x opaque send path. A plugin
// that rewrites msg["method"] / msg["path"] / msg["raw_query"] (request) or
// msg["status"] / msg["status_reason"] (response) must change the line the
// peer receives, the unchanged parts of that line and the rest of the head
// must stay byte-identical, and the recorded modified variant must hold
// exactly the bytes that were sent.
//
// The harness helpers (startRawCaptureUpstream, startRawWinsForward,
// startRawWinsMITM, openPlaintextProxyConn, dialForward, readOneResponse,
// waitFlow) live in plugin_raw_wins_http1_integration_test.go.

// lineReqTail is the header section the client sends after its request
// line: lowercase host and an odd OWS a normalizing serializer would lose.
const lineReqTail = "host: example.test\r\nX-Odd:  v\r\n\r\n"

// TestPluginRequestLine_HTTP1_Rewrite covers Test Plan #1 and #4: a
// plugin rewrite of path (both phases), method, or raw_query reaches the
// upstream's request line, nothing else in the head changes, and the
// modified send variant records exactly those bytes.
func TestPluginRequestLine_HTTP1_Rewrite(t *testing.T) {
	cases := []struct {
		name       string
		script     string
		wantLine   string
		wantMethod string
		wantPath   string
		wantQuery  string
	}{
		{
			name: "path pre_pipeline",
			script: `
def on_req(msg, ctx):
    msg["path"] = "/rewritten"
register_hook("http", "on_request", on_req)
`,
			wantLine: "GET /rewritten?a=1 HTTP/1.1", wantMethod: "GET", wantPath: "/rewritten", wantQuery: "a=1",
		},
		{
			name: "path post_pipeline",
			script: `
def on_req(msg, ctx):
    msg["path"] = "/rewritten"
register_hook("http", "on_request", on_req, phase="post_pipeline")
`,
			wantLine: "GET /rewritten?a=1 HTTP/1.1", wantMethod: "GET", wantPath: "/rewritten", wantQuery: "a=1",
		},
		{
			name: "method",
			script: `
def on_req(msg, ctx):
    msg["method"] = "PUT"
register_hook("http", "on_request", on_req)
`,
			wantLine: "PUT /orig?a=1 HTTP/1.1", wantMethod: "PUT", wantPath: "/orig", wantQuery: "a=1",
		},
		{
			name: "raw_query only",
			script: `
def on_req(msg, ctx):
    msg["raw_query"] = "b=2"
register_hook("http", "on_request", on_req)
`,
			wantLine: "GET /orig?b=2 HTTP/1.1", wantMethod: "GET", wantPath: "/orig", wantQuery: "b=2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startRawCaptureUpstream(t, true, nil)
			h, fwd := startRawWinsForward(t, ctx, tc.script, up.Addr(), "http", nil)

			const clientReq = "GET /orig?a=1 HTTP/1.1\r\n" + lineReqTail
			want := tc.wantLine + "\r\n" + lineReqTail

			c, br := dialForward(t, fwd)
			if _, err := c.Write([]byte(clientReq)); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, body, err := readOneResponse(br)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}

			if got := up.waitBytes(1, len(want)); string(got) != want {
				t.Errorf("upstream received %q, want %q", got, want)
			}
			wantTarget := strings.Fields(tc.wantLine)[1]
			if body != "path="+wantTarget+" conn=1" {
				t.Errorf("client response body = %q, want the response to target %q", body, wantTarget)
			}

			orig := waitFlow(h.store, "send", "original", nil)
			if orig == nil || string(orig.RawBytes) != clientReq {
				t.Errorf("original send variant missing or not the client bytes; flows:%s", describeFlows(h.store))
			}
			mod := waitFlow(h.store, "send", "modified", nil)
			if mod == nil {
				t.Fatalf("no modified send variant recorded; flows:%s", describeFlows(h.store))
			}
			if string(mod.RawBytes) != want {
				t.Errorf("modified send variant RawBytes = %q, want the wire bytes %q", mod.RawBytes, want)
			}
			if mod.Method != tc.wantMethod {
				t.Errorf("modified variant Method = %q, want %q", mod.Method, tc.wantMethod)
			}
			if mod.URL == nil || mod.URL.EscapedPath() != tc.wantPath || mod.URL.RawQuery != tc.wantQuery {
				t.Errorf("modified variant URL = %v, want path %q query %q", mod.URL, tc.wantPath, tc.wantQuery)
			}
		})
	}
}

// TestPluginRequestLine_HTTP1_AbsoluteForm covers Test Plan #2: on the
// plaintext forward-proxy path the request-target is absolute-form; a
// path rewrite keeps the wire "http://host:port" prefix and a method-only
// rewrite keeps the request-target byte-for-byte.
func TestPluginRequestLine_HTTP1_AbsoluteForm(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		wantLine func(prefix string) string
	}{
		{
			name: "path only",
			script: `
def on_req(msg, ctx):
    msg["path"] = "/rewritten"
register_hook("http", "on_request", on_req)
`,
			wantLine: func(prefix string) string { return "GET " + prefix + "/rewritten?a=1 HTTP/1.1\r\n" },
		},
		{
			name: "method only",
			script: `
def on_req(msg, ctx):
    msg["method"] = "PUT"
register_hook("http", "on_request", on_req)
`,
			wantLine: func(prefix string) string { return "PUT " + prefix + "/orig?a=1 HTTP/1.1\r\n" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startRawCaptureUpstream(t, true, nil)
			_, proxyAddr := startRawWinsMITM(t, ctx, tc.script)
			c, br, prefix := openPlaintextProxyConn(t, "forward", proxyAddr, up.Addr())

			if _, err := c.Write([]byte("GET " + prefix + "/orig?a=1 HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, _, err := readOneResponse(br); err != nil {
				t.Fatalf("read response: %v", err)
			}
			want := tc.wantLine(prefix)
			if got := string(up.waitBytes(1, len(want))); !strings.HasPrefix(got, want) {
				t.Errorf("upstream received %q, want request line %q", got, want)
			}
		})
	}
}

// TestPluginRequestLine_HTTP1_Response covers Test Plan #3 and #4: a
// plugin rewrite of status / status_reason reaches the client's status
// line, the rest of the response is untouched, and the modified receive
// variant records exactly those bytes.
func TestPluginRequestLine_HTTP1_Response(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantLine string
	}{
		{
			name:     "status and reason",
			body:     "    msg[\"status\"] = 404\n    msg[\"status_reason\"] = \"Gone Fishing\"\n",
			wantLine: "HTTP/1.1 404 Gone Fishing",
		},
		{
			name:     "status only keeps the wire reason",
			body:     "    msg[\"status\"] = 404\n",
			wantLine: "HTTP/1.1 404 OK",
		},
		{
			name:     "reason only",
			body:     "    msg[\"status_reason\"] = \"Fine\"\n",
			wantLine: "HTTP/1.1 200 Fine",
		},
		{
			name:     "empty reason",
			body:     "    msg[\"status_reason\"] = \"\"\n",
			wantLine: "HTTP/1.1 200",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			script := "def on_resp(msg, ctx):\n" + tc.body + "register_hook(\"http\", \"on_response\", on_resp)\n"
			up := startRawCaptureUpstream(t, true, nil)
			h, fwd := startRawWinsForward(t, ctx, script, up.Addr(), "http", nil)

			c, br := dialForward(t, fwd)
			if _, err := c.Write([]byte("GET /orig HTTP/1.1\r\n" + lineReqTail)); err != nil {
				t.Fatalf("write: %v", err)
			}
			raw, _, err := readOneResponse(br)
			if err != nil {
				t.Fatalf("read response: %v (got %q)", err, raw)
			}
			const respBody = "path=/orig conn=1"
			want := tc.wantLine + "\r\nContent-Length: 17\r\n\r\n" + respBody
			if string(raw) != want {
				t.Errorf("client received %q, want %q", raw, want)
			}
			mod := waitFlow(h.store, "receive", "modified", nil)
			if mod == nil {
				t.Fatalf("no modified receive variant recorded; flows:%s", describeFlows(h.store))
			}
			if string(mod.RawBytes) != want {
				t.Errorf("modified receive variant RawBytes = %q, want the wire bytes %q", mod.RawBytes, want)
			}
		})
	}
}

// TestPluginRequestLine_HTTP1_ReverseGuard covers Test Plan #6: plugins
// that leave the line fields at their wire values (no write, header-only
// write, same-value reassignment) keep the request line byte-identical,
// including a bare trailing "?" a rebuilt target would drop; a
// method-only rewrite also keeps that target verbatim.
func TestPluginRequestLine_HTTP1_ReverseGuard(t *testing.T) {
	const tail = "host: example.test\r\nX-Odd:  v\r\n\r\n"
	cases := []struct {
		name   string
		script string
		want   string
	}{
		{
			name: "no write",
			script: `
def on_req(msg, ctx):
    _ = msg["path"]
register_hook("http", "on_request", on_req)
`,
			want: "GET /p? HTTP/1.1\r\n" + tail,
		},
		{
			name: "same-value reassignment",
			script: `
def on_req(msg, ctx):
    msg["path"] = msg["path"]
    msg["raw_query"] = msg["raw_query"]
    msg["method"] = msg["method"]
register_hook("http", "on_request", on_req)
`,
			want: "GET /p? HTTP/1.1\r\n" + tail,
		},
		{
			name: "header-only write",
			script: `
def on_req(msg, ctx):
    msg["headers"].append("X-Added", "1")
register_hook("http", "on_request", on_req)
`,
			want: "GET /p? HTTP/1.1\r\nhost: example.test\r\nX-Odd:  v\r\nX-Added: 1\r\n\r\n",
		},
		{
			name: "method-only keeps bare query mark",
			script: `
def on_req(msg, ctx):
    msg["method"] = "PUT"
register_hook("http", "on_request", on_req)
`,
			want: "PUT /p? HTTP/1.1\r\n" + tail,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startRawCaptureUpstream(t, true, nil)
			_, fwd := startRawWinsForward(t, ctx, tc.script, up.Addr(), "http", nil)

			c, br := dialForward(t, fwd)
			if _, err := c.Write([]byte("GET /p? HTTP/1.1\r\n" + tail)); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, _, err := readOneResponse(br); err != nil {
				t.Fatalf("read response: %v", err)
			}
			if got := up.waitBytes(1, len(tc.want)); string(got) != tc.want {
				t.Errorf("upstream received %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPluginRequestLine_HTTP1_NoValidation covers Test Plan #7 (user
// decision 2026-10-20): plugin-written line fields are not validated. A
// path carrying CR / LF / SP reaches the upstream verbatim — here it
// splits the request in two — and a wire-observed target with an HTAB
// passes through unchanged under a header-only plugin.
func TestPluginRequestLine_HTTP1_NoValidation(t *testing.T) {
	t.Run("plugin path with CRLF splits the request", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		up := startRawCaptureUpstream(t, true, nil)
		_, fwd := startRawWinsForward(t, ctx, `
def on_req(msg, ctx):
    msg["path"] = "/a HTTP/1.1\r\nHost: x\r\n\r\nGET /smuggled"
register_hook("http", "on_request", on_req)
`, up.Addr(), "http", nil)

		c, br := dialForward(t, fwd)
		if _, err := c.Write([]byte("GET /orig HTTP/1.1\r\n" + lineReqTail)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, err := readOneResponse(br); err != nil {
			t.Fatalf("read response: %v", err)
		}
		want := "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /smuggled HTTP/1.1\r\n" + lineReqTail
		if got := up.waitBytes(1, len(want)); string(got) != want {
			t.Errorf("upstream received %q, want the plugin path verbatim %q", got, want)
		}
	})

	t.Run("wire HTAB target passes through", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		up := startRawCaptureUpstream(t, true, nil)
		_, fwd := startRawWinsForward(t, ctx, `
def on_req(msg, ctx):
    msg["headers"].append("X-Added", "1")
register_hook("http", "on_request", on_req)
`, up.Addr(), "http", nil)

		c, br := dialForward(t, fwd)
		if _, err := c.Write([]byte("GET /a\tb HTTP/1.1\r\n" + lineReqTail)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, err := readOneResponse(br); err != nil {
			t.Fatalf("read response: %v", err)
		}
		want := "GET /a\tb HTTP/1.1\r\nhost: example.test\r\nX-Odd:  v\r\nX-Added: 1\r\n\r\n"
		if got := up.waitBytes(1, len(want)); string(got) != want {
			t.Errorf("upstream received %q, want %q", got, want)
		}
	})
}

// TestPluginRequestLine_HTTP1_LineOnlyKeepsFoldedHeaders (USK-1148
// review F-1/F-2): a path-only rewrite of a request whose head carries
// header forms the parser folds or reinterprets (obs-fold continuation,
// colon-less line) must deliver the header section to the upstream
// byte-for-byte, and the modified send variant must record those bytes.
func TestPluginRequestLine_HTTP1_LineOnlyKeepsFoldedHeaders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startRawCaptureUpstream(t, true, nil)
	h, fwd := startRawWinsForward(t, ctx, `
def on_req(msg, ctx):
    msg["path"] = "/rewritten"
register_hook("http", "on_request", on_req)
`, up.Addr(), "http", nil)

	const tail = "host: example.test\r\nX-F:  a\r\n b\r\nNoColonHere\r\n\r\n"
	c, br := dialForward(t, fwd)
	if _, err := c.Write([]byte("GET /orig HTTP/1.1\r\n" + tail)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := readOneResponse(br); err != nil {
		t.Fatalf("read response: %v", err)
	}
	want := "GET /rewritten HTTP/1.1\r\n" + tail
	if got := up.waitBytes(1, len(want)); string(got) != want {
		t.Errorf("upstream received %q, want %q", got, want)
	}
	mod := waitFlow(h.store, "send", "modified", nil)
	if mod == nil {
		t.Fatalf("no modified send variant recorded; flows:%s", describeFlows(h.store))
	}
	if string(mod.RawBytes) != want {
		t.Errorf("modified send variant RawBytes = %q, want the wire bytes %q", mod.RawBytes, want)
	}
}

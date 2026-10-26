//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// USK-1388: a plugin RESPOND whose shape does not match the hook's protocol
// family is refused (Warn + CONTINUE). On the HTTP/1.x path that is
// action.RESPOND_GRPC from an http hook: its GRPCEndMessage cannot be
// rendered by the HTTP/1 Channel, so before the fix the session ended with
// "http1: Send requires *HTTPMessage" and the client got nothing. The
// harness helpers live in plugin_raw_wins_http1_integration_test.go.
func TestPluginRespondShape_HTTP1_RespondGRPCRefused(t *testing.T) {
	cases := []struct {
		name  string
		event string
	}{
		{name: "on_request", event: "on_request"},
		{name: "on_response", event: "on_response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			script := `
def deny(msg, ctx):
    return action.RESPOND_GRPC(status=7, message="denied by plugin")
register_hook("http", "` + tc.event + `", deny)
`
			up := startRawCaptureUpstream(t, true, nil)
			h, fwd := startRawWinsForward(t, ctx, script, up.Addr(), "http", nil)

			const clientReq = "GET /shape HTTP/1.1\r\nHost: example.test\r\n\r\n"
			c, br := dialForward(t, fwd)
			if _, err := c.Write([]byte(clientReq)); err != nil {
				t.Fatalf("write: %v", err)
			}
			raw, body, err := readOneResponse(br)
			if err != nil {
				t.Fatalf("read response: %v (got %q; want the upstream response, a refused RESPOND must not end the session)", err, raw)
			}
			if !strings.HasPrefix(string(raw), "HTTP/1.1 200 OK\r\n") {
				t.Errorf("status line = %q, want HTTP/1.1 200 OK from the upstream", strings.SplitN(string(raw), "\r\n", 2)[0])
			}
			if body != "path=/shape conn=1" {
				t.Errorf("body = %q, want the upstream's %q", body, "path=/shape conn=1")
			}
			if got := up.waitBytes(1, len(clientReq)); string(got) != clientReq {
				t.Errorf("upstream received %q, want the client request %q", got, clientReq)
			}
			// Stop the listeners so the session completes and its flows
			// are flushed to the store.
			_ = c.Close()
			_ = h.mgr.StopAll(context.Background())
			if f := waitFlow(h.store, "receive", "", func(b []byte) bool {
				return strings.HasPrefix(string(b), "HTTP/1.1 200")
			}); f == nil {
				t.Errorf("no receive flow with the upstream response recorded; flows:%s", describeFlows(h.store))
			}
		})
	}
}

// USK-1388: the HTTP/2 mirror of the case above. An http hook's
// action.RESPOND_GRPC over h2 reaches httpaggregator, whose Send also
// requires *HTTPMessage; the refused RESPOND must leave the original
// exchange intact. Only on_request discriminates the fix: on this path
// upstreamToClient does not deliver a Receive-direction Respond envelope
// (it forwards the original response), so on_response guards the
// end-to-end behavior without reaching the aggregator's Send. The h2c
// harness helpers live in plugin_raw_wins_h2_integration_test.go.
func TestPluginRespondShape_H2_RespondGRPCRefused(t *testing.T) {
	for _, event := range []string{"on_request", "on_response"} {
		t.Run(event, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			upAddr, seen := startCapturingH2CUpstream(t)
			h, fwd := startRawWinsForwardDeps(t, ctx, `
def deny(msg, ctx):
    return action.RESPOND_GRPC(status=7, message="denied by plugin")
register_hook("http", "`+event+`", deny)
`, upAddr, "http2", nil)

			status, body := doH2C(t, ctx, fwd, "GET", "/shape", nil)
			if status != 200 || body != "upstream:/shape" {
				t.Errorf("client got %d %q, want 200 upstream:/shape from the upstream", status, body)
			}
			path, hdr, _ := seen.snapshot()
			if path != "/shape" || hdr.Get("X-Marker") != "orig" {
				t.Errorf("upstream saw path=%q x-marker=%q, want the client request", path, hdr.Get("X-Marker"))
			}
			waitAnyFlow(t, h.store, "receive")
			if f := waitFlow(h.store, "receive", "", func(b []byte) bool {
				return bytes.Contains(b, []byte("upstream:/shape"))
			}); f == nil {
				t.Errorf("no receive flow with the upstream response recorded; flows:%s", describeFlows(h.store))
			}
		})
	}
}

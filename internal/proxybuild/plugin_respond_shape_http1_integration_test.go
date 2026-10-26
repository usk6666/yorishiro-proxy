//go:build e2e && !e2e_smoke

package proxybuild_test

import (
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

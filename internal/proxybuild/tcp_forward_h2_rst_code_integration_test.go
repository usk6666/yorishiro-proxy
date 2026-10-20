//go:build e2e && !e2e_smoke

// USK-1269 exhaustive tier on the tcp_forward path: the RST_STREAM error
// code an h2c upstream resets a stream with reaches a tcp_forward h2 client
// verbatim — not rewritten to CANCEL — for plain h2, native gRPC
// (protocol=grpc) and gRPC-Web over h2 (protocol=http2, grpc-web
// content-type). The CONNECT-path counterpart is
// h2_upstream_rst_code_integration_test.go; the origin, raw client and
// forward harness are shared with h2_upstream_refused_integration_test.go
// and h2_upstream_goaway_redial_integration_test.go.
package proxybuild_test

import (
	"context"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// sendGRPCWebUnary writes a binary gRPC-Web unary request (HEADERS + one
// empty LPM DATA frame with END_STREAM) on stream id.
func sendGRPCWebUnary(t *testing.T, c *rawH2Client, authority string, id uint32) {
	t.Helper()
	c.buf.Reset()
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: c.schemeOrHTTPS()},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: "/test.Svc/Call"},
		{Name: "content-type", Value: "application/grpc-web+proto"},
		{Name: "x-grpc-web", Value: "1"},
	} {
		if err := c.enc.WriteField(f); err != nil {
			t.Fatalf("hpack: %v", err)
		}
	}
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: c.buf.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("write HEADERS on stream %d: %v", id, err)
	}
	if err := c.fr.WriteData(id, true, []byte{0, 0, 0, 0, 0}); err != nil {
		t.Fatalf("write DATA on stream %d: %v", id, err)
	}
}

// TestTCPForwardH2_UpstreamRST_ClientSeesUpstreamCode: a tcp_forward h2c
// client sends one request; the h2c origin resets it with
// RST_STREAM(INTERNAL_ERROR). The client must see INTERNAL_ERROR (as it
// would against the origin directly), not CANCEL, and the Stream is
// recorded as an error with the wire-observed protocol family.
func TestTCPForwardH2_UpstreamRST_ClientSeesUpstreamCode(t *testing.T) {
	cases := []struct {
		name        string
		fwdProtocol string
		// wantProtocol is the recorded Stream protocol; empty skips the
		// check. A gRPC-Web stream reset before any response is recorded
		// as "http" on the CONNECT path too, so its classification is not
		// what this test is about.
		wantProtocol string
		send         func(t *testing.T, c *rawH2Client, authority string, id uint32)
	}{
		{
			name: "http2", fwdProtocol: "http2", wantProtocol: "http",
			send: func(t *testing.T, c *rawH2Client, authority string, id uint32) { c.sendGETs(t, authority, id) },
		},
		// protocol=grpc runs the content-type filter, whose replay wrapper
		// sits between the gRPC Channel and the HTTP/2 stream.
		{name: "grpc", fwdProtocol: "grpc", wantProtocol: "grpc", send: sendGRPCUnary},
		{name: "grpc-web", fwdProtocol: "http2", send: sendGRPCWebUnary},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			origin := startRefusingH2OriginOpts(t, refusingOriginOpts{
				mode: originRSTLast, batch: 1, plaintext: true, rstCode: http2.ErrCodeInternal,
			})
			_, fwdAddr, store := startH2ForwardForRedialTest(t, ctx, config.ForwardConfig{
				Target: origin.addr, Protocol: tc.fwdProtocol,
			})
			cli := dialRawH2Direct(t, fwdAddr, nil)
			tc.send(t, cli, origin.addr, 1)
			r := cli.collect(t, 10*time.Second, 1)[1]

			if !r.rst || r.rstCode != http2.ErrCodeInternal || len(r.statuses) != 0 {
				t.Errorf("stream 1: statuses=%v ended=%v rst=%v code=%v; want RST_STREAM(INTERNAL_ERROR)",
					r.statuses, r.ended, r.rst, r.rstCode)
			}
			waitStreamOutcomes(t, store, map[string]int{"error/internal_error": 1}, 5*time.Second)
			for _, st := range store.Streams() {
				if tc.wantProtocol != "" && st.Protocol != tc.wantProtocol {
					t.Errorf("stream %s protocol = %q, want %q", st.ID, st.Protocol, tc.wantProtocol)
				}
			}
		})
	}
}

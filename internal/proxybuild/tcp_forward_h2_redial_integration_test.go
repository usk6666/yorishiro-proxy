//go:build e2e && !e2e_smoke

// USK-1165 / USK-1178 exhaustive tier: tcp_forward HTTP/2 upstream GOAWAY
// redial across the (tls, upstream_tls) matrix, the protocol=grpc arm, the
// forward pre-warm, and teardown of redialed Layers. The h2c cell and the
// CONNECT pre-warm live in the smoke tier
// (h2_upstream_goaway_redial_integration_test.go), whose helpers these tests
// reuse.
package proxybuild_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

func boolPtr(b bool) *bool { return &b }

// TestTCPForwardH2_UpstreamGoAway_RedialMatrix is AC1 for the remaining
// (tls, upstream_tls) cells. For upstream_tls=true every completed Stream —
// including the one served by the redialed connection — records the
// upstream TLS snapshot (ALPN h2) of the connection that served it.
func TestTCPForwardH2_UpstreamGoAway_RedialMatrix(t *testing.T) {
	cases := []struct {
		name        string
		clientTLS   bool
		upstreamTLS bool
	}{
		{"tls=false/upstream_tls=true", false, true},
		{"tls=true/upstream_tls=false", true, false},
		{"tls=true/upstream_tls=true", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			origin := startRefusingH2OriginOpts(t, refusingOriginOpts{
				mode: originGoAwayAfterFirst, batch: 1, plaintext: !tc.upstreamTLS,
			})
			fc := config.ForwardConfig{
				Target:      origin.addr,
				Protocol:    "http2",
				TLS:         tc.clientTLS,
				UpstreamTLS: tc.upstreamTLS,
			}
			if tc.clientTLS {
				// tls=true + auto routes by the client's ALPN (h2 here).
				fc.Protocol = "auto"
			}
			if tc.upstreamTLS {
				fc.UpstreamInsecureSkipVerify = boolPtr(true)
			}
			mgr, fwdAddr, store := startH2ForwardForRedialTest(t, ctx, fc)

			var clientTLS *tls.Config
			if tc.clientTLS {
				clientTLS = &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // test
					NextProtos:         []string{"h2"},
				}
			}
			cli := dialRawH2Direct(t, fwdAddr, clientTLS)
			runForwardGoAwayRedial(t, cli, origin, mgr, store, func(id uint32) {
				cli.sendGETs(t, origin.addr, id)
			})

			if !tc.upstreamTLS {
				return
			}
			for _, st := range store.Streams() {
				alpn := ""
				for _, u := range store.updatesFor(st.ID) {
					if u.TLSALPN != "" {
						alpn = u.TLSALPN
					}
				}
				if alpn != "h2" {
					t.Errorf("stream %s (%s): recorded upstream TLS ALPN = %q, want h2", st.ID, st.State, alpn)
				}
			}
		})
	}
}

// sendGRPCUnary writes a unary gRPC request (HEADERS + one empty LPM DATA
// frame with END_STREAM) on stream id.
func sendGRPCUnary(t *testing.T, c *rawH2Client, authority string, id uint32) {
	t.Helper()
	c.buf.Reset()
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: c.schemeOrHTTPS()},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: "/test.Svc/Call"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
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

// TestTCPForwardGRPC_UpstreamGoAway_NextCallRedials: protocol=grpc forward —
// a gRPC call made after upstream GOAWAY succeeds on a redialed connection
// and is recorded as a complete grpc Stream.
func TestTCPForwardGRPC_UpstreamGoAway_NextCallRedials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2OriginOpts(t, refusingOriginOpts{
		mode: originGoAwayAfterFirst, batch: 1, plaintext: true, grpc: true,
	})
	mgr, fwdAddr, store := startH2ForwardForRedialTest(t, ctx, config.ForwardConfig{
		Target: origin.addr, Protocol: "grpc",
	})
	cli := dialRawH2Direct(t, fwdAddr, nil)
	runForwardGoAwayRedial(t, cli, origin, mgr, store, func(id uint32) {
		sendGRPCUnary(t, cli, origin.addr, id)
	})
	for _, st := range store.Streams() {
		if st.Protocol != "grpc" {
			t.Errorf("stream %s protocol = %q, want grpc", st.ID, st.Protocol)
		}
	}
}

// TestTCPForwardH2_UpstreamGoAway_PrewarmWithoutRequest is USK-1178 on the
// forward path: right after the forward connection's upstream receives
// GOAWAY, the pre-warm worker opens the next upstream connection without
// waiting for another request.
func TestTCPForwardH2_UpstreamGoAway_PrewarmWithoutRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2OriginOpts(t, refusingOriginOpts{
		mode: originGoAwayAfterFirst, batch: 1, plaintext: true,
	})
	mgr, fwdAddr, _ := startH2ForwardForRedialTest(t, ctx, config.ForwardConfig{
		Target: origin.addr, Protocol: "http2",
	})
	cli := dialRawH2Direct(t, fwdAddr, nil)
	cli.sendGETs(t, origin.addr, 1)
	requireOK(t, 1, cli.collect(t, 10*time.Second, 1)[1])

	if n := waitAccepts(origin, 2, 2*time.Second); n != 2 {
		t.Fatalf("origin accepted %d connections after GOAWAY, want 2 via pre-warm (metrics %+v)",
			n, mgr.H2UpstreamMetrics())
	}
	m := mgr.H2UpstreamMetrics()
	if m.RedialPrewarm < 1 || m.RedialFailedPrewarm != 0 {
		t.Errorf("RedialPrewarm = %d, RedialFailedPrewarm = %d; want >= 1 and 0", m.RedialPrewarm, m.RedialFailedPrewarm)
	}
}

// TestTCPForwardH2_UpstreamGoAway_StopReleasesRedialedLayers: stopping the
// forward listener after a redial leaves no goroutine behind — the redialed
// upstream Layers (owned by the forward connection, not by the stack) are
// closed together with the pre-warm worker.
func TestTCPForwardH2_UpstreamGoAway_StopReleasesRedialedLayers(t *testing.T) {
	ignore := goleak.IgnoreCurrent()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2OriginOpts(t, refusingOriginOpts{
		mode: originGoAwayAfterFirst, batch: 1, plaintext: true,
	})
	mgr, fwdAddr, store := startH2ForwardForRedialTest(t, ctx, config.ForwardConfig{
		Target: origin.addr, Protocol: "http2",
	})
	cli := dialRawH2Direct(t, fwdAddr, nil)
	runForwardGoAwayRedial(t, cli, origin, mgr, store, func(id uint32) {
		cli.sendGETs(t, origin.addr, id)
	})

	// Keep the client and the origin's second connection open: only the
	// proxy's own teardown may release the redialed Layer.
	if err := mgr.StopAll(context.Background()); err != nil {
		t.Fatalf("StopAll: %v", err)
	}
	cancel()
	_ = cli.conn.Close()
	goleak.VerifyNone(t, ignore,
		// The origin's per-connection serve goroutines exit at t.Cleanup.
		goleak.IgnoreAnyFunction("github.com/usk6666/yorishiro-proxy/internal/proxybuild_test.(*refusingH2Origin).acceptLoop.func1"),
		goleak.IgnoreTopFunction("github.com/usk6666/yorishiro-proxy/internal/proxybuild_test.(*refusingH2Origin).acceptLoop"),
	)
}

//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TestProxybuild_PlainForward_HeadOverRawCaptureCap_ByteIdentical
// (USK-1320, T10): through the production live stack (plain forward,
// absolute-form), a request and a response whose header sections exceed
// max_raw_capture_size reach the other side byte-identical. The cap is a
// recording policy only. The within-cap subtest is the control proving the
// fixture is forwarded verbatim at all.
func TestProxybuild_PlainForward_HeadOverRawCaptureCap_ByteIdentical(t *testing.T) {
	for _, tc := range []struct {
		name   string
		capN   int64
		capped bool
	}{
		{name: "within cap (control)", capN: 0},
		{name: "cap 64", capN: 64, capped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			respWire := "HTTP/1.1 200 OK\r\nX-Long: " + strings.Repeat("z", 300) +
				"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

			upLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen upstream: %v", err)
			}
			defer upLn.Close()
			upAddr := upLn.Addr().String()
			reqWire := fmt.Sprintf("POST http://%s/p HTTP/1.1\r\nHost: %s\r\nX-Long: %s\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
				upAddr, upAddr, strings.Repeat("a", 300))

			gotReq := make(chan []byte, 1)
			go func() {
				c, err := upLn.Accept()
				if err != nil {
					gotReq <- nil
					return
				}
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, len(reqWire))
				n, _ := io.ReadFull(c, buf)
				gotReq <- buf[:n]
				_, _ = c.Write([]byte(respWire))
			}()

			fix := startUSK1189Proxy(t, ctx, nil, func(bc *connector.BuildConfig) { bc.MaxRawCaptureSize = tc.capN }, 0)
			conn, err := net.DialTimeout("tcp", fix.proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte(reqWire)); err != nil {
				t.Fatalf("write request: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			resp := make([]byte, len(respWire))
			n, _ := io.ReadFull(conn, resp)
			resp = resp[:n]

			var up []byte
			select {
			case up = <-gotReq:
			case <-time.After(10 * time.Second):
				t.Fatal("upstream never accepted")
			}
			if string(up) != reqWire {
				t.Errorf("upstream request differs:\ngot  %q\nwant %q", up, reqWire)
			}
			if string(resp) != respWire {
				t.Errorf("client response differs:\ngot  %q\nwant %q", resp, respWire)
			}
		})
	}
}

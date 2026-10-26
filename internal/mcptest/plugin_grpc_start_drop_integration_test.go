//go:build e2e && !e2e_smoke

// USK-1387: a plugin DROP on grpc.on_start / grpc-web.on_start ends the RPC
// at Start time with no gRPC status — RST_STREAM(CANCEL) on HTTP/2, a closed
// connection on HTTP/1.x. The upstream is never dialed, so no request byte
// reaches it, the session ends cleanly (no state=error Stream) and the
// following Data envelope is never recorded against a Stream that does not
// exist. Driven through the production wiring (mcpserver.Run + proxybuild),
// so both PluginStepPre and PluginStepPost are installed and the plugin is
// loaded from the config file.
package mcptest_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// pluginGRPCStartDropScript returns a plugin that DROPs every grpc and
// grpc-web Start in the given phase.
func pluginGRPCStartDropScript(phase string) string {
	return fmt.Sprintf(`
def drop(msg, ctx):
    return action.DROP

register_hook("grpc", "on_start", drop, phase=%q)
register_hook("grpc-web", "on_start", drop, phase=%q)
`, phase, phase)
}

// startGRPCStartDropHarness boots the production server with the drop
// plugin loaded from config (phase pre_pipeline / post_pipeline) and the
// server log redirected to a file, starts the proxy and returns the
// harness, the proxy address and the log path.
func startGRPCStartDropHarness(t *testing.T, upstreamProto, phase string) (*mcptest.Harness, string, string) {
	t.Helper()
	script := writePluginScript(t, "grpc_start_drop.star", pluginGRPCStartDropScript(phase))
	logPath := filepath.Join(t.TempDir(), "server.log")
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    pluginsConfigJSON(t, script),
		UpstreamProto: upstreamProto,
		ExtraArgs:     []string{"-log-file", logPath},
	})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	return h, proxyAddr, logPath
}

// assertNoErrorStreams fails for every recorded Stream in state=error: a
// plugin DROP is the proxy ending the RPC on purpose, not a failure.
func assertNoErrorStreams(t *testing.T, h *mcptest.Harness) {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "flows", "limit": 200})
	flows, _ := res.Decoded["flows"].([]any)
	for _, raw := range flows {
		f, _ := raw.(map[string]any)
		if st, _ := f["state"].(string); strings.EqualFold(st, "error") {
			t.Errorf("Stream %v protocol=%v state=error, want no error Stream for a dropped RPC", f["id"], f["protocol"])
		}
	}
}

// assertNoServerErrorLog fails when the server logged at ERROR level — in
// particular RecordStep's "flow save failed" for a Data envelope of a
// Stream that was never created.
func assertNoServerErrorLog(t *testing.T, logPath string) {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read server log: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "level=ERROR") || strings.Contains(line, "flow save failed") {
			t.Errorf("server logged an error: %s", line)
		}
	}
}

// settle gives the session time to finish recording before the store and
// log are inspected (the client observes the reset before OnComplete runs).
func settle() { time.Sleep(300 * time.Millisecond) }

var grpcStartDropPhases = []string{"pre_pipeline", "post_pipeline"}

// T4: gRPC-Web over CONNECT + h2 — the client stream is reset with CANCEL,
// the upstream receives no request and no Stream ends in error.
func TestE2E_PluginDropGRPCWebStart_H2_ResetsStream(t *testing.T) {
	for _, phase := range grpcStartDropPhases {
		t.Run(phase, func(t *testing.T) {
			h, proxyAddr, logPath := startGRPCStartDropHarness(t, "grpc-web", phase)
			up := grpcUpstreamHostPort(t, h.UpstreamTLS.URL)

			resp, err := sendGRPCWebH2(proxyAddr, up, "", mcptest.GRPCWebSafetyEchoMethod, "application/grpc-web+proto",
				grpcweb.EncodeFrame(false, false, []byte("hi")))
			if err == nil {
				t.Fatalf("dropped gRPC-Web call answered %d (body %q); want the stream reset", resp.status, resp.body)
			}
			if !strings.Contains(err.Error(), "CANCEL") {
				t.Errorf("dropped gRPC-Web call err = %v; want an RST_STREAM(CANCEL) stream error", err)
			}
			settle()
			if got := h.GRPCWebObservedHits.Requests(); got != 0 {
				t.Errorf("upstream requests = %d, want 0", got)
			}
			assertNoErrorStreams(t, h)
			assertNoServerErrorLog(t, logPath)
		})
	}
}

// T5: gRPC-Web over plain-forward HTTP/1.x — the client connection closes
// without a response byte, the upstream receives no byte, and the
// following Data envelope is not recorded against a missing Stream.
func TestE2E_PluginDropGRPCWebStart_H1_ClosesConnection(t *testing.T) {
	for _, phase := range grpcStartDropPhases {
		t.Run(phase, func(t *testing.T) {
			upstreamAddr, received, lastHead := byteCountingHTTPUpstream(t)
			script := writePluginScript(t, "grpc_start_drop.star", pluginGRPCStartDropScript(phase))
			logPath := filepath.Join(t.TempDir(), "server.log")
			h := mcptest.StartHarness(t, mcptest.HarnessOptions{
				ConfigJSON: pluginsConfigJSON(t, script),
				ExtraArgs:  []string{"-log-file", logPath},
			})
			startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
			proxyAddr, _ := startRes.Decoded["listen_addr"].(string)

			body := string(grpcweb.EncodeFrame(false, false, []byte("hi")))
			req := fmt.Sprintf("POST http://%s/pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc-web\r\nContent-Length: %d\r\n\r\n%s",
				upstreamAddr, upstreamAddr, len(body), body)

			c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			start := time.Now()
			if _, err := io.WriteString(c, req); err != nil {
				t.Fatalf("write request: %v", err)
			}
			var got bytes.Buffer
			_, rerr := io.Copy(&got, c)
			elapsed := time.Since(start)
			var ne net.Error
			if errors.As(rerr, &ne) && ne.Timeout() {
				t.Errorf("client connection still open after %v; want it closed", elapsed)
			}
			if got.Len() != 0 {
				t.Errorf("client received %d bytes %q, want 0 (DROP answers no gRPC status)", got.Len(), got.Bytes())
			}
			if elapsed > grpcWebBlockedMaxWait {
				t.Errorf("client connection closed after %v, want < %v", elapsed, grpcWebBlockedMaxWait)
			}
			settle()
			if n := received.Load(); n != 0 {
				t.Errorf("upstream received %d bytes (head %q), want 0", n, lastHead())
			}
			assertNoErrorStreams(t, h)
			assertNoServerErrorLog(t, logPath)
		})
	}
}

// T6: native gRPC over CONNECT + h2 — the call fails with Canceled, the
// upstream handler never runs, no Stream ends in error, and a second call
// on the same ClientConn (same h2 connection) behaves the same.
func TestE2E_PluginDropGRPCStart_ResetsStream(t *testing.T) {
	for _, phase := range grpcStartDropPhases {
		t.Run(phase, func(t *testing.T) {
			h, proxyAddr, logPath := startGRPCStartDropHarness(t, "grpc", phase)
			up := grpcUpstreamHostPort(t, h.UpstreamTLS.URL)
			cc := dialGRPCThroughProxyAs(t, proxyAddr, up, "")

			for i := 0; i < 2; i++ {
				start := time.Now()
				err := invokeEcho(cc, mcptest.GRPCSafetyEchoMethod)
				elapsed := time.Since(start)
				if err == nil {
					t.Fatalf("call %d succeeded; want Canceled (plugin DROP)", i)
				}
				if got := status.Code(err); got != codes.Canceled {
					t.Errorf("call %d status = %v (%v); want Canceled", i, got, err)
				}
				if elapsed > grpcWebBlockedMaxWait {
					t.Errorf("call %d took %v; want < %v", i, elapsed, grpcWebBlockedMaxWait)
				}
			}
			settle()
			if got := h.GRPCObservedHits.Total(); got != 0 {
				t.Errorf("upstream hits = %d, want 0", got)
			}
			assertNoErrorStreams(t, h)
			assertNoServerErrorLog(t, logPath)
		})
	}
}

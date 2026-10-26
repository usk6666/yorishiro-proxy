//go:build e2e && !e2e_smoke

package grpcweb_test

import (
	"bytes"
	"context"
	"io"
	nethttp "net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// USK-1392: a plugin RESPOND_GRPC / DROP on the response-side
// grpc-web.on_start (the upstream's response) ends the RPC. RESPOND_GRPC
// renders as the proxy's gRPC-Web terminator (HTTP 200 + one trailer frame)
// instead of the upstream response; DROP answers no status — over HTTP/1.x
// the client connection closes with no response bytes, over HTTP/2 the
// stream is reset. The response-side Start carries no service / method.

func responseStartPluginEngine(t *testing.T, ctx context.Context, ret string) *pluginv2.Engine {
	t.Helper()
	script := filepath.Join(t.TempDir(), "response_start.star")
	if err := os.WriteFile(script, []byte(`
def on_start(msg, ctx):
    if msg["service"]:
        return None
    return `+ret+`

register_hook("grpc-web", "on_start", on_start)
`), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: script, OnError: "abort"}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	return eng
}

const responseStartRespond = `action.RESPOND_GRPC(status=7, message="denied by plugin")`

// TestGRPCWeb_PluginRespondGRPC_ResponseStart_HTTP1 covers Test Plan #9
// (RESPOND, HTTP/1.x).
func TestGRPCWeb_PluginRespondGRPC_ResponseStart_HTTP1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("upstream"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, result, sessionDone := startGRPCWebHTTP1Proxy(t, ctx,
		pipelineOpts{plugins: responseStartPluginEngine(t, ctx, responseStartRespond)})

	reqFrame := grpcweb.EncodeFrame(false, false, []byte("hi"))
	resp, _ := sendGRPCWebHTTP1(t, proxyAddr, target, "/pkg.Echo/Say", "application/grpc-web+proto", reqFrame)
	waitSession(t, sessionDone)

	assertGRPCWebTerminator(t, resp, "application/grpc-web+proto", "7", "denied by plugin")
	if err := result.get(); err != nil {
		t.Errorf("session result = %v, want nil", err)
	}
	_ = upstreamLn.Close()
	assertUpstreamBody(t, captured(), reqFrame)
}

// TestGRPCWeb_PluginDrop_ResponseStart_HTTP1 covers Test Plan #9 (DROP,
// HTTP/1.x).
func TestGRPCWeb_PluginDrop_ResponseStart_HTTP1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("upstream"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, result, sessionDone := startGRPCWebHTTP1Proxy(t, ctx,
		pipelineOpts{plugins: responseStartPluginEngine(t, ctx, `action.DROP`)})

	resp, elapsed := sendGRPCWebHTTP1(t, proxyAddr, target, "/pkg.Echo/Say", "application/grpc-web+proto",
		grpcweb.EncodeFrame(false, false, []byte("hi")))
	waitSession(t, sessionDone)

	if len(resp) != 0 {
		t.Errorf("client received %d bytes %q, want 0 (DROP answers no gRPC status)", len(resp), truncate(resp))
	}
	if elapsed > blockedResponseMaxWait {
		t.Errorf("client connection closed after %v, want < %v", elapsed, blockedResponseMaxWait)
	}
	if err := result.get(); err != nil {
		t.Errorf("session result = %v, want nil", err)
	}
}

// h2GRPCWebCall performs one gRPC-Web call over HTTP/2 through the proxy.
func h2GRPCWebCall(t *testing.T, ctx context.Context, proxyAddr, upAddr string) (*nethttp.Response, []byte, error) {
	t.Helper()
	cli := &nethttp.Client{Transport: h2TransportViaProxy(proxyAddr, upAddr), Timeout: 10 * time.Second}
	req, err := nethttp.NewRequestWithContext(ctx, "POST", "https://"+upAddr+"/pkg.Echo/Say",
		bytes.NewReader(grpcweb.EncodeFrame(false, false, []byte("hi"))))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	resp, err := cli.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

// TestGRPCWeb_PluginRespondGRPC_ResponseStart_HTTP2 covers Test Plan #9
// (RESPOND, HTTP/2).
func TestGRPCWeb_PluginRespondGRPC_ResponseStart_HTTP2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var upstreamCalls atomic.Int32
	upAddr, upShutdown := startGRPCWebHTTP2Upstream(t, func(_ *nethttp.Request) ([]byte, string) {
		upstreamCalls.Add(1)
		return buildGRPCWebResponseBody([]byte("upstream-h2"), 0, "OK", false), "application/grpc-web+proto"
	})
	defer upShutdown()

	proxyAddr, _, _ := startGRPCWebHTTP2Proxy(t, ctx,
		pipelineOpts{plugins: responseStartPluginEngine(t, ctx, responseStartRespond)})

	resp, body, err := h2GRPCWebCall(t, ctx, proxyAddr, upAddr)
	if err != nil {
		t.Fatalf("h2 call: %v (want the plugin terminator)", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	res, derr := grpcweb.DecodeBody(body, false)
	if derr != nil || res.TrailerFrame == nil {
		t.Fatalf("body %q is not a gRPC-Web trailer-only body (err %v)", truncate(body), derr)
	}
	if len(res.DataFrames) != 0 {
		t.Errorf("body carries %d data frames, want 0 (the upstream's message must not reach the client)", len(res.DataFrames))
	}
	tr, perr := grpcweb.ParseTrailers(res.TrailerFrame.Payload)
	if perr != nil || tr["grpc-status"] != "7" {
		t.Errorf("trailer grpc-status = %q (err %v), want 7 from the plugin", tr["grpc-status"], perr)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Errorf("upstream handled %d requests, want 1", got)
	}
}

// TestGRPCWeb_PluginDrop_ResponseStart_HTTP2 covers Test Plan #9 (DROP,
// HTTP/2): the client stream is reset, the upstream's message never
// reaches the client.
func TestGRPCWeb_PluginDrop_ResponseStart_HTTP2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upShutdown := startGRPCWebHTTP2Upstream(t, func(_ *nethttp.Request) ([]byte, string) {
		return buildGRPCWebResponseBody([]byte("upstream-h2"), 0, "OK", false), "application/grpc-web+proto"
	})
	defer upShutdown()

	proxyAddr, _, _ := startGRPCWebHTTP2Proxy(t, ctx,
		pipelineOpts{plugins: responseStartPluginEngine(t, ctx, `action.DROP`)})

	start := time.Now()
	resp, body, err := h2GRPCWebCall(t, ctx, proxyAddr, upAddr)
	if err == nil {
		t.Fatalf("h2 call succeeded (status %d body %q), want a reset stream", resp.StatusCode, truncate(body))
	}
	if bytes.Contains(body, []byte("upstream-h2")) {
		t.Errorf("client read the upstream message %q, want none", truncate(body))
	}
	if elapsed := time.Since(start); elapsed > blockedResponseMaxWait {
		t.Errorf("dropped call took %v, want < %v", elapsed, blockedResponseMaxWait)
	}
}

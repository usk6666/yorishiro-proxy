//go:build e2e && !e2e_smoke

package grpc_test

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// USK-1392: a plugin RESPOND_GRPC / DROP on the response-side
// grpc.on_start (the upstream's response HEADERS) ends the RPC. The hook
// fires for both directions; the response-side GRPCStartMessage carries no
// service / method, which is how a plugin tells the two apart.

// loadResponseStartPlugin loads a plugin whose grpc.on_start hook returns
// ret on the response-side Start only.
func loadResponseStartPlugin(t *testing.T, ctx context.Context, ret string) *pluginv2.Engine {
	t.Helper()
	script := filepath.Join(t.TempDir(), "response_start.star")
	if err := os.WriteFile(script, []byte(`
def on_start(msg, ctx):
    if msg["service"]:
        return None
    return `+ret+`

register_hook("grpc", "on_start", on_start)
`), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: script, OnError: "abort"}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	return eng
}

// assertCleanProxyEndedSession checks that every finished session reported
// a nil result: the proxy ended the RPC on purpose.
func assertCleanProxyEndedSession(t *testing.T, probe *sessionProbe) {
	t.Helper()
	probe.waitCompleted(t, 5*time.Second)
	for _, err := range probe.sessionResults() {
		if err != nil {
			t.Errorf("session result = %v; want nil (the proxy ended the RPC on purpose)", err)
		}
	}
}

// TestGRPC_PluginRespondGRPC_ResponseStart covers Test Plan #7: the client
// receives the plugin's status instead of the upstream's response, the
// session ends cleanly, and the shared h2 connections keep serving RPCs.
func TestGRPC_PluginRespondGRPC_ResponseStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	var hits atomic.Int32
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			hits.Add(1)
			return req, nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	probe := &sessionProbe{}
	eng := loadResponseStartPlugin(t, ctx, `action.RESPOND_GRPC(status=7, message="denied by plugin")`)
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{plugins: eng, probe: probe})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	assertBlockedUnary(t, ctx, cc, echoFullMethod(echoMethodUnary), []byte("hi"),
		codes.PermissionDenied, "denied by plugin")
	assertCleanProxyEndedSession(t, probe)
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream handler ran %d times; want 1 (the request reached the upstream)", got)
	}
}

// TestGRPC_PluginDrop_ResponseStart covers Test Plan #8: a DROP on the
// response-side on_start ends the RPC with no gRPC status (the client
// stream is reset, codes.Canceled), the upstream's response never reaches
// the client, the session ends cleanly and the h2 connections survive.
func TestGRPC_PluginDrop_ResponseStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) { return req, nil },
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	probe := &sessionProbe{}
	eng := loadResponseStartPlugin(t, ctx, `action.DROP`)
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{plugins: eng, probe: probe})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	assertBlockedUnary(t, ctx, cc, echoFullMethod(echoMethodUnary), []byte("hi"), codes.Canceled, "")
	assertCleanProxyEndedSession(t, probe)

	// A following RPC on the same ClientConn (same client h2 connection,
	// same upstream h2 connection) is dropped the same way — not failed
	// by a broken connection.
	assertBlockedUnary(t, ctx, cc, echoFullMethod(echoMethodUnary), []byte("again"), codes.Canceled, "")
}

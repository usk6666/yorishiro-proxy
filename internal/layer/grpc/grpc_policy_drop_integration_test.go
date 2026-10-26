//go:build e2e && !e2e_smoke

// USK-1202 exhaustive e2e coverage for proxy-terminated native-gRPC RPCs.
//
// A Pipeline Step that blocks a native-gRPC Send envelope (SafetyFilter,
// intercept drop) answers with a synthetic GRPCEndMessage carrying
// grpc-status 7 PERMISSION_DENIED; a plugin RESPOND_GRPC answers with its own
// status. The gRPC Layer renders that End as a Trailers-Only response when no
// response HEADERS were relayed yet, or as trailers when they were. The smoke
// tier covers the Data-target SafetyFilter block
// (TestGRPC_SafetyFilterBlocksPayload); this file covers the Start-target
// block, the mid-stream bidi block, intercept drop, and plugin RESPOND_GRPC.
// Every blocked call runs under its own short deadline and asserts the
// concrete status code plus an elapsed upper bound, so a proxy that leaves the
// RPC hanging fails instead of passing on DeadlineExceeded.
package grpc_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
)

// waitCompleted polls until at least one harness session finished.
func (p *sessionProbe) waitCompleted(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if p.completed.Load() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: no session completed within %v", timeout)
}

// TestGRPC_SafetyFilterBlocksMethod_StartTarget: a method-target rule matches
// on the GRPCStartMessage, before the upstream is dialed. The client gets
// PERMISSION_DENIED as a Trailers-Only response and the upstream is never
// dialed.
func TestGRPC_SafetyFilterBlocksMethod_StartTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) { return req, nil },
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	safety := grpcrules.NewSafetyEngine()
	safety.AddRule(common.CompiledRule{
		ID:      "custom:method",
		Name:    "block Unary",
		Pattern: regexp.MustCompile(`^` + echoMethodUnary + `$`),
		Targets: []common.Target{grpcrules.TargetMethod},
	})
	probe := &sessionProbe{}
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{safety: safety, probe: probe})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	assertBlockedUnary(t, ctx, cc, echoFullMethod(echoMethodUnary), []byte("anything"),
		codes.PermissionDenied, "safety_filter")

	probe.waitBlockedAndComplete(t, "safety_filter", 5*time.Second)
	if got := probe.dials.Load(); got != 0 {
		t.Errorf("upstream dialed %d times; want 0 (Start-target block precedes the dial)", got)
	}
}

// TestGRPC_SafetyFilterBlocksBidiMidStream: a benign bidi message is echoed
// (so response HEADERS were already relayed to the client), then a blocked
// message ends the RPC with PERMISSION_DENIED delivered as trailers. The
// client's h2 connection must survive: a second RPC on the same ClientConn
// succeeds.
func TestGRPC_SafetyFilterBlocksBidiMidStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			return append([]byte("echo:"), req...), nil
		},
		bidiStream: func(stream grpc.ServerStream) error {
			for {
				var in []byte
				if err := stream.RecvMsg(&in); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
				out := append([]byte("ack:"), in...)
				if err := stream.SendMsg(&out); err != nil {
					return err
				}
			}
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	safety := grpcrules.NewSafetyEngine()
	safety.AddRule(common.CompiledRule{
		ID:      "custom:blocked",
		Name:    "block marker",
		Pattern: regexp.MustCompile(`blocked-pattern`),
		Targets: []common.Target{grpcrules.TargetPayload},
	})
	probe := &sessionProbe{}
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{safety: safety, probe: probe})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	streamCtx, streamCancel := context.WithTimeout(ctx, 5*time.Second)
	defer streamCancel()
	desc := &grpc.StreamDesc{StreamName: echoMethodBidiStream, ServerStreams: true, ClientStreams: true}
	cs, err := cc.NewStream(streamCtx, desc, echoFullMethod(echoMethodBidiStream))
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	benign := []byte("benign")
	if err := cs.SendMsg(&benign); err != nil {
		t.Fatalf("SendMsg benign: %v", err)
	}
	var got []byte
	if err := cs.RecvMsg(&got); err != nil {
		t.Fatalf("RecvMsg benign: %v", err)
	}
	if string(got) != "ack:benign" {
		t.Fatalf("benign echo = %q, want %q", got, "ack:benign")
	}

	blocked := []byte("x blocked-pattern y")
	start := time.Now()
	if err := cs.SendMsg(&blocked); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("SendMsg blocked: %v", err)
	}
	rerr := cs.RecvMsg(&got)
	elapsed := time.Since(start)
	if rerr == nil {
		t.Fatalf("RecvMsg after blocked message returned a message %q; want PermissionDenied", got)
	}
	st, ok := status.FromError(rerr)
	if !ok {
		t.Fatalf("RecvMsg error is not a gRPC status: %T %v", rerr, rerr)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("bidi status = %v (%q) after %v; want PermissionDenied", st.Code(), st.Message(), elapsed)
	}
	if !strings.Contains(st.Message(), "safety_filter") {
		t.Errorf("bidi status message = %q; want it to contain safety_filter", st.Message())
	}
	if elapsed > blockedCallMaxWait {
		t.Errorf("blocked bidi message took %v to fail the RPC; want < %v", elapsed, blockedCallMaxWait)
	}

	probe.waitBlockedAndComplete(t, "safety_filter", 5*time.Second)

	// The terminator must not have broken the shared h2 connection (e.g. a
	// frame sent after END_STREAM is a STREAM_CLOSED connection error).
	callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
	defer callCancel()
	req := []byte("after")
	var resp []byte
	if err := cc.Invoke(callCtx, echoFullMethod(echoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("follow-up Unary on the same ClientConn: %v", err)
	}
	if string(resp) != "echo:after" {
		t.Errorf("follow-up Unary resp = %q, want %q", resp, "echo:after")
	}
}

// TestGRPC_InterceptDropStart_PermissionDenied (USK-1202 U1): dropping a
// held native-gRPC Start ends the RPC with PERMISSION_DENIED attributed to
// intercept_drop, mirroring the HTTP intercept-drop 403.
func TestGRPC_InterceptDropStart_PermissionDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) { return req, nil },
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	engine := grpcrules.NewInterceptEngine()
	engine.SetRules([]grpcrules.InterceptRule{{
		ID:            "hold-unary",
		Enabled:       true,
		Direction:     grpcrules.DirectionSend,
		MethodPattern: regexp.MustCompile(`^` + echoMethodUnary + `$`),
	}})
	queue := common.NewHoldQueue()
	probe := &sessionProbe{}
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		intercept: engine,
		queue:     queue,
		probe:     probe,
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	// Drop the first held envelope (the Start) as soon as it appears.
	go func() {
		for ctx.Err() == nil {
			if entries := queue.List(); len(entries) > 0 {
				_ = queue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionDrop})
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	assertBlockedUnary(t, ctx, cc, echoFullMethod(echoMethodUnary), []byte("held"),
		codes.PermissionDenied, "intercept_drop")

	probe.waitBlockedAndComplete(t, "intercept_drop", 5*time.Second)
	if got := probe.dials.Load(); got != 0 {
		t.Errorf("upstream dialed %d times; want 0 (Start dropped before the dial)", got)
	}
}

// TestGRPC_PluginRespondGRPC_TrailersOnly: a plugin RESPOND_GRPC on
// grpc.on_start reaches the client as a valid Trailers-Only response carrying
// the plugin's status (previously a HEADERS frame without :status).
func TestGRPC_PluginRespondGRPC_TrailersOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) { return req, nil },
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	script := filepath.Join(t.TempDir(), "deny.star")
	if err := os.WriteFile(script, []byte(`
def deny(msg, ctx):
    return action.RESPOND_GRPC(status=16, message="denied by plugin")

register_hook("grpc", "on_start", deny)
`), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: script, OnError: "abort"}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	probe := &sessionProbe{}
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{plugins: eng, probe: probe})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	assertBlockedUnary(t, ctx, cc, echoFullMethod(echoMethodUnary), []byte("hi"),
		codes.Unauthenticated, "denied by plugin")

	probe.waitCompleted(t, 5*time.Second)
	if got := probe.dials.Load(); got != 0 {
		t.Errorf("upstream dialed %d times; want 0 (plugin responded on Start)", got)
	}
}

// loadDropPlugin writes a plugin that returns DROP from grpc.on_start and
// loads it into a fresh Engine (USK-1387).
func loadDropPlugin(t *testing.T, ctx context.Context) *pluginv2.Engine {
	t.Helper()
	script := filepath.Join(t.TempDir(), "drop.star")
	if err := os.WriteFile(script, []byte(`
def drop(msg, ctx):
    return action.DROP

register_hook("grpc", "on_start", drop)
`), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: script, OnError: "abort"}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	return eng
}

// assertCleanDroppedSession checks the harness probe after a plugin DROP on
// grpc.on_start: the session finished with a nil result and the upstream was
// never dialed.
func assertCleanDroppedSession(t *testing.T, probe *sessionProbe, hits *atomic.Int32) {
	t.Helper()
	probe.waitCompleted(t, 5*time.Second)
	for _, err := range probe.sessionResults() {
		if err != nil {
			t.Errorf("session result = %v; want nil (the proxy dropped the RPC on purpose)", err)
		}
	}
	if got := probe.dials.Load(); got != 0 {
		t.Errorf("upstream dialed %d times; want 0 (Start dropped before the dial)", got)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("upstream handler ran %d times; want 0", got)
	}
}

// TestGRPC_PluginDropStart_Unary_Canceled (USK-1387): a plugin DROP on
// grpc.on_start ends a unary RPC at Start time with no gRPC status — the
// client stream is reset with RST_STREAM(CANCEL), surfacing as
// codes.Canceled — the upstream is never dialed and the session ends
// cleanly.
func TestGRPC_PluginDropStart_Unary_Canceled(t *testing.T) {
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
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{plugins: loadDropPlugin(t, ctx), probe: probe})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	assertBlockedUnary(t, ctx, cc, echoFullMethod(echoMethodUnary), []byte("hi"), codes.Canceled, "")
	assertCleanDroppedSession(t, probe, &hits)
}

// TestGRPC_PluginDropStart_BidiRecvFirst_Canceled (USK-1387): a bidi client
// that waits for the server before sending anything must not hang until its
// own deadline when a plugin DROPs the Start — the proxy resets the stream.
func TestGRPC_PluginDropStart_BidiRecvFirst_Canceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	var hits atomic.Int32
	srv := &echoServer{
		bidiStream: func(grpc.ServerStream) error {
			hits.Add(1)
			return nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	probe := &sessionProbe{}
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{plugins: loadDropPlugin(t, ctx), probe: probe})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	callCtx, callCancel := context.WithTimeout(ctx, 3*time.Second)
	defer callCancel()
	start := time.Now()
	desc := &grpc.StreamDesc{StreamName: echoMethodBidiStream, ServerStreams: true, ClientStreams: true}
	cs, err := cc.NewStream(callCtx, desc, echoFullMethod(echoMethodBidiStream))
	if err == nil {
		var resp []byte
		err = cs.RecvMsg(&resp)
	}
	elapsed := time.Since(start)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("RecvMsg err = %v; want a Canceled stream error", err)
	}
	if got := status.Code(err); got != codes.Canceled {
		t.Errorf("status code = %v (%v) after %v; want Canceled", got, err, elapsed)
	}
	if elapsed > blockedCallMaxWait {
		t.Errorf("dropped bidi RPC took %v; want < %v (the proxy must reset it, not the client deadline)", elapsed, blockedCallMaxWait)
	}
	assertCleanDroppedSession(t, probe, &hits)
}

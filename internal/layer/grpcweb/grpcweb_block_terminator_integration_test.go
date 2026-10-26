//go:build e2e && !e2e_smoke

// USK-1220 exhaustive e2e coverage for proxy-terminated gRPC-Web RPCs.
//
// A Pipeline Step that blocks a gRPC-Web Send Start or Data envelope
// (SafetyFilter, intercept drop) answers with the same synthetic
// GRPCEndMessage native gRPC gets (grpc-status 7 PERMISSION_DENIED); a plugin
// RESPOND_GRPC answers with its own status. The grpcweb Layer renders that End
// as an HTTP 200 response whose body is a single trailer frame, in the
// request's wire form (base64 for -text), and the session ends the RPC so the
// request — buffered by the upstream grpcweb Channel until the Send End
// sentinel — never reaches the upstream.
package grpcweb_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
)

// blockedResponseMaxWait bounds how long a blocked request may take to be
// answered. The proxy answers as soon as the Pipeline blocks; a proxy that
// leaves the client waiting for the upstream or its own read deadline fails.
const blockedResponseMaxWait = 3 * time.Second

// sendGRPCWebHTTP1 writes one HTTP/1.1 gRPC-Web request for path with body
// through the CONNECT proxy and returns whatever the client read until close
// plus the elapsed time.
func sendGRPCWebHTTP1(t *testing.T, proxyAddr, target, path, contentType string, body []byte) ([]byte, time.Duration) {
	t.Helper()
	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		path, target, contentType, len(body))
	start := time.Now()
	if _, err := tlsConn.Write(append([]byte(req), body...)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readUntilClose(tlsConn, 10*time.Second)
	return resp, time.Since(start)
}

// assertGRPCWebTerminator asserts raw is the proxy's gRPC-Web terminator: an
// HTTP 200 response with content-type wantCT whose body (base64-decoded for
// -text) is exactly one trailer frame carrying wantStatus and a grpc-message
// containing wantMsg. The status must not travel in the HTTP headers.
func assertGRPCWebTerminator(t *testing.T, raw []byte, wantCT string, wantStatus, wantMsg string) map[string]string {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("client received no response; want the gRPC-Web terminator")
	}
	head, body := splitHTTPMessage(t, raw)
	statusLine, _, _ := strings.Cut(head, "\r\n")
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200 ") {
		t.Errorf("status line = %q, want HTTP/1.1 200", statusLine)
	}
	if got := headerValues(head, "Content-Type"); len(got) != 1 || got[0] != wantCT {
		t.Errorf("Content-Type = %q, want [%q]", got, wantCT)
	}
	if got := headerValues(head, "grpc-status"); len(got) != 0 {
		t.Errorf("grpc-status header = %q, want none (status travels in the trailer frame)", got)
	}
	res, err := grpcweb.DecodeBody(body, grpcweb.IsBase64Encoded(wantCT))
	if err != nil {
		t.Fatalf("decode body %q: %v", truncate(body), err)
	}
	if len(res.DataFrames) != 0 {
		t.Errorf("body carries %d data frames, want 0", len(res.DataFrames))
	}
	if res.TrailerFrame == nil {
		t.Fatalf("body %q carries no trailer frame", truncate(body))
	}
	trailers, err := grpcweb.ParseTrailers(res.TrailerFrame.Payload)
	if err != nil {
		t.Fatalf("parse trailers: %v", err)
	}
	if trailers["grpc-status"] != wantStatus {
		t.Errorf("trailer grpc-status = %q, want %q (trailers %v)", trailers["grpc-status"], wantStatus, trailers)
	}
	if !strings.Contains(trailers["grpc-message"], wantMsg) {
		t.Errorf("trailer grpc-message = %q, want it to contain %q", trailers["grpc-message"], wantMsg)
	}
	return trailers
}

// waitSession waits for the harness session to finish.
func waitSession(t *testing.T, sessionDone <-chan struct{}) {
	t.Helper()
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}
}

// assertBlockedBy asserts the probe saw an OnPipelineDrop attributed to want.
func assertBlockedBy(t *testing.T, probe *sessionProbe, want string) {
	t.Helper()
	for _, b := range probe.blocked() {
		if b == want {
			return
		}
	}
	t.Errorf("OnPipelineDrop attributions = %v, want %q", probe.blocked(), want)
}

// assertNoUpstreamRequest closes the upstream listener and asserts it never
// received a request.
func assertNoUpstreamRequest(t *testing.T, closeUpstream func() error, captured func() [][]byte) {
	t.Helper()
	_ = closeUpstream()
	if reqs := captured(); len(reqs) != 0 {
		t.Errorf("upstream received %d requests, want 0; first: %q", len(reqs), truncate(reqs[0]))
	}
}

// TestGRPCWeb_SafetyBlock_Terminator (T2/T3 in-package): a SafetyFilter
// block of a gRPC-Web request — on the Data payload (binary and -text) or on
// the Start's query — answers the client with HTTP 200 + a trailer frame
// holding grpc-status 7, and the upstream receives no request.
func TestGRPCWeb_SafetyBlock_Terminator(t *testing.T) {
	sqlFrame := grpcweb.EncodeFrame(false, false, []byte("DROP TABLE users"))
	tests := []struct {
		name     string
		path     string
		ct       string
		body     []byte
		wantDial bool
	}{
		{name: "data binary", path: "/pkg.Echo/Say", ct: "application/grpc-web+proto", body: sqlFrame, wantDial: true},
		{name: "data text", path: "/pkg.Echo/Say", ct: "application/grpc-web-text+proto", body: grpcweb.EncodeBase64Body(sqlFrame), wantDial: true},
		{name: "start query", path: "/pkg.Echo/Say?q=DROP/**/TABLE/**/users", ct: "application/grpc-web",
			body: grpcweb.EncodeFrame(false, false, []byte("benign"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
				return buildGRPCWebResponseHTTP([]byte("upstream"), 0, "OK", grpcweb.IsBase64Encoded(tt.ct))
			})
			defer upstreamLn.Close()
			target := upstreamLn.Addr().String()

			safety := grpcrules.NewSafetyEngine()
			if err := safety.LoadPreset(common.PresetDestructiveSQL); err != nil {
				t.Fatalf("load preset: %v", err)
			}
			probe := &sessionProbe{}
			proxyAddr, _, result, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{safetyEngine: safety, probe: probe})

			resp, elapsed := sendGRPCWebHTTP1(t, proxyAddr, target, tt.path, tt.ct, tt.body)
			waitSession(t, sessionDone)

			trailers := assertGRPCWebTerminator(t, resp, tt.ct, "7", "safety_filter")
			if trailers["x-yorishiro-matched-rules"] != "destructive-sql:drop" {
				t.Errorf("x-yorishiro-matched-rules = %q, want destructive-sql:drop", trailers["x-yorishiro-matched-rules"])
			}
			if elapsed > blockedResponseMaxWait {
				t.Errorf("blocked request answered after %v, want < %v", elapsed, blockedResponseMaxWait)
			}
			assertNoUpstreamRequest(t, upstreamLn.Close, captured)
			assertBlockedBy(t, probe, "safety_filter")
			if err := result.get(); err != nil {
				t.Errorf("session result = %v, want nil (RPC terminated by proxy)", err)
			}
			if !tt.wantDial && probe.dials.Load() != 0 {
				t.Errorf("upstream dialed %d times, want 0 (Start block precedes the dial)", probe.dials.Load())
			}
		})
	}
}

// TestGRPCWeb_SafetyBlock_MultiMessage_NoLeak (T5): a request body of three
// LPM frames whose middle one is blocked must not leak the benign first (or
// last) frame upstream — the whole request is withheld.
func TestGRPCWeb_SafetyBlock_MultiMessage_NoLeak(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("upstream"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	safety := grpcrules.NewSafetyEngine()
	if err := safety.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("load preset: %v", err)
	}
	probe := &sessionProbe{}
	proxyAddr, _, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{safetyEngine: safety, probe: probe})

	var body bytes.Buffer
	body.Write(grpcweb.EncodeFrame(false, false, []byte("first-benign")))
	body.Write(grpcweb.EncodeFrame(false, false, []byte("DROP TABLE users")))
	body.Write(grpcweb.EncodeFrame(false, false, []byte("third-benign")))

	resp, _ := sendGRPCWebHTTP1(t, proxyAddr, target, "/pkg.Echo/Say", "application/grpc-web+proto", body.Bytes())
	waitSession(t, sessionDone)

	assertGRPCWebTerminator(t, resp, "application/grpc-web+proto", "7", "safety_filter")
	assertNoUpstreamRequest(t, upstreamLn.Close, captured)
	assertBlockedBy(t, probe, "safety_filter")
}

// TestGRPCWeb_InterceptDrop_Terminator (T4): dropping a held gRPC-Web Start,
// or a held Data after the Start was released, answers the client with the
// same terminator attributed to intercept_drop, and nothing reaches the
// upstream.
func TestGRPCWeb_InterceptDrop_Terminator(t *testing.T) {
	tests := []struct {
		name string
		// dropAt is the 0-based index of the held envelope to drop; every
		// earlier held envelope is released unchanged.
		dropAt   int
		wantDial bool
	}{
		{name: "start", dropAt: 0},
		{name: "data", dropAt: 1, wantDial: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
				return buildGRPCWebResponseHTTP([]byte("upstream"), 0, "OK", false)
			})
			defer upstreamLn.Close()
			target := upstreamLn.Addr().String()

			engine := grpcrules.NewInterceptEngine()
			engine.SetRules([]grpcrules.InterceptRule{{
				ID:            "hold-say",
				Enabled:       true,
				Direction:     grpcrules.DirectionSend,
				MethodPattern: regexp.MustCompile(`^Say$`),
			}})
			queue := common.NewHoldQueue()
			probe := &sessionProbe{}
			proxyAddr, _, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{
				interceptEngine: engine,
				queue:           queue,
				probe:           probe,
			})

			go func() {
				handled := map[string]bool{}
				n := 0
				for ctx.Err() == nil && n <= tt.dropAt {
					for _, e := range queue.List() {
						if handled[e.ID] {
							continue
						}
						handled[e.ID] = true
						action := &common.HoldAction{Type: common.ActionRelease}
						if n == tt.dropAt {
							action = &common.HoldAction{Type: common.ActionDrop}
						}
						_ = queue.Release(e.ID, action)
						n++
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()

			resp, _ := sendGRPCWebHTTP1(t, proxyAddr, target, "/pkg.Echo/Say", "application/grpc-web+proto",
				grpcweb.EncodeFrame(false, false, []byte("held")))
			waitSession(t, sessionDone)

			trailers := assertGRPCWebTerminator(t, resp, "application/grpc-web+proto", "7", "intercept_drop")
			if trailers["x-yorishiro-matched-rules"] != "hold-say" {
				t.Errorf("x-yorishiro-matched-rules = %q, want hold-say", trailers["x-yorishiro-matched-rules"])
			}
			assertNoUpstreamRequest(t, upstreamLn.Close, captured)
			assertBlockedBy(t, probe, "intercept_drop")
			if !tt.wantDial && probe.dials.Load() != 0 {
				t.Errorf("upstream dialed %d times, want 0 (Start dropped before the dial)", probe.dials.Load())
			}
		})
	}
}

// TestGRPCWeb_PluginRespondGRPC_Terminator (T7): a plugin RESPOND_GRPC on
// grpc-web.on_start reaches the client as a gRPC-Web response whose trailer
// frame carries the plugin's status; the upstream is never dialed.
// Previously the End-only Send failed with "GRPCEndMessage before
// GRPCStartMessage on Send".
func TestGRPCWeb_PluginRespondGRPC_Terminator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("upstream"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	script := filepath.Join(t.TempDir(), "deny.star")
	if err := os.WriteFile(script, []byte(`
def deny(msg, ctx):
    return action.RESPOND_GRPC(status=16, message="denied by plugin")

register_hook("grpc-web", "on_start", deny)
`), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: script, OnError: "abort"}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	probe := &sessionProbe{}
	proxyAddr, _, result, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{plugins: eng, probe: probe})

	resp, _ := sendGRPCWebHTTP1(t, proxyAddr, target, "/pkg.Echo/Say", "application/grpc-web-text",
		grpcweb.EncodeBase64Body(grpcweb.EncodeFrame(false, false, []byte("hi"))))
	waitSession(t, sessionDone)

	assertGRPCWebTerminator(t, resp, "application/grpc-web-text", "16", "denied by plugin")
	assertNoUpstreamRequest(t, upstreamLn.Close, captured)
	if got := probe.dials.Load(); got != 0 {
		t.Errorf("upstream dialed %d times, want 0 (plugin responded on Start)", got)
	}
	if err := result.get(); err != nil {
		t.Errorf("session result = %v, want nil", err)
	}
}

// TestGRPCWeb_PluginDropStart_ClosesConnection (USK-1387): a plugin DROP on
// grpc-web.on_start ends the RPC at Start time with no gRPC status. Over
// HTTP/1.x the client connection closes with no response bytes, the upstream
// is never dialed and receives no request, and the session ends cleanly.
// Previously the following Data dialed the upstream and failed with
// "GRPCDataMessage before GRPCStartMessage on Send".
func TestGRPCWeb_PluginDropStart_ClosesConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("upstream"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	script := filepath.Join(t.TempDir(), "drop.star")
	if err := os.WriteFile(script, []byte(`
def drop(msg, ctx):
    return action.DROP

register_hook("grpc-web", "on_start", drop)
`), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: script, OnError: "abort"}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	probe := &sessionProbe{}
	proxyAddr, _, result, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{plugins: eng, probe: probe})

	resp, elapsed := sendGRPCWebHTTP1(t, proxyAddr, target, "/pkg.Echo/Say", "application/grpc-web",
		grpcweb.EncodeFrame(false, false, []byte("hi")))
	waitSession(t, sessionDone)

	if len(resp) != 0 {
		t.Errorf("client received %d bytes %q, want 0 (DROP answers no gRPC status)", len(resp), truncate(resp))
	}
	if elapsed > blockedResponseMaxWait {
		t.Errorf("client connection closed after %v, want < %v", elapsed, blockedResponseMaxWait)
	}
	assertNoUpstreamRequest(t, upstreamLn.Close, captured)
	if got := probe.dials.Load(); got != 0 {
		t.Errorf("upstream dialed %d times, want 0 (plugin dropped the Start)", got)
	}
	if err := result.get(); err != nil {
		t.Errorf("session result = %v, want nil", err)
	}
}

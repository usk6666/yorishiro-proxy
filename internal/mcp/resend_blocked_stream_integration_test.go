//go:build e2e && !e2e_smoke

package mcp

// resend_blocked_stream_integration_test.go — USK-1375: a resend_http /
// resend_grpc result's stream_id must name a Stream that exists, or be
// empty.
//
// A post_pipeline plugin that Drops or Responds on the Send side exits the
// resend pipeline before RecordStep opens the Stream, and carries no
// blocked_by attribution, so nothing is recorded (the live path records
// nothing for an unlabelled plugin action either). Respond keeps its
// success result with the plugin's custom response; Drop stays an MCP
// error. A non-tripping control call pins that an ordinary resend still
// returns a recorded stream_id.

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// assertResendStreamIDResolves enforces the class rule on a resend result:
// a non-empty stream_id names a Stream reachable both from the store and
// through `query resource=flow`.
func assertResendStreamIDResolves(t *testing.T, cs *gomcp.ClientSession, store flow.Store, streamID string) {
	t.Helper()
	if streamID == "" {
		return
	}
	if _, err := store.GetStream(context.Background(), streamID); err != nil {
		t.Errorf("stream_id = %q names no Stream (GetStream: %v) — want empty when nothing was recorded", streamID, err)
		return
	}
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "flow", "id": streamID},
	})
	if err != nil {
		t.Fatalf("CallTool query flow: %v", err)
	}
	if res.IsError {
		t.Errorf("query resource=flow id=%s failed: %s", streamID, extractTextContent(res))
	}
}

// assertResendRecordedStreamID requires a non-empty stream_id naming a
// recorded Stream (the non-tripping control case).
func assertResendRecordedStreamID(t *testing.T, cs *gomcp.ClientSession, store flow.Store, streamID string) {
	t.Helper()
	if streamID == "" {
		t.Fatalf("stream_id is empty for an ordinary resend, want the recorded Stream's ID")
	}
	assertResendStreamIDResolves(t, cs, store, streamID)
}

// assertResendDropError checks a plugin Drop surfaces as an MCP error
// with no structured stream_id.
func assertResendDropError(t *testing.T, res *gomcp.CallToolResult) {
	t.Helper()
	if !res.IsError {
		t.Fatalf("plugin Drop: IsError = false, want an MCP error")
	}
	if txt := extractTextContent(res); !strings.Contains(txt, "dropped by pipeline") {
		t.Errorf("plugin Drop error = %q, want it to mention %q", txt, "dropped by pipeline")
	}
	if m, ok := res.StructuredContent.(map[string]any); ok {
		if id, _ := m["stream_id"].(string); id != "" {
			t.Errorf("plugin Drop returned structured stream_id %q, want none", id)
		}
	}
}

func setupResendBlockedHTTP(t *testing.T, result starlark.Value) (*gomcp.ClientSession, flow.Store, *int32, string) {
	t.Helper()
	tripped := new(int32)
	engine := pluginv2.NewEngine(nil)
	engine.Registry().Register(fuzzBlockedPluginHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, tripped, result))
	cs, store := setupFuzzBlockedSession(t, WithPluginv2Engine(engine))
	echo, _ := startFuzzHTTPEcho(t)
	return cs, store, tripped, strings.TrimPrefix(echo.URL, "http://")
}

func resendBlockedHTTPArgs(authority, body string) map[string]any {
	return map[string]any{
		"method":     "POST",
		"scheme":     "http",
		"authority":  authority,
		"path":       "/",
		"body":       body,
		"timeout_ms": 5000,
	}
}

func TestResendHTTP_PluginRespondLeavesNoDanglingStreamID(t *testing.T) {
	cs, store, tripped, authority := setupResendBlockedHTTP(t,
		&pluginv2.RespondAction{HTTPResponse: &pluginv2.HTTPRespondPayload{StatusCode: http.StatusTeapot}})
	res := callResendHTTP(t, cs, resendBlockedHTTPArgs(authority, "trip"))
	if atomic.LoadInt32(tripped) != 1 {
		t.Fatalf("plugin tripped %d times, want 1", atomic.LoadInt32(tripped))
	}
	if res.IsError {
		t.Fatalf("plugin Respond: tool returned error: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.StatusCode != http.StatusTeapot {
		t.Errorf("status_code = %d, want %d (the plugin's custom response)", out.StatusCode, http.StatusTeapot)
	}
	assertResendStreamIDResolves(t, cs, store, out.StreamID)
}

func TestResendHTTP_PluginDropReturnsErrorWithoutStreamID(t *testing.T) {
	cs, _, tripped, authority := setupResendBlockedHTTP(t, starlark.String("DROP"))
	res := callResendHTTP(t, cs, resendBlockedHTTPArgs(authority, "trip"))
	if atomic.LoadInt32(tripped) != 1 {
		t.Fatalf("plugin tripped %d times, want 1", atomic.LoadInt32(tripped))
	}
	assertResendDropError(t, res)
}

func TestResendHTTP_PluginContinueReturnsRecordedStreamID(t *testing.T) {
	cs, store, tripped, authority := setupResendBlockedHTTP(t, starlark.String("DROP"))
	res := callResendHTTP(t, cs, resendBlockedHTTPArgs(authority, "ok"))
	if atomic.LoadInt32(tripped) != 0 {
		t.Fatalf("plugin tripped %d times, want 0", atomic.LoadInt32(tripped))
	}
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.StatusCode != http.StatusOK {
		t.Errorf("status_code = %d, want %d", out.StatusCode, http.StatusOK)
	}
	assertResendRecordedStreamID(t, cs, store, out.StreamID)
}

func setupResendBlockedGRPC(t *testing.T, result starlark.Value) (*gomcp.ClientSession, flow.Store, *int32, string) {
	t.Helper()
	tripped := new(int32)
	engine := pluginv2.NewEngine(nil)
	engine.Registry().Register(fuzzBlockedPluginHook(pluginv2.ProtoGRPC, pluginv2.EventOnStart, tripped, result))
	cs, store := setupFuzzBlockedSession(t, WithPluginv2Engine(engine))
	addr, shutdown := startResendGRPCUpstream(t, &resendGRPCEchoServer{})
	t.Cleanup(shutdown)
	return cs, store, tripped, addr
}

func resendBlockedGRPCArgs(addr, marker string) map[string]any {
	return map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      resendGRPCMethodUnary,
		"messages":    []map[string]any{{"payload": "seed"}},
		"metadata":    []map[string]any{{"name": "x-marker", "value": marker}},
		"timeout_ms":  10000,
	}
}

func TestResendGRPC_PluginRespondLeavesNoDanglingStreamID(t *testing.T) {
	cs, store, tripped, addr := setupResendBlockedGRPC(t,
		&pluginv2.RespondAction{GRPCResponse: &pluginv2.GRPCRespondPayload{Status: 7, Message: "denied by plugin"}})
	res := callResendGRPC(t, cs, resendBlockedGRPCArgs(addr, "trip"))
	if atomic.LoadInt32(tripped) != 1 {
		t.Fatalf("plugin tripped %d times, want 1", atomic.LoadInt32(tripped))
	}
	var out resendGRPCResult
	decodeResendGRPCResult(t, res, &out)
	if out.End == nil {
		t.Fatalf("end is nil, want the plugin's custom status")
	}
	if out.End.Status != 7 || out.End.Message != "denied by plugin" {
		t.Errorf("end = {status %d, message %q}, want {7, %q}", out.End.Status, out.End.Message, "denied by plugin")
	}
	assertResendStreamIDResolves(t, cs, store, out.StreamID)
}

func TestResendGRPC_PluginDropReturnsErrorWithoutStreamID(t *testing.T) {
	cs, _, tripped, addr := setupResendBlockedGRPC(t, starlark.String("DROP"))
	res := callResendGRPC(t, cs, resendBlockedGRPCArgs(addr, "trip"))
	if atomic.LoadInt32(tripped) != 1 {
		t.Fatalf("plugin tripped %d times, want 1", atomic.LoadInt32(tripped))
	}
	assertResendDropError(t, res)
}

func TestResendGRPC_PluginContinueReturnsRecordedStreamID(t *testing.T) {
	cs, store, tripped, addr := setupResendBlockedGRPC(t, starlark.String("DROP"))
	res := callResendGRPC(t, cs, resendBlockedGRPCArgs(addr, "ok"))
	if atomic.LoadInt32(tripped) != 0 {
		t.Fatalf("plugin tripped %d times, want 0", atomic.LoadInt32(tripped))
	}
	var out resendGRPCResult
	decodeResendGRPCResult(t, res, &out)
	assertResendRecordedStreamID(t, cs, store, out.StreamID)
}

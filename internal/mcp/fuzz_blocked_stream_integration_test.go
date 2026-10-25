//go:build e2e && !e2e_smoke

package mcp

// fuzz_blocked_stream_integration_test.go — USK-1371: a fuzz variant's
// stream_id must name a Stream that exists.
//
//   - A variant rejected by the per-variant TargetScope re-check or the
//     Input SafetyFilter leaves a metadata-only blocked_by audit Stream
//     (State=error, BlockedBy, Origin=fuzz, user tag, no Flow rows) under
//     its stream_id — the resend/fuzz mirror of the live path's
//     buildPipelineDropRecorder. The scope half lives in
//     fuzz_scope_recheck_integration_test.go.
//   - A variant that exits the pipeline before RecordStep without a
//     blocked_by attribution (plugin Drop / Respond on the Send side)
//     records nothing, so its stream_id must be empty.

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// fuzzBlockedSafetyPayloads is the [allowed, destructive] payload pair every
// Safety case fuzzes; index 1 trips the destructive-sql preset.
var fuzzBlockedSafetyPayloads = []string{"ok", "DROP TABLE users"}

// setupFuzzBlockedSession boots an MCP server with a fresh flow store wired
// as both flow.Store and flow.FuzzStore, an InsecureSkipVerify TLSTransport
// (fuzz_grpc dials TLS), and any extra options.
func setupFuzzBlockedSession(t *testing.T, extra ...ServerOption) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()
	opts := []ServerOption{WithTLSTransport(&transport.StandardTransport{InsecureSkipVerify: true})}
	if fs, ok := store.(flow.FuzzStore); ok {
		opts = append(opts, WithFuzzStore(fs))
	}
	opts = append(opts, extra...)
	srv := newServer(ctx, nil, store, nil, opts...)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-blocked-stream-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, store
}

// setupFuzzBlockedSafetySession wires the destructive-sql Input
// SafetyFilter preset.
func setupFuzzBlockedSafetySession(t *testing.T) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{{Preset: "destructive-sql"}},
	})
	if err != nil {
		t.Fatalf("safety.NewEngine: %v", err)
	}
	return setupFuzzBlockedSession(t, WithSafetyEngine(engine))
}

// assertFuzzBlockedAuditStream pins the USK-1371 contract for one blocked
// variant: its stream_id resolves through `query resource=flow` to a
// metadata-only audit Stream carrying the blocked_by attribution, the
// fuzz origin, the variant's protocol and the user tag, with no Flow rows.
func assertFuzzBlockedAuditStream(t *testing.T, cs *gomcp.ClientSession, store flow.Store, streamID, wantProtocol, wantBlockedBy, wantTag string) {
	t.Helper()
	if streamID == "" {
		t.Fatalf("blocked variant stream_id is empty, want an audit Stream ID")
	}
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "flow", "id": streamID},
	})
	if err != nil {
		t.Fatalf("CallTool query flow: %v", err)
	}
	if res.IsError {
		t.Fatalf("query resource=flow id=%s failed — the blocked variant's stream_id names no Stream: %s", streamID, extractTextContent(res))
	}
	st, err := store.GetStream(context.Background(), streamID)
	if err != nil {
		t.Fatalf("GetStream(%s): %v", streamID, err)
	}
	if st.State != "error" {
		t.Errorf("audit Stream State = %q, want error", st.State)
	}
	if st.BlockedBy != wantBlockedBy {
		t.Errorf("audit Stream BlockedBy = %q, want %q", st.BlockedBy, wantBlockedBy)
	}
	if st.Origin != flow.OriginFuzz {
		t.Errorf("audit Stream Origin = %q, want %q", st.Origin, flow.OriginFuzz)
	}
	if st.Protocol != wantProtocol {
		t.Errorf("audit Stream Protocol = %q, want %q", st.Protocol, wantProtocol)
	}
	if wantTag != "" && st.Tags["tag"] != wantTag {
		t.Errorf("audit Stream Tags[tag] = %q, want %q", st.Tags["tag"], wantTag)
	}
	if st.Tags["error"] == "" {
		t.Errorf("audit Stream Tags[error] is empty, want the rejection reason")
	}
	flows, err := store.GetFlows(context.Background(), streamID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows(%s): %v", streamID, err)
	}
	if len(flows) != 0 {
		t.Errorf("audit Stream has %d Flow rows, want 0 (metadata-only; a blocked payload must not reach the flow store)", len(flows))
	}
}

// assertFuzzResultsStreamIDs checks that fuzz_results.flow_id persisted the
// same stream_id the tool returned for each variant index.
func assertFuzzResultsStreamIDs(t *testing.T, cs *gomcp.ClientSession, fuzzID string, want map[int]string) {
	t.Helper()
	out := decodeQueryFuzzResults(t, queryFuzzResults(t, cs, fuzzID, nil))
	got := make(map[int]string, len(out.Results))
	for _, r := range out.Results {
		got[r.IndexNum] = r.StreamID
	}
	for idx, w := range want {
		if g, ok := got[idx]; !ok || g != w {
			t.Errorf("fuzz_results[index=%d].flow_id = %q (present=%v), want %q", idx, g, ok, w)
		}
	}
}

// assertSuccessStreamRecorded checks that the allowed variant still owns a
// regular (non-blocked) recorded Stream.
func assertSuccessStreamRecorded(t *testing.T, store flow.Store, streamID, rowErr string) {
	t.Helper()
	if rowErr != "" {
		t.Fatalf("allowed variant error = %q, want empty", rowErr)
	}
	st, err := store.GetStream(context.Background(), streamID)
	if err != nil {
		t.Fatalf("allowed variant GetStream(%q): %v", streamID, err)
	}
	if st.BlockedBy != "" {
		t.Errorf("allowed variant BlockedBy = %q, want empty", st.BlockedBy)
	}
}

func assertSafetyRowError(t *testing.T, rowErr string) {
	t.Helper()
	if !strings.Contains(rowErr, "SafetyFilter blocked") {
		t.Fatalf("variant[1].error = %q, want a SafetyFilter rejection", rowErr)
	}
}

// ---------------------------------------------------------------------------
// Safety rejects — all four fuzz tools.
// ---------------------------------------------------------------------------

func TestFuzzHTTP_SafetyBlockedVariantRecordsAuditStream(t *testing.T) {
	cs, store := setupFuzzBlockedSafetySession(t)
	echo, _ := startFuzzHTTPEcho(t)
	const tag = "usk1371-http"
	out := callFuzzHTTP(t, cs, map[string]any{
		"method":    "POST",
		"scheme":    "http",
		"authority": strings.TrimPrefix(echo.URL, "http://"),
		"path":      "/",
		"body":      "seed",
		"positions": []map[string]any{
			{"path": "body", "payloads": fuzzBlockedSafetyPayloads},
		},
		"tag":        tag,
		"timeout_ms": 5000,
	})
	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	assertSuccessStreamRecorded(t, store, out.Variants[0].StreamID, out.Variants[0].Error)
	assertSafetyRowError(t, out.Variants[1].Error)
	assertFuzzBlockedAuditStream(t, cs, store, out.Variants[1].StreamID, "http", pipeline.BlockedBySafetyFilter, tag)
	assertFuzzResultsStreamIDs(t, cs, out.FuzzID, map[int]string{0: out.Variants[0].StreamID, 1: out.Variants[1].StreamID})
}

func TestFuzzWS_SafetyBlockedVariantRecordsAuditStream(t *testing.T) {
	cs, store := setupFuzzBlockedSafetySession(t)
	addr, closeFn := newWebSocketEchoServer(t)
	t.Cleanup(closeFn)
	const tag = "usk1371-ws"
	out := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": fuzzBlockedSafetyPayloads},
		},
		"tag":        tag,
		"timeout_ms": 5000,
	})
	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	assertSuccessStreamRecorded(t, store, out.Variants[0].StreamID, out.Variants[0].Error)
	assertSafetyRowError(t, out.Variants[1].Error)
	assertFuzzBlockedAuditStream(t, cs, store, out.Variants[1].StreamID, "ws", pipeline.BlockedBySafetyFilter, tag)
	assertFuzzResultsStreamIDs(t, cs, out.FuzzID, map[int]string{0: out.Variants[0].StreamID, 1: out.Variants[1].StreamID})
}

func TestFuzzGRPC_SafetyBlockedVariantRecordsAuditStream(t *testing.T) {
	cs, store := setupFuzzBlockedSafetySession(t)
	addr, shutdown := startFuzzGRPCUpstream(t, &fuzzGRPCEchoServer{})
	defer shutdown()
	const tag = "usk1371-grpc"
	out := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages":    []map[string]any{{"payload": "seed"}},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": fuzzBlockedSafetyPayloads},
		},
		"tag":        tag,
		"timeout_ms": 10000,
	})
	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	assertSuccessStreamRecorded(t, store, out.Variants[0].StreamID, out.Variants[0].Error)
	assertSafetyRowError(t, out.Variants[1].Error)
	assertFuzzBlockedAuditStream(t, cs, store, out.Variants[1].StreamID, "grpc", pipeline.BlockedBySafetyFilter, tag)
	assertFuzzResultsStreamIDs(t, cs, out.FuzzID, map[int]string{0: out.Variants[0].StreamID, 1: out.Variants[1].StreamID})
}

func TestFuzzRaw_SafetyBlockedVariantRecordsAuditStream(t *testing.T) {
	cs, store := setupFuzzBlockedSafetySession(t)
	addr, _ := startFuzzRawTCPServer(t)
	const tag = "usk1371-raw"
	out := callFuzzRaw(t, cs, map[string]any{
		"target_addr": addr,
		"positions": []map[string]any{
			{"path": "payload", "payloads": fuzzBlockedSafetyPayloads},
		},
		"tag":        tag,
		"timeout_ms": 5000,
	})
	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	assertSuccessStreamRecorded(t, store, out.Variants[0].StreamID, out.Variants[0].Error)
	assertSafetyRowError(t, out.Variants[1].Error)
	assertFuzzBlockedAuditStream(t, cs, store, out.Variants[1].StreamID, "raw", pipeline.BlockedBySafetyFilter, tag)
	assertFuzzResultsStreamIDs(t, cs, out.FuzzID, map[int]string{0: out.Variants[0].StreamID, 1: out.Variants[1].StreamID})
}

// ---------------------------------------------------------------------------
// Unlabelled pre-RecordStep exits (plugin Drop / Respond on Send).
// ---------------------------------------------------------------------------

// fuzzBlockedPluginHook returns a post-pipeline hook whose action depends
// on whether the request carries the "trip" marker: the marked variant is
// dropped / answered by the plugin, the other continues to the wire.
func fuzzBlockedPluginHook(proto, event string, tripped *int32, result starlark.Value) pluginv2.Hook {
	return pluginv2.Hook{
		Protocol:   proto,
		Event:      event,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "usk1371-" + proto + "-" + event,
		Fn: starlark.NewBuiltin("usk1371", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			if len(args) == 0 {
				return starlark.None, nil
			}
			msg, ok := args[0].(starlark.Mapping)
			if !ok {
				return starlark.None, nil
			}
			for _, key := range []string{"body", "metadata"} {
				v, found, err := msg.Get(starlark.String(key))
				if err != nil || !found {
					continue
				}
				if strings.Contains(v.String(), "trip") {
					atomic.AddInt32(tripped, 1)
					return result, nil
				}
			}
			return starlark.None, nil
		}),
	}
}

// assertNoDanglingStreamID enforces the class rule: a non-empty stream_id
// must name an existing Stream. For a plugin Drop / Respond on the Send
// side nothing is recorded, so the stream_id must be empty.
func assertNoDanglingStreamID(t *testing.T, store flow.Store, idx int, streamID string) {
	t.Helper()
	if streamID == "" {
		return
	}
	if _, err := store.GetStream(context.Background(), streamID); err != nil {
		t.Errorf("variants[%d].stream_id = %q names no Stream (GetStream: %v) — want empty when nothing was recorded", idx, streamID, err)
	}
}

func TestFuzzHTTP_PluginSendExitLeavesNoDanglingStreamID(t *testing.T) {
	cases := []struct {
		name   string
		result starlark.Value
		check  func(t *testing.T, row fuzzHTTPVariantRow)
	}{
		{
			name:   "drop",
			result: starlark.String("DROP"),
			check: func(t *testing.T, row fuzzHTTPVariantRow) {
				if row.Error == "" {
					t.Errorf("dropped variant error is empty, want the pipeline drop reason")
				}
			},
		},
		{
			name:   "respond",
			result: &pluginv2.RespondAction{HTTPResponse: &pluginv2.HTTPRespondPayload{StatusCode: http.StatusTeapot}},
			check: func(t *testing.T, row fuzzHTTPVariantRow) {
				if row.StatusCode != http.StatusTeapot {
					t.Errorf("responded variant status = %d, want %d (the plugin's custom response)", row.StatusCode, http.StatusTeapot)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tripped int32
			engine := pluginv2.NewEngine(nil)
			engine.Registry().Register(fuzzBlockedPluginHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, &tripped, tc.result))
			cs, store := setupFuzzBlockedSession(t, WithPluginv2Engine(engine))
			echo, _ := startFuzzHTTPEcho(t)
			out := callFuzzHTTP(t, cs, map[string]any{
				"method":    "POST",
				"scheme":    "http",
				"authority": strings.TrimPrefix(echo.URL, "http://"),
				"path":      "/",
				"body":      "seed",
				"positions": []map[string]any{
					{"path": "body", "payloads": []string{"ok", "trip"}},
				},
				"timeout_ms": 5000,
			})
			if atomic.LoadInt32(&tripped) != 1 {
				t.Fatalf("plugin tripped %d times, want 1", tripped)
			}
			if len(out.Variants) != 2 {
				t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
			}
			assertSuccessStreamRecorded(t, store, out.Variants[0].StreamID, out.Variants[0].Error)
			tc.check(t, out.Variants[1])
			assertNoDanglingStreamID(t, store, 1, out.Variants[1].StreamID)
			assertFuzzResultsStreamIDs(t, cs, out.FuzzID, map[int]string{1: out.Variants[1].StreamID})
		})
	}
}

func TestFuzzGRPC_PluginSendExitLeavesNoDanglingStreamID(t *testing.T) {
	cases := []struct {
		name   string
		result starlark.Value
	}{
		{name: "drop", result: starlark.String("DROP")},
		{name: "respond", result: &pluginv2.RespondAction{GRPCResponse: &pluginv2.GRPCRespondPayload{Status: 7, Message: "denied by plugin"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tripped int32
			engine := pluginv2.NewEngine(nil)
			engine.Registry().Register(fuzzBlockedPluginHook(pluginv2.ProtoGRPC, pluginv2.EventOnStart, &tripped, tc.result))
			cs, store := setupFuzzBlockedSession(t, WithPluginv2Engine(engine))
			addr, shutdown := startFuzzGRPCUpstream(t, &fuzzGRPCEchoServer{})
			defer shutdown()
			out := callFuzzGRPC(t, cs, map[string]any{
				"target_addr": addr,
				"scheme":      "https",
				"service":     fuzzGRPCServiceName,
				"method":      fuzzGRPCMethodUnary,
				"messages":    []map[string]any{{"payload": "seed"}},
				"metadata":    []map[string]any{{"name": "x-marker", "value": "base"}},
				"positions": []map[string]any{
					{"path": "metadata[0].value", "payloads": []string{"ok", "trip"}},
				},
				"timeout_ms": 10000,
			})
			if atomic.LoadInt32(&tripped) != 1 {
				t.Fatalf("plugin tripped %d times, want 1", tripped)
			}
			if len(out.Variants) != 2 {
				t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
			}
			assertSuccessStreamRecorded(t, store, out.Variants[0].StreamID, out.Variants[0].Error)
			assertNoDanglingStreamID(t, store, 1, out.Variants[1].StreamID)
			assertFuzzResultsStreamIDs(t, cs, out.FuzzID, map[int]string{1: out.Variants[1].StreamID})
		})
	}
}

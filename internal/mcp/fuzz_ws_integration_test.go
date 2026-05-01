//go:build e2e

package mcp

// fuzz_ws_integration_test.go — RFC-001 N8 acceptance gate for the
// fuzz_ws MCP tool (USK-678).
//
// Acceptance criteria:
//   AC#1: N variant generation + per-variant Stream rows in flow store
//   AC#2: PluginStepPost fires per variant; PluginStepPre never fires
//   AC#3: Position field path syntax aligned with WSMessage struct
//         (payload | close_reason)
//   AC#4: Legacy `fuzz` tool unaffected (parallel coexistence)

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// fuzzWSHookCallable wraps a Go counter increment in a Starlark
// Callable. Mirrors helpers in resend_*_integration_test.go.
func fuzzWSHookCallable(name string, fn func()) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		fn()
		return starlark.None, nil
	})
}

// setupFuzzWSSession spins up an MCP server pre-wired with a fresh
// flow store and a pluginv2.Engine that pre-registers pre/post counter
// hooks for ("ws", "on_message"). Returns the client session, the
// flow store, and the (preCount, postCount) atomic pointers.
func setupFuzzWSSession(t *testing.T) (*gomcp.ClientSession, flow.Store, *int32, *int32) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	var preCount, postCount int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoWS,
		Event:      pluginv2.EventOnMessage,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "fuzz-ws-pre",
		Fn: fuzzWSHookCallable("pre", func() {
			atomic.AddInt32(&preCount, 1)
		}),
	})
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoWS,
		Event:      pluginv2.EventOnMessage,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "fuzz-ws-post",
		Fn: fuzzWSHookCallable("post", func() {
			atomic.AddInt32(&postCount, 1)
		}),
	})

	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil, WithPluginv2Engine(engine))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-ws-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store, &preCount, &postCount
}

// callFuzzWS issues the fuzz_ws tool and decodes the structured
// result. Test fails on transport errors or IsError responses.
func callFuzzWS(t *testing.T, cs *gomcp.ClientSession, input map[string]any) *fuzzWSResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "fuzz_ws",
		Arguments: input,
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_ws: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("tool returned error: %s", msg.String())
	}
	if res.StructuredContent == nil {
		t.Fatal("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out fuzzWSResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	return &out
}

// ---------------------------------------------------------------------------
// AC#1 + AC#2 — N variant generation + per-variant Stream rows + plugin
// hook firing per variant (post fires N+ times; pre never fires).
// ---------------------------------------------------------------------------

func TestFuzzWS_PayloadPositionGeneratesVariants(t *testing.T) {
	cs, store, preCount, postCount := setupFuzzWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	payloads := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
	})

	if result.TotalVariants != len(payloads) {
		t.Errorf("TotalVariants = %d, want %d", result.TotalVariants, len(payloads))
	}
	if result.CompletedVariants != len(payloads) {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}
	if len(result.Variants) != len(payloads) {
		t.Fatalf("len(Variants) = %d, want %d", len(result.Variants), len(payloads))
	}

	// Per-variant Stream rows + AC#3 echo verification via the recorded
	// receive Flow body. The variant row only carries scalar metadata
	// (size + opcode + close fields) — full payloads are intentionally
	// not stored on the row to bound worst-case memory (CWE-770).
	seen := map[string]bool{}
	for i, row := range result.Variants {
		if row.StreamID == "" {
			t.Errorf("variants[%d].StreamID is empty", i)
			continue
		}
		s, err := store.GetStream(context.Background(), row.StreamID)
		if err != nil || s == nil {
			t.Errorf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
			continue
		}
		flows, err := store.GetFlows(context.Background(), row.StreamID, flow.FlowListOptions{Direction: "receive"})
		if err != nil {
			t.Errorf("variants[%d]: GetFlows(%s) err=%v", i, row.StreamID, err)
			continue
		}
		for _, f := range flows {
			if len(f.Body) > 0 {
				seen[string(f.Body)] = true
			}
		}
	}
	for _, p := range payloads {
		if !seen[p] {
			t.Errorf("upstream did not echo back payload %q (saw %v)", p, seen)
		}
	}

	// AC#2: post fires at least once per variant (Send envelope; the
	// receive frame fires too, so the count is >= N). Pre never fires
	// (resend bypass).
	if got := atomic.LoadInt32(preCount); got != 0 {
		t.Errorf("on_message pre hook fired %d times, want 0 (PluginStepPre bypassed)", got)
	}
	wantPostMin := int32(len(payloads))
	if got := atomic.LoadInt32(postCount); got < wantPostMin {
		t.Errorf("on_message post hook fired %d times, want >= %d (one Send envelope per variant)", got, wantPostMin)
	}
}

// ---------------------------------------------------------------------------
// AC#3 — Position path syntax: close_reason mutation.
// ---------------------------------------------------------------------------

func TestFuzzWS_CloseReasonPosition(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	reasons := []string{"goodbye", "see-ya", "ciao"}
	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "close",
		"close_code":  1000,
		"positions": []map[string]any{
			{"path": "close_reason", "payloads": reasons},
		},
		"timeout_ms": 5000,
	})

	if result.CompletedVariants != len(reasons) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(reasons))
	}

	// AC#3 mutation assertion: the echo server echoes the Close frame
	// back with the same payload, so each variant's CloseReason should
	// match what we sent.
	seen := map[string]bool{}
	for _, row := range result.Variants {
		seen[row.CloseReason] = true
	}
	for _, want := range reasons {
		if !seen[want] {
			t.Errorf("upstream did not echo back close_reason=%q (saw %v)", want, seen)
		}
	}
}

// ---------------------------------------------------------------------------
// Cartesian product across two positions.
// ---------------------------------------------------------------------------

func TestFuzzWS_TwoPositionCartesian(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	payloads := []string{"p1", "p2"}
	reasons := []string{"r1", "r2", "r3"}
	expectedTotal := len(payloads) * len(reasons) // 6

	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "close",
		"close_code":  1000,
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
			{"path": "close_reason", "payloads": reasons},
		},
		"timeout_ms": 10000,
	})
	if result.TotalVariants != expectedTotal {
		t.Errorf("TotalVariants = %d, want %d", result.TotalVariants, expectedTotal)
	}
	if result.CompletedVariants != expectedTotal {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, expectedTotal)
	}
}

// ---------------------------------------------------------------------------
// Validation: empty positions rejected.
// ---------------------------------------------------------------------------

func TestFuzzWS_RejectsEmptyPositions(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_ws",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"path":        "/echo",
			"opcode":      "text",
			"positions":   []map[string]any{},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for empty positions; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: invalid path syntax rejected.
// ---------------------------------------------------------------------------

func TestFuzzWS_RejectsInvalidPath(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_ws",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"path":        "/echo",
			"opcode":      "text",
			"positions": []map[string]any{
				{"path": "opcode", "payloads": []string{"x"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for invalid path; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: variant count cap enforced.
// ---------------------------------------------------------------------------

func TestFuzzWS_RejectsExcessiveVariantCount(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	bigList := make([]string, 100)
	for i := range bigList {
		bigList[i] = fmt.Sprintf("p%d", i)
	}
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_ws",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"path":        "/echo",
			"opcode":      "text",
			"positions": []map[string]any{
				{"path": "payload", "payloads": bigList},
				{"path": "close_reason", "payloads": bigList},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for excessive variant count; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: empty payloads in a position rejected.
// ---------------------------------------------------------------------------

func TestFuzzWS_RejectsEmptyPayloads(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_ws",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"path":        "/echo",
			"opcode":      "text",
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for empty payloads; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// stop_on_close aborts remaining variants when an upstream returns Close.
// ---------------------------------------------------------------------------

func TestFuzzWS_StopOnCloseAbortsRemaining(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	// Variant 0 is "text" opcode → upstream echoes a text frame back
	// (no close); variant 1 sends "close" via the close_reason override.
	// Wait — close_reason path doesn't change the opcode. The echo
	// server echoes Close frames back, so any variant with opcode=close
	// terminates as Close. Use payload positions on a close-opcode
	// frame: every variant terminates as Close, so stop_on_close fires
	// at variant 0 and only 1 variant runs.
	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "close",
		"close_code":  1000,
		"positions": []map[string]any{
			{"path": "close_reason", "payloads": []string{"r1", "r2", "r3"}},
		},
		"stop_on_close": true,
		"timeout_ms":    5000,
	})
	if result.CompletedVariants != 1 {
		t.Errorf("CompletedVariants = %d, want 1 (first variant returned Close, rest aborted)", result.CompletedVariants)
	}
	if result.StoppedReason == "" {
		t.Error("StoppedReason is empty; want a stop_on_close reason")
	}
}

// ---------------------------------------------------------------------------
// Tag application — every variant Stream gets the tag.
// ---------------------------------------------------------------------------

func TestFuzzWS_TagAppliedToEachVariantStream(t *testing.T) {
	cs, store, _, _ := setupFuzzWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"v1", "v2"}},
		},
		"tag":        "fuzz-ws-tag-7",
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}
	for i, row := range result.Variants {
		s, err := store.GetStream(context.Background(), row.StreamID)
		if err != nil || s == nil {
			t.Fatalf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
		}
		if s.Tags["tag"] != "fuzz-ws-tag-7" {
			t.Errorf("variants[%d].Tags[tag] = %q, want fuzz-ws-tag-7", i, s.Tags["tag"])
		}
	}
}

// ---------------------------------------------------------------------------
// Validation: per-payload decoded size cap (CWE-770).
// ---------------------------------------------------------------------------

func TestFuzzWS_RejectsExcessivePayloadSize(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	bigPayload := strings.Repeat("A", 2<<20) // 2 MiB > 1 MiB cap
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_ws",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"path":        "/echo",
			"opcode":      "text",
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{bigPayload}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for oversized payload; got %+v", res)
	}
	var msg strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			msg.WriteString(tc.Text)
		}
	}
	if !strings.Contains(msg.String(), "exceeds") {
		t.Errorf("error message %q does not mention size cap", msg.String())
	}
}

// ---------------------------------------------------------------------------
// AC#4 — Legacy `fuzz` tool unaffected (parallel coexistence).
// ---------------------------------------------------------------------------

func TestFuzzWS_LegacyCoexists(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	res, err := cs.ListTools(context.Background(), &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var hasFuzz, hasFuzzWS bool
	for _, tool := range res.Tools {
		switch tool.Name {
		case "fuzz":
			hasFuzz = true
		case "fuzz_ws":
			hasFuzzWS = true
		}
	}
	if !hasFuzz {
		t.Errorf("legacy 'fuzz' tool missing")
	}
	if !hasFuzzWS {
		t.Errorf("'fuzz_ws' tool missing")
	}
}

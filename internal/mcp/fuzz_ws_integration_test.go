//go:build e2e && !e2e_smoke

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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
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
	// USK-836: the underlying SQLiteStore implements both flow.Store and
	// flow.FuzzStore. Wire it through WithFuzzStore so handleFuzzWS can
	// persist fuzz_jobs / fuzz_results rows and the query tool can read
	// them back via the same session.
	opts := []ServerOption{WithPluginv2Engine(engine)}
	if fs, ok := store.(flow.FuzzStore); ok {
		opts = append(opts, WithFuzzStore(fs))
	}
	srv := newServer(ctx, nil, store, nil, opts...)
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
// USK-836 — sync fuzz_ws persists fuzz_jobs + fuzz_results rows so the
// AI agent's "issue many variants -> query aggregate -> triage outliers"
// workflow is reachable end-to-end (mirrors USK-827 for fuzz_http).
// ---------------------------------------------------------------------------

// TestFuzzWS_PersistsFuzzJobAndResults is the canonical four-step repro
// from USK-836: run a sync fuzz, capture fuzz_id from the response, then
// exercise query fuzz_jobs + query fuzz_results + outliers_only filter
// end-to-end. Without USK-836 the fuzz_jobs row would not exist and
// outliers_only would fail with "fuzz_id is required".
func TestFuzzWS_PersistsFuzzJobAndResults(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	payloads := []string{"alpha", "beta", "gamma", "delta"}
	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"tag":        "usk-836-canonical",
		"timeout_ms": 5000,
	})

	// 1. Response carries fuzz_id (UUID).
	if result.FuzzID == "" {
		t.Fatal("fuzz_ws response missing fuzz_id")
	}
	if result.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}

	// 2. query fuzz_jobs returns exactly one row matching fuzz_id + tag.
	jobsRes, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "fuzz_jobs",
			"filter":   map[string]any{"tag": "usk-836-canonical"},
		},
	})
	if err != nil {
		t.Fatalf("query fuzz_jobs: %v", err)
	}
	if jobsRes.IsError {
		t.Fatalf("query fuzz_jobs returned error: %+v", jobsRes.Content)
	}
	var jobsOut queryFuzzJobsResult
	jobsText, ok := jobsRes.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("jobs content[0] type = %T", jobsRes.Content[0])
	}
	if err := json.Unmarshal([]byte(jobsText.Text), &jobsOut); err != nil {
		t.Fatalf("unmarshal jobs: %v", err)
	}
	if jobsOut.Total != 1 {
		t.Fatalf("query fuzz_jobs total = %d, want 1 (jobs=%+v)", jobsOut.Total, jobsOut.Jobs)
	}
	if jobsOut.Jobs[0].ID != result.FuzzID {
		t.Errorf("fuzz_jobs row id = %q, want %q", jobsOut.Jobs[0].ID, result.FuzzID)
	}
	if jobsOut.Jobs[0].Status != "completed" {
		t.Errorf("fuzz_jobs status = %q, want completed", jobsOut.Jobs[0].Status)
	}
	if jobsOut.Jobs[0].CompletedAt == nil {
		t.Error("fuzz_jobs completed_at = nil, want non-nil")
	}
	if jobsOut.Jobs[0].Total != len(payloads) {
		t.Errorf("fuzz_jobs total = %d, want %d", jobsOut.Jobs[0].Total, len(payloads))
	}
	if jobsOut.Jobs[0].CompletedCount != len(payloads) {
		t.Errorf("fuzz_jobs completed_count = %d, want %d", jobsOut.Jobs[0].CompletedCount, len(payloads))
	}

	// 3. query fuzz_results returns one row per variant. Reuse the
	// package-level helpers queryFuzzResults / decodeQueryFuzzResults
	// from fuzz_http_integration_test.go (per design decision #9).
	resultsRes := queryFuzzResults(t, cs, result.FuzzID, nil)
	resultsOut := decodeQueryFuzzResults(t, resultsRes)
	if resultsOut.Total != len(payloads) {
		t.Errorf("fuzz_results total = %d, want %d", resultsOut.Total, len(payloads))
	}
	if resultsOut.Count != len(payloads) {
		t.Errorf("fuzz_results count = %d, want %d", resultsOut.Count, len(payloads))
	}
	if resultsOut.Summary == nil {
		t.Fatal("fuzz_results summary = nil, want non-nil")
	}

	// Per-row sanity: each row references a variant Stream + the right fuzz_id.
	streamIDsByVariant := map[string]string{}
	for _, v := range result.Variants {
		streamIDsByVariant[v.StreamID] = v.Payloads["payload"]
	}
	for _, r := range resultsOut.Results {
		if r.FuzzID != result.FuzzID {
			t.Errorf("fuzz_results row fuzz_id = %q, want %q", r.FuzzID, result.FuzzID)
		}
		if r.StreamID == "" {
			t.Errorf("fuzz_results row %d stream_id is empty", r.IndexNum)
		}
		if _, ok := streamIDsByVariant[r.StreamID]; !ok {
			t.Errorf("fuzz_results stream_id %q not found in response variants", r.StreamID)
		}
		// WebSocket variants terminating on a non-Close echo frame map
		// row.CloseCode == 0 (per design decision #11). StatusCode is
		// int(row.CloseCode), so it should be 0 on a successful text echo.
		if r.StatusCode != 0 {
			t.Errorf("fuzz_results row %d status_code = %d, want 0 (text echo: no Close frame)", r.IndexNum, r.StatusCode)
		}
	}

	// 4. outliers_only filter no longer fails with the "fuzz_id required"
	// error — it now reaches the aggregation path.
	outliersRes := queryFuzzResults(t, cs, result.FuzzID, map[string]any{"outliers_only": true})
	if outliersRes.IsError {
		t.Fatalf("query fuzz_results { outliers_only:true } returned error: %+v", outliersRes.Content)
	}
}

// TestFuzzWS_ErrorVariantRecordedAsFuzzResult covers the error path: a
// variant whose upstream connection fails still produces a fuzz_results
// row with a non-empty error column. Without this, the aggregation
// under-counts by the error-variant population.
//
// The listener accepts the TCP connection but immediately closes it
// without responding to the WebSocket upgrade — this produces an
// "upgrade" error per variant regardless of which payload was
// substituted.
func TestFuzzWS_ErrorVariantRecordedAsFuzzResult(t *testing.T) {
	cs, store, _, _ := setupFuzzWSSession(t)

	// Listener that accepts then immediately closes — emulates a
	// dead-on-arrival upstream that fails the upgrade handshake.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := ln.Addr().String()

	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"v1", "v2"}},
		},
		"tag":        "usk-836-error-path",
		"timeout_ms": 2000,
	})

	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}

	// Each variant should surface an error (upgrade or receive fails
	// because the upstream closed without responding).
	for i, v := range result.Variants {
		if v.Error == "" {
			t.Errorf("variants[%d]: Error is empty, want non-empty (upstream closes before upgrade)", i)
		}
	}

	// USK-882: every variant Stream must transition to State="error"
	// when the exchange failed. Without finalizeResendStream in
	// runFuzzWSSingleVariant the rows stay pinned at "active" and
	// stream-state filtering would surface completed-but-failed fuzz
	// variants as still-running.
	for i, row := range result.Variants {
		if row.StreamID == "" {
			continue
		}
		s, err := store.GetStream(context.Background(), row.StreamID)
		if err != nil || s == nil {
			t.Errorf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
			continue
		}
		if s.State != "error" {
			t.Errorf("variants[%d].State = %q, want %q (USK-882: fuzz_ws must finalise failed variants as error)", i, s.State, "error")
		}
	}

	// fuzz_results row exists for BOTH variants — error variants must
	// not be silently dropped.
	resultsRes := queryFuzzResults(t, cs, result.FuzzID, nil)
	resultsOut := decodeQueryFuzzResults(t, resultsRes)
	if resultsOut.Total != 2 {
		t.Fatalf("fuzz_results total = %d, want 2", resultsOut.Total)
	}
	for _, r := range resultsOut.Results {
		if r.Error == "" {
			t.Errorf("fuzz_results row %d error is empty, want non-empty", r.IndexNum)
		}
	}

	// fuzz_jobs row reflects error_count == 2 (both variants errored).
	// Status stays "completed" — the run itself ran to natural
	// exhaustion; per-variant errors do not flip the run-level status.
	jobsRes, callErr := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "fuzz_jobs",
			"filter":   map[string]any{"tag": "usk-836-error-path"},
		},
	})
	if callErr != nil {
		t.Fatalf("query fuzz_jobs: %v", callErr)
	}
	if jobsRes.IsError {
		t.Fatalf("query fuzz_jobs returned error: %+v", jobsRes.Content)
	}
	var jobsOut queryFuzzJobsResult
	if err := json.Unmarshal([]byte(jobsRes.Content[0].(*gomcp.TextContent).Text), &jobsOut); err != nil {
		t.Fatalf("unmarshal jobs: %v", err)
	}
	if jobsOut.Total != 1 {
		t.Fatalf("jobs total = %d, want 1", jobsOut.Total)
	}
	if jobsOut.Jobs[0].ErrorCount != 2 {
		t.Errorf("fuzz_jobs error_count = %d, want 2", jobsOut.Jobs[0].ErrorCount)
	}
	if jobsOut.Jobs[0].Status != "completed" {
		t.Errorf("fuzz_jobs status = %q, want completed", jobsOut.Jobs[0].Status)
	}
}

// TestFuzzWS_VariantStreamStampedOriginFuzz verifies the
// pipeline.WithOrigin(flow.OriginFuzz) wiring on buildFuzzWSPipeline.
// Each variant Stream must carry Origin = "fuzz" so the query tool can
// separate fuzz-originated streams from live capture.
func TestFuzzWS_VariantStreamStampedOriginFuzz(t *testing.T) {
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
		if s.Origin != flow.OriginFuzz {
			t.Errorf("variants[%d].Origin = %q, want %q", i, s.Origin, flow.OriginFuzz)
		}
	}
}

// TestFuzzWS_FinalizesUnderCallerCancel pins decision #3: even when the
// caller cancels their context mid-run, the fuzz_jobs row must still
// get its closing UPDATE (status / completed_at) because
// finalizeFuzzWSJob is dispatched with a fresh background context.
//
// Repro: many variants against a real echo server so the variant loop
// is still running when we cancel. After the cancel returns, the
// fuzz_jobs row must still have completed_at != nil.
func TestFuzzWS_FinalizesUnderCallerCancel(t *testing.T) {
	cs, _, _, _ := setupFuzzWSSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	callCtx, cancel := context.WithCancel(context.Background())
	// Cancel after a short delay so the fuzz_jobs row is guaranteed
	// inserted before we exercise the finalize path. Each WS variant
	// involves a fresh TCP dial + upgrade dance + frame round-trip, so
	// 50 ms is enough to let the run start but reliably cancels before
	// 50 variants complete.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	payloads := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		payloads = append(payloads, fmt.Sprintf("v%d", i))
	}
	res, _ := cs.CallTool(callCtx, &gomcp.CallToolParams{
		Name: "fuzz_ws",
		Arguments: map[string]any{
			"target_addr": addr,
			"scheme":      "ws",
			"path":        "/echo",
			"opcode":      "text",
			"positions": []map[string]any{
				{"path": "payload", "payloads": payloads},
			},
			"tag":        "usk-836-cancel",
			"timeout_ms": 5000,
		},
	})
	_ = res // either an in-band stopped_reason or a transport-level cancel error is OK

	// The MCP in-memory transport's Await returns ctx.Err() on cancel
	// without waiting for the server handler to finish (jsonrpc2/conn.go
	// AsyncCall.Await), so the finalize UPDATE may still be in flight
	// when CallTool returns. Poll fuzz_jobs through a fresh context until
	// the closing UPDATE lands or a deadline elapses — without this
	// deterministic sync the assertion races the handler goroutine.
	var jobsOut queryFuzzJobsResult
	deadline := time.Now().Add(3 * time.Second)
	for {
		jobsRes, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "query",
			Arguments: map[string]any{
				"resource": "fuzz_jobs",
				"filter":   map[string]any{"tag": "usk-836-cancel"},
			},
		})
		if err != nil {
			t.Fatalf("query fuzz_jobs: %v", err)
		}
		if jobsRes.IsError {
			t.Fatalf("query fuzz_jobs returned error: %+v", jobsRes.Content)
		}
		jobsOut = queryFuzzJobsResult{}
		if err := json.Unmarshal([]byte(jobsRes.Content[0].(*gomcp.TextContent).Text), &jobsOut); err != nil {
			t.Fatalf("unmarshal jobs: %v", err)
		}
		if jobsOut.Total == 1 && jobsOut.Jobs[0].CompletedAt != nil {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if jobsOut.Total != 1 {
		t.Fatalf("jobs total = %d, want 1 (start INSERT must land via background ctx)", jobsOut.Total)
	}
	if jobsOut.Jobs[0].CompletedAt == nil {
		t.Errorf("fuzz_jobs.completed_at = nil after caller cancel; finalize did not land")
	}
}

// TestFuzzWS_PingAllVariantsComplete is the USK-880 regression gate on
// the fuzz_ws side: fuzz_ws reuses runResendWS per variant, so the
// shared receive-loop fix must propagate. Each variant sends a Ping
// against an upstream that replies with a Pong; every variant must
// complete (not hang on the old absorb-pong continue) and surface no
// error.
//
// USK-882: fuzz_ws now calls finalizeResendStream per variant (mirror of
// USK-832 for fuzz_http). The per-variant Stream therefore transitions
// out of State="active" and we assert State="complete" below.
func TestFuzzWS_PingAllVariantsComplete(t *testing.T) {
	cs, store, _, _ := setupFuzzWSSession(t)
	addr, cleanup := newWSPongOnPingEchoServer(t)
	defer cleanup()

	payloads := []string{"p1", "p2", "p3"}

	done := make(chan struct{})
	var result *fuzzWSResult
	go func() {
		result = callFuzzWS(t, cs, map[string]any{
			"target_addr": addr,
			"scheme":      "ws",
			"path":        "/echo",
			"opcode":      "ping",
			"positions": []map[string]any{
				{"path": "payload", "payloads": payloads},
			},
			"timeout_ms": 5000,
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("fuzz_ws ping did not complete within 5s; USK-880 regression (ping variants hang)")
	}

	if result.TotalVariants != len(payloads) {
		t.Errorf("TotalVariants = %d, want %d", result.TotalVariants, len(payloads))
	}
	if result.CompletedVariants != len(payloads) {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}
	for i, row := range result.Variants {
		if row.Error != "" {
			t.Errorf("variants[%d].Error = %q, want empty", i, row.Error)
		}
		if row.StreamID == "" {
			t.Errorf("variants[%d].StreamID is empty", i)
			continue
		}
		// Each variant terminated on a Pong frame: opcode must be "pong"
		// (proves the ping plan returned on the matching reply rather
		// than absorbing it and hanging until a later frame).
		if row.Opcode != "pong" {
			t.Errorf("variants[%d].Opcode = %q, want pong", i, row.Opcode)
		}
		s, err := store.GetStream(context.Background(), row.StreamID)
		if err != nil || s == nil {
			t.Errorf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
			continue
		}
		// USK-882: every variant Stream must transition out of
		// State="active" once the exchange returns. Without the
		// finalizeResendStream call in runFuzzWSSingleVariant, fuzz_ws
		// bypasses session.RunSession's OnComplete hook so the rows
		// would stay pinned at "active".
		if s.State != "complete" {
			t.Errorf("variants[%d].State = %q, want %q (USK-882: fuzz_ws must finalise variant stream lifecycle)", i, s.State, "complete")
		}
	}
}

// ---------------------------------------------------------------------------
// USK-882 opcode-coverage tests for the per-variant finalize fix. Each
// opcode that terminates on an echoed reply (text / binary / close) must
// leave its variant Stream at State="complete". Pong is exercised
// separately because the existing echo server has no semantics that lets
// the receive-loop return naturally on an inbound Pong (it would absorb
// per RFC 6455 §5.5.3 and re-block).
// ---------------------------------------------------------------------------

// TestFuzzWS_OpcodeAllVariantsComplete drives text / binary / close
// opcodes against the shared echo server (newWebSocketEchoServer). Each
// case verifies every variant's Stream lands at State="complete" after
// the per-variant finalizeResendStream call in runFuzzWSSingleVariant.
func TestFuzzWS_OpcodeAllVariantsComplete(t *testing.T) {
	cases := []struct {
		name             string
		opcode           string
		positionPath     string
		positionEncoding string
		payloads         []string
		extra            map[string]any
	}{
		{
			name:         "text",
			opcode:       "text",
			positionPath: "payload",
			payloads:     []string{"t1", "t2", "t3"},
		},
		{
			name:             "binary",
			opcode:           "binary",
			positionPath:     "payload",
			positionEncoding: "base64",
			payloads:         []string{"YjE=", "YjI=", "YjM="}, // base64("b1","b2","b3")
		},
		{
			name:         "close",
			opcode:       "close",
			positionPath: "close_reason",
			payloads:     []string{"bye-1", "bye-2", "bye-3"},
			extra: map[string]any{
				"close_code": 1000,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs, store, _, _ := setupFuzzWSSession(t)
			addr, cleanup := newWebSocketEchoServer(t)
			defer cleanup()

			position := map[string]any{
				"path":     tc.positionPath,
				"payloads": tc.payloads,
			}
			if tc.positionEncoding != "" {
				position["encoding"] = tc.positionEncoding
			}

			args := map[string]any{
				"target_addr": addr,
				"scheme":      "ws",
				"path":        "/echo",
				"opcode":      tc.opcode,
				"positions":   []map[string]any{position},
				"timeout_ms":  5000,
			}
			for k, v := range tc.extra {
				args[k] = v
			}

			result := callFuzzWS(t, cs, args)

			if result.CompletedVariants != len(tc.payloads) {
				t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(tc.payloads))
			}

			for i, row := range result.Variants {
				if row.Error != "" {
					t.Errorf("variants[%d].Error = %q, want empty", i, row.Error)
				}
				if row.StreamID == "" {
					t.Errorf("variants[%d].StreamID is empty", i)
					continue
				}
				s, err := store.GetStream(context.Background(), row.StreamID)
				if err != nil || s == nil {
					t.Errorf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
					continue
				}
				// USK-882: per-variant Stream must transition out of
				// State="active" — the finalizeResendStream call in
				// runFuzzWSSingleVariant is what makes this hold.
				if s.State != "complete" {
					t.Errorf("variants[%d].State = %q, want %q (USK-882: fuzz_ws must finalise variant stream lifecycle for opcode=%s)", i, s.State, "complete", tc.opcode)
				}
			}
		})
	}
}

// newWSReplyOnPongServer accepts the WebSocket upgrade, reads one inbound
// Pong frame, and writes back a Text frame with payload "ack". The
// purpose is exclusively to let runResendWS's receive loop return on a
// non-control frame after the variant sends an unsolicited Pong — the
// real-world receive-loop semantics absorb an inbound Pong via
// `continue`, so without a follow-up frame the loop would block until
// timeout. The reply frame is independent of the variant payload (the
// test does not assert on it).
func newWSReplyOnPongServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleWSReplyOnPongConn(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleWSReplyOnPongConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	r := bufio.NewReader(conn)
	if _, err := http.ReadRequest(r); err != nil {
		return
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: dummy\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}
	// Read the inbound frame (expected: Pong) then reply with a Text
	// frame so the runResendWS receive loop terminates on a non-control
	// frame rather than absorbing the Pong and re-blocking.
	if _, err := ws.ReadFrame(r); err != nil {
		return
	}
	reply := &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte("ack")}
	_ = ws.WriteFrame(conn, reply)
}

// TestFuzzWS_PongAllVariantsComplete exercises the Pong opcode path: the
// variant sends an unsolicited Pong (RFC 6455 §5.5.4), and the upstream
// replies with a Text frame so runResendWS's receive loop can terminate
// on a non-control frame. Without USK-882 each variant's Stream would
// stay pinned at State="active"; with the finalize call it transitions
// to State="complete".
func TestFuzzWS_PongAllVariantsComplete(t *testing.T) {
	cs, store, _, _ := setupFuzzWSSession(t)
	addr, cleanup := newWSReplyOnPongServer(t)
	defer cleanup()

	payloads := []string{"p1", "p2", "p3"}
	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "pong",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
	})

	if result.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}
	for i, row := range result.Variants {
		if row.Error != "" {
			t.Errorf("variants[%d].Error = %q, want empty", i, row.Error)
		}
		if row.StreamID == "" {
			t.Errorf("variants[%d].StreamID is empty", i)
			continue
		}
		s, err := store.GetStream(context.Background(), row.StreamID)
		if err != nil || s == nil {
			t.Errorf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
			continue
		}
		// USK-882: per-variant Stream must transition out of State="active"
		// even when the send opcode is a control frame (Pong).
		if s.State != "complete" {
			t.Errorf("variants[%d].State = %q, want %q (USK-882: fuzz_ws pong variants must finalise)", i, s.State, "complete")
		}
	}
}

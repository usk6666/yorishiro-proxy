//go:build e2e && !e2e_smoke

package mcp

// fuzz_ws_macro_integration_test.go — USK-984 acceptance gate for the
// per-iteration + per-job pre_macro / post_macro hooks on the fuzz_ws
// MCP tool. Mirrors the fuzz_http macro acceptance suite (USK-960 /
// USK-961 / USK-981) with WS-specific assertions on the terminating
// frame reserved keys (__response_opcode / __response_payload /
// __response_close_code / __response_close_reason).
//
// Acceptance criteria (parent USK-984):
//   1. TestFuzzWSMacro_PreMacroFiresBeforeDial
//   2. TestFuzzWSMacro_PostMacroFiresAfterTerminatingFrame
//   3. TestFuzzWSMacro_OnErrorSkip_SubsequentVariantsRun
//   4. TestFuzzWSMacro_OnErrorAbort_StopsLoop
//   5. TestFuzzWSMacro_OnErrorContinue_LiteralTokensPassThru
//   6. TestFuzzWSMacro_ScopeJobPre_FiresOnce
//   7. TestFuzzWSMacro_ScopeJobPost_FiresOnce
//   8. TestFuzzWSMacro_ResponseOpcodeInjected_ForTextFrame

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// setupFuzzWSMacroSession is like setupFuzzWSSession but additionally
// wires the permissive httpDoer onto jobRunner.replayDoer so hook macros
// targeting 127.0.0.1 httptest servers work end-to-end. Mirrors
// setupFuzzHTTPMacroSession (fuzz_http_macro_integration_test.go).
func setupFuzzWSMacroSession(t *testing.T) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()
	opts := []ServerOption{}
	if fs, ok := store.(flow.FuzzStore); ok {
		opts = append(opts, WithFuzzStore(fs))
	}
	srv := newServer(ctx, nil, store, nil, opts...)
	srv.jobRunner.replayDoer = newPermissiveClient()

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-ws-macro-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store
}

// callFuzzWSMacro issues the fuzz_ws tool with macro args and decodes
// the structured result. Distinct from callFuzzWS (which fatals on
// IsError) because some macro tests deliberately exercise IsError paths
// (e.g., abort semantics).
func callFuzzWSMacro(t *testing.T, cs *gomcp.ClientSession, args map[string]any) (*gomcp.CallToolResult, *fuzzWSResult) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "fuzz_ws",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_ws: %v", err)
	}
	if res.IsError || res.StructuredContent == nil {
		return res, nil
	}
	var out fuzzWSResult
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode fuzz_ws result: %v", err)
	}
	return res, &out
}

// ---------------------------------------------------------------------------
// 1 — pre_macro fires before dial + upgrade.
// ---------------------------------------------------------------------------

func TestFuzzWSMacro_PreMacroFiresBeforeDial(t *testing.T) {
	cs, store := setupFuzzWSMacroSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	// pre macro records ordering: each call appends to preCalls. The fuzz
	// dial happens after the pre macro fires, so the relative count must
	// monotonically be "pre N times, fuzz N times" where pre fires first
	// per iteration. We assert pre fires the expected count.
	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&preCalls, 1)
		fmt.Fprint(w, `{"ok":1}`)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/auth", nil, nil)
	defineMacroForTest(t, cs, "pre-noop", preFlowID, "", "", nil)

	payloads := []string{"v1", "v2", "v3"}
	_, out := callFuzzWSMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
		"pre_macro":  map[string]any{"name": "pre-noop"},
	})
	if out == nil {
		t.Fatal("fuzz_ws returned IsError or nil structured content")
	}
	if out.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", out.CompletedVariants, len(payloads))
	}
	if got := atomic.LoadInt32(&preCalls); got != int32(len(payloads)) {
		t.Errorf("pre macro fired %d times, want %d (once per variant before dial)", got, len(payloads))
	}

	// fuzz_macro_results: 3 pre rows, all "ok".
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	preRows := 0
	for _, r := range results {
		if r.HookName == "pre" {
			preRows++
			if r.Status != "ok" {
				t.Errorf("pre row idx=%d status=%q, want ok", r.IndexNum, r.Status)
			}
		}
	}
	if preRows != len(payloads) {
		t.Errorf("pre rows = %d, want %d", preRows, len(payloads))
	}
}

// ---------------------------------------------------------------------------
// 2 — post_macro fires after the terminating frame.
// ---------------------------------------------------------------------------

func TestFuzzWSMacro_PostMacroFiresAfterTerminatingFrame(t *testing.T) {
	cs, store := setupFuzzWSMacroSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	var postCalls int32
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&postCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(postServer.Close)

	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)
	defineMacroForTest(t, cs, "post-noop", postFlowID, "", "", nil)

	payloads := []string{"a", "b"}
	_, out := callFuzzWSMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
		"post_macro": map[string]any{"name": "post-noop"},
	})
	if out == nil {
		t.Fatal("fuzz_ws returned IsError or nil structured content")
	}
	if out.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", out.CompletedVariants, len(payloads))
	}
	if got := atomic.LoadInt32(&postCalls); got != int32(len(payloads)) {
		t.Errorf("post macro fired %d times, want %d (once per variant after terminating frame)", got, len(payloads))
	}

	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	postRows := 0
	for _, r := range results {
		if r.HookName == "post" {
			postRows++
			if r.Status != "ok" {
				t.Errorf("post row idx=%d status=%q, want ok", r.IndexNum, r.Status)
			}
		}
	}
	if postRows != len(payloads) {
		t.Errorf("post rows = %d, want %d", postRows, len(payloads))
	}
}

// ---------------------------------------------------------------------------
// 3 — on_error=skip: a pre-macro failure on iteration K skips K only;
// subsequent variants still run.
// ---------------------------------------------------------------------------

func TestFuzzWSMacro_OnErrorSkip_SubsequentVariantsRun(t *testing.T) {
	cs, store := setupFuzzWSMacroSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	// preServer returns 500 so the extract with required=true fails on
	// every iteration → every variant short-circuits with on_error=skip.
	// The loop must still iterate to completion (each variant records a
	// skipped row).
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/auth", nil, nil)
	defineMacroForTest(t, cs, "pre-required-fail", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	payloads := []string{"v1", "v2", "v3"}
	_, out := callFuzzWSMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
		"pre_macro":  map[string]any{"name": "pre-required-fail", "on_error": "skip"},
	})
	if out == nil {
		t.Fatal("fuzz_ws returned IsError or nil structured content")
	}
	// Every variant short-circuited via skip but the loop still iterated
	// to completion — the response carries N rows, each with non-empty
	// Error containing the pre-skip diagnostic.
	if out.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d (every variant skipped but loop iterates to end)", out.CompletedVariants, len(payloads))
	}
	for i, row := range out.Variants {
		if row.Error == "" {
			t.Errorf("variants[%d].Error is empty, want pre-skip diagnostic", i)
		}
		if !strings.Contains(row.Error, "pre_macro hook failed") {
			t.Errorf("variants[%d].Error = %q, want to contain 'pre_macro hook failed'", i, row.Error)
		}
	}

	// fuzz_macro_results: 3 pre rows, all "skipped"; 0 post rows.
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	preSkipped := 0
	postRows := 0
	for _, r := range results {
		switch r.HookName {
		case "pre":
			if r.Status == "skipped" {
				preSkipped++
			}
		case "post":
			postRows++
		}
	}
	if preSkipped != len(payloads) {
		t.Errorf("pre skipped rows = %d, want %d", preSkipped, len(payloads))
	}
	if postRows != 0 {
		t.Errorf("post rows = %d, want 0 (post must not fire when pre is skipped)", postRows)
	}
}

// ---------------------------------------------------------------------------
// 4 — on_error=abort: the first pre-macro failure aborts the whole run.
// ---------------------------------------------------------------------------

func TestFuzzWSMacro_OnErrorAbort_StopsLoop(t *testing.T) {
	cs, store := setupFuzzWSMacroSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/auth", nil, nil)
	defineMacroForTest(t, cs, "pre-required-abort", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	payloads := []string{"v1", "v2", "v3"}
	res, _ := callFuzzWSMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
		"pre_macro":  map[string]any{"name": "pre-required-abort", "on_error": "abort"},
	})
	// abort short-circuits the whole run with a tool-level error.
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError on abort, got res=%+v", res)
	}
	var msg strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			msg.WriteString(tc.Text)
		}
	}
	if !strings.Contains(msg.String(), "abort") {
		t.Errorf("error message %q does not mention 'abort'", msg.String())
	}
}

// ---------------------------------------------------------------------------
// 5 — on_error=continue: unresolved §var§ tokens pass through literally.
// ---------------------------------------------------------------------------

func TestFuzzWSMacro_OnErrorContinue_LiteralTokensPassThru(t *testing.T) {
	cs, store := setupFuzzWSMacroSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/auth", nil, nil)
	defineMacroForTest(t, cs, "pre-missing", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	// positions payload includes a §session_token§ token. With pre failing
	// under on_error=continue, the kvStore does not contain session_token,
	// so the template stays literal and the WS server echoes it back.
	_, out := callFuzzWSMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"prefix-§session_token§-suffix"}},
		},
		"timeout_ms": 5000,
		"pre_macro":  map[string]any{"name": "pre-missing", "on_error": "continue"},
	})
	if out == nil {
		t.Fatal("fuzz_ws returned IsError or nil structured content")
	}
	if out.CompletedVariants != 1 {
		t.Fatalf("CompletedVariants = %d, want 1 (on_error=continue must let the variant send)", out.CompletedVariants)
	}

	// Per-variant Stream Send Flow should carry the literal token in the
	// payload bytes (the echo server echoes payloads verbatim; we read
	// the receive Flow body to confirm wire fidelity).
	row := out.Variants[0]
	if row.StreamID == "" {
		t.Fatal("variant StreamID is empty")
	}
	flows, err := store.GetFlows(context.Background(), row.StreamID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	gotLiteral := false
	for _, f := range flows {
		if strings.Contains(string(f.Body), "§session_token§") {
			gotLiteral = true
			break
		}
	}
	if !gotLiteral {
		t.Errorf("receive Flow bodies did not contain literal §session_token§ (continue must pass through); flows=%d", len(flows))
	}
}

// ---------------------------------------------------------------------------
// 6 — scope="job" pre fires exactly once before the variant loop.
// ---------------------------------------------------------------------------

func TestFuzzWSMacro_ScopeJobPre_FiresOnce(t *testing.T) {
	cs, store := setupFuzzWSMacroSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&preCalls, 1)
		fmt.Fprint(w, `{"session_token":"job-tok-shared"}`)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-job-login", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	payloads := []string{"a", "b", "c"}
	_, out := callFuzzWSMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
		"pre_macro":  map[string]any{"name": "pre-job-login", "scope": "job"},
	})
	if out == nil {
		t.Fatal("fuzz_ws returned IsError or nil structured content")
	}
	if out.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", out.CompletedVariants, len(payloads))
	}

	// pre-job fired exactly once (scope=job is single-fire by construction).
	if got := atomic.LoadInt32(&preCalls); got != 1 {
		t.Errorf("pre macro fired %d times, want 1 (scope=job)", got)
	}

	// fuzz_macro_results: exactly one pre row at index_num=-1 (the job
	// scope sentinel).
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	preRows := 0
	sentinelRow := false
	for _, r := range results {
		if r.HookName == "pre" {
			preRows++
			if r.IndexNum == -1 {
				sentinelRow = true
			}
		}
	}
	if preRows != 1 {
		t.Errorf("pre rows = %d, want 1 (scope=job)", preRows)
	}
	if !sentinelRow {
		t.Error("pre-job row missing index_num=-1 sentinel")
	}
}

// ---------------------------------------------------------------------------
// 7 — scope="job" post fires exactly once after the variant loop.
// ---------------------------------------------------------------------------

func TestFuzzWSMacro_ScopeJobPost_FiresOnce(t *testing.T) {
	cs, store := setupFuzzWSMacroSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	var postCalls int32
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&postCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(postServer.Close)

	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)
	defineMacroForTest(t, cs, "post-job-summary", postFlowID, "", "", nil)

	payloads := []string{"a", "b", "c", "d"}
	_, out := callFuzzWSMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
		"post_macro": map[string]any{"name": "post-job-summary", "scope": "job"},
	})
	if out == nil {
		t.Fatal("fuzz_ws returned IsError or nil structured content")
	}
	if out.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", out.CompletedVariants, len(payloads))
	}

	if got := atomic.LoadInt32(&postCalls); got != 1 {
		t.Errorf("post macro fired %d times, want 1 (scope=job)", got)
	}

	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	postRows := 0
	sentinelRow := false
	for _, r := range results {
		if r.HookName == "post" {
			postRows++
			if r.IndexNum == -1 {
				sentinelRow = true
			}
		}
	}
	if postRows != 1 {
		t.Errorf("post rows = %d, want 1 (scope=job)", postRows)
	}
	if !sentinelRow {
		t.Error("post-job row missing index_num=-1 sentinel")
	}
}

// ---------------------------------------------------------------------------
// 8 — __response_opcode reserved key injected for a text terminating frame.
// ---------------------------------------------------------------------------

func TestFuzzWSMacro_ResponseOpcodeInjected_ForTextFrame(t *testing.T) {
	cs, store := setupFuzzWSMacroSession(t)
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	// postServer's URL template references §__response_opcode§ and
	// §__response_payload§ so the macro engine's template expansion
	// proves the WS-specific reserved keys landed in the kvStore. The
	// server records the query string for assertion.
	var postRecords atomic.Pointer[[]map[string]string]
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := map[string]string{"query": r.URL.RawQuery}
		for {
			old := postRecords.Load()
			var cur []map[string]string
			if old != nil {
				cur = append(cur, *old...)
			}
			cur = append(cur, rec)
			if postRecords.CompareAndSwap(old, &cur) {
				break
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(postServer.Close)

	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)
	overrideURL := postServer.URL + "/audit?op=§__response_opcode§&body=§__response_payload§&code=§__response_close_code§"
	defineMacroForTest(t, cs, "post-injects-opcode", postFlowID, overrideURL, "summary", nil)

	// Text echo: every variant terminates with an opcode=text echo of the
	// substituted payload. close_code stays 0 (no Close frame).
	payloads := []string{"alpha", "beta"}
	_, out := callFuzzWSMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
		"post_macro": map[string]any{"name": "post-injects-opcode"},
	})
	if out == nil {
		t.Fatal("fuzz_ws returned IsError or nil structured content")
	}
	if out.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", out.CompletedVariants, len(payloads))
	}

	if postRecords.Load() == nil {
		t.Fatal("post server received no requests")
	}
	recs := *postRecords.Load()
	if len(recs) != len(payloads) {
		t.Fatalf("post server received %d requests, want %d", len(recs), len(payloads))
	}
	for i, rec := range recs {
		// __response_opcode = "text" (text frame echo).
		if !strings.Contains(rec["query"], "op=text") {
			t.Errorf("post[%d] query = %q, want to contain op=text", i, rec["query"])
		}
		// __response_close_code = 0 (no Close frame).
		if !strings.Contains(rec["query"], "code=0") {
			t.Errorf("post[%d] query = %q, want to contain code=0 (no Close frame)", i, rec["query"])
		}
		// __response_payload echoes one of the position payloads.
		matched := false
		for _, p := range payloads {
			if strings.Contains(rec["query"], "body="+p) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("post[%d] query = %q, want body= one of %v", i, rec["query"], payloads)
		}
	}
}

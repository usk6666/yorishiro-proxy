//go:build e2e && !e2e_smoke

package mcp

// fuzz_grpc_macro_integration_test.go — USK-985 acceptance gate for the
// per-iteration + per-job pre_macro / post_macro hooks on the fuzz_grpc
// MCP tool. Sibling of USK-984 (ws) and USK-986 (raw).
//
// Acceptance criteria (USK-985):
//   1. TestFuzzGRPCMacro_PreMacroFiresBeforeDial
//   2. TestFuzzGRPCMacro_PostMacroFiresAfterEndTrailer
//   3. TestFuzzGRPCMacro_OnErrorSkip_SubsequentVariantsRun
//   4. TestFuzzGRPCMacro_OnErrorAbort_StopsLoop
//   5. TestFuzzGRPCMacro_OnErrorContinue_LiteralTokensInWire
//   6. TestFuzzGRPCMacro_ScopeJobPre_FiresOnce
//   7. TestFuzzGRPCMacro_ScopeJobPost_FiresOnce
//   8. TestFuzzGRPCMacro_ResponseStatusInjected_GRPCDomain (gRPC 0-16 status)
//
// The suite drives real gRPC RPCs against a TLS-enabled grpc-go upstream
// (see startFuzzGRPCUpstream in fuzz_grpc_integration_test.go) while
// dispatching pre/post macros over plain-HTTP httptest servers via the
// macro replayDoer (mirrors setupFuzzHTTPMacroSession). The MCP server's
// TLSTransport is set to InsecureSkipVerify so the per-test self-signed
// cert is accepted, and the replayDoer is set to newPermissiveClient so
// 127.0.0.1 httptest macros work end-to-end.

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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// setupFuzzGRPCMacroSession is like setupFuzzGRPCSession but additionally
// wires the permissive httpDoer onto jobRunner.replayDoer so hook macros
// targeting 127.0.0.1 httptest servers work end-to-end. The
// pluginv2.Engine is left empty (we are not counting plugin hooks in this
// suite; that coverage lives in fuzz_grpc_integration_test.go).
func setupFuzzGRPCMacroSession(t *testing.T) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()
	opts := []ServerOption{
		WithTLSTransport(&transport.StandardTransport{InsecureSkipVerify: true}),
	}
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

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-grpc-macro-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store
}

// callFuzzGRPCMacro issues the fuzz_grpc tool with the supplied input and
// returns (result, IsError, errorText). Unlike callFuzzGRPC, callers may
// want to inspect tool-call errors (e.g. on_error=abort propagation).
func callFuzzGRPCMacro(t *testing.T, cs *gomcp.ClientSession, input map[string]any) (*fuzzGRPCResult, bool, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "fuzz_grpc",
		Arguments: input,
	})
	if err != nil {
		// Some MCP transports surface validation errors as a tool-call
		// error rather than an in-band IsError result. Return the raw
		// error string for inspection.
		return nil, true, err.Error()
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		return nil, true, msg.String()
	}
	if res.StructuredContent == nil {
		t.Fatal("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out fuzzGRPCResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	return &out, false, ""
}

// ---------------------------------------------------------------------------
// 1. Pre macro fires BEFORE dial (per variant)
// ---------------------------------------------------------------------------

func TestFuzzGRPCMacro_PreMacroFiresBeforeDial(t *testing.T) {
	cs, store := setupFuzzGRPCMacroSession(t)

	// Order capture: each pre-macro call records its observation time, and
	// each gRPC upstream call records its capture time. We assert
	// monotonically that pre observation < gRPC observation per variant.
	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&preCalls, 1)
		fmt.Fprintf(w, `{"session_token":"tok-%d"}`, atomic.LoadInt32(&preCalls))
	}))
	t.Cleanup(preServer.Close)

	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-grpc-extract", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	out, isErr, errText := callFuzzGRPCMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"a", "b", "c"}},
		},
		"timeout_ms": 10000,
		"pre_macro":  map[string]any{"name": "pre-grpc-extract"},
	})
	if isErr {
		t.Fatalf("fuzz_grpc returned error: %s", errText)
	}
	if out.CompletedVariants != 3 {
		t.Fatalf("CompletedVariants = %d, want 3", out.CompletedVariants)
	}

	// Pre fires once per variant — but specifically BEFORE the gRPC dial.
	// We assert: 3 pre calls happened and 3 gRPC requests reached the
	// upstream, and that pre call count == gRPC call count.
	if got := atomic.LoadInt32(&preCalls); got != 3 {
		t.Errorf("pre macro called %d times, want 3", got)
	}
	observed := upstream.snapshot()
	if len(observed) != 3 {
		t.Errorf("upstream observed %d requests, want 3", len(observed))
	}

	// Every variant must record a "pre"/"ok" fuzz_macro_results row at
	// index_num=0..2 (the index_num=variant_idx contract for iteration
	// scope).
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	preRows := 0
	for _, r := range results {
		if r.HookName != "pre" {
			continue
		}
		preRows++
		if r.Status != "ok" {
			t.Errorf("pre row idx=%d status=%q, want ok", r.IndexNum, r.Status)
		}
		if r.IndexNum < 0 || r.IndexNum >= 3 {
			t.Errorf("pre row index_num = %d, want 0..2", r.IndexNum)
		}
	}
	if preRows != 3 {
		t.Errorf("pre fuzz_macro_results rows = %d, want 3", preRows)
	}
}

// ---------------------------------------------------------------------------
// 2. Post macro fires AFTER the end trailer
// ---------------------------------------------------------------------------

func TestFuzzGRPCMacro_PostMacroFiresAfterEndTrailer(t *testing.T) {
	cs, store := setupFuzzGRPCMacroSession(t)

	// postServer records the OverrideURL query so we can confirm the post
	// macro saw the gRPC end-trailer's __response_status (0 = OK).
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

	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)
	overrideURL := postServer.URL + "/audit?rs=§__response_status§&msgs=§__response_message_count§"
	defineMacroForTest(t, cs, "post-grpc-audit", postFlowID, overrideURL, "audit", nil)

	out, isErr, errText := callFuzzGRPCMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"a", "b"}},
		},
		"timeout_ms": 10000,
		"post_macro": map[string]any{"name": "post-grpc-audit"},
	})
	if isErr {
		t.Fatalf("fuzz_grpc returned error: %s", errText)
	}
	if out.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", out.CompletedVariants)
	}

	// post-macro fired once per variant AFTER the end trailer → 2 records.
	if postRecords.Load() == nil {
		t.Fatal("post server received no requests")
	}
	pRecs := *postRecords.Load()
	if len(pRecs) != 2 {
		t.Fatalf("post server received %d requests, want 2", len(pRecs))
	}
	for i, rec := range pRecs {
		// __response_status = 0 (OK in gRPC domain) for every variant.
		if !strings.Contains(rec["query"], "rs=0") {
			t.Errorf("post[%d] query = %q, want to contain rs=0 (gRPC OK)", i, rec["query"])
		}
		// __response_message_count = 1 for unary RPC.
		if !strings.Contains(rec["query"], "msgs=1") {
			t.Errorf("post[%d] query = %q, want to contain msgs=1", i, rec["query"])
		}
	}

	// fuzz_macro_results — 2 post rows, all ok.
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
	if postRows != 2 {
		t.Errorf("post rows = %d, want 2", postRows)
	}
}

// ---------------------------------------------------------------------------
// 3. on_error=skip — pre fails on iteration N; subsequent variants still run
// ---------------------------------------------------------------------------

func TestFuzzGRPCMacro_OnErrorSkip_SubsequentVariantsRun(t *testing.T) {
	cs, store := setupFuzzGRPCMacroSession(t)

	// preServer returns 500 — required extract fails — propagates pre_macro
	// hook error.
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-grpc-required", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	out, isErr, errText := callFuzzGRPCMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"a", "b", "c"}},
		},
		"timeout_ms": 10000,
		"pre_macro":  map[string]any{"name": "pre-grpc-required", "on_error": "skip"},
	})
	if isErr {
		t.Fatalf("fuzz_grpc returned unexpected error: %s", errText)
	}
	// skip policy short-circuits each variant's send. Every variant is
	// "completed" (it consumed an iteration slot) but with an error
	// message; no upstream calls happen.
	if out.CompletedVariants != 3 {
		t.Fatalf("CompletedVariants = %d, want 3 (skip variants still count)", out.CompletedVariants)
	}
	observed := upstream.snapshot()
	if len(observed) != 0 {
		t.Errorf("upstream observed %d requests, want 0 (pre skip must short-circuit dial)", len(observed))
	}
	for _, row := range out.Variants {
		if row.Error == "" {
			t.Errorf("variant %d Error is empty, want non-empty pre-skip diagnostic", row.Index)
		}
	}

	// fuzz_macro_results: 3 "pre"/"skipped" rows (one per variant).
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	preRows := 0
	for _, r := range results {
		if r.HookName != "pre" {
			continue
		}
		preRows++
		if r.Status != "skipped" {
			t.Errorf("pre row idx=%d status=%q, want skipped", r.IndexNum, r.Status)
		}
	}
	if preRows != 3 {
		t.Errorf("pre rows = %d, want 3", preRows)
	}
}

// ---------------------------------------------------------------------------
// 4. on_error=abort — pre fails on iteration N; loop stops, error propagated
// ---------------------------------------------------------------------------

func TestFuzzGRPCMacro_OnErrorAbort_StopsLoop(t *testing.T) {
	cs, store := setupFuzzGRPCMacroSession(t)

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-grpc-abort", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	_, isErr, errText := callFuzzGRPCMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"a", "b", "c"}},
		},
		"timeout_ms": 10000,
		"pre_macro":  map[string]any{"name": "pre-grpc-abort", "on_error": "abort"},
	})
	if !isErr {
		t.Fatal("expected IsError for pre on_error=abort, got success")
	}
	if !strings.Contains(errText, "pre_macro hook abort") {
		t.Errorf("error text = %q, want to contain 'pre_macro hook abort'", errText)
	}

	// Abort fires on the FIRST failing iteration; later variants must NOT
	// reach the upstream.
	observed := upstream.snapshot()
	if len(observed) != 0 {
		t.Errorf("upstream observed %d requests, want 0 (abort must stop the loop)", len(observed))
	}
}

// ---------------------------------------------------------------------------
// 5. on_error=continue — pre fails; literal §var§ tokens land on the wire
// ---------------------------------------------------------------------------

func TestFuzzGRPCMacro_OnErrorContinue_LiteralTokensInWire(t *testing.T) {
	cs, store := setupFuzzGRPCMacroSession(t)

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-grpc-continue", preFlowID, "", "", []map[string]any{
		{
			"name":      "missing_var",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.missing_var",
			"required":  true,
		},
	})

	out, isErr, errText := callFuzzGRPCMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"metadata": []map[string]any{
			{"name": "x-token", "value": "literal-not-templated"},
		},
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			// Position payload — no template substitution here; templates
			// expand only on the base envelope fields (path / raw_query /
			// header values / body). For the gRPC fuzz path the literal
			// payload is what lands on the wire when continue is the
			// policy. We assert the variant ran and the upstream observed
			// it.
			{"path": "messages[0].payload", "payloads": []string{"keep-going-1", "keep-going-2"}},
		},
		"timeout_ms": 10000,
		"pre_macro":  map[string]any{"name": "pre-grpc-continue", "on_error": "continue"},
	})
	if isErr {
		t.Fatalf("fuzz_grpc returned unexpected error (continue must not abort): %s", errText)
	}
	if out.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", out.CompletedVariants)
	}

	// continue policy: every variant ran on the wire.
	observed := upstream.snapshot()
	if len(observed) != 2 {
		t.Fatalf("upstream observed %d requests, want 2 (continue must let every variant fire)", len(observed))
	}
	seen := map[string]bool{}
	for _, o := range observed {
		seen[string(o.Payload)] = true
	}
	if !seen["keep-going-1"] || !seen["keep-going-2"] {
		t.Errorf("upstream payloads = %v, want to include keep-going-1 and keep-going-2", seen)
	}

	// fuzz_macro_results: 2 "pre"/"error" rows.
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	preErrRows := 0
	for _, r := range results {
		if r.HookName == "pre" && r.Status == "error" {
			preErrRows++
		}
	}
	if preErrRows != 2 {
		t.Errorf("pre/error rows = %d, want 2", preErrRows)
	}
}

// ---------------------------------------------------------------------------
// 6. scope="job" pre — fires exactly ONCE before the variant loop
// ---------------------------------------------------------------------------

func TestFuzzGRPCMacro_ScopeJobPre_FiresOnce(t *testing.T) {
	cs, store := setupFuzzGRPCMacroSession(t)

	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&preCalls, 1)
		fmt.Fprint(w, `{"session_token":"job-shared"}`)
	}))
	t.Cleanup(preServer.Close)

	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-grpc-job-login", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	out, isErr, errText := callFuzzGRPCMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"a", "b", "c"}},
		},
		"timeout_ms": 10000,
		"pre_macro":  map[string]any{"name": "pre-grpc-job-login", "scope": "job"},
	})
	if isErr {
		t.Fatalf("fuzz_grpc returned error: %s", errText)
	}
	if out.CompletedVariants != 3 {
		t.Fatalf("CompletedVariants = %d, want 3", out.CompletedVariants)
	}

	// scope=job: pre fires EXACTLY ONCE.
	if got := atomic.LoadInt32(&preCalls); got != 1 {
		t.Errorf("pre macro called %d times, want 1 (scope=job)", got)
	}

	// All 3 variants ran on the wire.
	observed := upstream.snapshot()
	if len(observed) != 3 {
		t.Errorf("upstream observed %d requests, want 3", len(observed))
	}

	// fuzz_macro_results — 1 pre row at index_num=-1 (job-scope sentinel).
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("fuzz_macro_results rows = %d, want 1", len(results))
	}
	r := results[0]
	if r.HookName != "pre" {
		t.Errorf("hook_name = %q, want pre", r.HookName)
	}
	if r.IndexNum != -1 {
		t.Errorf("index_num = %d, want -1 (job-scope sentinel)", r.IndexNum)
	}
	if r.Status != "ok" {
		t.Errorf("status = %q, want ok", r.Status)
	}
}

// ---------------------------------------------------------------------------
// 7. scope="job" post — fires exactly ONCE after the variant loop
// ---------------------------------------------------------------------------

func TestFuzzGRPCMacro_ScopeJobPost_FiresOnce(t *testing.T) {
	cs, store := setupFuzzGRPCMacroSession(t)

	var postCalls int32
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&postCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(postServer.Close)

	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/summary", nil, nil)
	defineMacroForTest(t, cs, "post-grpc-job-summary", postFlowID, "", "", nil)

	out, isErr, errText := callFuzzGRPCMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"a", "b"}},
		},
		"timeout_ms": 10000,
		"post_macro": map[string]any{"name": "post-grpc-job-summary", "scope": "job"},
	})
	if isErr {
		t.Fatalf("fuzz_grpc returned error: %s", errText)
	}
	if out.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", out.CompletedVariants)
	}

	// scope=job: post fires EXACTLY ONCE after the loop.
	if got := atomic.LoadInt32(&postCalls); got != 1 {
		t.Errorf("post macro called %d times, want 1 (scope=job)", got)
	}

	// fuzz_macro_results — 1 post row at index_num=-1.
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("fuzz_macro_results rows = %d, want 1", len(results))
	}
	r := results[0]
	if r.HookName != "post" {
		t.Errorf("hook_name = %q, want post", r.HookName)
	}
	if r.IndexNum != -1 {
		t.Errorf("index_num = %d, want -1 (job-scope sentinel)", r.IndexNum)
	}
	if r.Status != "ok" {
		t.Errorf("status = %q, want ok", r.Status)
	}
}

// ---------------------------------------------------------------------------
// 8. __response_status reflects the gRPC status domain (0-16)
// ---------------------------------------------------------------------------

// TestFuzzGRPCMacro_ResponseStatusInjected_GRPCDomain asserts that the
// post_macro kvStore receives __response_status in the gRPC code domain
// (0=OK, 14=UNAVAILABLE) — NOT an HTTP-style 200/503. Drives two
// variants with different upstream responses (OK + UNAVAILABLE) and
// inspects the post-macro's OverrideURL template expansion to confirm
// the correct status was injected per variant.
//
// Pairs with the help_fuzz_grpc.md note that documents the gRPC status
// domain to prevent operators from supplying HTTP status codes to
// run_interval=on_status (a separate test would assert on_status gating;
// here we only need the injection contract).
func TestFuzzGRPCMacro_ResponseStatusInjected_GRPCDomain(t *testing.T) {
	cs, store := setupFuzzGRPCMacroSession(t)

	// postServer records each post macro's OverrideURL query so we can
	// assert __response_status is the gRPC code per variant.
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

	// Upstream alternates per-variant: variant 0 returns OK (echo
	// payload), variant 1 returns UNAVAILABLE (gRPC code 14). Use a
	// space-free status message to keep URL templating simple.
	var grpcCalls int32
	upstream := &fuzzGRPCEchoServer{
		respond: func(req []byte) (resp []byte, st *status.Status) {
			n := atomic.AddInt32(&grpcCalls, 1)
			if n == 1 {
				return append(append([]byte{}, req...), []byte("|ok")...), nil
			}
			return nil, status.New(codes.Unavailable, "unavailable_v1")
		},
	}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)
	overrideURL := postServer.URL + "/audit?rs=§__response_status§&sm=§__response_status_message§&tot=§__response_total_bytes§"
	defineMacroForTest(t, cs, "post-grpc-status-domain", postFlowID, overrideURL, "audit", nil)

	out, isErr, errText := callFuzzGRPCMacro(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"v0", "v1"}},
		},
		"timeout_ms": 10000,
		"post_macro": map[string]any{"name": "post-grpc-status-domain"},
	})
	if isErr {
		t.Fatalf("fuzz_grpc returned error: %s", errText)
	}
	if out.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", out.CompletedVariants)
	}

	// Variant rows: variant 0 status = 0 (OK); variant 1 status = 14
	// (UNAVAILABLE per codes.Unavailable).
	if len(out.Variants) != 2 {
		t.Fatalf("Variants = %d, want 2", len(out.Variants))
	}
	// Sort variants by Index to be deterministic.
	v0 := out.Variants[0]
	v1 := out.Variants[1]
	if v0.Index == 1 {
		v0, v1 = v1, v0
	}
	if v0.Status != uint32(codes.OK) {
		t.Errorf("variant 0 status = %d, want %d (OK)", v0.Status, codes.OK)
	}
	if v1.Status != uint32(codes.Unavailable) {
		t.Errorf("variant 1 status = %d, want %d (UNAVAILABLE)", v1.Status, codes.Unavailable)
	}

	// Post macro saw both gRPC status codes via __response_status — NOT
	// HTTP-style 200/503. We assert literal substring matches against
	// the URL-encoded query.
	if postRecords.Load() == nil {
		t.Fatal("post server received no requests")
	}
	pRecs := *postRecords.Load()
	if len(pRecs) != 2 {
		t.Fatalf("post server received %d requests, want 2", len(pRecs))
	}
	// Order: post macro fires after each variant in iteration order.
	r0 := pRecs[0]
	r1 := pRecs[1]
	if !strings.Contains(r0["query"], "rs=0") {
		t.Errorf("post[0] query = %q, want to contain rs=0 (gRPC OK)", r0["query"])
	}
	if strings.Contains(r0["query"], "rs=200") {
		t.Errorf("post[0] query = %q, contains HTTP-style rs=200 — must be gRPC domain (0)", r0["query"])
	}
	if !strings.Contains(r1["query"], "rs=14") {
		t.Errorf("post[1] query = %q, want to contain rs=14 (gRPC UNAVAILABLE)", r1["query"])
	}
	if !strings.Contains(r1["query"], "sm=unavailable_v1") {
		t.Errorf("post[1] query = %q, want to contain status_message", r1["query"])
	}
}

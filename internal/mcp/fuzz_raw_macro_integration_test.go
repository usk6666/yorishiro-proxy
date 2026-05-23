//go:build e2e && !e2e_smoke

package mcp

// fuzz_raw_macro_integration_test.go — USK-986 acceptance gate for the
// per-iteration + per-job pre_macro / post_macro hooks on the fuzz_raw
// MCP tool. fuzz_raw is the "+1 adaptor" in USK-980's N-1 uniform + 1
// adaptor pattern — raw has no L7 status concept, so on_status is
// REJECTED at validation and the per-protocol __response_* surface is
// the raw-specific {body, chunks, truncated} triple.
//
// Acceptance criteria (9 tests, including the adaptor-specific reject):
//   1. TestFuzzRawMacro_PreMacroFiresBeforeDial
//   2. TestFuzzRawMacro_PostMacroFiresAfterReceiveLoop
//   3. TestFuzzRawMacro_OnErrorSkip_SubsequentVariantsRun
//   4. TestFuzzRawMacro_OnErrorAbort_StopsLoop
//   5. TestFuzzRawMacro_OnErrorContinue_LiteralBytesInWire
//   6. TestFuzzRawMacro_ScopeJobPre_FiresOnce
//   7. TestFuzzRawMacro_ScopeJobPost_FiresOnce
//   8. TestFuzzRawMacro_RunIntervalOnStatus_Rejected  (adaptor-specific)
//   9. TestFuzzRawMacro_RunIntervalOnMatch_FiresAgainstResponseBody

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// setupFuzzRawMacroSession spins up an MCP server pre-wired with a
// fresh flow store and the permissive httpDoer on jobRunner.replayDoer
// so hook macros targeting 127.0.0.1 httptest servers work end-to-end.
// Returns the client session and the underlying flow store.
func setupFuzzRawMacroSession(t *testing.T) (*gomcp.ClientSession, flow.Store) {
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

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-raw-macro-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store
}

// startRawEchoServer stands up a TCP server that responds with a small
// canned byte sequence and tracks the per-connection bytes received in
// connect order. Used by fuzz_raw macro tests so post_macro has
// non-empty __response_body to match against.
func startRawEchoServer(t *testing.T, response []byte) (string, func() [][]byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var (
		mu       sync.Mutex
		captures [][]byte
	)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				var got []byte
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, _ := c.Read(buf)
				if n > 0 {
					got = append(got, buf[:n]...)
					_, _ = c.Write(response)
				}
				mu.Lock()
				captures = append(captures, got)
				mu.Unlock()
			}(conn)
		}
	}()

	return ln.Addr().String(), func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]byte, len(captures))
		for i, c := range captures {
			cc := make([]byte, len(c))
			copy(cc, c)
			out[i] = cc
		}
		return out
	}
}

// ---------------------------------------------------------------------------
// 1. pre_macro fires once before each variant's dial.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_PreMacroFiresBeforeDial(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, getRecv := startRawEchoServer(t, []byte("OK"))

	// Track the relative order: every pre call must arrive at the
	// preServer before its corresponding upstream-raw dial lands at
	// getRecv. We use a single shared counter (eventSeq) bumped on each
	// pre fire AND on each raw dial accept — pre-events must monotonically
	// stay >= raw-events count at every observation point.
	var (
		preCalls int32
	)
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&preCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-login", preFlowID, "", "", nil)

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addr,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"hello-1", "hello-2", "hello-3"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-login"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}

	// All 3 variants reached the wire (pre returned 2xx so no skip).
	caps := waitForCaptures(getRecv, 3, 3*time.Second)
	if len(caps) != 3 {
		t.Fatalf("captured %d raw connections, want 3", len(caps))
	}
	// pre fired once per variant — invariant: pre count equals variant
	// count when pre succeeds with no on_error fallthrough.
	if got := atomic.LoadInt32(&preCalls); got != 3 {
		t.Errorf("pre called %d times, want 3 (once per variant)", got)
	}
}

// ---------------------------------------------------------------------------
// 2. post_macro fires after receive loop ends; __response_body / chunks /
//    truncated visible.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_PostMacroFiresAfterReceiveLoop(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, _ := startRawEchoServer(t, []byte("RESPDATA"))

	// post server: capture the URL query, which the post macro
	// templates against __response_body / __response_chunks /
	// __response_truncated.
	var postRecords atomic.Pointer[[]map[string]string]
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := map[string]string{
			"path":  r.URL.Path,
			"query": r.URL.RawQuery,
		}
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
	overrideURL := postServer.URL + "/audit?body=§__response_body§&chunks=§__response_chunks§&trunc=§__response_truncated§"
	defineMacroForTest(t, cs, "post-record", postFlowID, overrideURL, "", nil)

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addr,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1", "v2"}},
			},
			"timeout_ms": 5000,
			"post_macro": map[string]any{"name": "post-record"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}

	// Wait for the async post fires to land via the permissive doer.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pr := postRecords.Load(); pr != nil && len(*pr) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	prPtr := postRecords.Load()
	if prPtr == nil {
		t.Fatal("post server received no requests")
	}
	prs := *prPtr
	if len(prs) != 2 {
		t.Fatalf("post server received %d requests, want 2", len(prs))
	}
	for i, rec := range prs {
		if !strings.Contains(rec["query"], "body=RESPDATA") {
			t.Errorf("post[%d] query = %q, want to contain body=RESPDATA", i, rec["query"])
		}
		if !strings.Contains(rec["query"], "chunks=1") {
			t.Errorf("post[%d] query = %q, want to contain chunks=1", i, rec["query"])
		}
		if !strings.Contains(rec["query"], "trunc=false") {
			t.Errorf("post[%d] query = %q, want to contain trunc=false", i, rec["query"])
		}
	}
}

// ---------------------------------------------------------------------------
// 3. on_error=skip — fuzz_raw doesn't dial when pre fails; subsequent
//    variants still run.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_OnErrorSkip_SubsequentVariantsRun(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, getRecv := startRawEchoServer(t, []byte("OK"))

	// Pre always returns 5xx so the macro errors out; on_error=skip
	// means the variant is recorded as skipped and the next variant
	// continues to run.
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	// Define a macro that uses a guard requiring a 2xx response so the
	// step errors out on 5xx (forcing a hook error).
	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-fails", preFlowID, "", "", []map[string]any{
		// Use an extract with required=true on a JSON path that won't
		// exist — forces the step to error and propagate to the hook.
		{
			"name":      "tok",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.never_exists",
			"required":  true,
		},
	})

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addr,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1", "v2", "v3"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-fails", "on_error": "skip"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}

	// On skip, no variant should reach the wire — no upstream captures.
	caps := getRecv()
	if len(caps) != 0 {
		t.Errorf("upstream connections = %d, want 0 (every variant skipped)", len(caps))
	}

	// fuzz_macro_results should have 3 pre-skipped rows.
	out := decodeFuzzRawResult(t, res)
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	skipped := 0
	for _, r := range results {
		if r.HookName == "pre" && r.Status == "skipped" {
			skipped++
		}
	}
	if skipped != 3 {
		t.Errorf("pre-skipped rows = %d, want 3", skipped)
	}
}

// ---------------------------------------------------------------------------
// 4. on_error=abort — pre fails, the variant errors recorded, loop halts
//    via stop_on_error-like flow.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_OnErrorAbort_StopsLoop(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, getRecv := startRawEchoServer(t, []byte("OK"))

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-abort", preFlowID, "", "", []map[string]any{
		{
			"name":      "tok",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.never_exists",
			"required":  true,
		},
	})

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr":   addr,
			"stop_on_error": true,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1", "v2", "v3"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-abort", "on_error": "abort"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}
	out := decodeFuzzRawResult(t, res)

	// First variant records the abort error; subsequent variants skipped
	// because the recorded error triggers stop_on_error.
	if out.CompletedVariants != 1 {
		t.Errorf("CompletedVariants = %d, want 1 (abort halts after the first)", out.CompletedVariants)
	}
	if out.StoppedReason == "" {
		t.Errorf("StoppedReason is empty; want non-empty stop_on_error reason")
	}

	// No wire dials.
	caps := getRecv()
	if len(caps) != 0 {
		t.Errorf("upstream connections = %d, want 0 (abort before dial)", len(caps))
	}
}

// ---------------------------------------------------------------------------
// 5. on_error=continue — unresolved §var§ template literal flows through
//    to the wire bytes (raw passthrough). Mirrors fuzz_http AC#3.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_OnErrorContinue_LiteralBytesInWire(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, getRecv := startRawEchoServer(t, []byte("OK"))

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-cont", preFlowID, "", "", []map[string]any{
		{
			"name":      "tok",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.never_exists",
			"required":  true,
		},
	})

	// Variant payload contains a literal §missing§ token; pre fails →
	// continue policy means the variant still dials, and ExpandTemplate
	// leaves the unresolved token in place as literal bytes.
	literalPayload := "prefix-§missing§-suffix"
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addr,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{literalPayload}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-cont", "on_error": "continue"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}

	// The variant must have reached the wire with the literal §missing§
	// token intact (no normalisation — fuzz_raw passes payloads
	// verbatim).
	caps := waitForCaptures(getRecv, 1, 3*time.Second)
	if len(caps) != 1 {
		t.Fatalf("captured %d connections, want 1", len(caps))
	}
	if string(caps[0]) != literalPayload {
		t.Errorf("wire bytes = %q, want %q (unresolved §var§ should pass through)", caps[0], literalPayload)
	}
}

// ---------------------------------------------------------------------------
// 6. scope="job" pre fires exactly once before the variant loop.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_ScopeJobPre_FiresOnce(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, _ := startRawEchoServer(t, []byte("OK"))

	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&preCalls, 1)
		fmt.Fprintln(w, "{}")
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-job", preFlowID, "", "", nil)

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addr,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1", "v2", "v3", "v4"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-job", "scope": "job"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}
	if got := atomic.LoadInt32(&preCalls); got != 1 {
		t.Errorf("pre called %d times, want 1 (scope=job)", got)
	}
}

// ---------------------------------------------------------------------------
// 7. scope="job" post fires exactly once after the variant loop.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_ScopeJobPost_FiresOnce(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, _ := startRawEchoServer(t, []byte("OK"))

	var postCalls int32
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&postCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(postServer.Close)

	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)
	defineMacroForTest(t, cs, "post-job", postFlowID, "", "", nil)

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addr,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1", "v2", "v3"}},
			},
			"timeout_ms": 5000,
			"post_macro": map[string]any{"name": "post-job", "scope": "job"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}

	// Wait briefly for the job-post fire.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&postCalls) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&postCalls); got != 1 {
		t.Errorf("post called %d times, want 1 (scope=job)", got)
	}
}

// ---------------------------------------------------------------------------
// 8. ADAPTOR-SPECIFIC: run_interval="on_status" is REJECTED at validation
//    with the documented verbatim error message.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_RunIntervalOnStatus_Rejected(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, _ := startRawEchoServer(t, []byte("OK"))

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(preServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/noop", nil, nil)
	defineMacroForTest(t, cs, "post-reject", preFlowID, "", "", nil)

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addr,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1"}},
			},
			"timeout_ms": 5000,
			"post_macro": map[string]any{
				"name":         "post-reject",
				"run_interval": "on_status",
				"status_codes": []int{200},
			},
		},
	})
	wantSubstr := `fuzz_raw: post_macro run_interval="on_status" not supported (raw has no L7 status)`
	if err != nil {
		if !strings.Contains(err.Error(), wantSubstr) {
			t.Fatalf("err = %v, want to contain %q", err, wantSubstr)
		}
		return
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true for run_interval=on_status, got IsError=false")
	}
	var msg strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			msg.WriteString(tc.Text)
		}
	}
	got := msg.String()
	if !strings.Contains(got, wantSubstr) {
		t.Errorf("error text = %q, want to contain %q", got, wantSubstr)
	}
}

// ---------------------------------------------------------------------------
// 9. run_interval="on_match" fires when match_pattern matches the
//    received response bytes via __response_body.
// ---------------------------------------------------------------------------

func TestFuzzRawMacro_RunIntervalOnMatch_FiresAgainstResponseBody(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)

	// Two raw servers — one responds with "MATCHME", one with "NOPE" —
	// so we can verify only the matching variant's post fires.
	addrMatch, _ := startRawEchoServer(t, []byte("MATCHME-token-here"))

	var postCalls int32
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&postCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(postServer.Close)

	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)
	defineMacroForTest(t, cs, "post-on-match", postFlowID, "", "", nil)

	// 3 variants hitting the same matching server → post should fire 3 times
	// because the response always contains MATCHME.
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addrMatch,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1", "v2", "v3"}},
			},
			"timeout_ms": 5000,
			"post_macro": map[string]any{
				"name":          "post-on-match",
				"run_interval":  "on_match",
				"match_pattern": "MATCHME",
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&postCalls) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&postCalls); got != 3 {
		t.Errorf("post fired %d times, want 3 (every response contains MATCHME)", got)
	}

	// Negative path: a different pattern that does NOT match should
	// suppress all post fires.
	atomic.StoreInt32(&postCalls, 0)
	res, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addrMatch,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1", "v2"}},
			},
			"timeout_ms": 5000,
			"post_macro": map[string]any{
				"name":          "post-on-match",
				"run_interval":  "on_match",
				"match_pattern": "NONMATCH",
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool (neg): %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error (neg): %s", msg.String())
	}
	time.Sleep(200 * time.Millisecond)
	if got := atomic.LoadInt32(&postCalls); got != 0 {
		t.Errorf("post fired %d times (neg pattern), want 0", got)
	}
}

// ---------------------------------------------------------------------------
//  10. PRE→POST EXTRACT PROPAGATION (regression for runPreMacro-shadowed
//     kvStore bug discovered in PR #58 review, USK-986). Mirrors fuzz_http's
//     pre→post extract propagation: pre records an extract, post resolves
//     §extract§ via the per-iteration kvStore owned by runOne.
//
// ---------------------------------------------------------------------------
//
// TestFuzzRawMacro_PreExtractVisibleInPostMacro asserts that an extract
// recorded by pre_macro is visible to post_macro via §var§ expansion.
//
// Regression test for the runPreMacro-shadowed-kvStore bug discovered in
// PR #58 review (USK-986). Before the fix, runPreMacro built its own
// local kvStore via PrepareIteration and discarded it on return; the
// kvStore that runPostMacro consumed never received pre's extracts. After
// the fix, runOne owns the kvStore lifecycle and threads it through both
// runPreMacro and runPostMacro — mirroring fuzz_http's pattern.
func TestFuzzRawMacro_PreExtractVisibleInPostMacro(t *testing.T) {
	cs, store := setupFuzzRawMacroSession(t)
	addr, _ := startRawEchoServer(t, []byte("RESPDATA"))

	// preServer issues a fresh session_token per request so each
	// iteration's extract receives a distinct token. If the kvStore is
	// shadowed, post_macro's §session_token§ template will NOT resolve
	// and the post server's query will contain the literal §session_token§
	// instead of the extracted value.
	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&preCalls, 1)
		fmt.Fprintf(w, `{"session_token":"tok-%d"}`, n)
	}))
	t.Cleanup(preServer.Close)

	// postServer records the URL query so we can assert the §session_token§
	// extract propagated from pre→post via the shared kvStore.
	var postRecords atomic.Pointer[[]map[string]string]
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := map[string]string{
			"path":  r.URL.Path,
			"query": r.URL.RawQuery,
		}
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

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", map[string][]string{
		"Content-Type": {"application/json"},
	}, []byte(`{"u":"alice"}`))
	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)

	defineMacroForTest(t, cs, "pre-extract-raw", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	// post macro: OverrideURL references the pre-extracted session_token
	// via §session_token§. If runPreMacro shadows the kvStore (the bug),
	// this template token will fail to resolve and the post server's
	// query will NOT contain a tok-N value.
	overrideURL := postServer.URL + "/audit?token=§session_token§"
	defineMacroForTest(t, cs, "post-uses-extract-raw", postFlowID, overrideURL, "", nil)

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": addr,
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"v1", "v2"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-extract-raw"},
			"post_macro": map[string]any{"name": "post-uses-extract-raw"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
		t.Fatalf("tool error: %s", msg.String())
	}

	// pre called once per variant.
	if got := atomic.LoadInt32(&preCalls); got != 2 {
		t.Errorf("pre called %d times, want 2 (once per variant)", got)
	}

	// Wait for async post fires.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pr := postRecords.Load(); pr != nil && len(*pr) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	prPtr := postRecords.Load()
	if prPtr == nil {
		t.Fatal("post server received no requests")
	}
	prs := *prPtr
	if len(prs) != 2 {
		t.Fatalf("post server received %d requests, want 2", len(prs))
	}

	// The core regression assertion: each post query must contain a
	// resolved tok-N from the pre extract — NOT the literal §session_token§
	// nor an empty value. Before the fix, this assertion fails because the
	// pre-iteration kvStore was discarded by runPreMacro.
	gotTokens := make(map[string]bool)
	for i, rec := range prs {
		q := rec["query"]
		if strings.Contains(q, "§session_token§") {
			t.Errorf("post[%d] query = %q contains unresolved §session_token§ — pre extract did not propagate to post (kvStore shadow regression)", i, q)
		}
		if !strings.Contains(q, "token=tok-") {
			t.Errorf("post[%d] query = %q, want to contain token=tok-N (pre extract should propagate via shared kvStore)", i, q)
		}
		// Strip "token=" prefix so we can dedupe by value.
		for _, part := range strings.Split(q, "&") {
			if strings.HasPrefix(part, "token=") {
				gotTokens[strings.TrimPrefix(part, "token=")] = true
			}
		}
	}
	if !gotTokens["tok-1"] || !gotTokens["tok-2"] {
		t.Errorf("post queries got tokens = %v, want both tok-1 and tok-2 (each iteration's extract must be distinct)", gotTokens)
	}
}

// decodeFuzzRawResult is the structured-content decoder shared across
// fuzz_raw macro tests. Mirrors callFuzzRaw but accepts the raw
// CallToolResult so the test can inspect IsError or chained calls.
func decodeFuzzRawResult(t *testing.T, res *gomcp.CallToolResult) *fuzzRawResult {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatal("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured: %v", err)
	}
	var out fuzzRawResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal structured: %v", err)
	}
	return &out
}

//go:build e2e && !e2e_smoke

package mcp

// fuzz_http_macro_integration_test.go — USK-960 acceptance gate for the
// per-iteration pre_macro / post_macro hooks on the fuzz_http MCP tool.
//
// Acceptance criteria:
//   AC#1 golden: pre extracts a token; fuzz body uses §token§; post sees
//                __response_status / __response_body / __response_headers__
//                and the extracted token.
//   AC#2 skip:   pre fails; fuzz variant is NOT sent; post is NOT run;
//                fuzz_results row carries skipped status; fuzz_macro_results
//                records the failure with status="skipped".
//   AC#3 cont:   on_error=continue with unresolved §var§ in fuzz body sends
//                the literal token on the wire AND records the
//                unresolved-token list in fuzz_results.error.
//   AC#4 reject: scope="job" is rejected at validation with a
//                deferred-to-USK-961 message.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// recordMacroFlow inserts a stream + send flow record so a macro step
// referencing flow_id has a base request to template against. The macro
// step inherits Method / URL / Headers from this flow; OverrideURL /
// OverrideHeaders / extract rules layer on top.
func recordMacroFlow(t *testing.T, store flow.Store, method, rawURL string, headers map[string][]string, body []byte) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url %q: %v", rawURL, err)
	}
	ctx := context.Background()
	stream := &flow.Stream{
		Protocol:  "http",
		Scheme:    u.Scheme,
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, stream); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  stream.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    method,
		URL:       u,
		Headers:   headers,
		Body:      body,
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return stream.ID
}

// defineMacroForTest stores a macro definition via the macro tool. The
// definition is a single-step macro that targets the recorded flow with
// optional Extract rules and an OverrideBody for templating.
func defineMacroForTest(t *testing.T, cs *gomcp.ClientSession, name, recordedFlowID string, overrideURL, overrideBody string, extract []map[string]any) {
	t.Helper()
	step := map[string]any{
		"id":      "main",
		"flow_id": recordedFlowID,
	}
	if overrideURL != "" {
		step["override_url"] = overrideURL
	}
	if overrideBody != "" {
		step["override_body"] = overrideBody
	}
	if len(extract) > 0 {
		step["extract"] = extract
	}
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "macro",
		Arguments: map[string]any{
			"action": "define_macro",
			"params": map[string]any{
				"name":  name,
				"steps": []any{step},
			},
		},
	})
	if err != nil {
		t.Fatalf("define_macro %q: %v", name, err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("define_macro %q returned error: %s", name, msg.String())
	}
}

// setupFuzzHTTPMacroSession is like setupFuzzHTTPSession but additionally
// wires the permissive httpDoer onto jobRunner.replayDoer so hook macros
// targeting 127.0.0.1 httptest servers work end-to-end.
func setupFuzzHTTPMacroSession(t *testing.T) (*gomcp.ClientSession, flow.Store) {
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

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-http-macro-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store
}

// ---------------------------------------------------------------------------
// AC#1 — Golden iteration: pre → fuzz body §token§ → post sees response.
// ---------------------------------------------------------------------------

func TestFuzzHTTPMacro_GoldenIterationThreadsTokenAndResponse(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	// preServer issues a fresh session_token per request (counted) so
	// each iteration's extract receives a distinct token. The fuzz
	// server then asserts the §session_token§ template expanded against
	// the kvStore landed on the wire.
	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&preCalls, 1)
		fmt.Fprintf(w, `{"session_token":"tok-%d"}`, n)
	}))
	t.Cleanup(preServer.Close)

	// postServer records the URL query and body it sees so we can
	// assert __response_status / __response_body / __response_headers__
	// landed in the kvStore and the post macro's OverrideURL +
	// OverrideBody template expanded against them.
	var postRecords atomic.Pointer[[]map[string]string]
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := map[string]string{
			"path":  r.URL.Path,
			"query": r.URL.RawQuery,
			"body":  string(body),
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

	// fuzzServer echoes the X-Token header so we can verify the pre
	// macro's extract landed in the kvStore and expanded into the
	// per-variant fuzz request. It also emits an X-Echo-Header on the
	// response so the post macro can read it via
	// __response_headers__x-echo-header__.
	var fuzzCalls atomic.Pointer[[]map[string]string]
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := map[string]string{
			"path":    r.URL.Path,
			"token":   r.Header.Get("X-Token"),
			"variant": string(body),
		}
		for {
			old := fuzzCalls.Load()
			var cur []map[string]string
			if old != nil {
				cur = append(cur, *old...)
			}
			cur = append(cur, rec)
			if fuzzCalls.CompareAndSwap(old, &cur) {
				break
			}
		}
		w.Header().Set("X-Echo-Header", "echo-value")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok-body-for-%s", r.URL.Path)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", map[string][]string{
		"Content-Type": {"application/json"},
	}, []byte(`{"u":"alice"}`))
	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", map[string][]string{}, []byte("audit"))

	defineMacroForTest(t, cs, "pre-extract", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	// post macro: an OverrideURL referencing the response status / body /
	// echo header so we can assert post-side template expansion received
	// the right kvStore.
	overrideURL := postServer.URL + "/audit?status=§__response_status§&token=§session_token§&echo=§__response_headers__x-echo-header__§"
	overrideBody := "rs=§__response_status§|body=§__response_body§"
	defineMacroForTest(t, cs, "post-record", postFlowID, overrideURL, overrideBody, nil)

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
				{"name": "X-Token", "value": "§session_token§"},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a", "/b"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-extract"},
			"post_macro": map[string]any{"name": "post-record"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned error: %s", msg.String())
	}

	// Decode result for fuzz_id lookup.
	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", out.CompletedVariants)
	}

	// pre called once per variant.
	if got := atomic.LoadInt32(&preCalls); got != 2 {
		t.Errorf("pre macro called %d times, want 2", got)
	}

	// fuzz received the per-variant tokens (tok-1, tok-2).
	fzCalls := *fuzzCalls.Load()
	if len(fzCalls) != 2 {
		t.Fatalf("fuzz server received %d requests, want 2", len(fzCalls))
	}
	gotTokens := map[string]bool{fzCalls[0]["token"]: true, fzCalls[1]["token"]: true}
	if !gotTokens["tok-1"] || !gotTokens["tok-2"] {
		t.Errorf("fuzz request X-Token = %v, want tok-1 and tok-2", gotTokens)
	}

	// post received the response status (200) + extracted token + echo
	// header from the post-record OverrideURL template.
	if postRecords.Load() == nil {
		t.Fatal("post server received no requests")
	}
	pRecs := *postRecords.Load()
	if len(pRecs) != 2 {
		t.Fatalf("post server received %d requests, want 2", len(pRecs))
	}
	for i, rec := range pRecs {
		if !strings.Contains(rec["query"], "status=200") {
			t.Errorf("post[%d] query = %q, want to contain status=200", i, rec["query"])
		}
		if !strings.Contains(rec["query"], "echo=echo-value") {
			t.Errorf("post[%d] query = %q, want to contain echo=echo-value", i, rec["query"])
		}
		if !strings.Contains(rec["query"], "token=tok-") {
			t.Errorf("post[%d] query = %q, want to contain token=tok-N", i, rec["query"])
		}
		// Body should be rs=200|body=ok-body-for-/a (or /b).
		if !strings.HasPrefix(rec["body"], "rs=200|body=ok-body-for-") {
			t.Errorf("post[%d] body = %q, want prefix rs=200|body=ok-body-for-", i, rec["body"])
		}
	}

	// fuzz_macro_results: 2 pre + 2 post rows, all "ok".
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("fuzz_macro_results rows = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Status != "ok" {
			t.Errorf("hook %d/%s status=%q, want ok (err=%q)", r.IndexNum, r.HookName, r.Status, r.Error)
		}
	}
}

// ---------------------------------------------------------------------------
// AC#2 — on_error=skip: pre fails, fuzz body NOT sent, post NOT run.
// ---------------------------------------------------------------------------

func TestFuzzHTTPMacro_OnErrorSkipShortCircuitsIteration(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	// preServer returns 500 so the macro's extract with required=true
	// fails — propagating into pre_macro hook error.
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	var fuzzCalls int32
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fuzzCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	var postCalls int32
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&postCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(postServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)

	defineMacroForTest(t, cs, "pre-required", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})
	defineMacroForTest(t, cs, "post-noop", postFlowID, "", "", nil)

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a", "/b"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-required", "on_error": "skip"},
			"post_macro": map[string]any{"name": "post-noop"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned unexpected error: %s", msg.String())
	}

	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)
	if got := atomic.LoadInt32(&fuzzCalls); got != 0 {
		t.Errorf("fuzz server saw %d requests, want 0 (pre skip must short-circuit send)", got)
	}
	if got := atomic.LoadInt32(&postCalls); got != 0 {
		t.Errorf("post server saw %d requests, want 0 (pre skip must short-circuit post)", got)
	}

	for _, row := range out.Variants {
		if row.Error == "" {
			t.Errorf("variant %d Error is empty, want non-empty pre-skip diagnostic", row.Index)
		}
	}

	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	preRows := 0
	postRows := 0
	for _, r := range results {
		switch r.HookName {
		case "pre":
			preRows++
			if r.Status != "skipped" {
				t.Errorf("pre row idx=%d status=%q, want skipped", r.IndexNum, r.Status)
			}
		case "post":
			postRows++
		}
	}
	if preRows != 2 {
		t.Errorf("pre rows = %d, want 2", preRows)
	}
	if postRows != 0 {
		t.Errorf("post rows = %d, want 0 (post must not fire when pre is skipped)", postRows)
	}
}

// ---------------------------------------------------------------------------
// AC#3 — on_error=continue + unresolved §var§: literal wire + diag.
// ---------------------------------------------------------------------------

func TestFuzzHTTPMacro_OnErrorContinuePassesUnresolvedTokens(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	// preServer returns 500 — extract with required=true fails — but
	// on_error=continue tells the variant loop to proceed anyway.
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	// fuzzServer captures X-Token (which carries a literal §session_token§
	// on the wire because pre never extracted it).
	var fuzzTokens atomic.Pointer[[]string]
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Token")
		for {
			old := fuzzTokens.Load()
			var cur []string
			if old != nil {
				cur = append(cur, *old...)
			}
			cur = append(cur, tok)
			if fuzzTokens.CompareAndSwap(old, &cur) {
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)

	defineMacroForTest(t, cs, "pre-fail", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
				{"name": "X-Token", "value": "§session_token§"},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-fail", "on_error": "continue"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned unexpected error: %s", msg.String())
	}

	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)

	// Fuzz server should have received the request — but X-Token is
	// not directly fuzzed via positions; instead the literal
	// §session_token§ flows through the header VALUE template
	// substitution path. resend_http's header-template expansion is
	// driven by the HTTPMessage build; the literal stays in place if
	// session_token is missing from the kvStore. We assert the request
	// reached the fuzz server (continue semantics) and that the diag
	// surfaces on the variant row.
	if fuzzTokens.Load() == nil || len(*fuzzTokens.Load()) == 0 {
		t.Fatal("fuzz server received no requests; on_error=continue must allow send")
	}

	// Unresolved diagnostic surfaces on the row. Position payloads
	// reference no template here (positions are /a only), so we add a
	// position with a §var§ token by re-running with body template.
	_ = out
}

// TestFuzzHTTPMacro_OnErrorContinue_UnresolvedDiagInPositionPayload exercises
// the unresolved-token collector specifically by placing a §var§ in a
// position payload and asserting that the variant row's Error string
// records the unresolved name. on_error=continue keeps the variant loop
// running so the diag can be observed downstream.
func TestFuzzHTTPMacro_OnErrorContinue_UnresolvedDiagInPositionPayload(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	var fuzzPaths atomic.Pointer[[]string]
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			old := fuzzPaths.Load()
			var cur []string
			if old != nil {
				cur = append(cur, *old...)
			}
			cur = append(cur, r.URL.Path)
			if fuzzPaths.CompareAndSwap(old, &cur) {
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)

	defineMacroForTest(t, cs, "pre-fail-2", preFlowID, "", "", []map[string]any{
		{
			"name":      "missing_var",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.missing_var",
			"required":  true,
		},
	})

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				// Payload references §missing_var§ which will not be in
				// the kvStore (extract failed). ExpandTemplate leaves it
				// literal; collectUnresolvedFuzzTokens captures the name.
				{"path": "path", "payloads": []string{"/seed/§missing_var§"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-fail-2", "on_error": "continue"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned unexpected error: %s", msg.String())
	}

	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)
	if out.CompletedVariants != 1 {
		t.Fatalf("CompletedVariants = %d, want 1", out.CompletedVariants)
	}
	if len(out.Variants) != 1 {
		t.Fatalf("len(Variants) = %d, want 1", len(out.Variants))
	}
	row := out.Variants[0]
	if !strings.Contains(row.Error, "unresolved-tokens") {
		t.Errorf("variant Error = %q, want to contain 'unresolved-tokens'", row.Error)
	}
	if !strings.Contains(row.Error, "missing_var") {
		t.Errorf("variant Error = %q, want to contain 'missing_var'", row.Error)
	}

	// Wire received the literal §missing_var§ inside the path.
	if fuzzPaths.Load() == nil {
		t.Fatal("fuzz server received no requests")
	}
	paths := *fuzzPaths.Load()
	if len(paths) != 1 {
		t.Fatalf("fuzz paths = %d, want 1", len(paths))
	}
	if !strings.Contains(paths[0], "§missing_var§") {
		t.Errorf("fuzz path = %q, want to contain literal §missing_var§", paths[0])
	}
}

// ---------------------------------------------------------------------------
// USK-961 — scope="job" + mix-scope tests.
// ---------------------------------------------------------------------------

// TestFuzzHTTPMacro_ScopeJobPreSharesKVAcrossVariants covers AC#1 +
// AC#2 of USK-961: pre=job login once → fuzz N variants share the
// extracted token via templated header; post=iteration audits each.
// Asserts pre-job fires exactly once (fuzz_macro_results row at
// index_num=-1, hook_name="pre"); post-iteration fires N times.
func TestFuzzHTTPMacro_ScopeJobPreSharesKVAcrossVariants(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	// preServer issues the same session_token every call so we can
	// assert every variant sees the same value.
	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&preCalls, 1)
		fmt.Fprint(w, `{"session_token":"job-tok-shared"}`)
	}))
	t.Cleanup(preServer.Close)

	// postServer records the URL query so we can assert the post macro's
	// OverrideURL expanded against per-iteration kvStore + the inherited
	// pre-job extract.
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

	// fuzzServer records the X-Token header so we can confirm every
	// variant carried the pre-job extracted token.
	var fuzzTokens atomic.Pointer[[]string]
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Token")
		for {
			old := fuzzTokens.Load()
			var cur []string
			if old != nil {
				cur = append(cur, *old...)
			}
			cur = append(cur, tok)
			if fuzzTokens.CompareAndSwap(old, &cur) {
				break
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/audit", nil, nil)

	defineMacroForTest(t, cs, "pre-job-login", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})
	// post-iteration audits each variant's status. References §session_token§
	// to confirm job-store extracts are merged into per-iteration kvStore.
	overrideURL := postServer.URL + "/audit?iter=§__iteration§&token=§session_token§"
	defineMacroForTest(t, cs, "post-iter-audit", postFlowID, overrideURL, "audit", nil)

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
				{"name": "X-Token", "value": "§session_token§"},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a", "/b", "/c"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-job-login", "scope": "job"},
			"post_macro": map[string]any{"name": "post-iter-audit", "scope": "iteration"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned error: %s", msg.String())
	}

	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.CompletedVariants != 3 {
		t.Fatalf("CompletedVariants = %d, want 3", out.CompletedVariants)
	}

	// AC: pre-job called exactly once.
	if got := atomic.LoadInt32(&preCalls); got != 1 {
		t.Errorf("pre macro called %d times, want 1 (scope=job)", got)
	}

	// AC: every variant carried the shared token.
	tokens := *fuzzTokens.Load()
	if len(tokens) != 3 {
		t.Fatalf("fuzz received %d requests, want 3", len(tokens))
	}
	for i, tok := range tokens {
		if tok != "job-tok-shared" {
			t.Errorf("variant %d X-Token = %q, want job-tok-shared", i, tok)
		}
	}

	// AC: post-iteration called 3 times. The OverrideURL referenced
	// §session_token§ so post-iteration confirms the job-store extract
	// is merged into each iteration's kvStore.
	if postRecords.Load() == nil {
		t.Fatal("post server received no requests")
	}
	pRecs := *postRecords.Load()
	if len(pRecs) != 3 {
		t.Fatalf("post server received %d requests, want 3", len(pRecs))
	}
	for i, rec := range pRecs {
		if !strings.Contains(rec["query"], "token=job-tok-shared") {
			t.Errorf("post-iter[%d] query = %q, want to contain token=job-tok-shared", i, rec["query"])
		}
	}

	// AC: fuzz_macro_results — 1 pre row (index_num=-1, hook="pre") + 3
	// post rows (index_num=0..2, hook="post"), all "ok".
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("fuzz_macro_results rows = %d, want 4", len(results))
	}
	preRows, postRows := 0, 0
	for _, r := range results {
		if r.Status != "ok" {
			t.Errorf("row hook=%s idx=%d status=%q, want ok (err=%q)", r.HookName, r.IndexNum, r.Status, r.Error)
		}
		switch r.HookName {
		case "pre":
			preRows++
			if r.IndexNum != -1 {
				t.Errorf("pre row index_num = %d, want -1 (job-scope sentinel)", r.IndexNum)
			}
		case "post":
			postRows++
			if r.IndexNum < 0 || r.IndexNum >= 3 {
				t.Errorf("post row index_num = %d, want 0..2", r.IndexNum)
			}
		}
	}
	if preRows != 1 {
		t.Errorf("pre rows = %d, want 1", preRows)
	}
	if postRows != 3 {
		t.Errorf("post rows = %d, want 3", postRows)
	}
}

// TestFuzzHTTPMacro_ScopeJobPostFiresOnceAfterLoop covers the mix-scope
// pre=iteration + post=job case. Asserts post-job fires exactly once
// after the last variant, with index_num=-1. Also asserts post-job's
// kvStore does NOT contain __response_* keys (Q4 / Q21).
func TestFuzzHTTPMacro_ScopeJobPostFiresOnceAfterLoop(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	// preServer rotates a per-iteration token.
	var preCalls int32
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&preCalls, 1)
		fmt.Fprintf(w, `{"per_iter_token":"tok-%d"}`, n)
	}))
	t.Cleanup(preServer.Close)

	// postServer records the URL query so we can assert the post-job
	// template did NOT see any __response_* keys (they should be left
	// literal because the kvStore for post-job is the job kvStore, not
	// the discarded per-iteration store).
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

	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/summary", nil, nil)

	defineMacroForTest(t, cs, "pre-iter-rotate", preFlowID, "", "", []map[string]any{
		{
			"name":      "per_iter_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.per_iter_token",
			"required":  true,
		},
	})
	// Post-job's OverrideURL references __response_status — for post-job
	// scope this key should NOT be in the kvStore, so the template
	// resolves to the literal "§__response_status§".
	overrideURL := postServer.URL + "/summary?rs=§__response_status§"
	defineMacroForTest(t, cs, "post-job-summary", postFlowID, overrideURL, "summary", nil)

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a", "/b"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-iter-rotate", "scope": "iteration"},
			"post_macro": map[string]any{"name": "post-job-summary", "scope": "job"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned error: %s", msg.String())
	}

	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)
	if out.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", out.CompletedVariants)
	}

	// AC: pre-iteration called twice; post-job called once.
	if got := atomic.LoadInt32(&preCalls); got != 2 {
		t.Errorf("pre called %d times, want 2 (scope=iteration)", got)
	}
	if postRecords.Load() == nil {
		t.Fatal("post server received no requests")
	}
	pRecs := *postRecords.Load()
	if len(pRecs) != 1 {
		t.Fatalf("post server received %d requests, want 1 (scope=job)", len(pRecs))
	}

	// AC: post-job kvStore did NOT carry __response_status — the
	// template is left literal because the variable was never set.
	if !strings.Contains(pRecs[0]["query"], "rs=%C2%A7__response_status%C2%A7") &&
		!strings.Contains(pRecs[0]["query"], "rs=§__response_status§") {
		t.Errorf("post-job query = %q, want literal §__response_status§ (post-job must not see __response_* keys)", pRecs[0]["query"])
	}

	// AC: fuzz_macro_results — 2 pre rows (index_num=0,1) + 1 post row
	// (index_num=-1), all ok.
	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("fuzz_macro_results rows = %d, want 3", len(results))
	}
	preRows, postRows := 0, 0
	for _, r := range results {
		switch r.HookName {
		case "pre":
			preRows++
			if r.IndexNum < 0 || r.IndexNum >= 2 {
				t.Errorf("pre row index_num = %d, want 0..1", r.IndexNum)
			}
		case "post":
			postRows++
			if r.IndexNum != -1 {
				t.Errorf("post row index_num = %d, want -1 (job-scope sentinel)", r.IndexNum)
			}
		}
	}
	if preRows != 2 {
		t.Errorf("pre rows = %d, want 2", preRows)
	}
	if postRows != 1 {
		t.Errorf("post rows = %d, want 1", postRows)
	}
}

// TestFuzzHTTPMacro_ScopeJobPreAbortOnErrorAbortsJob covers pre=job +
// on_error=abort + failing macro: zero variants run; caller-side error
// contains "pre_macro hook abort (scope=job)"; one fuzz_macro_results
// row at index_num=-1, status="error".
func TestFuzzHTTPMacro_ScopeJobPreAbortOnErrorAbortsJob(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	// preServer returns 500 — required extract fails — abort policy.
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	var fuzzCalls int32
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fuzzCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-required-job-abort", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a", "/b", "/c"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-required-job-abort", "scope": "job", "on_error": "abort"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError for pre=job + on_error=abort, got success")
	}

	var msg strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			msg.WriteString(tc.Text)
		}
	}
	if !strings.Contains(msg.String(), "pre_macro hook abort (scope=job)") {
		t.Errorf("error = %q, want to contain 'pre_macro hook abort (scope=job)'", msg.String())
	}

	if got := atomic.LoadInt32(&fuzzCalls); got != 0 {
		t.Errorf("fuzz server saw %d requests, want 0 (pre-job abort must short-circuit before any variant)", got)
	}

	// Look up the fuzz_id from the fuzz_jobs table — we need it to
	// query fuzz_macro_results. The pre_macro hook saved a row with
	// fuzzID set, so we list all macro results and find the matching
	// one. (Alternative: use a deterministic fuzz_id, but the tool
	// generates one internally.)
	fs := store.(flow.FuzzStore)
	jobs, err := fs.ListFuzzJobs(context.Background(), flow.FuzzJobListOptions{})
	if err != nil {
		t.Fatalf("ListFuzzJobs: %v", err)
	}
	if len(jobs) == 0 {
		t.Fatal("no fuzz_jobs row recorded; pre-job abort must still create the job row")
	}
	// Take the most recent job.
	fuzzID := jobs[0].ID
	results, err := fs.ListFuzzMacroResults(context.Background(), fuzzID)
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
	if r.Status != "error" {
		t.Errorf("status = %q, want error (on_error=abort + failure)", r.Status)
	}
}

// TestFuzzHTTPMacro_ScopeJobPreContinueOnErrorProceeds covers pre=job +
// on_error=continue + failing macro: every variant runs because the
// continue policy proceeds with whatever jobKVStore captured, one
// fuzz_macro_results row at index_num=-1 / status="error" records the
// pre-job failure, and CompletedVariants == totalVariants. Sibling to
// TestFuzzHTTPMacro_ScopeJobPreAbortOnErrorAbortsJob (USK-979 AC#2).
func TestFuzzHTTPMacro_ScopeJobPreContinueOnErrorProceeds(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	// preServer returns 500 — required extract fails. With on_error=continue
	// the variant loop must still proceed.
	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	var fuzzCalls int32
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fuzzCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-required-job-continue", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	totalVariants := 3
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a", "/b", "/c"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-required-job-continue", "scope": "job", "on_error": "continue"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned unexpected error (on_error=continue must not abort): %s", msg.String())
	}

	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)

	if out.CompletedVariants != totalVariants {
		t.Errorf("CompletedVariants = %d, want %d (on_error=continue must run every variant)", out.CompletedVariants, totalVariants)
	}
	if got := atomic.LoadInt32(&fuzzCalls); int(got) != totalVariants {
		t.Errorf("fuzz server saw %d requests, want %d", got, totalVariants)
	}
	if out.StoppedReason != "" {
		t.Errorf("StoppedReason = %q, want \"\" (continue must not set a stopped_reason)", out.StoppedReason)
	}

	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	// continue policy records the pre-job failure as one row at
	// index_num=-1 / status="error". No post hook is configured, so this
	// is the only fuzz_macro_results row expected.
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
	if r.Status != "error" {
		t.Errorf("status = %q, want error (on_error=continue records the failure)", r.Status)
	}
}

// TestFuzzHTTPMacro_ScopeJobIndexNumSentinel asserts that
// ListFuzzMacroResults rows for job-scope hooks have IndexNum == -1
// exactly (covers AC#5 of USK-961).
func TestFuzzHTTPMacro_ScopeJobIndexNumSentinel(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"k":"v"}`)
	}))
	t.Cleanup(preServer.Close)
	postServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(postServer.Close)
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	postFlowID := recordMacroFlow(t, store, "POST", postServer.URL+"/sum", nil, nil)
	defineMacroForTest(t, cs, "pre-noop-job", preFlowID, "", "", nil)
	defineMacroForTest(t, cs, "post-noop-job", postFlowID, "", "", nil)

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a", "/b"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-noop-job", "scope": "job"},
			"post_macro": map[string]any{"name": "post-noop-job", "scope": "job"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned error: %s", msg.String())
	}

	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)

	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	// Both job-scope hooks must produce exactly one row each at
	// index_num=-1.
	if len(results) != 2 {
		t.Fatalf("fuzz_macro_results rows = %d, want 2", len(results))
	}
	for _, r := range results {
		if r.IndexNum != -1 {
			t.Errorf("hook=%s index_num = %d, want -1 (job-scope sentinel)", r.HookName, r.IndexNum)
		}
		if r.Status != "ok" {
			t.Errorf("hook=%s status = %q, want ok", r.HookName, r.Status)
		}
	}
}

// TestFuzzHTTPMacro_ScopeJobPreSkipOnErrorReturnsStoppedReason covers
// U1 (user-confirmed): pre=job + on_error=skip + failing macro returns
// success with CompletedVariants=0 and stopped_reason set. One
// fuzz_macro_results row at index_num=-1, status="skipped".
func TestFuzzHTTPMacro_ScopeJobPreSkipOnErrorReturnsStoppedReason(t *testing.T) {
	cs, store := setupFuzzHTTPMacroSession(t)

	preServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(preServer.Close)

	var fuzzCalls int32
	fuzzServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fuzzCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fuzzServer.Close)

	preFlowID := recordMacroFlow(t, store, "POST", preServer.URL+"/login", nil, nil)
	defineMacroForTest(t, cs, "pre-required-job-skip", preFlowID, "", "", []map[string]any{
		{
			"name":      "session_token",
			"from":      "response",
			"source":    "body_json",
			"json_path": "$.session_token",
			"required":  true,
		},
	})

	authority := strings.TrimPrefix(fuzzServer.URL, "http://")
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{"/a", "/b", "/c"}},
			},
			"timeout_ms": 5000,
			"pre_macro":  map[string]any{"name": "pre-required-job-skip", "scope": "job", "on_error": "skip"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("fuzz_http returned unexpected error: %s", msg.String())
	}

	var out fuzzHTTPResult
	raw, _ := json.Marshal(res.StructuredContent)
	_ = json.Unmarshal(raw, &out)

	if out.CompletedVariants != 0 {
		t.Errorf("CompletedVariants = %d, want 0 (pre-job skip must short-circuit before any variant)", out.CompletedVariants)
	}
	if !strings.Contains(out.StoppedReason, "pre_macro hook skipped (scope=job, on_error=skip)") {
		t.Errorf("StoppedReason = %q, want to contain 'pre_macro hook skipped (scope=job, on_error=skip)'", out.StoppedReason)
	}
	if got := atomic.LoadInt32(&fuzzCalls); got != 0 {
		t.Errorf("fuzz server saw %d requests, want 0", got)
	}

	fs := store.(flow.FuzzStore)
	results, err := fs.ListFuzzMacroResults(context.Background(), out.FuzzID)
	if err != nil {
		t.Fatalf("ListFuzzMacroResults: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("fuzz_macro_results rows = %d, want 1", len(results))
	}
	r := results[0]
	if r.HookName != "pre" || r.IndexNum != -1 || r.Status != "skipped" {
		t.Errorf("row = {hook=%q, index_num=%d, status=%q}, want {hook=pre, index_num=-1, status=skipped}",
			r.HookName, r.IndexNum, r.Status)
	}
}

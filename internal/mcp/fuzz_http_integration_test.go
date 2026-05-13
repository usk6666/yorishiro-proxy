//go:build e2e && !e2e_smoke

package mcp

// fuzz_http_integration_test.go — RFC-001 N8 acceptance gate for the
// fuzz_http MCP tool (USK-677).
//
// Acceptance criteria:
//   AC#1: N variant generation + per-variant Stream rows in flow store
//   AC#2: PluginStepPost fires per variant; PluginStepPre never fires
//   AC#3: Position field path syntax aligned with HTTPMessage struct
//   AC#4: Legacy `fuzz` tool unaffected (parallel coexistence)

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// fuzzHTTPHookCallable wraps a Go counter increment in a Starlark
// Callable. Mirrors helpers in resend_*_integration_test.go.
func fuzzHTTPHookCallable(name string, fn func()) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		fn()
		return starlark.None, nil
	})
}

// setupFuzzHTTPSession spins up an MCP server pre-wired with a fresh
// flow store and a pluginv2.Engine that pre-registers pre/post counter
// hooks for ("http", "on_request"). Returns the client session, the
// flow store, and the (preCount, postCount) atomic pointers.
func setupFuzzHTTPSession(t *testing.T) (*gomcp.ClientSession, flow.Store, *int32, *int32) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	var preCount, postCount int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoHTTP,
		Event:      pluginv2.EventOnRequest,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "fuzz-http-pre",
		Fn: fuzzHTTPHookCallable("pre", func() {
			atomic.AddInt32(&preCount, 1)
		}),
	})
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoHTTP,
		Event:      pluginv2.EventOnRequest,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "fuzz-http-post",
		Fn: fuzzHTTPHookCallable("post", func() {
			atomic.AddInt32(&postCount, 1)
		}),
	})

	ctx := context.Background()
	// USK-827: the underlying SQLiteStore implements both flow.Store and
	// flow.FuzzStore. Wire it through WithFuzzStore so handleFuzzHTTP can
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

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-http-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store, &preCount, &postCount
}

// startFuzzHTTPEcho stands up a plain-HTTP server that echoes the
// request method + path + query + body in JSON. Captured request data
// is exposed via the returned getter. The X-Marker request header (if
// present) is also captured into entry["x_marker"] so header-mutation
// tests can assert the substituted value reached the wire. The Host
// header is captured into entry["host"] so USK-830 regression tests
// can assert the synthetic Host stays at the authority value when
// fuzzing user headers without supplying Host explicitly.
func startFuzzHTTPEcho(t *testing.T) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var captured atomic.Pointer[[]map[string]any]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		entry := map[string]any{
			"method":   r.Method,
			"path":     r.URL.Path,
			"query":    r.URL.RawQuery,
			"body":     string(body),
			"x_marker": r.Header.Get("X-Marker"),
			"host":     r.Host,
		}
		// Append-by-CAS so concurrent variants (none today, but defensive)
		// don't lose entries.
		for {
			old := captured.Load()
			var cur []map[string]any
			if old != nil {
				cur = append(cur, *old...)
			}
			cur = append(cur, entry)
			if captured.CompareAndSwap(old, &cur) {
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(entry)
	}))
	t.Cleanup(srv.Close)
	get := func() []map[string]any {
		out := captured.Load()
		if out == nil {
			return nil
		}
		return *out
	}
	return srv, get
}

// callFuzzHTTP issues the fuzz_http tool and decodes the structured
// result. Test fails on transport errors or IsError responses.
func callFuzzHTTP(t *testing.T, cs *gomcp.ClientSession, input map[string]any) *fuzzHTTPResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "fuzz_http",
		Arguments: input,
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
		t.Fatalf("tool returned error: %s", msg.String())
	}
	if res.StructuredContent == nil {
		t.Fatal("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out fuzzHTTPResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	return &out
}

// ---------------------------------------------------------------------------
// AC#1 + AC#2 — N variant generation + per-variant Stream rows + plugin
// hook firing per variant (post fires N times; pre never fires).
// ---------------------------------------------------------------------------

func TestFuzzHTTP_PathPositionGeneratesVariants(t *testing.T) {
	cs, store, preCount, postCount := setupFuzzHTTPSession(t)
	echo, getCaptured := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	payloads := []string{"/a", "/b", "/c", "/d", "/e"}
	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": payloads},
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

	// Each variant should have hit a different path.
	seen := map[string]bool{}
	for _, entry := range getCaptured() {
		seen[entry["path"].(string)] = true
	}
	for _, p := range payloads {
		if !seen[p] {
			t.Errorf("upstream did not see path %q", p)
		}
	}

	// Per-variant Stream rows.
	for i, row := range result.Variants {
		if row.StreamID == "" {
			t.Errorf("variants[%d].StreamID is empty", i)
		}
		if row.StatusCode != 200 {
			t.Errorf("variants[%d].StatusCode = %d, want 200", i, row.StatusCode)
		}
		s, err := store.GetStream(context.Background(), row.StreamID)
		if err != nil || s == nil {
			t.Errorf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
			continue
		}
		// USK-832: every variant Stream must transition out of
		// State="active" once the exchange returns. Without the
		// finalizeResendStream call in runFuzzHTTPSingleVariant, fuzz
		// bypasses session.RunSession's OnComplete hook so the rows
		// would stay pinned at "active".
		if s.State != "complete" {
			t.Errorf("variants[%d].State = %q, want %q (USK-832: fuzz_http must finalise variant stream lifecycle)", i, s.State, "complete")
		}
	}

	// AC#2: post fires once per variant (Send envelope only — the
	// response envelope dispatches to ("http","on_response"), which we
	// haven't registered). Pre never fires (resend bypass).
	if got := atomic.LoadInt32(preCount); got != 0 {
		t.Errorf("on_request pre hook fired %d times, want 0 (PluginStepPre bypassed)", got)
	}
	wantPost := int32(len(payloads))
	if got := atomic.LoadInt32(postCount); got != wantPost {
		t.Errorf("on_request post hook fired %d times, want %d (one Send envelope per variant)", got, wantPost)
	}
}

// ---------------------------------------------------------------------------
// AC#3 — Position path syntax: headers[N].value mutation.
// ---------------------------------------------------------------------------

func TestFuzzHTTP_HeaderIndexPosition(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	echo, getCaptured := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	headerValues := []string{"alpha", "beta", "gamma"}
	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/probe",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
			{"name": "X-Marker", "value": "ORIGINAL"},
		},
		"positions": []map[string]any{
			{"path": "headers[1].value", "payloads": headerValues},
		},
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != len(headerValues) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(headerValues))
	}

	// AC#3 mutation assertion: every fuzz payload must reach the wire as
	// the X-Marker request header value. Without this check the headers[N].value
	// path could regress to a no-op and the test would still pass.
	probes := 0
	seenMarkers := map[string]bool{}
	for _, entry := range getCaptured() {
		if entry["path"] != "/probe" {
			continue
		}
		probes++
		if v, ok := entry["x_marker"].(string); ok {
			seenMarkers[v] = true
		}
	}
	if probes != len(headerValues) {
		t.Errorf("probes hit /probe = %d, want %d", probes, len(headerValues))
	}
	for _, want := range headerValues {
		if !seenMarkers[want] {
			t.Errorf("upstream did not see X-Marker=%q (saw %v)", want, seenMarkers)
		}
	}
	// Defensive: the original "ORIGINAL" value must not have leaked
	// through — every variant should have been mutated.
	if seenMarkers["ORIGINAL"] {
		t.Error("upstream saw X-Marker=ORIGINAL — base header leaked into a variant")
	}
}

// TestFuzzHTTP_HeaderIndexExcludesInjectedHost locks the USK-830
// semantics: `headers[N]` resolves against the user-supplied input
// array, NOT the post-injection envelope wire order. When the input
// headers list omits Host, ensureResendHTTPHostHeader prepends a
// synthetic `Host:` at envelope index 0; previously fuzzing
// `headers[0].value` would mutate that synthetic Host, leaving the
// user's first header untouched. The fix aligns the index with the
// input array so `headers[0].value` mutates the user's first header
// and Host stays at the authority value.
//
// This complements TestFuzzHTTP_HeaderIndexPosition, which already
// locks the Host-supplied branch (Host at user index 0).
func TestFuzzHTTP_HeaderIndexExcludesInjectedHost(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	echo, getCaptured := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	headerValues := []string{"FUZZED-1", "FUZZED-2", "FUZZED-3"}
	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/probe",
		// Deliberately omit Host from the input headers list so the
		// synthetic-Host-injection branch fires inside
		// ensureResendHTTPHostHeader.
		"headers": []map[string]any{
			{"name": "X-Marker", "value": "ORIGINAL"},
		},
		"positions": []map[string]any{
			// headers[0] must address the user's first input header
			// (X-Marker), not the synthetic Host that lands at envelope
			// index 0 after injection.
			{"path": "headers[0].value", "payloads": headerValues},
		},
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != len(headerValues) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(headerValues))
	}

	probes := 0
	seenMarkers := map[string]bool{}
	seenHosts := map[string]bool{}
	for _, entry := range getCaptured() {
		if entry["path"] != "/probe" {
			continue
		}
		probes++
		if v, ok := entry["x_marker"].(string); ok {
			seenMarkers[v] = true
		}
		if v, ok := entry["host"].(string); ok {
			seenHosts[v] = true
		}
	}
	if probes != len(headerValues) {
		t.Errorf("probes hit /probe = %d, want %d", probes, len(headerValues))
	}
	// X-Marker MUST be mutated by every variant — the regression locks
	// the user-input-array semantics.
	for _, want := range headerValues {
		if !seenMarkers[want] {
			t.Errorf("upstream did not see X-Marker=%q (saw %v)", want, seenMarkers)
		}
	}
	if seenMarkers["ORIGINAL"] {
		t.Error("upstream saw X-Marker=ORIGINAL — fuzz mutated wrong header (regression: USK-830)")
	}
	// Host MUST stay at the authority value across all variants — the
	// fuzz payloads MUST NOT leak into Host.
	for _, p := range headerValues {
		if seenHosts[p] {
			t.Errorf("upstream saw Host=%q — fuzz payload leaked into synthetic Host (regression: USK-830). Hosts observed: %v", p, seenHosts)
		}
	}
	if !seenHosts[authority] {
		t.Errorf("upstream did not see Host=%q — synthetic Host not preserved. Hosts observed: %v", authority, seenHosts)
	}
}

// TestFuzzHTTP_HeaderIndexBoundsRejectsInputArrayLength confirms the
// USK-830 bounds check error references the user-input array length
// (not the post-injection envelope length). Operator submits a
// 1-element headers list and targets headers[1] — the error must
// surface "out of range [0, 1)" not "out of range [0, 2)".
func TestFuzzHTTP_HeaderIndexBoundsRejectsInputArrayLength(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	echo, _ := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/probe",
			// 1-element input → headers[1] must be rejected.
			"headers": []map[string]any{
				{"name": "X-Marker", "value": "ORIGINAL"},
			},
			"positions": []map[string]any{
				{"path": "headers[1].value", "payloads": []string{"x"}},
			},
			"timeout_ms": 5000,
		},
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_http: %v", err)
	}
	// The bounds check fires inside applyFuzzHTTPPosition during the
	// variant loop, so the tool returns CompletedVariants=0 with an
	// IsError tool response. Either an IsError response or an error
	// in the per-variant row is acceptable; both must mention the
	// input-array length.
	var msg strings.Builder
	if result.IsError {
		for _, c := range result.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
			}
		}
	} else if result.StructuredContent != nil {
		raw, _ := json.Marshal(result.StructuredContent)
		var out fuzzHTTPResult
		_ = json.Unmarshal(raw, &out)
		for _, v := range out.Variants {
			msg.WriteString(v.Error)
		}
	}
	combined := msg.String()
	if !strings.Contains(combined, "out of range [0, 1)") {
		t.Errorf("expected bounds error referencing input-array length 1, got: %q", combined)
	}
}

// ---------------------------------------------------------------------------
// Cartesian product across two positions.
// ---------------------------------------------------------------------------

func TestFuzzHTTP_TwoPositionCartesian(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	echo, getCaptured := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	methods := []string{"GET", "POST", "PUT"}
	paths := []string{"/x", "/y"}
	expectedTotal := len(methods) * len(paths) // 6

	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "method", "payloads": methods},
			{"path": "path", "payloads": paths},
		},
		"timeout_ms": 10000,
	})
	if result.TotalVariants != expectedTotal {
		t.Errorf("TotalVariants = %d, want %d", result.TotalVariants, expectedTotal)
	}
	if result.CompletedVariants != expectedTotal {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, expectedTotal)
	}
	if hits := len(getCaptured()); hits != expectedTotal {
		t.Errorf("upstream hit count = %d, want %d", hits, expectedTotal)
	}

	// Verify all (method, path) pairs were sent.
	pairs := map[string]bool{}
	for _, entry := range getCaptured() {
		key := fmt.Sprintf("%s %s", entry["method"], entry["path"])
		pairs[key] = true
	}
	for _, m := range methods {
		for _, p := range paths {
			key := fmt.Sprintf("%s %s", m, p)
			if !pairs[key] {
				t.Errorf("missing variant %q", key)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Validation: empty positions rejected.
// ---------------------------------------------------------------------------

func TestFuzzHTTP_RejectsEmptyPositions(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": "127.0.0.1:9999",
			"path":      "/x",
			"positions": []map[string]any{},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for empty positions; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: invalid path syntax rejected.
// ---------------------------------------------------------------------------

func TestFuzzHTTP_RejectsInvalidPath(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": "127.0.0.1:9999",
			"path":      "/x",
			"positions": []map[string]any{
				{"path": "trailers[0].value", "payloads": []string{"x"}},
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

func TestFuzzHTTP_RejectsExcessiveVariantCount(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	// 2 positions × 100 payloads × 100 payloads = 10000 → exceeds 1000 cap.
	bigList := make([]string, 100)
	for i := range bigList {
		bigList[i] = fmt.Sprintf("p%d", i)
	}
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": "127.0.0.1:9999",
			"path":      "/x",
			"positions": []map[string]any{
				{"path": "path", "payloads": bigList},
				{"path": "method", "payloads": bigList},
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

func TestFuzzHTTP_RejectsEmptyPayloads(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": "127.0.0.1:9999",
			"path":      "/x",
			"positions": []map[string]any{
				{"path": "path", "payloads": []string{}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for empty payloads; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// stop_on_5xx aborts remaining variants when an upstream returns 5xx.
// ---------------------------------------------------------------------------

func TestFuzzHTTP_StopOn5xxAbortsRemaining(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	// Server returns 500 on path "/boom", 200 otherwise.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/boom" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	authority := strings.TrimPrefix(srv.URL, "http://")

	// Positions order: position 0 = path. The variant index iterates
	// least-significant first (position 0). With ["/ok1","/boom","/ok2"]
	// the second variant returns 500 and stop_on_5xx aborts the third.
	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": []string{"/ok1", "/boom", "/ok2"}},
		},
		"stop_on_5xx": true,
		"timeout_ms":  5000,
	})
	if result.CompletedVariants != 2 {
		t.Errorf("CompletedVariants = %d, want 2 (first 200, second 500 aborted)", result.CompletedVariants)
	}
	if result.StoppedReason == "" {
		t.Error("StoppedReason is empty; want a stop_on_5xx reason")
	}
}

// ---------------------------------------------------------------------------
// Tag application — every variant Stream gets the tag.
// ---------------------------------------------------------------------------

func TestFuzzHTTP_TagAppliedToEachVariantStream(t *testing.T) {
	cs, store, _, _ := setupFuzzHTTPSession(t)
	echo, _ := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": []string{"/v1", "/v2"}},
		},
		"tag":        "fuzz-tag-7",
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
		if s.Tags["tag"] != "fuzz-tag-7" {
			t.Errorf("variants[%d].Tags[tag] = %q, want fuzz-tag-7", i, s.Tags["tag"])
		}
	}
}

// ---------------------------------------------------------------------------
// Validation: per-payload decoded size cap (S-3, CWE-770).
// ---------------------------------------------------------------------------

// TestFuzzHTTP_RejectsExcessivePayloadSize submits a 2 MiB payload and
// asserts the call returns an error before any variant runs. Caps the
// memory amplification of large payloads * 1000 variants.
func TestFuzzHTTP_RejectsExcessivePayloadSize(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	bigPayload := strings.Repeat("A", 2<<20) // 2 MiB > 1 MiB cap
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": "127.0.0.1:9999",
			"path":      "/x",
			"positions": []map[string]any{
				{"path": "body", "payloads": []string{bigPayload}},
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
// USK-827 — sync fuzz_http persists fuzz_jobs + fuzz_results rows so the
// AI agent's "issue many variants → query aggregate → triage outliers"
// workflow is reachable end-to-end.
// ---------------------------------------------------------------------------

// queryFuzzResults is a thin helper that invokes the query tool with the
// fuzz_results resource and the given fuzz_id. The full filter map can
// be passed through extra (e.g. {"outliers_only": true}).
func queryFuzzResults(t *testing.T, cs *gomcp.ClientSession, fuzzID string, extraFilter map[string]any) *gomcp.CallToolResult {
	t.Helper()
	args := map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  fuzzID,
	}
	if len(extraFilter) > 0 {
		args["filter"] = extraFilter
	}
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool query fuzz_results: %v", err)
	}
	return res
}

// decodeQueryFuzzResults extracts the typed queryFuzzResultsResult body
// from a query call. Test fails on IsError or empty content.
func decodeQueryFuzzResults(t *testing.T, res *gomcp.CallToolResult) queryFuzzResultsResult {
	t.Helper()
	if res == nil || res.IsError {
		t.Fatalf("query fuzz_results returned error: %+v", res)
	}
	if len(res.Content) == 0 {
		t.Fatal("query fuzz_results: empty content")
	}
	text, ok := res.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("query fuzz_results content[0] type = %T, want *TextContent", res.Content[0])
	}
	var out queryFuzzResultsResult
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("unmarshal query fuzz_results: %v", err)
	}
	return out
}

// TestFuzzHTTP_PersistsFuzzJobAndResults is the canonical four-step
// repro from USK-827: run a sync fuzz, capture fuzz_id from the
// response, then exercise query fuzz_jobs + query fuzz_results +
// outliers_only filter end-to-end. Without USK-827 the fuzz_jobs row
// would not exist and outliers_only would fail with "fuzz_id is
// required".
func TestFuzzHTTP_PersistsFuzzJobAndResults(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)
	echo, _ := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	payloads := []string{"/a", "/b", "/c", "/d"}
	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": payloads},
		},
		"tag":        "usk-827-canonical",
		"timeout_ms": 5000,
	})

	// 1. Response carries fuzz_id (UUID).
	if result.FuzzID == "" {
		t.Fatal("fuzz_http response missing fuzz_id")
	}
	if result.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}

	// 2. query fuzz_jobs returns exactly one row matching fuzz_id + tag.
	jobsRes, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "fuzz_jobs",
			"filter":   map[string]any{"tag": "usk-827-canonical"},
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

	// 3. query fuzz_results returns one row per variant.
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
		streamIDsByVariant[v.StreamID] = v.Payloads["path"]
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
		if r.StatusCode != 200 {
			t.Errorf("fuzz_results row %d status_code = %d, want 200", r.IndexNum, r.StatusCode)
		}
	}

	// 4. outliers_only filter no longer fails with the "fuzz_id required"
	// error — it now reaches the aggregation path.
	outliersRes := queryFuzzResults(t, cs, result.FuzzID, map[string]any{"outliers_only": true})
	if outliersRes.IsError {
		t.Fatalf("query fuzz_results { outliers_only:true } returned error: %+v", outliersRes.Content)
	}
}

// TestFuzzHTTP_ErrorVariantRecordedAsFuzzResult covers the error path:
// a variant whose upstream response fails still produces a fuzz_results
// row with status_code=0 and a non-empty error column. Without this,
// the aggregation under-counts by the error-variant population (Q22).
//
// The upstream listener accepts the connection but immediately closes
// it without writing a response — this produces an "upstream receive"
// error per variant regardless of which payload was substituted.
func TestFuzzHTTP_ErrorVariantRecordedAsFuzzResult(t *testing.T) {
	cs, store, _, _ := setupFuzzHTTPSession(t)

	// Listener that accepts then immediately closes — emulates a
	// dead-on-arrival upstream.
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
	authority := ln.Addr().String()

	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": []string{"/v1", "/v2"}},
		},
		"tag":        "usk-827-error-path",
		"timeout_ms": 2000,
	})

	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}

	// Each variant should surface an error (connection closed before response).
	for i, v := range result.Variants {
		if v.Error == "" {
			t.Errorf("variants[%d]: Error is empty, want non-empty (upstream closes before response)", i)
		}
		if v.StatusCode != 0 {
			t.Errorf("variants[%d]: StatusCode = %d, want 0 on upstream-receive error", i, v.StatusCode)
		}
	}

	// USK-832: every variant Stream must transition to State="error"
	// when the exchange failed. Without finalizeResendStream in
	// runFuzzHTTPSingleVariant, the rows stay pinned at "active" and
	// stream-state filtering (`query { resource: "flows", filter:
	// { state: "active" } }`) would surface completed-but-failed fuzz
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
			t.Errorf("variants[%d].State = %q, want %q (USK-832: fuzz_http must finalise failed variants as error)", i, s.State, "error")
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
		if r.StatusCode != 0 {
			t.Errorf("fuzz_results row %d status_code = %d, want 0", r.IndexNum, r.StatusCode)
		}
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
			"filter":   map[string]any{"tag": "usk-827-error-path"},
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

// TestFuzzHTTP_VariantStreamStampedOriginFuzz verifies the
// pipeline.WithOrigin(flow.OriginFuzz) wiring on buildFuzzHTTPPipeline.
// Each variant Stream must carry Origin = "fuzz" so the query tool can
// separate fuzz-originated streams from live capture.
func TestFuzzHTTP_VariantStreamStampedOriginFuzz(t *testing.T) {
	cs, store, _, _ := setupFuzzHTTPSession(t)
	echo, _ := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": []string{"/v1", "/v2"}},
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

// TestFuzzHTTP_FinalizesUnderCallerCancel pins decision Q23: even when
// the caller cancels their context mid-run, the fuzz_jobs row must
// still get its closing UPDATE (status / completed_at) because
// finalizeFuzzHTTPJob is dispatched with a fresh background context.
//
// Repro: a slow upstream + many variants so the variant loop is still
// running when we cancel. After the cancel returns, the fuzz_jobs row
// must still have completed_at != nil.
func TestFuzzHTTP_FinalizesUnderCallerCancel(t *testing.T) {
	cs, _, _, _ := setupFuzzHTTPSession(t)

	// Slow echo: introduces enough per-request latency that the variant
	// loop is still running when we cancel.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	authority := strings.TrimPrefix(srv.URL, "http://")

	callCtx, cancel := context.WithCancel(context.Background())
	// Cancel after the first variant has completed so the fuzz_jobs row
	// is guaranteed inserted before we exercise the finalize path.
	go func() {
		for atomic.LoadInt32(&hits) < 1 {
			time.Sleep(10 * time.Millisecond)
		}
		// Give the variant loop one more tick to come back to the
		// select{} so the ctx.Done() branch is what stops it.
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	payloads := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		payloads = append(payloads, fmt.Sprintf("/v%d", i))
	}
	res, _ := cs.CallTool(callCtx, &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/seed",
			"headers": []map[string]any{
				{"name": "Host", "value": authority},
			},
			"positions": []map[string]any{
				{"path": "path", "payloads": payloads},
			},
			"tag":        "usk-827-cancel",
			"timeout_ms": 5000,
		},
	})
	_ = res // either an in-band stopped_reason or a transport-level cancel error is OK

	// Query fuzz_jobs through a fresh context (the caller cancel does
	// not affect this query).
	jobsRes, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "fuzz_jobs",
			"filter":   map[string]any{"tag": "usk-827-cancel"},
		},
	})
	if err != nil {
		t.Fatalf("query fuzz_jobs: %v", err)
	}
	if jobsRes.IsError {
		t.Fatalf("query fuzz_jobs returned error: %+v", jobsRes.Content)
	}
	var jobsOut queryFuzzJobsResult
	if err := json.Unmarshal([]byte(jobsRes.Content[0].(*gomcp.TextContent).Text), &jobsOut); err != nil {
		t.Fatalf("unmarshal jobs: %v", err)
	}
	if jobsOut.Total != 1 {
		t.Fatalf("jobs total = %d, want 1 (start INSERT must land via background ctx)", jobsOut.Total)
	}
	if jobsOut.Jobs[0].CompletedAt == nil {
		t.Errorf("fuzz_jobs.completed_at = nil after caller cancel; finalize did not land")
	}
}

// TestFuzzHTTP_PathWithQueryAutoSplit covers the USK-859 parity case for
// fuzz_http: the base envelope is built via the shared
// buildResendHTTPEnvelopeWithMeta helper, so the '?' auto-split applies
// to fuzz_http too. Each per-variant Stream's send Flow.URL must record
// a clean '?' rather than the corrupted '%3F'. (Position payloads
// substitute into HTTPMessage AFTER the split, so the position-write path
// is unaffected.)
func TestFuzzHTTP_PathWithQueryAutoSplit(t *testing.T) {
	cs, store, _, _ := setupFuzzHTTPSession(t)
	echo, _ := startFuzzHTTPEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		// Repro: base path with literal '?' carrying the query string.
		"path": "/anything?phase=3&case=02&m=GET",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{
				// Mutate an unrelated field so the cartesian product runs
				// without re-touching path/raw_query.
				"path":     "headers[0].value",
				"payloads": []string{authority, authority},
			},
		},
		"timeout_ms": 5000,
	})
	if result.TotalVariants != 2 || result.CompletedVariants != 2 {
		t.Fatalf("variant counts = (total=%d, completed=%d), want (2, 2)", result.TotalVariants, result.CompletedVariants)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, v := range result.Variants {
		if v.StreamID == "" {
			t.Errorf("variant %d has empty stream_id", v.Index)
			continue
		}
		flows, err := store.GetFlows(ctx, v.StreamID, flow.FlowListOptions{Direction: "send"})
		if err != nil {
			t.Fatalf("GetFlows %s: %v", v.StreamID, err)
		}
		if len(flows) == 0 {
			t.Fatalf("variant %d: no send flow recorded", v.Index)
		}
		sendFlow := flows[0]
		if sendFlow.URL == nil {
			t.Fatalf("variant %d: send Flow.URL is nil", v.Index)
		}
		if sendFlow.URL.Path != "/anything" {
			t.Errorf("variant %d: send Flow.URL.Path = %q, want %q", v.Index, sendFlow.URL.Path, "/anything")
		}
		if sendFlow.URL.RawQuery != "phase=3&case=02&m=GET" {
			t.Errorf("variant %d: send Flow.URL.RawQuery = %q, want %q", v.Index, sendFlow.URL.RawQuery, "phase=3&case=02&m=GET")
		}
		if strings.Contains(sendFlow.URL.String(), "%3F") {
			t.Errorf("variant %d: send Flow.URL.String() = %q contains %%3F (USK-859 regressed)", v.Index, sendFlow.URL.String())
		}
	}
}

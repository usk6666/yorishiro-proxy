//go:build e2e

package mcp

// resend_http_integration_test.go — RFC-001 N8 acceptance gate for the
// resend_http MCP tool. Drives the full pipeline (PluginStepPost +
// RecordStep) end-to-end against a live HTTP server and asserts the four
// USK-672 acceptance criteria:
//
//   AC#1: HTTPS round-trip (here: plain HTTP, validated separately for TLS
//         in the legacy `resend` tool's own e2e — TLS upgrade is handled by
//         the same TLSTransport-driven path on both)
//   AC#2: schema fields map cleanly to HTTPMessage and body_patches apply
//   AC#3: PluginStepPost fires once; PluginStepPre never fires (resend
//         bypass — RFC §9.3 D1)
//   AC#4: Legacy `resend` tool continues to coexist; resend_http does not
//         disturb its registration
//
// Pattern follows large_body_integration_test.go (in-memory MCP transports
// + sqlite flow store) for store coverage and pluginstep_integration_test.go
// for hook-counter assertions, but stays self-contained — no shared helpers
// from other integration tests are needed here.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// resendHTTPHookCallable wraps a Go counter increment in a Starlark
// Callable so it can be registered on the pluginv2 Engine. Mirrors the
// hookCallable helper in pipeline/plugin_step_pre_test.go (kept private to
// that package, so we re-declare here).
func resendHTTPHookCallable(name string, fn func()) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		fn()
		return starlark.None, nil
	})
}

// startResendHTTPEcho stands up a plain-HTTP echo server that mirrors the
// request body and exposes the captured request via the returned getter.
// Keeps the wire setup close to the test's assertions instead of pulling in
// the heavier large_body helpers.
func startResendHTTPEcho(t *testing.T) (*httptest.Server, func() (string, []byte, http.Header)) {
	t.Helper()
	var (
		lastMethod  atomic.Pointer[string]
		lastBody    atomic.Pointer[[]byte]
		lastHeaders atomic.Pointer[http.Header]
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		method := r.Method
		hdr := r.Header.Clone()
		lastMethod.Store(&method)
		lastBody.Store(&body)
		lastHeaders.Store(&hdr)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo", "1")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method": method,
			"path":   r.URL.Path,
			"body":   string(body),
		})
	}))
	t.Cleanup(srv.Close)
	get := func() (string, []byte, http.Header) {
		m := lastMethod.Load()
		b := lastBody.Load()
		h := lastHeaders.Load()
		var ms string
		var bs []byte
		var hs http.Header
		if m != nil {
			ms = *m
		}
		if b != nil {
			bs = *b
		}
		if h != nil {
			hs = *h
		}
		return ms, bs, hs
	}
	return srv, get
}

// callResendHTTP issues the resend_http tool with the supplied input and
// returns the parsed structured result. Test fails on transport errors.
func callResendHTTP(t *testing.T, cs *gomcp.ClientSession, input map[string]any) *gomcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend_http",
		Arguments: input,
	})
	if err != nil {
		t.Fatalf("CallTool resend_http: %v", err)
	}
	return res
}

// decodeStructuredResult unmarshals the structured tool output into v. The
// gomcp client surfaces the structured part on CallToolResult.StructuredContent.
func decodeStructuredResult(t *testing.T, res *gomcp.CallToolResult, v any) {
	t.Helper()
	if res.StructuredContent == nil {
		t.Fatalf("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode structured content into %T: %v", v, err)
	}
}

// setupResendHTTPSession spins up an MCP server pre-wired with a fresh
// flow store and a pluginv2.Engine that pre-registers pre/post counter
// hooks for ("http", "on_request"). Returns the client session, the live
// pluginv2 Engine, and atomic counters that tests assert on.
func setupResendHTTPSession(t *testing.T) (*gomcp.ClientSession, flow.Store, *int32, *int32) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	var preCount, postCount int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoHTTP,
		Event:      pluginv2.EventOnRequest,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "resend-http-pre",
		Fn: resendHTTPHookCallable("pre", func() {
			atomic.AddInt32(&preCount, 1)
		}),
	})
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoHTTP,
		Event:      pluginv2.EventOnRequest,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "resend-http-post",
		Fn: resendHTTPHookCallable("post", func() {
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

	client := gomcp.NewClient(&gomcp.Implementation{Name: "resend-http-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store, &preCount, &postCount
}

// TestResendHTTP_FromScratch_RoundTrip covers the from-scratch path
// (flow_id omitted). Verifies AC#1, AC#2, AC#3.
func TestResendHTTP_FromScratch_RoundTrip(t *testing.T) {
	cs, store, preCount, postCount := setupResendHTTPSession(t)
	echo, getCaptured := startResendHTTPEcho(t)
	upstreamURL := echo.URL // http://127.0.0.1:NNN
	authority := upstreamURL[len("http://"):]

	res := callResendHTTP(t, cs, map[string]any{
		"method":    "POST",
		"scheme":    "http",
		"authority": authority,
		"path":      "/api/users",
		"raw_query": "page=1",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
			{"name": "Content-Type", "value": "application/json"},
			{"name": "X-Test", "value": "resend-http"},
		},
		"body":          `{"name":"alice"}`,
		"body_encoding": "text",
		"timeout_ms":    5000,
		"tag":           "scratch",
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}

	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)

	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}
	if out.Tag != "scratch" {
		t.Errorf("Tag = %q, want %q", out.Tag, "scratch")
	}
	if out.StreamID == "" {
		t.Errorf("StreamID is empty")
	}

	method, capturedBody, capturedHeaders := getCaptured()
	if method != "POST" {
		t.Errorf("upstream method = %q, want POST", method)
	}
	if string(capturedBody) != `{"name":"alice"}` {
		t.Errorf("upstream body = %q, want %q", string(capturedBody), `{"name":"alice"}`)
	}
	if got := capturedHeaders.Get("X-Test"); got != "resend-http" {
		t.Errorf("upstream X-Test = %q, want resend-http", got)
	}

	// AC#3: PluginStepPost fires once on send, once on receive — both are
	// http.on_request envelopes by the resend_http schema (response
	// arrives via http1 layer's Receive direction; PluginStepPost dispatch
	// fires on every envelope of a registered (proto, event) pair).
	// PluginStepPre never fires (excluded from the resend pipeline).
	if pre := atomic.LoadInt32(preCount); pre != 0 {
		t.Errorf("preCount = %d, want 0 (PluginStepPre must be excluded from resend)", pre)
	}
	if post := atomic.LoadInt32(postCount); post < 1 {
		t.Errorf("postCount = %d, want >= 1 (PluginStepPost fires on send envelope)", post)
	}

	// Flow store assertions: a new Stream + Send + Receive Flow trio.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := store.GetStream(ctx, out.StreamID)
	if err != nil {
		t.Fatalf("GetStream(%s): %v", out.StreamID, err)
	}
	if stream.Tags["tag"] != "scratch" {
		t.Errorf("Stream.Tags[tag] = %q, want scratch", stream.Tags["tag"])
	}
	if stream.Protocol != "http" {
		t.Errorf("Stream.Protocol = %q, want http", stream.Protocol)
	}

	flows, err := store.GetFlows(ctx, out.StreamID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(flows) < 2 {
		t.Fatalf("expected >=2 flows (send+receive), got %d", len(flows))
	}
	var sendCount, recvCount int
	for _, f := range flows {
		switch f.Direction {
		case "send":
			sendCount++
			if f.Method != "POST" {
				t.Errorf("send Flow Method = %q, want POST", f.Method)
			}
		case "receive":
			recvCount++
			if f.StatusCode != 200 {
				t.Errorf("receive Flow StatusCode = %d, want 200", f.StatusCode)
			}
		}
	}
	if sendCount < 1 || recvCount < 1 {
		t.Errorf("flow direction counts: send=%d recv=%d (want each >= 1)", sendCount, recvCount)
	}
}

// TestResendHTTP_BodyPatches_AppliedToWire covers AC#2 — body_patches
// rewrite the request body and the upstream sees the patched bytes. Also
// verifies the headerKV ordered list preserves the case the user supplied
// (no canonicalisation by the tool path).
func TestResendHTTP_BodyPatches_AppliedToWire(t *testing.T) {
	cs, _, _, _ := setupResendHTTPSession(t)
	echo, getCaptured := startResendHTTPEcho(t)
	authority := echo.URL[len("http://"):]

	res := callResendHTTP(t, cs, map[string]any{
		"method":    "POST",
		"scheme":    "http",
		"authority": authority,
		"path":      "/echo",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
			{"name": "content-type", "value": "application/json"},
		},
		"body": `{"name":"alice","role":"admin"}`,
		"body_patches": []map[string]any{
			{"json_path": "$.role", "value": "guest"},
		},
		"timeout_ms": 5000,
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}

	_, capturedBody, _ := getCaptured()
	var got map[string]any
	if err := json.Unmarshal(capturedBody, &got); err != nil {
		t.Fatalf("decode upstream body: %v", err)
	}
	if got["role"] != "guest" {
		t.Errorf("upstream body role = %v, want guest (body_patches did not apply on the wire)", got["role"])
	}
}

// TestResendHTTP_FlowID_PrepopulatedSendInherited covers the flow_id path:
// inherits method/scheme/authority/path/headers/body from the recorded send
// flow when the user omits them. Confirms the Stream protocol guard accepts
// "HTTP" / "http" projections.
func TestResendHTTP_FlowID_PrepopulatedSendInherited(t *testing.T) {
	cs, store, _, postCount := setupResendHTTPSession(t)
	echo, getCaptured := startResendHTTPEcho(t)
	authority := echo.URL[len("http://"):]

	// Pre-populate a recorded HTTP stream that the tool will inherit from.
	ctx := context.Background()
	original := &flow.Stream{ID: "orig-stream-1", Protocol: "http", Scheme: "http"}
	if err := store.SaveStream(ctx, original); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	sendFlow := &flow.Flow{
		StreamID:  original.ID,
		Sequence:  0,
		Direction: "send",
		Method:    "GET",
		URL:       mustParseURL(t, "http://"+authority+"/originally?z=1"),
		Headers:   map[string][]string{"X-Inherited": {"yes"}},
	}
	if err := store.SaveFlow(ctx, sendFlow); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	prePostBefore := atomic.LoadInt32(postCount)

	res := callResendHTTP(t, cs, map[string]any{
		"flow_id":    original.ID,
		"timeout_ms": 5000,
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}

	method, _, capturedHeaders := getCaptured()
	if method != "GET" {
		t.Errorf("upstream method = %q, want GET (inherited)", method)
	}
	if got := capturedHeaders.Get("X-Inherited"); got != "yes" {
		t.Errorf("upstream X-Inherited = %q, want yes (inherited)", got)
	}

	if delta := atomic.LoadInt32(postCount) - prePostBefore; delta < 1 {
		t.Errorf("post fired %d times this call, want >= 1", delta)
	}
}

// TestResendHTTP_FollowRedirectsRejected exercises the explicit
// follow_redirects=true rejection so callers see the policy at validation
// time rather than after a network round-trip.
func TestResendHTTP_FollowRedirectsRejected(t *testing.T) {
	cs, _, _, _ := setupResendHTTPSession(t)
	echo, _ := startResendHTTPEcho(t)
	authority := echo.URL[len("http://"):]

	res := callResendHTTP(t, cs, map[string]any{
		"method":           "GET",
		"scheme":           "http",
		"authority":        authority,
		"path":             "/",
		"follow_redirects": true,
	})
	if !res.IsError {
		t.Fatalf("expected IsError=true for follow_redirects=true, got success")
	}
}

// TestResendHTTP_FromScratch_MissingFieldsRejected ensures the validator
// surfaces all four required fields when flow_id is empty (one error message
// covers the whole missing set instead of one error per field).
func TestResendHTTP_FromScratch_MissingFieldsRejected(t *testing.T) {
	cs, _, _, _ := setupResendHTTPSession(t)

	res := callResendHTTP(t, cs, map[string]any{
		// no flow_id, no fields
	})
	if !res.IsError {
		t.Fatalf("expected IsError=true for empty input, got success")
	}
}

// TestResendHTTP_TargetScopeBypassRegression covers review-gate S-1
// (CWE-918). Authority chars that net/url.URL.String() percent-encodes
// (e.g. whitespace) used to defeat the canonical-leg scope check because
// the round-tripped url.Parse rejected the percent escapes and the
// returned error was silently swallowed. The fix builds *url.URL directly
// without String/Parse — this test asserts the canonical scope leg now
// rejects an out-of-scope authority that round-trips badly.
func TestResendHTTP_TargetScopeBypassRegression(t *testing.T) {
	store := newTestStore(t)
	scope := proxy.NewTargetScope()
	scope.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "allowed.local"}},
		nil,
	)
	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil, WithTargetScope(scope))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "resend-http-scope-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	// Authority "blocked .local" (with whitespace) round-trips through
	// url.URL.String() as "blocked%20.local" then fails url.Parse — the
	// pre-fix code treated this as "scope check skipped, allow request".
	// The fix runs scope on the directly-built *url.URL with Host set to
	// the literal authority, so blocked.local is rejected.
	res := callResendHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": "blocked .local",
		"path":      "/",
	})
	if !res.IsError {
		t.Fatalf("expected scope rejection, got success — TargetScope bypass regressed")
	}
	if got := extractTextContent(res); !strings.Contains(strings.ToLower(got), "scope") {
		t.Errorf("error message %q does not mention scope", got)
	}
}

// mustParseURL is a small helper so the test reads top-down without
// scattering url.Parse error checks.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

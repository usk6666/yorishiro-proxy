//go:build e2e && !e2e_smoke

package mcp

// fuzz_scope_recheck_integration_test.go — USK-1158: every fuzz tool
// re-checks TargetScope per variant, on the post-mutation message, just
// before the per-variant SafetyFilter gate.
//
// The reload half drives the same engine call the SIGHUP reloader makes
// (TargetScope.ReplacePolicyRules, internal/mcpserver/policy_reload.go)
// while variant 0 is held inside a gated upstream, then releases it. The
// remaining variants must never reach the upstream; they are recorded
// with a scope rejection in row.Error and the run continues.
//
// The mutation half needs no reload: a position that rewrites the part of
// the message the scope engine matches on (gRPC `service`) must be judged
// on the rewritten value.

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// scopeRecheckErrSubstr is the prefix every TargetScope rejection carries
// (checkTargetScopeURLHelper / checkTargetScopeAddrHelper in helpers.go).
const scopeRecheckErrSubstr = "request blocked by target scope"

// setupFuzzScopeRecheckSession boots an MCP server wired to the given
// TargetScope (the engine the reloader mutates) and returns a client
// session.
func setupFuzzScopeRecheckSession(t *testing.T, scope *connector.TargetScope) *gomcp.ClientSession {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()
	opts := []ServerOption{
		WithTargetScope(scope),
		// fuzz_grpc dials its TLS upstream through the TLSTransport
		// (setupFuzzGRPCSession precedent).
		WithTLSTransport(&transport.StandardTransport{InsecureSkipVerify: true}),
	}
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

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-scope-recheck-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// variantGate counts upstream requests and holds the FIRST one until
// open() is called, so a test can change the policy while variant 0 is in
// flight and before variant 1 is built.
type variantGate struct {
	hits      atomic.Int64
	arrived   chan struct{}
	release   chan struct{}
	closeOnce sync.Once
}

func newVariantGate(t *testing.T) *variantGate {
	t.Helper()
	g := &variantGate{arrived: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(g.open) // never leave an upstream handler parked
	return g
}

// enter is called by the upstream once per received request.
func (g *variantGate) enter() {
	if g.hits.Add(1) == 1 {
		close(g.arrived)
		<-g.release
	}
}

func (g *variantGate) open() { g.closeOnce.Do(func() { close(g.release) }) }

func (g *variantGate) waitArrived(t *testing.T) {
	t.Helper()
	select {
	case <-g.arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("variant 0 never reached the upstream")
	}
}

// fuzzCallOutcome carries an async CallTool result back to the test
// goroutine (t.Fatal must not be called from the calling goroutine).
type fuzzCallOutcome struct {
	res *gomcp.CallToolResult
	err error
}

func callFuzzToolAsync(cs *gomcp.ClientSession, name string, input map[string]any) <-chan fuzzCallOutcome {
	ch := make(chan fuzzCallOutcome, 1)
	go func() {
		res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{Name: name, Arguments: input})
		ch <- fuzzCallOutcome{res: res, err: err}
	}()
	return ch
}

// awaitFuzzResult waits for the async call and decodes its structured
// content into out.
func awaitFuzzResult(t *testing.T, ch <-chan fuzzCallOutcome, out any) {
	t.Helper()
	var o fuzzCallOutcome
	select {
	case o = <-ch:
	case <-time.After(30 * time.Second):
		t.Fatal("fuzz call did not return within 30s")
	}
	if o.err != nil {
		t.Fatalf("CallTool: %v", o.err)
	}
	if o.res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(o.res))
	}
	raw, err := json.Marshal(o.res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
}

// reloadDenyLoopback is the engine call the SIGHUP reloader makes, with a
// policy that denies the loopback upstream every test uses.
func reloadDenyLoopback(scope *connector.TargetScope) {
	scope.ReplacePolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}},
		connector.PolicyOrigin{Source: "policy file", LoadedAt: time.Now()})
}

func allowLoopbackScope() *connector.TargetScope {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	return scope
}

// assertScopeRecheckRows checks the R9 recording contract: variant 0 (in
// flight at reload time) completed without error; every later variant
// carries a scope rejection; the run was not stopped; only one request
// reached the upstream.
func assertScopeRecheckRows(t *testing.T, errs []string, completed int, stopped string, hits int64) {
	t.Helper()
	if hits != 1 {
		t.Errorf("upstream hits = %d, want 1 — variants built after the reload reached a newly denied host", hits)
	}
	if len(errs) != 3 {
		t.Fatalf("len(variants) = %d, want 3 (denied variants are recorded, the loop continues)", len(errs))
	}
	if completed != 3 {
		t.Errorf("completed_variants = %d, want 3", completed)
	}
	if stopped != "" {
		t.Errorf("stopped_reason = %q, want empty (a scope denial does not stop the run)", stopped)
	}
	if errs[0] != "" {
		t.Errorf("variants[0].error = %q, want empty (in flight at reload time, must complete)", errs[0])
	}
	for i := 1; i < len(errs); i++ {
		if !strings.Contains(errs[i], scopeRecheckErrSubstr) {
			t.Errorf("variants[%d].error = %q, want a %q rejection", i, errs[i], scopeRecheckErrSubstr)
		}
	}
}

// ---------------------------------------------------------------------------
// fuzz_raw
// ---------------------------------------------------------------------------

// startGatedRawServer accepts TCP connections, reads one chunk, passes
// through the gate, replies and closes so the fuzz_raw receive loop ends.
func startGatedRawServer(t *testing.T, g *variantGate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				buf := make([]byte, 4096)
				if _, rerr := c.Read(buf); rerr != nil {
					return
				}
				g.enter()
				_, _ = c.Write([]byte("ok"))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestFuzzRaw_ScopeRecheck_ReloadDeniesRemainingVariants(t *testing.T) {
	scope := allowLoopbackScope()
	cs := setupFuzzScopeRecheckSession(t, scope)
	g := newVariantGate(t)
	addr := startGatedRawServer(t, g)

	ch := callFuzzToolAsync(cs, "fuzz_raw", map[string]any{
		"target_addr": addr,
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"v0", "v1", "v2"}},
		},
		"timeout_ms": 10000,
	})
	g.waitArrived(t)
	reloadDenyLoopback(scope)
	g.open()

	var out fuzzRawResult
	awaitFuzzResult(t, ch, &out)
	errs := make([]string, len(out.Variants))
	for i, v := range out.Variants {
		errs[i] = v.Error
	}
	assertScopeRecheckRows(t, errs, out.CompletedVariants, out.StoppedReason, g.hits.Load())
}

// ---------------------------------------------------------------------------
// fuzz_ws
// ---------------------------------------------------------------------------

// startGatedWSServer completes the upgrade, reads the variant frame,
// passes through the gate and replies with a Text frame so the fuzz_ws
// receive loop terminates (pattern: handleWSReplyOnPongConn).
func startGatedWSServer(t *testing.T, g *variantGate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				r := bufio.NewReader(c)
				if _, rerr := http.ReadRequest(r); rerr != nil {
					return
				}
				resp := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: dummy\r\n" +
					"\r\n"
				if _, werr := c.Write([]byte(resp)); werr != nil {
					return
				}
				if _, ferr := ws.ReadFrame(r); ferr != nil {
					return
				}
				g.enter()
				_ = ws.WriteFrame(c, &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte("ack")})
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestFuzzWS_ScopeRecheck_ReloadDeniesRemainingVariants(t *testing.T) {
	scope := allowLoopbackScope()
	cs := setupFuzzScopeRecheckSession(t, scope)
	g := newVariantGate(t)
	addr := startGatedWSServer(t, g)

	ch := callFuzzToolAsync(cs, "fuzz_ws", map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"v0", "v1", "v2"}},
		},
		"timeout_ms": 10000,
	})
	g.waitArrived(t)
	reloadDenyLoopback(scope)
	g.open()

	var out fuzzWSResult
	awaitFuzzResult(t, ch, &out)
	errs := make([]string, len(out.Variants))
	for i, v := range out.Variants {
		errs[i] = v.Error
	}
	assertScopeRecheckRows(t, errs, out.CompletedVariants, out.StoppedReason, g.hits.Load())
}

// ---------------------------------------------------------------------------
// fuzz_grpc
// ---------------------------------------------------------------------------

func TestFuzzGRPC_ScopeRecheck_ReloadDeniesRemainingVariants(t *testing.T) {
	scope := allowLoopbackScope()
	cs := setupFuzzScopeRecheckSession(t, scope)
	g := newVariantGate(t)
	upstream := &fuzzGRPCEchoServer{respond: func(req []byte) ([]byte, *status.Status) {
		g.enter()
		return append([]byte(nil), req...), nil
	}}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	ch := callFuzzToolAsync(cs, "fuzz_grpc", map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages":    []map[string]any{{"payload": "seed"}},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"v0", "v1", "v2"}},
		},
		"timeout_ms": 10000,
	})
	g.waitArrived(t)
	reloadDenyLoopback(scope)
	g.open()

	var out fuzzGRPCResult
	awaitFuzzResult(t, ch, &out)
	errs := make([]string, len(out.Variants))
	for i, v := range out.Variants {
		errs[i] = v.Error
	}
	assertScopeRecheckRows(t, errs, out.CompletedVariants, out.StoppedReason, g.hits.Load())
	if got := len(upstream.snapshot()); got != 1 {
		t.Errorf("upstream observed %d gRPC requests, want 1", got)
	}
}

// TestFuzzGRPC_ScopeRecheck_ServicePositionJudgedOnMutatedPath is the
// non-reload gap: the `service` position rewrites the request path the
// scope engine matches on (:path = /<service>/<method>), so a variant
// whose service lands under a denied path_prefix must be rejected even
// though the base message passed the plan-time check.
func TestFuzzGRPC_ScopeRecheck_ServicePositionJudgedOnMutatedPath(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(
		[]connector.TargetRule{{Hostname: "127.0.0.1"}},
		[]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/admin."}},
	)
	cs := setupFuzzScopeRecheckSession(t, scope)
	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	ch := callFuzzToolAsync(cs, "fuzz_grpc", map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages":    []map[string]any{{"payload": "seed"}},
		"positions": []map[string]any{
			{"path": "service", "payloads": []string{fuzzGRPCServiceName, "admin.Secret"}},
		},
		"timeout_ms": 10000,
	})
	var out fuzzGRPCResult
	awaitFuzzResult(t, ch, &out)
	if len(out.Variants) != 2 {
		t.Fatalf("len(variants) = %d, want 2", len(out.Variants))
	}
	if out.Variants[0].Error != "" {
		t.Errorf("variants[0].error = %q, want empty (allowed service)", out.Variants[0].Error)
	}
	if !strings.Contains(out.Variants[1].Error, scopeRecheckErrSubstr) {
		t.Errorf("variants[1].error = %q, want a %q rejection — the mutated :path /admin.Secret/... reached the wire (status=%d %s)",
			out.Variants[1].Error, scopeRecheckErrSubstr, out.Variants[1].Status, codes.Code(out.Variants[1].Status))
	}
}

// ---------------------------------------------------------------------------
// fuzz_http — dial leg
// ---------------------------------------------------------------------------

// TestFuzzHTTP_ScopeRecheck_DialLegCheckedWhenAuthorityMutated pins that
// the per-variant check covers the plan's dial address, not only the
// mutated message. fuzz_http dials plan.dialAddr (derived from the BASE
// authority) for every variant; an `authority` position that moves the
// canonical URL to a still-allowed host must not let the variant reach a
// dial target the reload has just taken out of scope.
func TestFuzzHTTP_ScopeRecheck_DialLegCheckedWhenAuthorityMutated(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "allowed.test"}}, nil)
	cs := setupFuzzScopeRecheckSession(t, scope)
	g := newVariantGate(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		g.enter()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	authority := strings.TrimPrefix(upstream.URL, "http://")

	ch := callFuzzToolAsync(cs, "fuzz_http", map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/",
		"positions": []map[string]any{
			{"path": "authority", "payloads": []string{authority, "allowed.test", "allowed.test"}},
		},
		"timeout_ms": 10000,
	})
	g.waitArrived(t)
	// Reload: only allowed.test stays in scope; the dial target 127.0.0.1
	// drops out.
	scope.ReplacePolicyRules([]connector.TargetRule{{Hostname: "allowed.test"}}, nil,
		connector.PolicyOrigin{Source: "policy file", LoadedAt: time.Now()})
	g.open()

	var out fuzzHTTPResult
	awaitFuzzResult(t, ch, &out)
	errs := make([]string, len(out.Variants))
	for i, v := range out.Variants {
		errs[i] = v.Error
	}
	assertScopeRecheckRows(t, errs, out.CompletedVariants, out.StoppedReason, g.hits.Load())
}

// ---------------------------------------------------------------------------
// fuzz_http — the dial leg judges what is put on the wire
// ---------------------------------------------------------------------------
//
// fuzz_http fixes the connection at plan time: plan.dialAddr (base authority
// or override_host) and plan.useTLS (base scheme). The HTTP/1 encoder then
// writes the variant's path as the request target. The dial leg of the
// per-variant check must therefore judge (connection scheme, dial address,
// variant path) — not the mutated variant scheme, and not an empty path.

// pathRecorder is an upstream handler that records every request path it
// receives.
type pathRecorder struct {
	mu    sync.Mutex
	paths []string
}

func (r *pathRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.paths = append(r.paths, req.URL.Path)
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
}

func (r *pathRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.paths...)
}

// assertNoDeniedPathOnWire fails when the upstream ever saw a path under
// the denied prefix.
func assertNoDeniedPathOnWire(t *testing.T, rec *pathRecorder, deniedPrefix string) {
	t.Helper()
	for _, p := range rec.snapshot() {
		if strings.HasPrefix(p, deniedPrefix) {
			t.Errorf("upstream received %q — a path the policy denies on this host reached the wire", p)
		}
	}
}

// assertFuzzHTTPRowsByPayload checks every variant row: a row is expected
// to carry a scope rejection iff denied(row.Payloads) is true; any other
// row must have completed with status 200.
func assertFuzzHTTPRowsByPayload(t *testing.T, out fuzzHTTPResult, wantRows int, denied func(map[string]string) bool) {
	t.Helper()
	if len(out.Variants) != wantRows {
		t.Fatalf("len(variants) = %d, want %d", len(out.Variants), wantRows)
	}
	for _, v := range out.Variants {
		if denied(v.Payloads) {
			if !strings.Contains(v.Error, scopeRecheckErrSubstr) {
				t.Errorf("variant %v: error = %q status = %d, want a %q rejection", v.Payloads, v.Error, v.StatusCode, scopeRecheckErrSubstr)
			}
			continue
		}
		if v.Error != "" || v.StatusCode != http.StatusOK {
			t.Errorf("variant %v: error = %q status = %d, want status 200 and no error (wrongly denied)", v.Payloads, v.Error, v.StatusCode)
		}
	}
}

// TestFuzzHTTP_ScopeRecheck_OverrideHostScheme_PlaintextDialStillDenied
// pins F-1 (wrongly allowed): with override_host, a `scheme` position that
// flips the canonical scheme to https does not change the connection —
// plan.useTLS came from the base http scheme, so the dial to the override
// target stays plaintext. A reload that denies plaintext to that target
// must reject every later variant.
func TestFuzzHTTP_ScopeRecheck_OverrideHostScheme_PlaintextDialStillDenied(t *testing.T) {
	allows := []connector.TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "vhost.test"}}
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(allows, nil)
	cs := setupFuzzScopeRecheckSession(t, scope)
	g := newVariantGate(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		g.enter()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	ch := callFuzzToolAsync(cs, "fuzz_http", map[string]any{
		"method":        "GET",
		"scheme":        "http",
		"authority":     "vhost.test",
		"path":          "/",
		"override_host": strings.TrimPrefix(upstream.URL, "http://"),
		"positions": []map[string]any{
			{"path": "scheme", "payloads": []string{"http", "https", "https"}},
		},
		"timeout_ms": 10000,
	})
	g.waitArrived(t)
	scope.ReplacePolicyRules(allows,
		[]connector.TargetRule{{Hostname: "127.0.0.1", Schemes: []string{"http"}}},
		connector.PolicyOrigin{Source: "policy file", LoadedAt: time.Now()})
	g.open()

	var out fuzzHTTPResult
	awaitFuzzResult(t, ch, &out)
	errs := make([]string, len(out.Variants))
	for i, v := range out.Variants {
		errs[i] = v.Error
	}
	assertScopeRecheckRows(t, errs, out.CompletedVariants, out.StoppedReason, g.hits.Load())
}

// TestFuzzHTTP_ScopeRecheck_OverrideHostScheme_TLSDialNotWronglyDenied
// pins F-1 (wrongly denied): base https + override_host, a variant whose
// canonical scheme is http still travels over the TLS connection the plan
// opened. A deny scoped to plaintext on the override target must not
// block it.
func TestFuzzHTTP_ScopeRecheck_OverrideHostScheme_TLSDialNotWronglyDenied(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(
		[]connector.TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "vhost.test"}},
		[]connector.TargetRule{{Hostname: "127.0.0.1", Schemes: []string{"http"}}},
	)
	cs := setupFuzzScopeRecheckSession(t, scope)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	ch := callFuzzToolAsync(cs, "fuzz_http", map[string]any{
		"method":        "GET",
		"scheme":        "https",
		"authority":     "vhost.test",
		"path":          "/",
		"override_host": strings.TrimPrefix(upstream.URL, "https://"),
		"positions": []map[string]any{
			{"path": "scheme", "payloads": []string{"https", "http"}},
		},
		"timeout_ms": 10000,
	})
	var out fuzzHTTPResult
	awaitFuzzResult(t, ch, &out)
	assertFuzzHTTPRowsByPayload(t, out, 2, func(map[string]string) bool { return false })
}

// TestFuzzHTTP_ScopeRecheck_AuthorityUnderPathPrefixAllow pins F-2: an
// `authority` position (Host-header fuzzing) under path-scoped allow rules
// must not be wrongly denied — the dial leg is judged on the path that is
// actually sent, which the allow rule covers.
func TestFuzzHTTP_ScopeRecheck_AuthorityUnderPathPrefixAllow(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{
		{Hostname: "127.0.0.1", PathPrefix: "/api"},
		{Hostname: "vhost.test", PathPrefix: "/api"},
	}, nil)
	cs := setupFuzzScopeRecheckSession(t, scope)
	rec := &pathRecorder{}
	upstream := httptest.NewServer(rec.handler())
	t.Cleanup(upstream.Close)
	authority := strings.TrimPrefix(upstream.URL, "http://")

	ch := callFuzzToolAsync(cs, "fuzz_http", map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/api/items",
		"positions": []map[string]any{
			{"path": "authority", "payloads": []string{authority, "vhost.test"}},
		},
		"timeout_ms": 10000,
	})
	var out fuzzHTTPResult
	awaitFuzzResult(t, ch, &out)
	assertFuzzHTTPRowsByPayload(t, out, 2, func(map[string]string) bool { return false })
	if got := len(rec.snapshot()); got != 2 {
		t.Errorf("upstream hits = %d, want 2", got)
	}
}

// TestFuzzHTTP_ScopeRecheck_AuthorityPlusPathDeniedOnDialTarget pins S-1:
// moving the authority does not move the connection. A variant with
// authority=decoy.test and path=/admin is still sent as `GET /admin` to
// the base host, so a path deny on the base host must reject it. A
// variant whose path stays away from the denied prefix must still go out.
func TestFuzzHTTP_ScopeRecheck_AuthorityPlusPathDeniedOnDialTarget(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(
		[]connector.TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "decoy.test"}},
		[]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/admin"}},
	)
	cs := setupFuzzScopeRecheckSession(t, scope)
	rec := &pathRecorder{}
	upstream := httptest.NewServer(rec.handler())
	t.Cleanup(upstream.Close)
	authority := strings.TrimPrefix(upstream.URL, "http://")

	ch := callFuzzToolAsync(cs, "fuzz_http", map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/public",
		"positions": []map[string]any{
			{"path": "authority", "payloads": []string{authority, "decoy.test"}},
			{"path": "path", "payloads": []string{"/public", "/admin"}},
		},
		"timeout_ms": 10000,
	})
	var out fuzzHTTPResult
	awaitFuzzResult(t, ch, &out)
	assertFuzzHTTPRowsByPayload(t, out, 4, func(p map[string]string) bool { return p["path"] == "/admin" })
	assertNoDeniedPathOnWire(t, rec, "/admin")
}

// TestFuzzHTTP_ScopeRecheck_SchemePlusPathDeniedOnPlaintextDial pins the
// scheme half of S-1: a `scheme` position flipping the canonical scheme to
// https leaves the plaintext connection in place, so a deny on
// {schemes:[http], path_prefix:/admin} must still reject `GET /admin`.
func TestFuzzHTTP_ScopeRecheck_SchemePlusPathDeniedOnPlaintextDial(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(
		[]connector.TargetRule{{Hostname: "127.0.0.1"}},
		[]connector.TargetRule{{Hostname: "127.0.0.1", Schemes: []string{"http"}, PathPrefix: "/admin"}},
	)
	cs := setupFuzzScopeRecheckSession(t, scope)
	rec := &pathRecorder{}
	upstream := httptest.NewServer(rec.handler())
	t.Cleanup(upstream.Close)
	authority := strings.TrimPrefix(upstream.URL, "http://")

	ch := callFuzzToolAsync(cs, "fuzz_http", map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/public",
		"positions": []map[string]any{
			{"path": "scheme", "payloads": []string{"http", "https"}},
			{"path": "path", "payloads": []string{"/public", "/admin"}},
		},
		"timeout_ms": 10000,
	})
	var out fuzzHTTPResult
	awaitFuzzResult(t, ch, &out)
	assertFuzzHTTPRowsByPayload(t, out, 4, func(p map[string]string) bool { return p["path"] == "/admin" })
	assertNoDeniedPathOnWire(t, rec, "/admin")
}

// TestResendHTTP_OverrideHostPathDenyApplies pins S-2: resend_http sends
// the request path to the override_host target, so a path deny on that
// target must apply even though the canonical authority is allowed.
func TestResendHTTP_OverrideHostPathDenyApplies(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(
		[]connector.TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "vhost.test"}},
		[]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/admin"}},
	)
	cs := setupFuzzScopeRecheckSession(t, scope)
	rec := &pathRecorder{}
	upstream := httptest.NewServer(rec.handler())
	t.Cleanup(upstream.Close)
	override := strings.TrimPrefix(upstream.URL, "http://")

	allowed := callResendHTTP(t, cs, map[string]any{
		"method":        "GET",
		"scheme":        "http",
		"authority":     "vhost.test",
		"path":          "/public",
		"override_host": override,
	})
	if allowed.IsError {
		t.Fatalf("resend of /public via override_host rejected: %s", extractTextContent(allowed))
	}

	denied := callResendHTTP(t, cs, map[string]any{
		"method":        "GET",
		"scheme":        "http",
		"authority":     "vhost.test",
		"path":          "/admin",
		"override_host": override,
	})
	if !denied.IsError {
		t.Errorf("resend of /admin via override_host succeeded — the override target's path deny was not applied")
	} else if got := extractTextContent(denied); !strings.Contains(got, scopeRecheckErrSubstr) {
		t.Errorf("error = %q, want a %q rejection", got, scopeRecheckErrSubstr)
	}
	assertNoDeniedPathOnWire(t, rec, "/admin")
}

// TestScopeRecheck_PathLegsJudgeWirePath pins the path form the path-
// bearing address legs hand CheckTarget after USK-1139: the wire path
// (== msg.Path), the form TargetScope.CheckURL and the live HTTPScopeStep
// match on. A path_prefix written in encoded form ("/a%20b") names wire
// bytes; CheckTarget matches it against the wire path or its single
// decoding. Handing the leg the already-decoded URL.Path ("/a b/x") would
// make the encoded deny on the dial / override target never match.
func TestScopeRecheck_PathLegsJudgeWirePath(t *testing.T) {
	newScope := func() *connector.TargetScope {
		scope := connector.NewTargetScope()
		scope.SetPolicyRules(
			[]connector.TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "vhost.test"}},
			[]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/a%20b"}},
		)
		return scope
	}

	t.Run("resend_http override leg", func(t *testing.T) {
		cs := setupFuzzScopeRecheckSession(t, newScope())
		rec := &pathRecorder{}
		upstream := httptest.NewServer(rec.handler())
		t.Cleanup(upstream.Close)
		override := strings.TrimPrefix(upstream.URL, "http://")

		denied := callResendHTTP(t, cs, map[string]any{
			"method":        "GET",
			"scheme":        "http",
			"authority":     "vhost.test",
			"path":          "/a%20b/x",
			"override_host": override,
		})
		if !denied.IsError {
			t.Errorf("resend of /a%%20b/x via override_host succeeded — the encoded path_prefix deny on the override target was not applied")
		} else if got := extractTextContent(denied); !strings.Contains(got, scopeRecheckErrSubstr) {
			t.Errorf("error = %q, want a %q rejection", got, scopeRecheckErrSubstr)
		}
		assertNoDeniedPathOnWire(t, rec, "/a b")
	})

	t.Run("fuzz_http dial leg", func(t *testing.T) {
		cs := setupFuzzScopeRecheckSession(t, newScope())
		rec := &pathRecorder{}
		upstream := httptest.NewServer(rec.handler())
		t.Cleanup(upstream.Close)
		authority := strings.TrimPrefix(upstream.URL, "http://")

		ch := callFuzzToolAsync(cs, "fuzz_http", map[string]any{
			"method":    "GET",
			"scheme":    "http",
			"authority": authority,
			"path":      "/public",
			"positions": []map[string]any{
				{"path": "authority", "payloads": []string{"vhost.test"}},
				{"path": "path", "payloads": []string{"/public", "/a%20b/x"}},
			},
			"timeout_ms": 10000,
		})
		var out fuzzHTTPResult
		awaitFuzzResult(t, ch, &out)
		assertFuzzHTTPRowsByPayload(t, out, 2, func(p map[string]string) bool { return p["path"] == "/a%20b/x" })
		assertNoDeniedPathOnWire(t, rec, "/a b")
	})
}

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

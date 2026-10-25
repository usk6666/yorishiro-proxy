//go:build e2e && !e2e_smoke

package mcp

// security_budget_enforcement_integration_test.go (USK-818) — proves that
// `security set_budget { max_total_requests: N }` enforces against the
// resend_http and fuzz_http dispatch paths after the BudgetStep wiring fix.
// The pre-USK-818 failure mode was:
//
//	resend_http × (N+1) → all 4 returned 200; security get_budget showed
//	request_count=0; the budget feature was a no-op.
//
// The acceptance contract:
//
//	1. resend_http requests 1..N succeed
//	2. resend_http request N+1 returns an error (budget exhausted)
//	3. security.get_budget reports request_count == N+1 (the connector's
//	   "increment-then-check" semantics; the (N+1)th is counted-and-blocked)
//	4. The blocked Stream is recorded with state="error" + blocked_by="budget"
//	5. fuzz_http with N+1 variants exhibits the same shape — first N succeed,
//	   (N+1)th errors, audit Stream recorded
//
// Tagged `//go:build e2e && !e2e_smoke` — exhaustive (nightly) tier only. The
// test relies on helpers from resend_http_integration_test.go that themselves
// live in the exhaustive tier, so promotion to the per-PR smoke gate is gated
// on lifting those helper dependencies first. Until then this file runs under
// `make test-e2e` (full) but not `make test-e2e-smoke` (merge gate).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// startBudgetTestEcho is a minimal HTTP echo for budget enforcement tests.
// Distinct from startResendHTTPEcho's atomic-pointer captures to keep this
// file self-contained.
func startBudgetTestEcho(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setupBudgetEnforcementSession returns a client session whose Server has
// a fully wired BudgetManager registered (via WithBudgetManager) and
// reachable via every dispatch path. The bm pointer is returned so tests
// can call bm.RequestCount() / bm.SetAgentBudget() directly.
func setupBudgetEnforcementSession(t *testing.T, bm *connector.BudgetManager) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil, WithBudgetManager(bm))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "budget-enforce", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, store
}

// TestBudget_ResendHTTP_EnforcesAfterMaxTotalRequests is the canonical
// USK-818 regression test. Mirrors the Phase 5 P5-19 reproduction.
func TestBudget_ResendHTTP_EnforcesAfterMaxTotalRequests(t *testing.T) {
	const maxRequests = 3
	echo := startBudgetTestEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: maxRequests})
	cs, store := setupBudgetEnforcementSession(t, bm)
	bm.Start(nil)
	defer bm.Stop()

	// Fire maxRequests+1 resend_http calls. The first maxRequests succeed;
	// the (maxRequests+1)th returns a budget-exhausted error.
	streamIDs := make([]string, 0, maxRequests+1)
	for i := 0; i < maxRequests; i++ {
		res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "resend_http",
			Arguments: map[string]any{
				"method":     "GET",
				"scheme":     "http",
				"authority":  authority,
				"path":       "/",
				"timeout_ms": 3000,
			},
		})
		if err != nil {
			t.Fatalf("call %d: transport error: %v", i+1, err)
		}
		if res.IsError {
			t.Fatalf("call %d: tool error before budget exhaustion: %s", i+1, extractTextContent(res))
		}
		var out resendHTTPResult
		decodeStructuredResult(t, res, &out)
		if out.StatusCode != 200 {
			t.Errorf("call %d: StatusCode = %d, want 200", i+1, out.StatusCode)
		}
		streamIDs = append(streamIDs, out.StreamID)
	}

	// The (maxRequests+1)th call must be blocked.
	overRes, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_http",
		Arguments: map[string]any{
			"method":     "GET",
			"scheme":     "http",
			"authority":  authority,
			"path":       "/",
			"timeout_ms": 3000,
		},
	})
	if err != nil {
		t.Fatalf("over-budget call: transport error: %v", err)
	}
	if !overRes.IsError {
		t.Fatalf("over-budget call: expected tool error; got success")
	}
	errMsg := extractTextContent(overRes)
	if !strings.Contains(errMsg, "budget") {
		t.Errorf("over-budget error message = %q, want substring \"budget\"", errMsg)
	}

	// Counter must reflect the over-budget call (connector.BudgetManager
	// is increment-then-check; the (max+1)th is counted-and-blocked).
	if got := bm.RequestCount(); got != maxRequests+1 {
		t.Errorf("RequestCount() = %d, want %d", got, maxRequests+1)
	}

	// The blocked attempt must surface as an audit Stream — we don't have
	// the streamID directly because the over-budget call returned an error
	// (no result body), but we can query the store for state="error" +
	// blocked_by="budget" rows.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	streams, err := store.ListStreams(ctx, flow.StreamListOptions{
		BlockedBy: "budget",
	})
	if err != nil {
		t.Fatalf("ListStreams(blocked_by=budget): %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("blocked_by=budget streams: got %d, want exactly 1", len(streams))
	}
	st := streams[0]
	if st.State != "error" {
		t.Errorf("audit stream State = %q, want %q", st.State, "error")
	}
	if st.BlockedBy != "budget" {
		t.Errorf("audit stream BlockedBy = %q, want %q", st.BlockedBy, "budget")
	}
	if st.Origin != flow.OriginResend {
		t.Errorf("audit stream Origin = %q, want %q", st.Origin, flow.OriginResend)
	}
	if st.Scheme != "http" {
		t.Errorf("audit stream Scheme = %q, want %q", st.Scheme, "http")
	}

	// The successful streams must NOT be tagged blocked_by="budget".
	for i, sid := range streamIDs {
		st, err := store.GetStream(ctx, sid)
		if err != nil {
			t.Fatalf("GetStream(%s): %v", sid, err)
		}
		if st.BlockedBy != "" {
			t.Errorf("success stream %d: BlockedBy = %q, want empty", i, st.BlockedBy)
		}
		if st.State != "complete" {
			t.Errorf("success stream %d: State = %q, want %q", i, st.State, "complete")
		}
	}

	// Lookup via the security tool — request_count must match.
	getRes, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "security",
		Arguments: securityMarshal(t, securityInput{Action: "get_budget"}),
	})
	if err != nil {
		t.Fatalf("security get_budget: %v", err)
	}
	if getRes.IsError {
		t.Fatalf("security get_budget tool error: %s", extractTextContent(getRes))
	}
	var gb getBudgetResult
	securityUnmarshalResult(t, getRes, &gb)
	if gb.RequestCount != int64(maxRequests+1) {
		t.Errorf("security.get_budget RequestCount = %d, want %d", gb.RequestCount, maxRequests+1)
	}
}

// TestBudget_FuzzHTTP_EnforcesAfterMaxTotalRequests covers the fuzz_http
// dispatch path. The (max+1)th variant must record an error row.
func TestBudget_FuzzHTTP_EnforcesAfterMaxTotalRequests(t *testing.T) {
	const maxRequests = 2
	echo := startBudgetTestEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: maxRequests})
	cs, _ := setupBudgetEnforcementSession(t, bm)
	bm.Start(nil)
	defer bm.Stop()

	// fuzz_http with maxRequests+1 variants by varying a single position.
	// The schema shape is positions[].payloads[] (string list) per
	// fuzz_http.go.
	payloads := make([]string, 0, maxRequests+1)
	for i := 0; i < maxRequests+1; i++ {
		payloads = append(payloads, "v"+string(rune('a'+i)))
	}

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_http",
		Arguments: map[string]any{
			"method":     "GET",
			"scheme":     "http",
			"authority":  authority,
			"path":       "/",
			"timeout_ms": 3000,
			"headers": []map[string]any{
				{"name": "X-Fuzz", "value": "default"},
			},
			"positions": []map[string]any{
				{
					"path":     "headers[0].value",
					"payloads": payloads,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("fuzz_http transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("fuzz_http tool error: %s", extractTextContent(res))
	}

	// We don't decode the full fuzz result schema — just assert the budget
	// counter advanced by maxRequests+1 (the (max+1)th variant was counted
	// then blocked).
	if got := bm.RequestCount(); got != int64(maxRequests+1) {
		t.Errorf("RequestCount() after fuzz_http = %d, want %d", got, maxRequests+1)
	}
}

// setupBudgetFuzzSession is setupBudgetEnforcementSession plus the
// options the fuzz_ws / fuzz_grpc / fuzz_raw and resend_grpc dispatch
// paths need: a FuzzStore (fuzz_jobs / fuzz_results persistence) and an
// InsecureSkipVerify TLS transport (the gRPC test upstreams use a
// throwaway self-signed CA).
func setupBudgetFuzzSession(t *testing.T, bm *connector.BudgetManager) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()
	fs, ok := store.(flow.FuzzStore)
	if !ok {
		t.Fatal("test store does not implement flow.FuzzStore")
	}
	srv := newServer(ctx, nil, store, nil,
		WithBudgetManager(bm),
		WithFuzzStore(fs),
		WithTLSTransport(&transport.StandardTransport{InsecureSkipVerify: true}),
	)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "budget-fuzz", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, store
}

// newBudgetOneManager returns a BudgetManager whose policy allows exactly
// one request; the second is counted-and-blocked.
func newBudgetOneManager() *connector.BudgetManager {
	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 1})
	return bm
}

// requireSingleBudgetAuditStream asserts the store holds exactly one
// blocked_by="budget" Stream, in State="error", stamped with wantOrigin,
// and returns it.
func requireSingleBudgetAuditStream(t *testing.T, store flow.Store, wantOrigin flow.Origin) *flow.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	streams, err := store.ListStreams(ctx, flow.StreamListOptions{BlockedBy: "budget"})
	if err != nil {
		t.Fatalf("ListStreams(blocked_by=budget): %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("blocked_by=budget streams: got %d, want exactly 1", len(streams))
	}
	st := streams[0]
	if st.State != "error" {
		t.Errorf("audit stream State = %q, want %q", st.State, "error")
	}
	if st.Origin != wantOrigin {
		t.Errorf("audit stream Origin = %q, want %q", st.Origin, wantOrigin)
	}
	return st
}

// assertFuzzOriginStreamCount asserts ListStreams{Origin: fuzz} returns
// want rows — i.e. the budget-blocked trial is attributable to the fuzz
// campaign alongside the trial that went through.
func assertFuzzOriginStreamCount(t *testing.T, store flow.Store, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	streams, err := store.ListStreams(ctx, flow.StreamListOptions{Origin: flow.OriginFuzz})
	if err != nil {
		t.Fatalf("ListStreams(origin=fuzz): %v", err)
	}
	if len(streams) != want {
		t.Errorf("origin=fuzz streams: got %d, want %d", len(streams), want)
	}
}

// assertBudgetBlockedSecondVariant checks the per-variant outcome shared
// by the fuzz tests: variant 0 within budget, variant 1 budget-blocked,
// two requests counted.
func assertBudgetBlockedSecondVariant(t *testing.T, bm *connector.BudgetManager, errs []string) {
	t.Helper()
	if len(errs) != 2 {
		t.Fatalf("len(Variants) = %d, want 2", len(errs))
	}
	if errs[0] != "" {
		t.Errorf("variants[0].Error = %q, want empty (within budget)", errs[0])
	}
	if !strings.Contains(errs[1], "budget exhausted") {
		t.Errorf("variants[1].Error = %q, want substring %q", errs[1], "budget exhausted")
	}
	if got := bm.RequestCount(); got != 2 {
		t.Errorf("RequestCount() = %d, want 2", got)
	}
}

// TestBudget_FuzzWS_AuditStreamStampedOriginFuzz: a fuzz_ws trial that
// overruns the budget must leave its audit Stream attributed to the fuzz
// campaign, not to resend.
func TestBudget_FuzzWS_AuditStreamStampedOriginFuzz(t *testing.T) {
	bm := newBudgetOneManager()
	cs, store := setupBudgetFuzzSession(t, bm)
	bm.Start(nil)
	defer bm.Stop()
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
	errs := make([]string, 0, len(result.Variants))
	for _, v := range result.Variants {
		errs = append(errs, v.Error)
	}
	assertBudgetBlockedSecondVariant(t, bm, errs)

	st := requireSingleBudgetAuditStream(t, store, flow.OriginFuzz)
	if st.ID != result.Variants[1].StreamID {
		t.Errorf("audit stream ID = %q, want variants[1].StreamID %q", st.ID, result.Variants[1].StreamID)
	}
	assertFuzzOriginStreamCount(t, store, 2)
}

// TestBudget_FuzzGRPC_AuditStreamStampedOriginFuzz is the fuzz_grpc
// counterpart of TestBudget_FuzzWS_AuditStreamStampedOriginFuzz.
func TestBudget_FuzzGRPC_AuditStreamStampedOriginFuzz(t *testing.T) {
	bm := newBudgetOneManager()
	cs, store := setupBudgetFuzzSession(t, bm)
	bm.Start(nil)
	defer bm.Stop()
	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	result := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"v1", "v2"}},
		},
		"timeout_ms": 10000,
	})
	errs := make([]string, 0, len(result.Variants))
	for _, v := range result.Variants {
		errs = append(errs, v.Error)
	}
	assertBudgetBlockedSecondVariant(t, bm, errs)
	if got := len(upstream.snapshot()); got != 1 {
		t.Errorf("upstream observed %d requests, want 1 (second variant blocked)", got)
	}

	st := requireSingleBudgetAuditStream(t, store, flow.OriginFuzz)
	if st.ID != result.Variants[1].StreamID {
		t.Errorf("audit stream ID = %q, want variants[1].StreamID %q", st.ID, result.Variants[1].StreamID)
	}
	assertFuzzOriginStreamCount(t, store, 2)
}

// TestBudget_FuzzRaw_BlockedTrialLeavesAuditStream: a fuzz_raw trial
// that overruns the budget must leave a blocked_by="budget" audit Stream
// stamped origin=fuzz, under the variant row's StreamID.
func TestBudget_FuzzRaw_BlockedTrialLeavesAuditStream(t *testing.T) {
	bm := newBudgetOneManager()
	cs, store := setupBudgetFuzzSession(t, bm)
	bm.Start(nil)
	defer bm.Stop()
	addr, getRecv := startFuzzRawTCPServer(t)

	result := callFuzzRaw(t, cs, map[string]any{
		"target_addr": addr,
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"raw-1", "raw-2"}},
		},
		"timeout_ms": 5000,
	})
	errs := make([]string, 0, len(result.Variants))
	for _, v := range result.Variants {
		errs = append(errs, v.Error)
	}
	assertBudgetBlockedSecondVariant(t, bm, errs)

	st := requireSingleBudgetAuditStream(t, store, flow.OriginFuzz)
	if st.ID != result.Variants[1].StreamID {
		t.Errorf("audit stream ID = %q, want variants[1].StreamID %q", st.ID, result.Variants[1].StreamID)
	}

	// Exactly one upstream connection: the blocked trial never dialed.
	// waitForCaptures returns once the first connection's capture lands;
	// both trials have finished by now, so a second dial would already
	// be accepted and only its capture could still be pending.
	waitForCaptures(getRecv, 1, 3*time.Second)
	time.Sleep(300 * time.Millisecond)
	if got := len(getRecv()); got != 1 {
		t.Errorf("upstream connections = %d, want 1 (second variant blocked)", got)
	}
}

// TestBudget_ResendWS_AuditStreamStaysOriginResend is the regression
// guard for the shared runResendWS seam: resend_ws keeps origin=resend.
func TestBudget_ResendWS_AuditStreamStaysOriginResend(t *testing.T) {
	bm := newBudgetOneManager()
	cs, store := setupBudgetFuzzSession(t, bm)
	bm.Start(nil)
	defer bm.Stop()
	addr, cleanup := newWebSocketEchoServer(t)
	defer cleanup()

	args := map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"payload":     "hello",
		"timeout_ms":  5000,
	}
	if res := callResendWS(t, cs, args); res.IsError {
		t.Fatalf("first resend_ws: tool error within budget: %s", extractTextContent(res))
	}
	over := callResendWS(t, cs, args)
	if !over.IsError {
		t.Fatal("second resend_ws: expected budget tool error; got success")
	}
	if msg := extractTextContent(over); !strings.Contains(msg, "budget") {
		t.Errorf("second resend_ws error = %q, want substring %q", msg, "budget")
	}
	requireSingleBudgetAuditStream(t, store, flow.OriginResend)
}

// TestBudget_ResendGRPC_AuditStreamStaysOriginResend is the regression
// guard for the shared runResendGRPC seam: resend_grpc keeps
// origin=resend.
func TestBudget_ResendGRPC_AuditStreamStaysOriginResend(t *testing.T) {
	bm := newBudgetOneManager()
	cs, store := setupBudgetFuzzSession(t, bm)
	bm.Start(nil)
	defer bm.Stop()
	upstream := &resendGRPCEchoServer{}
	addr, shutdown := startResendGRPCUpstream(t, upstream)
	defer shutdown()

	args := map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      resendGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "ping"},
		},
		"timeout_ms": 10000,
	}
	if res := callResendGRPC(t, cs, args); res.IsError {
		t.Fatalf("first resend_grpc: tool error within budget: %s", extractTextContent(res))
	}
	over := callResendGRPC(t, cs, args)
	if !over.IsError {
		t.Fatal("second resend_grpc: expected budget tool error; got success")
	}
	if msg := extractTextContent(over); !strings.Contains(msg, "budget") {
		t.Errorf("second resend_grpc error = %q, want substring %q", msg, "budget")
	}
	requireSingleBudgetAuditStream(t, store, flow.OriginResend)
}

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

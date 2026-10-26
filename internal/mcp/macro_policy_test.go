package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// The tests in this file pin that both macro SendFuncs — run_macro's
// Server.macroSendFunc and the fuzz pre/post_macro hookMacroSendFunc —
// obey the same Policy-layer limits as resend_* / fuzz_*: the security
// rate limit (waitRateLimit), the diagnostic budget (RecordRequest), and
// the SafetyFilter Input Filter.

// newHitCountingServer returns an httptest server that counts every
// request it receives.
func newHitCountingServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// newBurstOneHostLimiter returns a RateLimiter with a per-host limit so low
// that each host bucket holds exactly one token (burst 1) and effectively
// never refills during a test. No global limiter is configured.
func newBurstOneHostLimiter(t *testing.T) *connector.RateLimiter {
	t.Helper()
	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerHostPerSecond: 0.001})
	return rl
}

// boundedCtx returns a context that expires after 2s, so a regression that
// makes a SendFunc wait on an empty rate bucket fails the test instead of
// blocking for the bucket's ~1000s refill interval.
func boundedCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// macroSendFuncsUnderTest enumerates both macro SendFunc constructors so
// every policy assertion runs against each.
func macroSendFuncsUnderTest() []struct {
	name string
	mk   func(s *Server) macro.SendFunc
} {
	return []struct {
		name string
		mk   func(s *Server) macro.SendFunc
	}{
		{name: "run_macro", mk: func(s *Server) macro.SendFunc { return s.macroSendFunc("m") }},
		{name: "hook_macro", mk: func(s *Server) macro.SendFunc { return hookMacroSendFunc(s, "m") }},
	}
}

// TestMacroSendFuncs_RateLimit_WaitsOnHostBucket verifies that a macro step
// sent to a host whose per-host bucket is empty waits on the rate limiter
// and fails once the step context expires, without reaching upstream.
func TestMacroSendFuncs_RateLimit_WaitsOnHostBucket(t *testing.T) {
	for _, tc := range macroSendFuncsUnderTest() {
		t.Run(tc.name, func(t *testing.T) {
			echo, hits := newHitCountingServer(t)
			u, _ := url.Parse(echo.URL)

			rl := newBurstOneHostLimiter(t)
			// Drain the host's single token.
			if !rl.Allow(u.Hostname()) {
				t.Fatal("setup: first Allow on a fresh bucket must succeed")
			}

			s := mkServerFromLegacyDeps(legacyDeps{rateLimiter: rl})
			send := tc.mk(s)

			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			_, err := send(ctx, &macro.SendRequest{Method: "GET", URL: echo.URL + "/x", StepID: "s1"})
			if err == nil {
				t.Fatal("expected a rate-limit error for an empty host bucket, got nil")
			}
			if !strings.Contains(err.Error(), "rate limit") {
				t.Errorf("error should mention rate limit, got: %v", err)
			}
			if got := hits.Load(); got != 0 {
				t.Errorf("upstream hits = %d, want 0", got)
			}
		})
	}
}

// TestMacroSendFuncs_RateLimit_ScopeRefusalConsumesNoToken guards the
// ordering: a step refused by TargetScope must not consume a rate token.
func TestMacroSendFuncs_RateLimit_ScopeRefusalConsumesNoToken(t *testing.T) {
	for _, tc := range macroSendFuncsUnderTest() {
		t.Run(tc.name, func(t *testing.T) {
			ts := connector.NewTargetScope()
			_ = ts.SetAgentRules([]connector.TargetRule{{Hostname: "allowed.example.com"}}, nil)
			rl := newBurstOneHostLimiter(t)

			s := mkServerFromLegacyDeps(legacyDeps{targetScope: ts, rateLimiter: rl})
			send := tc.mk(s)

			_, err := send(boundedCtx(t), &macro.SendRequest{
				Method: "GET", URL: "http://blocked.example.com/x", StepID: "s1",
			})
			if err == nil || !strings.Contains(err.Error(), "target scope") {
				t.Fatalf("expected target scope error, got: %v", err)
			}
			if !rl.Allow("blocked.example.com") {
				t.Error("scope-refused step consumed the host's rate token")
			}
		})
	}
}

// TestMacroSendFuncs_SafetyInput_BlocksDestructiveBody verifies that both
// macro SendFuncs run the SafetyFilter Input Filter on the step body, so a
// destructive payload never reaches upstream, and that the refusal consumes
// no rate token.
func TestMacroSendFuncs_SafetyInput_BlocksDestructiveBody(t *testing.T) {
	for _, tc := range macroSendFuncsUnderTest() {
		t.Run(tc.name, func(t *testing.T) {
			echo, hits := newHitCountingServer(t)
			u, _ := url.Parse(echo.URL)

			engine, err := safety.NewEngine(safety.Config{
				InputRules: []safety.RuleConfig{{Preset: "destructive-sql"}},
			})
			if err != nil {
				t.Fatalf("safety.NewEngine: %v", err)
			}
			rl := newBurstOneHostLimiter(t)
			s := mkServerFromLegacyDeps(legacyDeps{safetyEngine: engine, rateLimiter: rl})
			send := tc.mk(s)

			_, err = send(boundedCtx(t), &macro.SendRequest{
				Method: "POST",
				URL:    echo.URL + "/q",
				Body:   []byte("query=DROP TABLE users;"),
				StepID: "s1",
			})
			if err == nil {
				t.Fatal("expected SafetyFilter block, got nil")
			}
			if !strings.Contains(err.Error(), "SafetyFilter") {
				t.Errorf("error should mention SafetyFilter, got: %v", err)
			}
			if got := hits.Load(); got != 0 {
				t.Errorf("upstream hits = %d, want 0", got)
			}
			if !rl.Allow(u.Hostname()) {
				t.Error("safety-refused step consumed the host's rate token")
			}
		})
	}
}

// TestMacroSendFuncs_Budget_RefusesWhenExhausted verifies that each macro
// step send counts one request toward the diagnostic budget and that a step
// is refused (errBudgetExhausted) without reaching upstream once the budget
// is spent.
func TestMacroSendFuncs_Budget_RefusesWhenExhausted(t *testing.T) {
	for _, tc := range macroSendFuncsUnderTest() {
		t.Run(tc.name, func(t *testing.T) {
			echo, hits := newHitCountingServer(t)

			bm := connector.NewBudgetManager()
			bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 1})
			s := mkServerFromLegacyDeps(legacyDeps{budgetManager: bm})
			send := tc.mk(s)

			if _, err := send(boundedCtx(t), &macro.SendRequest{
				Method: "GET", URL: echo.URL + "/1", StepID: "s1",
			}); err != nil {
				t.Fatalf("first step: unexpected error: %v", err)
			}
			_, err := send(boundedCtx(t), &macro.SendRequest{
				Method: "GET", URL: echo.URL + "/2", StepID: "s2",
			})
			if !errors.Is(err, errBudgetExhausted) {
				t.Fatalf("second step error = %v, want errBudgetExhausted", err)
			}
			if got := hits.Load(); got != 1 {
				t.Errorf("upstream hits = %d, want 1", got)
			}
			if got := bm.RequestCount(); got != 2 {
				t.Errorf("budget RequestCount = %d, want 2 (one per step attempt)", got)
			}
		})
	}
}

// saveHTTPSendFlow stores a minimal recorded HTTP flow whose send message
// targets rawURL and returns its stream ID.
func saveHTTPSendFlow(t *testing.T, store flow.Store, rawURL string) string {
	t.Helper()
	ctx := context.Background()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	st := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: st.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: u,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return st.ID
}

// TestRunMacro_RateLimit_SecondStepWaitsOnHostBucket drives the MCP macro
// tool end to end: with a burst-1 per-host bucket, step 1 completes and
// step 2 (same host) waits on the rate limiter until its timeout_ms
// elapses, so upstream sees exactly one request.
func TestRunMacro_RateLimit_SecondStepWaitsOnHostBucket(t *testing.T) {
	echo, hits := newHitCountingServer(t)
	store := newTestStore(t)
	ctx := context.Background()
	id1 := saveHTTPSendFlow(t, store, echo.URL+"/a")
	id2 := saveHTTPSendFlow(t, store, echo.URL+"/b")

	rl := newBurstOneHostLimiter(t)
	s := newServer(ctx, nil, store, nil, WithRateLimiter(rl))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "rl-macro",
			"steps": []any{
				map[string]any{"id": "one", "flow_id": id1, "timeout_ms": 300},
				map[string]any{"id": "two", "flow_id": id2, "timeout_ms": 300},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{"name": "rl-macro"},
	})
	if runResult.IsError {
		t.Fatalf("run_macro returned MCP error: %v", runResult.Content)
	}
	var out macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &out)
	if out.Status == "completed" {
		t.Fatalf("macro completed; want step two to fail on the rate limit: %+v", out)
	}
	var stepTwoErr string
	for _, sr := range out.StepResults {
		if sr.ID == "two" {
			stepTwoErr = sr.Error
		}
	}
	if !strings.Contains(stepTwoErr, "rate limit") && !strings.Contains(out.Error, "rate limit") {
		t.Errorf("expected a rate limit error for step two, got: %+v", out)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
}

// TestHookMacro_RateLimit_OneTokenPerStep verifies the counting rule on the
// fuzz pre_macro path: a 1-step hook macro consumes exactly one token of the
// step host's bucket — the hook succeeds on a fresh burst-1 bucket (so it is
// not counted twice) and the bucket is empty afterwards (so it is counted).
func TestHookMacro_RateLimit_OneTokenPerStep(t *testing.T) {
	echo, hits := newHitCountingServer(t)
	u, _ := url.Parse(echo.URL)
	store := newTestStore(t)
	id := saveHTTPSendFlow(t, store, echo.URL+"/pre")

	cfgJSON, err := json.Marshal(macroConfig{Steps: []macroStepInput{{ID: "pre", StreamID: id}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := store.SaveMacro(context.Background(), "pre-macro", "test", string(cfgJSON)); err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}

	rl := newBurstOneHostLimiter(t)
	s := mkServerFromLegacyDeps(legacyDeps{store: store, rateLimiter: rl})
	he := newHookExecutor(s, &hooksInput{
		PreMacro: &hookConfig{Macro: "pre-macro", RunInterval: "always"},
	}, &hookState{})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := he.executePreMacro(ctx, nil); err != nil {
		t.Fatalf("executePreMacro: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer waitCancel()
	if err := s.waitRateLimit(waitCtx, u.Hostname()); err == nil {
		t.Error("host bucket still had a token after the hook macro step; the step did not consume one")
	}
}

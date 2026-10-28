package connector

import (
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// USK-1115: runtime replacement of the Policy Layer. These tests drive the
// three engines' replacement methods directly; the reload orchestration
// (load -> validate -> build -> replace) is covered in internal/mcpserver.

// TestReplacePolicyRules_NarrowingKeepsAgentRulesWithoutWidening is T6 at
// the engine seam (design decision R2): when the operator narrows the
// policy, the agent's allows are kept verbatim (pruning them would drop the
// agent's self-restriction and widen access), those now outside the policy
// are reported to the caller, and they stop matching — they are blocked as
// "not in policy allow list".
func TestReplacePolicyRules_NarrowingKeepsAgentRulesWithoutWidening(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "*.a.test"}, {Hostname: "*.b.test"}}, nil)
	if err := s.SetAgentRules([]TargetRule{{Hostname: "x.a.test"}, {Hostname: "y.b.test"}}, nil); err != nil {
		t.Fatalf("SetAgentRules: %v", err)
	}

	loadedAt := time.Date(2026, 10, 16, 1, 2, 3, 0, time.UTC)
	outside := s.ReplacePolicyRules([]TargetRule{{Hostname: "*.a.test"}}, nil,
		PolicyOrigin{Source: "policy file", LoadedAt: loadedAt})

	if len(outside) != 1 || outside[0].Hostname != "y.b.test" {
		t.Errorf("ReplacePolicyRules outside = %+v, want exactly [y.b.test]", outside)
	}
	allows, _ := s.PolicyRules()
	if len(allows) != 1 || allows[0].Hostname != "*.a.test" {
		t.Errorf("PolicyRules allows after replace = %+v, want [*.a.test]", allows)
	}
	agentAllows, _ := s.AgentRules()
	if len(agentAllows) != 2 {
		t.Errorf("AgentRules allows after narrowing = %+v, want both agent rules kept", agentAllows)
	}
	if ok, reason := s.CheckTarget("https", "y.b.test", 443, "/"); ok || reason != "not in policy allow list" {
		t.Errorf("CheckTarget(y.b.test) = (%v, %q), want blocked by \"not in policy allow list\"", ok, reason)
	}
	if ok, reason := s.CheckTarget("https", "x.a.test", 443, "/"); !ok {
		t.Errorf("CheckTarget(x.a.test) blocked (%s), want allowed", reason)
	}
	if got := s.PolicyOrigin(); got.Source != "policy file" || !got.LoadedAt.Equal(loadedAt) {
		t.Errorf("PolicyOrigin = %+v, want {policy file %v}", got, loadedAt)
	}

	// Every agent allow outside the new policy: the agent still restricted
	// itself, so nothing becomes reachable — neither the new policy host nor
	// the agent's own hosts.
	outside = s.ReplacePolicyRules([]TargetRule{{Hostname: "*.c.test"}}, nil, PolicyOrigin{Source: "policy file"})
	if len(outside) != 2 {
		t.Errorf("outside after second narrowing = %+v, want both agent allows", outside)
	}
	if ok, reason := s.CheckTarget("https", "z.c.test", 443, "/"); ok || reason != "not in agent allow list" {
		t.Errorf("CheckTarget(z.c.test) = (%v, %q), want blocked by \"not in agent allow list\" (no widening)", ok, reason)
	}
	if ok, _ := s.CheckTarget("https", "x.a.test", 443, "/"); ok {
		t.Error("CheckTarget(x.a.test) allowed after the policy dropped *.a.test")
	}
}

// TestReplacePolicyRules_OpenPolicyReportsNothingOutside: removing every
// policy allow lifts the boundary, so no agent allow is outside it.
func TestReplacePolicyRules_OpenPolicyReportsNothingOutside(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "*.a.test"}}, nil)
	if err := s.SetAgentRules([]TargetRule{{Hostname: "x.a.test"}}, nil); err != nil {
		t.Fatalf("SetAgentRules: %v", err)
	}
	outside := s.ReplacePolicyRules(nil, []TargetRule{{Hostname: "evil.test"}}, PolicyOrigin{Source: "config file"})
	if len(outside) != 0 {
		t.Errorf("outside = %+v, want none", outside)
	}
	if ok, reason := s.CheckTarget("https", "evil.test", 443, "/"); ok || reason != "blocked by policy deny rule" {
		t.Errorf("CheckTarget(evil.test) = (%v, %q), want the new policy deny", ok, reason)
	}
}

// TestReplacePolicyBudget_RearmsDurationWithoutResettingCounters is T7
// (decision R6): a policy budget reload re-arms the duration timer against
// the new effective limit but keeps request_count — the session goes on.
// Plain SetPolicyBudget only stores the config, so the timer would never
// fire.
func TestReplacePolicyBudget_RearmsDurationWithoutResettingCounters(t *testing.T) {
	bm := NewBudgetManager()
	var fired atomic.Int32
	reasons := make(chan string, 1)
	bm.Start(func(reason string) {
		fired.Add(1)
		select {
		case reasons <- reason:
		default:
		}
	})
	defer bm.Stop()

	for i := 0; i < 3; i++ {
		if !bm.RecordRequest() {
			t.Fatalf("RecordRequest %d denied with no budget", i)
		}
	}

	if exhausted := bm.ReplacePolicyBudget(BudgetConfig{MaxDuration: 50 * time.Millisecond}); exhausted != "" {
		t.Errorf("ReplacePolicyBudget exhausted = %q, want \"\" (the session is younger than the new 50ms limit)", exhausted)
	}
	if got := bm.RequestCount(); got != 3 {
		t.Errorf("RequestCount after ReplacePolicyBudget = %d, want 3 (counters must not reset)", got)
	}
	select {
	case reason := <-reasons:
		if !strings.Contains(reason, "duration budget exhausted") {
			t.Errorf("shutdown reason = %q, want a duration budget message", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("duration timer did not fire within 2s after ReplacePolicyBudget(MaxDuration=50ms)")
	}
	if got := bm.PolicyBudget().MaxDuration; got != 50*time.Millisecond {
		t.Errorf("PolicyBudget().MaxDuration = %v, want 50ms", got)
	}
}

// TestReplacePolicyBudget_ReportsAlreadyExhaustedRequestBudget: narrowing
// max_total_requests to at or below the current count is reported so the
// reloader can warn that the next request stops the proxy.
func TestReplacePolicyBudget_ReportsAlreadyExhaustedRequestBudget(t *testing.T) {
	bm := NewBudgetManager()
	bm.Start(func(string) {})
	defer bm.Stop()
	for i := 0; i < 5; i++ {
		bm.RecordRequest()
	}
	exhausted := bm.ReplacePolicyBudget(BudgetConfig{MaxTotalRequests: 5})
	if !strings.Contains(exhausted, "request budget") {
		t.Errorf("ReplacePolicyBudget exhausted = %q, want a request budget message", exhausted)
	}
	if bm.RecordRequest() {
		t.Error("RecordRequest allowed after the policy budget was narrowed to the current count")
	}
}

// TestReplacePolicyLimits_LowerRPSDeniesCONNECTBurst is T8, a
// characterization: SetPolicyLimits already rebuilds the limiters, so a
// lowered policy RPS takes effect on the very next CONNECT gate check.
func TestReplacePolicyLimits_LowerRPSDeniesCONNECTBurst(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{MaxRequestsPerSecond: 1000})
	cfg := CONNECTHandlerConfig{RateLimiter: rl}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for i := 0; i < 5; i++ {
		if resp, _, _ := connectPolicyReject(cfg, "burst.test:443", false, logger); resp != nil {
			t.Fatalf("CONNECT %d denied at 1000 rps", i)
		}
	}

	rl.SetPolicyLimits(RateLimitConfig{MaxRequestsPerSecond: 1})
	denied := false
	for i := 0; i < 5; i++ {
		if resp, _, _ := connectPolicyReject(cfg, "burst.test:443", false, logger); resp != nil {
			denied = true
			break
		}
	}
	if !denied {
		t.Error("CONNECT burst of 5 all allowed after the policy RPS dropped to 1")
	}
}

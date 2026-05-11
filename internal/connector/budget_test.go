package connector

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBudgetManager_NoLimits(t *testing.T) {
	bm := NewBudgetManager()
	bm.Start(nil)
	defer bm.Stop()

	if bm.HasBudget() {
		t.Error("HasBudget() = true, want false")
	}
	// Should always allow when no limits.
	for i := 0; i < 100; i++ {
		if !bm.RecordRequest() {
			t.Fatalf("RecordRequest returned false at iteration %d", i)
		}
	}
}

func TestBudgetManager_MaxTotalRequests_Policy(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxTotalRequests: 5})

	var shutdownReason string
	bm.Start(func(reason string) {
		shutdownReason = reason
	})
	defer bm.Stop()

	if !bm.HasBudget() {
		t.Error("HasBudget() = false, want true")
	}

	// First 5 requests should succeed.
	for i := 0; i < 5; i++ {
		if !bm.RecordRequest() {
			t.Fatalf("RecordRequest returned false at iteration %d", i)
		}
	}

	// 6th request should fail.
	if bm.RecordRequest() {
		t.Error("RecordRequest returned true after budget exhausted")
	}

	if shutdownReason == "" {
		t.Error("shutdown callback was not called")
	}
	if bm.ShutdownReason() == "" {
		t.Error("ShutdownReason() is empty")
	}
	if bm.RequestCount() != 6 {
		t.Errorf("RequestCount() = %d, want 6", bm.RequestCount())
	}
}

func TestBudgetManager_MaxTotalRequests_Agent(t *testing.T) {
	bm := NewBudgetManager()
	if err := bm.SetAgentBudget(BudgetConfig{MaxTotalRequests: 3}); err != nil {
		t.Fatalf("SetAgentBudget: %v", err)
	}

	var called atomic.Bool
	bm.Start(func(_ string) { called.Store(true) })
	defer bm.Stop()

	for i := 0; i < 3; i++ {
		if !bm.RecordRequest() {
			t.Fatalf("RecordRequest returned false at iteration %d", i)
		}
	}

	if bm.RecordRequest() {
		t.Error("RecordRequest returned true after budget exhausted")
	}
	if !called.Load() {
		t.Error("shutdown callback was not called")
	}
}

func TestBudgetManager_AgentLimitsWithinPolicy(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxTotalRequests: 100})

	err := bm.SetAgentBudget(BudgetConfig{MaxTotalRequests: 50})
	if err != nil {
		t.Fatalf("SetAgentBudget: %v", err)
	}

	eff := bm.EffectiveBudget()
	if eff.MaxTotalRequests != 50 {
		t.Errorf("effective.MaxTotalRequests = %d, want 50", eff.MaxTotalRequests)
	}
}

func TestBudgetManager_AgentLimitsExceedPolicy(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxTotalRequests: 100})

	err := bm.SetAgentBudget(BudgetConfig{MaxTotalRequests: 200})
	if err == nil {
		t.Error("SetAgentBudget should fail when exceeding policy")
	}
}

func TestBudgetManager_AgentDurationExceedPolicy(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxDuration: 30 * time.Minute})

	err := bm.SetAgentBudget(BudgetConfig{MaxDuration: time.Hour})
	if err == nil {
		t.Error("SetAgentBudget should fail when exceeding policy duration")
	}
}

func TestBudgetManager_MaxDuration(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxDuration: 50 * time.Millisecond})

	var reason string
	var mu sync.Mutex
	bm.Start(func(r string) {
		mu.Lock()
		reason = r
		mu.Unlock()
	})
	defer bm.Stop()

	// Wait for the timer to fire.
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	r := reason
	mu.Unlock()

	if r == "" {
		t.Error("shutdown callback was not called after duration expired")
	}
}

func TestBudgetManager_EffectiveBudget_StricterWins(t *testing.T) {
	tests := []struct {
		name     string
		policy   BudgetConfig
		agent    BudgetConfig
		wantReqs int64
		wantDur  time.Duration
	}{
		{
			name:     "both zero",
			policy:   BudgetConfig{},
			agent:    BudgetConfig{},
			wantReqs: 0,
			wantDur:  0,
		},
		{
			name:     "policy only",
			policy:   BudgetConfig{MaxTotalRequests: 100, MaxDuration: time.Hour},
			agent:    BudgetConfig{},
			wantReqs: 100,
			wantDur:  time.Hour,
		},
		{
			name:     "agent only",
			policy:   BudgetConfig{},
			agent:    BudgetConfig{MaxTotalRequests: 50, MaxDuration: 30 * time.Minute},
			wantReqs: 50,
			wantDur:  30 * time.Minute,
		},
		{
			name:     "agent stricter",
			policy:   BudgetConfig{MaxTotalRequests: 100, MaxDuration: time.Hour},
			agent:    BudgetConfig{MaxTotalRequests: 50, MaxDuration: 30 * time.Minute},
			wantReqs: 50,
			wantDur:  30 * time.Minute,
		},
		{
			name:     "policy stricter",
			policy:   BudgetConfig{MaxTotalRequests: 50, MaxDuration: 30 * time.Minute},
			agent:    BudgetConfig{MaxTotalRequests: 50, MaxDuration: 30 * time.Minute},
			wantReqs: 50,
			wantDur:  30 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bm := NewBudgetManager()
			bm.SetPolicyBudget(tt.policy)
			if err := bm.SetAgentBudget(tt.agent); err != nil {
				t.Fatalf("SetAgentBudget: %v", err)
			}
			eff := bm.EffectiveBudget()
			if eff.MaxTotalRequests != tt.wantReqs {
				t.Errorf("MaxTotalRequests = %d, want %d", eff.MaxTotalRequests, tt.wantReqs)
			}
			if eff.MaxDuration != tt.wantDur {
				t.Errorf("MaxDuration = %v, want %v", eff.MaxDuration, tt.wantDur)
			}
		})
	}
}

func TestBudgetManager_TriggerShutdown(t *testing.T) {
	bm := NewBudgetManager()

	var reason string
	bm.Start(func(r string) { reason = r })
	defer bm.Stop()

	bm.TriggerShutdown("plugin: too many errors")

	if reason != "plugin: too many errors" {
		t.Errorf("reason = %q, want %q", reason, "plugin: too many errors")
	}
	if bm.ShutdownReason() != "plugin: too many errors" {
		t.Errorf("ShutdownReason() = %q, want %q", bm.ShutdownReason(), "plugin: too many errors")
	}
}

func TestBudgetManager_TriggerShutdownOnlyOnce(t *testing.T) {
	bm := NewBudgetManager()

	var count atomic.Int32
	bm.Start(func(_ string) { count.Add(1) })
	defer bm.Stop()

	bm.TriggerShutdown("first")
	bm.TriggerShutdown("second")

	if count.Load() != 1 {
		t.Errorf("shutdown called %d times, want 1", count.Load())
	}
	if bm.ShutdownReason() != "first" {
		t.Errorf("ShutdownReason() = %q, want %q", bm.ShutdownReason(), "first")
	}
}

func TestBudgetManager_ConcurrentAccess(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxTotalRequests: 1000})
	bm.Start(func(_ string) {})
	defer bm.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				bm.RecordRequest()
			}
		}()
	}
	wg.Wait()

	if bm.RequestCount() != 1000 {
		t.Errorf("RequestCount() = %d, want 1000", bm.RequestCount())
	}
}

// TestBudgetManager_SetAgentBudget_ResetsState verifies USK-828: every
// SetAgentBudget call clears request_count, shutdown_reason, re-arms the
// shutdownOnce, and advances startTime so the new budget begins a fresh
// diagnostic session.
func TestBudgetManager_SetAgentBudget_ResetsState(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxTotalRequests: 1000})
	if err := bm.SetAgentBudget(BudgetConfig{MaxTotalRequests: 3}); err != nil {
		t.Fatalf("initial SetAgentBudget: %v", err)
	}

	var shutdownCount atomic.Int32
	var lastReason atomic.Value // string
	lastReason.Store("")
	bm.Start(func(r string) {
		shutdownCount.Add(1)
		lastReason.Store(r)
	})
	defer bm.Stop()

	startBefore := func() time.Time {
		bm.mu.Lock()
		defer bm.mu.Unlock()
		return bm.startTime
	}()

	// Exhaust the budget by overflowing it.
	for i := 0; i < 4; i++ {
		bm.RecordRequest()
	}
	if bm.RequestCount() == 0 {
		t.Fatal("RequestCount is 0 after exhaustion loop; expected >0")
	}
	if bm.ShutdownReason() == "" {
		t.Fatal("ShutdownReason is empty after exhaustion; expected non-empty")
	}
	if shutdownCount.Load() != 1 {
		t.Fatalf("shutdown callback fired %d times before reset, want 1", shutdownCount.Load())
	}

	// Ensure clock can advance so startTime change is observable.
	time.Sleep(2 * time.Millisecond)

	// Set a new budget — this must reset counters and clear stop_reason.
	if err := bm.SetAgentBudget(BudgetConfig{MaxTotalRequests: 5}); err != nil {
		t.Fatalf("SetAgentBudget (reset): %v", err)
	}

	if got := bm.RequestCount(); got != 0 {
		t.Errorf("RequestCount after reset = %d, want 0", got)
	}
	if got := bm.ShutdownReason(); got != "" {
		t.Errorf("ShutdownReason after reset = %q, want empty", got)
	}

	startAfter := func() time.Time {
		bm.mu.Lock()
		defer bm.mu.Unlock()
		return bm.startTime
	}()
	if !startAfter.After(startBefore) {
		t.Errorf("startTime did not advance: before=%v after=%v", startBefore, startAfter)
	}

	// shutdownOnce must be re-armed: TriggerShutdown after reset should fire
	// the callback again (count goes from 1 → 2) and ShutdownReason updates.
	bm.TriggerShutdown("post-reset trigger")
	if shutdownCount.Load() != 2 {
		t.Errorf("shutdown callback fired %d times after reset, want 2 (was 1 before reset)", shutdownCount.Load())
	}
	if got, _ := lastReason.Load().(string); got != "post-reset trigger" {
		t.Errorf("last shutdown reason = %q, want %q", got, "post-reset trigger")
	}
	if got := bm.ShutdownReason(); got != "post-reset trigger" {
		t.Errorf("ShutdownReason after re-trigger = %q, want %q", got, "post-reset trigger")
	}
}

// TestBudgetManager_SetAgentBudget_ResetsAfterDurationExhaustion verifies that
// SetAgentBudget restores a working session after the duration timer fired,
// not only after request-count exhaustion.
func TestBudgetManager_SetAgentBudget_ResetsAfterDurationExhaustion(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxDuration: time.Hour})
	if err := bm.SetAgentBudget(BudgetConfig{MaxDuration: 30 * time.Millisecond}); err != nil {
		t.Fatalf("initial SetAgentBudget: %v", err)
	}

	var shutdownCount atomic.Int32
	bm.Start(func(_ string) { shutdownCount.Add(1) })
	defer bm.Stop()

	// Wait for the duration timer to fire.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if bm.ShutdownReason() != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if bm.ShutdownReason() == "" {
		t.Fatal("duration timer did not fire within deadline")
	}
	if shutdownCount.Load() != 1 {
		t.Fatalf("shutdown callback fired %d times, want 1", shutdownCount.Load())
	}

	// New budget should reset state.
	if err := bm.SetAgentBudget(BudgetConfig{MaxDuration: time.Minute}); err != nil {
		t.Fatalf("SetAgentBudget (reset): %v", err)
	}
	if got := bm.ShutdownReason(); got != "" {
		t.Errorf("ShutdownReason after reset = %q, want empty", got)
	}
	if got := bm.RequestCount(); got != 0 {
		t.Errorf("RequestCount after reset = %d, want 0", got)
	}

	// Sanity: shutdownOnce re-armed.
	bm.TriggerShutdown("manual after duration reset")
	if shutdownCount.Load() != 2 {
		t.Errorf("shutdown callback fired %d times after reset+trigger, want 2", shutdownCount.Load())
	}
}

// TestBudgetManager_StaleTimerFire_AfterReset reproduces the captured-pointer
// race that motivated the *sync.Once + identity-check pattern (USK-828
// review F-1). Scenario: a duration timer was armed for the prior session,
// the user calls SetAgentBudget which resets state, and only *then* the
// stale timer fires its triggerShutdown.
//
// Before the fix, the stale fire would acquire bm.mu after the reset, see
// the NEW once pointer, pass the identity check against itself, and clobber
// the freshly cleared shutdownReason plus invoke the new session's
// onShutdown callback. After the fix, resetDurationTimerLocked captures
// the OLD once at arm time and triggerShutdownOnce's identity check
// detects bm.shutdownOnce != oldOnce, dropping the stale fire entirely.
//
// We simulate the race deterministically by manually invoking
// triggerShutdownOnce with the captured-at-arm-time pointer, exactly as
// the timer goroutine would do post-reset.
func TestBudgetManager_StaleTimerFire_AfterReset(t *testing.T) {
	bm := NewBudgetManager()
	bm.SetPolicyBudget(BudgetConfig{MaxDuration: time.Hour})
	if err := bm.SetAgentBudget(BudgetConfig{MaxDuration: 10 * time.Second}); err != nil {
		t.Fatalf("initial SetAgentBudget: %v", err)
	}

	var shutdownCount atomic.Int32
	bm.Start(func(_ string) { shutdownCount.Add(1) })
	defer bm.Stop()

	// Capture the session-1 once pointer (what a freshly armed duration
	// timer would have closed over inside resetDurationTimerLocked).
	bm.mu.Lock()
	session1Once := bm.shutdownOnce
	bm.mu.Unlock()
	if session1Once == nil {
		t.Fatal("session 1 once is nil; Start should have armed it")
	}

	// SetAgentBudget swaps in a new once for session 2.
	if err := bm.SetAgentBudget(BudgetConfig{MaxDuration: time.Minute}); err != nil {
		t.Fatalf("SetAgentBudget (reset): %v", err)
	}

	bm.mu.Lock()
	session2Once := bm.shutdownOnce
	bm.mu.Unlock()
	if session2Once == session1Once {
		t.Fatal("shutdownOnce was not swapped on SetAgentBudget; reset is broken")
	}

	// Now simulate the stale timer fire: a goroutine that was armed for
	// session 1 finally calls triggerShutdownOnce post-reset.
	bm.triggerShutdownOnce(session1Once, "duration budget exhausted: limit 10s reached")

	if got := bm.ShutdownReason(); got != "" {
		t.Errorf("ShutdownReason after stale fire = %q, want empty (stale reason leaked)", got)
	}
	if got := shutdownCount.Load(); got != 0 {
		t.Errorf("shutdown callback fired %d time(s) on stale once, want 0", got)
	}

	// Sanity: a session-2 trigger still works.
	bm.TriggerShutdown("session 2 explicit")
	if got := bm.ShutdownReason(); got != "session 2 explicit" {
		t.Errorf("ShutdownReason after session-2 trigger = %q, want %q", got, "session 2 explicit")
	}
	if got := shutdownCount.Load(); got != 1 {
		t.Errorf("shutdown callback fired %d time(s) after session-2 trigger, want 1", got)
	}
}

func TestBudgetConfig_IsZero(t *testing.T) {
	if !(BudgetConfig{}).IsZero() {
		t.Error("zero config should be IsZero")
	}
	if (BudgetConfig{MaxTotalRequests: 1}).IsZero() {
		t.Error("non-zero config should not be IsZero")
	}
	if (BudgetConfig{MaxDuration: time.Second}).IsZero() {
		t.Error("non-zero config should not be IsZero")
	}
}

package proxy

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

func TestEffectiveBudgetInt64(t *testing.T) {
	tests := []struct {
		policy, agent, want int64
	}{
		{0, 0, 0},
		{100, 0, 100},
		{0, 50, 50},
		{100, 50, 50},
		{50, 100, 50},
		{50, 50, 50},
	}
	for _, tt := range tests {
		got := effectiveBudgetInt64(tt.policy, tt.agent)
		if got != tt.want {
			t.Errorf("effectiveBudgetInt64(%d, %d) = %d, want %d", tt.policy, tt.agent, got, tt.want)
		}
	}
}

func TestEffectiveBudgetDuration(t *testing.T) {
	tests := []struct {
		policy, agent, want time.Duration
	}{
		{0, 0, 0},
		{time.Hour, 0, time.Hour},
		{0, 30 * time.Minute, 30 * time.Minute},
		{time.Hour, 30 * time.Minute, 30 * time.Minute},
		{30 * time.Minute, time.Hour, 30 * time.Minute},
	}
	for _, tt := range tests {
		got := effectiveBudgetDuration(tt.policy, tt.agent)
		if got != tt.want {
			t.Errorf("effectiveBudgetDuration(%v, %v) = %v, want %v", tt.policy, tt.agent, got, tt.want)
		}
	}
}

package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_NoLimits(t *testing.T) {
	rl := NewRateLimiter()
	if rl.HasLimits() {
		t.Error("expected no limits")
	}
	if !rl.Allow("example.com") {
		t.Error("expected Allow to return true with no limits")
	}
}

func TestRateLimiter_GlobalLimit(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 1,
	})
	if !rl.HasLimits() {
		t.Error("expected limits")
	}

	// First request should be allowed (burst).
	if !rl.Allow("example.com") {
		t.Error("first request should be allowed")
	}
	// Second request should also be allowed (burst = 2 for rate 1).
	if !rl.Allow("example.com") {
		t.Error("second request should be allowed (burst)")
	}
	// Third request should be rate limited.
	if rl.Allow("example.com") {
		t.Error("third request should be rate limited")
	}
}

func TestRateLimiter_PerHostLimit(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerHostPerSecond: 1,
	})

	// First request to host A should be allowed.
	if !rl.Allow("a.example.com") {
		t.Error("first request to host A should be allowed")
	}
	// Burst for host A.
	if !rl.Allow("a.example.com") {
		t.Error("burst request to host A should be allowed")
	}
	// Third to A: rate limited.
	if rl.Allow("a.example.com") {
		t.Error("third request to host A should be rate limited")
	}

	// Host B should still be allowed.
	if !rl.Allow("b.example.com") {
		t.Error("request to different host B should be allowed")
	}
}

func TestRateLimiter_PerHostCaseInsensitive(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerHostPerSecond: 1,
	})

	// Exhaust the burst for the host.
	rl.Allow("Example.COM")
	rl.Allow("example.com")

	// Should be rate limited regardless of case.
	if rl.Allow("EXAMPLE.COM") {
		t.Error("expected case-insensitive rate limiting")
	}
}

func TestRateLimiter_AgentLimitsWithinPolicy(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond:        10,
		MaxRequestsPerHostPerSecond: 5,
	})

	// Agent can set stricter limits.
	err := rl.SetAgentLimits(RateLimitConfig{
		MaxRequestsPerSecond:        5,
		MaxRequestsPerHostPerSecond: 2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	effective := rl.EffectiveLimits()
	if effective.MaxRequestsPerSecond != 5 {
		t.Errorf("effective global = %v, want 5", effective.MaxRequestsPerSecond)
	}
	if effective.MaxRequestsPerHostPerSecond != 2 {
		t.Errorf("effective per-host = %v, want 2", effective.MaxRequestsPerHostPerSecond)
	}
}

func TestRateLimiter_AgentLimitsExceedPolicy(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 10,
	})

	err := rl.SetAgentLimits(RateLimitConfig{
		MaxRequestsPerSecond: 20,
	})
	if err == nil {
		t.Fatal("expected error when agent exceeds policy")
	}
}

func TestRateLimiter_AgentPerHostExceedsPolicy(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerHostPerSecond: 5,
	})

	err := rl.SetAgentLimits(RateLimitConfig{
		MaxRequestsPerHostPerSecond: 10,
	})
	if err == nil {
		t.Fatal("expected error when agent per-host exceeds policy")
	}
}

func TestRateLimiter_AgentOnlyLimit(t *testing.T) {
	rl := NewRateLimiter()
	// No policy limits.

	err := rl.SetAgentLimits(RateLimitConfig{
		MaxRequestsPerSecond: 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	effective := rl.EffectiveLimits()
	if effective.MaxRequestsPerSecond != 1 {
		t.Errorf("effective global = %v, want 1", effective.MaxRequestsPerSecond)
	}
}

func TestRateLimiter_PolicyOnlyLimit(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 5,
	})

	effective := rl.EffectiveLimits()
	if effective.MaxRequestsPerSecond != 5 {
		t.Errorf("effective global = %v, want 5", effective.MaxRequestsPerSecond)
	}
}

func TestRateLimiter_ClearAgentLimits(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 10,
	})
	if err := rl.SetAgentLimits(RateLimitConfig{
		MaxRequestsPerSecond: 5,
	}); err != nil {
		t.Fatal(err)
	}

	// Clear agent limits.
	if err := rl.SetAgentLimits(RateLimitConfig{}); err != nil {
		t.Fatal(err)
	}

	effective := rl.EffectiveLimits()
	if effective.MaxRequestsPerSecond != 10 {
		t.Errorf("effective global = %v, want 10 (policy only)", effective.MaxRequestsPerSecond)
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond:        1000,
		MaxRequestsPerHostPerSecond: 100,
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				rl.Allow("example.com")
			}
		}()
	}
	wg.Wait()
	// No panic or data race expected.
}

func TestRateLimiter_HostLimitersEviction(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerHostPerSecond: 1000, // High rate so requests aren't denied.
	})

	// Fill up to the cap with unique hostnames.
	for i := 0; i < maxHostLimiters; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		if !rl.Allow(host) {
			t.Fatalf("request to %s should be allowed", host)
		}
	}

	// Verify the map is at the cap.
	rl.mu.Lock()
	size := len(rl.hostLimiters)
	rl.mu.Unlock()
	if size != maxHostLimiters {
		t.Fatalf("expected %d host limiters, got %d", maxHostLimiters, size)
	}

	// One more unique host should trigger eviction (map cleared then new entry added).
	if !rl.Allow("overflow.example.com") {
		t.Error("request after eviction should be allowed")
	}

	rl.mu.Lock()
	sizeAfter := len(rl.hostLimiters)
	rl.mu.Unlock()
	if sizeAfter != 1 {
		t.Errorf("expected 1 host limiter after eviction, got %d", sizeAfter)
	}
}

func TestRateLimiter_Check_GlobalDenial(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 1,
	})

	// Exhaust burst (rate=1, burst=2).
	rl.Allow("example.com")
	rl.Allow("example.com")

	// Third request should be denied with global limit type.
	denial := rl.Check("example.com")
	if denial == nil {
		t.Fatal("expected denial, got nil")
	}
	if denial.LimitType != "global" {
		t.Errorf("LimitType = %q, want %q", denial.LimitType, "global")
	}
	if denial.EffectiveRPS != 1 {
		t.Errorf("EffectiveRPS = %v, want 1", denial.EffectiveRPS)
	}
}

func TestRateLimiter_Check_PerHostDenial(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerHostPerSecond: 1,
	})

	// Exhaust burst for host A (rate=1, burst=2).
	rl.Allow("a.example.com")
	rl.Allow("a.example.com")

	// Third request to host A should be denied with per_host limit type.
	denial := rl.Check("a.example.com")
	if denial == nil {
		t.Fatal("expected denial, got nil")
	}
	if denial.LimitType != "per_host" {
		t.Errorf("LimitType = %q, want %q", denial.LimitType, "per_host")
	}
	if denial.EffectiveRPS != 1 {
		t.Errorf("EffectiveRPS = %v, want 1", denial.EffectiveRPS)
	}

	// Host B should still be allowed.
	denial = rl.Check("b.example.com")
	if denial != nil {
		t.Errorf("expected nil denial for host B, got %+v", denial)
	}
}

func TestRateLimiter_Check_Allowed(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond:        1000,
		MaxRequestsPerHostPerSecond: 1000,
	})

	// Should be allowed with high limits.
	denial := rl.Check("example.com")
	if denial != nil {
		t.Errorf("expected nil denial, got %+v", denial)
	}
}

func TestRateLimiter_Check_NoLimits(t *testing.T) {
	rl := NewRateLimiter()
	// No limits configured.
	denial := rl.Check("example.com")
	if denial != nil {
		t.Errorf("expected nil denial with no limits, got %+v", denial)
	}
}

func TestRateLimiter_Check_GlobalBeforePerHost(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond:        1,
		MaxRequestsPerHostPerSecond: 1,
	})

	// Exhaust global burst (rate=1, burst=2).
	rl.Allow("a.example.com")
	rl.Allow("b.example.com")

	// Next request should hit global limit first.
	denial := rl.Check("c.example.com")
	if denial == nil {
		t.Fatal("expected denial, got nil")
	}
	if denial.LimitType != "global" {
		t.Errorf("LimitType = %q, want %q (global should be checked first)", denial.LimitType, "global")
	}
}

func TestRateLimiter_Check_EffectiveRPS_AgentStricter(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 10,
	})
	if err := rl.SetAgentLimits(RateLimitConfig{
		MaxRequestsPerSecond: 2,
	}); err != nil {
		t.Fatal(err)
	}

	// Exhaust burst for agent limit (rate=2, burst=3).
	rl.Allow("example.com")
	rl.Allow("example.com")
	rl.Allow("example.com")

	denial := rl.Check("example.com")
	if denial == nil {
		t.Fatal("expected denial, got nil")
	}
	if denial.EffectiveRPS != 2 {
		t.Errorf("EffectiveRPS = %v, want 2 (agent stricter)", denial.EffectiveRPS)
	}
}

func TestRateLimitDenial_Tags(t *testing.T) {
	t.Run("nil denial returns nil", func(t *testing.T) {
		var d *RateLimitDenial
		if tags := d.Tags(); tags != nil {
			t.Errorf("Tags() = %v, want nil", tags)
		}
	})

	t.Run("global denial", func(t *testing.T) {
		d := &RateLimitDenial{LimitType: "global", EffectiveRPS: 10}
		tags := d.Tags()
		if tags["rate_limit_type"] != "global" {
			t.Errorf("rate_limit_type = %q, want %q", tags["rate_limit_type"], "global")
		}
		if tags["rate_limit_effective_rps"] != "10.0" {
			t.Errorf("rate_limit_effective_rps = %q, want %q", tags["rate_limit_effective_rps"], "10.0")
		}
	})

	t.Run("per_host denial", func(t *testing.T) {
		d := &RateLimitDenial{LimitType: "per_host", EffectiveRPS: 5.5}
		tags := d.Tags()
		if tags["rate_limit_type"] != "per_host" {
			t.Errorf("rate_limit_type = %q, want %q", tags["rate_limit_type"], "per_host")
		}
		if tags["rate_limit_effective_rps"] != "5.5" {
			t.Errorf("rate_limit_effective_rps = %q, want %q", tags["rate_limit_effective_rps"], "5.5")
		}
	})
}

func TestRateLimiter_Wait_NoLimitsFastPath(t *testing.T) {
	rl := NewRateLimiter()
	// No limits configured — Wait should return nil immediately even with
	// an already-cancelled ctx (no rate.Limiter.Wait is called).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rl.Wait(ctx, "example.com"); err != nil {
		t.Errorf("Wait with no limits returned error: %v", err)
	}
}

func TestRateLimiter_Wait_PacesAtConfiguredRate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping pacing assertion under -short")
	}
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 5,
	})

	// 4 calls at 5 RPS with a burst of (rate+1)=6 should drain the burst
	// quickly. To observe pacing we need calls > burst. Use 8 calls: the
	// first ~6 are immediate (burst), the next 2 are paced — elapsed
	// should be at least (8-6)*200ms = ~400ms (loose lower bound to
	// stay flake-free).
	const calls = 8
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	for i := 0; i < calls; i++ {
		if err := rl.Wait(ctx, "example.com"); err != nil {
			t.Fatalf("Wait[%d] error: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	const minElapsed = 200 * time.Millisecond
	if elapsed < minElapsed {
		t.Errorf("Wait pacing too fast: elapsed=%v, want >=%v (rate=5/s, %d calls)", elapsed, minElapsed, calls)
	}
}

func TestRateLimiter_Wait_CtxCancellation(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 1,
	})

	// Drain the burst (rate=1, burst=2) so the next Wait call must block.
	bg := context.Background()
	if err := rl.Wait(bg, "example.com"); err != nil {
		t.Fatalf("Wait[0]: %v", err)
	}
	if err := rl.Wait(bg, "example.com"); err != nil {
		t.Fatalf("Wait[1]: %v", err)
	}

	// Now Wait would block ~1s; supply a short deadline. rate.Limiter.Wait
	// surfaces this as either a wrapped ctx error or its own
	// "would exceed context deadline" sentinel — our wrapper preserves
	// the underlying error via %w. Either form is acceptable; what we
	// must verify is that Wait does not silently allow the request.
	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	err := rl.Wait(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error from short-deadline Wait, got nil")
	}
	if !strings.Contains(err.Error(), "rate limit wait") {
		t.Errorf("error missing wrapper prefix: %v", err)
	}
	// Sanity: the underlying error should mention either context cancellation
	// or rate-limit budget exhaustion. (Both indicate Wait did not succeed.)
	if !errors.Is(err, context.DeadlineExceeded) &&
		!errors.Is(err, context.Canceled) &&
		!strings.Contains(err.Error(), "would exceed context deadline") {
		t.Errorf("error = %v, want ctx cancellation or budget-exhaustion message", err)
	}
}

func TestRateLimiter_Wait_NoDeadlockUnderConcurrentSetAgentLimits(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 1000, // high enough to make Wait near-instant
	})

	// Spawn N concurrent Wait callers, then mid-flight call SetAgentLimits.
	// The lock-window invariant says SetAgentLimits should not block on
	// in-flight Wait calls, and Wait callers should not deadlock on the
	// SetAgentLimits update.
	const callers = 8
	const perCaller = 25
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perCaller; j++ {
				host := fmt.Sprintf("host-%d.example.com", id)
				if err := rl.Wait(ctx, host); err != nil {
					t.Errorf("caller %d Wait[%d]: %v", id, j, err)
					return
				}
			}
		}(i)
	}

	// Update agent limits a few times mid-flight; each call must complete
	// without blocking on the in-flight Wait callers.
	updateDone := make(chan struct{})
	go func() {
		defer close(updateDone)
		for k := 0; k < 5; k++ {
			if err := rl.SetAgentLimits(RateLimitConfig{
				MaxRequestsPerSecond: 500,
			}); err != nil {
				t.Errorf("SetAgentLimits %d: %v", k, err)
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	wg.Wait()
	<-updateDone
}

func TestRateLimitConfig_IsZero(t *testing.T) {
	if !(RateLimitConfig{}).IsZero() {
		t.Error("zero config should be zero")
	}
	if (RateLimitConfig{MaxRequestsPerSecond: 1}).IsZero() {
		t.Error("non-zero config should not be zero")
	}
	if (RateLimitConfig{MaxRequestsPerHostPerSecond: 1}).IsZero() {
		t.Error("non-zero config should not be zero")
	}
}

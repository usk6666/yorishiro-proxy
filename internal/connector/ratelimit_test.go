package connector

import (
	"fmt"
	"sync"
	"testing"
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

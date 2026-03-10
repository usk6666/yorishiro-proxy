package proxy

import (
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

func TestEffectiveRate(t *testing.T) {
	tests := []struct {
		name   string
		policy float64
		agent  float64
		want   float64
	}{
		{"both zero", 0, 0, 0},
		{"policy only", 10, 0, 10},
		{"agent only", 0, 5, 5},
		{"agent stricter", 10, 5, 5},
		{"policy stricter", 5, 10, 5},
		{"equal", 5, 5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := effectiveRate(tt.policy, tt.agent)
			if got != tt.want {
				t.Errorf("effectiveRate(%v, %v) = %v, want %v", tt.policy, tt.agent, got, tt.want)
			}
		})
	}
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

package proxy

import (
	"fmt"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimitConfig holds the rate limit settings for the TargetScope.
// It supports two levels: global (all requests) and per-host.
// Both Policy and Agent layers can set rate limits. The Agent layer
// can only set limits that are equal to or stricter than the Policy layer.
type RateLimitConfig struct {
	// MaxRequestsPerSecond is the global rate limit (requests per second).
	// 0 means no global rate limit.
	MaxRequestsPerSecond float64 `json:"max_requests_per_second"`

	// MaxRequestsPerHostPerSecond is the per-host rate limit (requests per second).
	// 0 means no per-host rate limit.
	MaxRequestsPerHostPerSecond float64 `json:"max_requests_per_host_per_second"`
}

// IsZero reports whether no rate limits are configured.
func (c RateLimitConfig) IsZero() bool {
	return c.MaxRequestsPerSecond == 0 && c.MaxRequestsPerHostPerSecond == 0
}

// maxHostLimiters is the maximum number of per-host rate limiters to keep.
// When this cap is reached, the entire map is cleared to prevent unbounded
// memory growth from unique subdomain flooding (CWE-400).
const maxHostLimiters = 1024

// RateLimiter manages global and per-host rate limiting using token bucket
// algorithm via golang.org/x/time/rate. It supports two layers (Policy and Agent)
// matching the TargetScope architecture.
//
// RateLimiter is safe for concurrent use.
type RateLimiter struct {
	mu sync.Mutex

	// Policy layer rate limits (immutable after initialization).
	policyConfig RateLimitConfig
	// Agent layer rate limits (mutable at runtime).
	agentConfig RateLimitConfig

	// Effective limiters (rebuilt when config changes).
	globalLimiter *rate.Limiter
	hostLimiters  map[string]*rate.Limiter

	// Effective rates used for current limiters.
	effectiveGlobalRPS float64
	effectiveHostRPS   float64
}

// NewRateLimiter creates a new RateLimiter with no limits configured.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		hostLimiters: make(map[string]*rate.Limiter),
	}
}

// SetPolicyLimits sets the immutable policy layer rate limits.
// This should only be called during initialization.
func (rl *RateLimiter) SetPolicyLimits(cfg RateLimitConfig) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.policyConfig = cfg
	rl.rebuildLimitersLocked()
}

// PolicyLimits returns a copy of the current policy rate limit config.
func (rl *RateLimiter) PolicyLimits() RateLimitConfig {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.policyConfig
}

// SetAgentLimits sets the agent layer rate limits. Agent limits must be
// equal to or stricter than (less than or equal to) the policy limits.
// Returns an error if the agent limits exceed the policy limits.
func (rl *RateLimiter) SetAgentLimits(cfg RateLimitConfig) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if err := rl.validateAgentLimitsLocked(cfg); err != nil {
		return err
	}

	rl.agentConfig = cfg
	rl.rebuildLimitersLocked()
	return nil
}

// AgentLimits returns a copy of the current agent rate limit config.
func (rl *RateLimiter) AgentLimits() RateLimitConfig {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.agentConfig
}

// EffectiveLimits returns the effective rate limits applied, which are the
// stricter of the policy and agent limits.
func (rl *RateLimiter) EffectiveLimits() RateLimitConfig {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return RateLimitConfig{
		MaxRequestsPerSecond:        rl.effectiveGlobalRPS,
		MaxRequestsPerHostPerSecond: rl.effectiveHostRPS,
	}
}

// Allow checks whether a request to the given hostname is allowed by the
// rate limiter. It consumes one token from both the global limiter and
// the per-host limiter (if configured). Returns true if the request is
// allowed, false if rate limited.
func (rl *RateLimiter) Allow(hostname string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check global limiter first.
	if rl.globalLimiter != nil && !rl.globalLimiter.Allow() {
		return false
	}

	// Check per-host limiter.
	if rl.effectiveHostRPS > 0 {
		key := strings.ToLower(hostname)
		limiter, ok := rl.hostLimiters[key]
		if !ok {
			// Evict all entries when the map exceeds the cap to prevent
			// unbounded memory growth from unique subdomain flooding.
			if len(rl.hostLimiters) >= maxHostLimiters {
				rl.hostLimiters = make(map[string]*rate.Limiter)
			}
			burst := int(rl.effectiveHostRPS) + 1
			if burst < 1 {
				burst = 1
			}
			limiter = rate.NewLimiter(rate.Limit(rl.effectiveHostRPS), burst)
			rl.hostLimiters[key] = limiter
		}
		if !limiter.Allow() {
			return false
		}
	}

	return true
}

// HasLimits reports whether any rate limits are configured (either policy or agent).
func (rl *RateLimiter) HasLimits() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.effectiveGlobalRPS > 0 || rl.effectiveHostRPS > 0
}

// validateAgentLimitsLocked checks that agent limits don't exceed policy limits.
// Must be called with rl.mu held.
func (rl *RateLimiter) validateAgentLimitsLocked(cfg RateLimitConfig) error {
	// If policy has a global limit, agent's global limit must not exceed it.
	if rl.policyConfig.MaxRequestsPerSecond > 0 && cfg.MaxRequestsPerSecond > 0 {
		if cfg.MaxRequestsPerSecond > rl.policyConfig.MaxRequestsPerSecond {
			return fmt.Errorf("agent max_requests_per_second (%.1f) exceeds policy limit (%.1f)",
				cfg.MaxRequestsPerSecond, rl.policyConfig.MaxRequestsPerSecond)
		}
	}

	// If policy has a per-host limit, agent's per-host limit must not exceed it.
	if rl.policyConfig.MaxRequestsPerHostPerSecond > 0 && cfg.MaxRequestsPerHostPerSecond > 0 {
		if cfg.MaxRequestsPerHostPerSecond > rl.policyConfig.MaxRequestsPerHostPerSecond {
			return fmt.Errorf("agent max_requests_per_host_per_second (%.1f) exceeds policy limit (%.1f)",
				cfg.MaxRequestsPerHostPerSecond, rl.policyConfig.MaxRequestsPerHostPerSecond)
		}
	}

	return nil
}

// rebuildLimitersLocked rebuilds the effective limiters based on policy and agent configs.
// The effective rate is the stricter (lower non-zero) of policy and agent.
// Must be called with rl.mu held.
func (rl *RateLimiter) rebuildLimitersLocked() {
	rl.effectiveGlobalRPS = effectiveRate(rl.policyConfig.MaxRequestsPerSecond, rl.agentConfig.MaxRequestsPerSecond)
	rl.effectiveHostRPS = effectiveRate(rl.policyConfig.MaxRequestsPerHostPerSecond, rl.agentConfig.MaxRequestsPerHostPerSecond)

	// Rebuild global limiter.
	if rl.effectiveGlobalRPS > 0 {
		burst := int(rl.effectiveGlobalRPS) + 1
		if burst < 1 {
			burst = 1
		}
		rl.globalLimiter = rate.NewLimiter(rate.Limit(rl.effectiveGlobalRPS), burst)
	} else {
		rl.globalLimiter = nil
	}

	// Clear host limiters — they'll be recreated on demand with the new rate.
	rl.hostLimiters = make(map[string]*rate.Limiter)
}

// effectiveRate returns the stricter (lower non-zero) of two rates.
// If either is zero, the other is used. If both are zero, returns 0.
func effectiveRate(policyRate, agentRate float64) float64 {
	if policyRate == 0 && agentRate == 0 {
		return 0
	}
	if policyRate == 0 {
		return agentRate
	}
	if agentRate == 0 {
		return policyRate
	}
	if agentRate < policyRate {
		return agentRate
	}
	return policyRate
}

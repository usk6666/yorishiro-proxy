package connector

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// BudgetConfig holds the budget settings for a diagnostic session.
// It supports two levels: Policy (immutable, set at startup) and Agent (mutable at runtime).
// The Agent layer can only set limits that are equal to or stricter than the Policy layer.
//
// MaxDuration is serialized as a human-readable string (e.g. "30m", "1h") in JSON
// responses, not as raw nanoseconds.
type BudgetConfig struct {
	// MaxTotalRequests is the maximum number of requests allowed in the session.
	// 0 means no request count limit.
	MaxTotalRequests int64 `json:"max_total_requests"`

	// MaxDuration is the maximum duration of the diagnostic session.
	// 0 means no duration limit.
	// JSON: serialized as a human-readable string (e.g. "30m") via custom marshaler.
	MaxDuration time.Duration `json:"-"`
}

// MarshalJSON implements json.Marshaler for BudgetConfig.
// MaxDuration is serialized as a human-readable duration string (e.g. "30m")
// instead of raw nanoseconds.
func (c BudgetConfig) MarshalJSON() ([]byte, error) {
	type Alias struct {
		MaxTotalRequests int64  `json:"max_total_requests"`
		MaxDuration      string `json:"max_duration"`
	}
	return json.Marshal(Alias{
		MaxTotalRequests: c.MaxTotalRequests,
		MaxDuration:      c.MaxDuration.String(),
	})
}

// UnmarshalJSON implements json.Unmarshaler for BudgetConfig.
// MaxDuration accepts both human-readable duration strings (e.g. "30m") and
// raw nanosecond numbers for backward compatibility.
func (c *BudgetConfig) UnmarshalJSON(data []byte) error {
	type Alias struct {
		MaxTotalRequests int64           `json:"max_total_requests"`
		MaxDuration      json.RawMessage `json:"max_duration"`
	}
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	c.MaxTotalRequests = a.MaxTotalRequests

	if len(a.MaxDuration) == 0 || string(a.MaxDuration) == "null" {
		c.MaxDuration = 0
		return nil
	}

	// Try string first (e.g. "30m").
	var s string
	if err := json.Unmarshal(a.MaxDuration, &s); err == nil {
		if s == "" || s == "0" || s == "0s" {
			c.MaxDuration = 0
			return nil
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid max_duration %q: %w", s, err)
		}
		c.MaxDuration = d
		return nil
	}

	// Fall back to number (nanoseconds) for backward compatibility.
	var ns int64
	if err := json.Unmarshal(a.MaxDuration, &ns); err != nil {
		return fmt.Errorf("max_duration must be a duration string (e.g. \"30m\") or number: %w", err)
	}
	c.MaxDuration = time.Duration(ns)
	return nil
}

// IsZero reports whether no budget limits are configured.
func (c BudgetConfig) IsZero() bool {
	return c.MaxTotalRequests == 0 && c.MaxDuration == 0
}

// BudgetManager manages diagnostic session budgets using a two-layer architecture
// (Policy and Agent) matching the TargetScope pattern. It tracks request counts
// and session duration, triggering a shutdown callback when a budget is exhausted.
//
// BudgetManager is safe for concurrent use.
type BudgetManager struct {
	mu sync.Mutex

	// Policy layer budget (immutable after initialization).
	policyConfig BudgetConfig
	// Agent layer budget (mutable at runtime).
	agentConfig BudgetConfig

	// requestCount tracks the total number of requests processed.
	requestCount atomic.Int64

	// startTime is the time the budget manager was started (duration tracking).
	startTime time.Time

	// shutdownReason records why the proxy was stopped.
	shutdownReason string

	// shutdownOnce ensures the shutdown callback is called at most once.
	shutdownOnce sync.Once

	// onShutdown is called when a budget is exhausted or plugin triggers shutdown.
	onShutdown func(reason string)

	// durationTimer fires when max_duration is reached.
	durationTimer *time.Timer
}

// NewBudgetManager creates a new BudgetManager.
func NewBudgetManager() *BudgetManager {
	return &BudgetManager{}
}

// SetPolicyBudget sets the immutable policy layer budget.
// This should only be called during initialization.
func (bm *BudgetManager) SetPolicyBudget(cfg BudgetConfig) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.policyConfig = cfg
}

// PolicyBudget returns a copy of the current policy budget config.
func (bm *BudgetManager) PolicyBudget() BudgetConfig {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return bm.policyConfig
}

// SetAgentBudget sets the agent layer budget. Agent limits must be
// equal to or stricter than (less than or equal to) the policy limits.
// Returns an error if the agent limits exceed the policy limits.
func (bm *BudgetManager) SetAgentBudget(cfg BudgetConfig) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if err := bm.validateAgentBudgetLocked(cfg); err != nil {
		return err
	}

	bm.agentConfig = cfg
	bm.resetDurationTimerLocked()
	return nil
}

// AgentBudget returns a copy of the current agent budget config.
func (bm *BudgetManager) AgentBudget() BudgetConfig {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return bm.agentConfig
}

// EffectiveBudget returns the effective budget applied, which is the
// stricter of the policy and agent limits.
func (bm *BudgetManager) EffectiveBudget() BudgetConfig {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return BudgetConfig{
		MaxTotalRequests: effectiveBudgetInt64(bm.policyConfig.MaxTotalRequests, bm.agentConfig.MaxTotalRequests),
		MaxDuration:      effectiveBudgetDuration(bm.policyConfig.MaxDuration, bm.agentConfig.MaxDuration),
	}
}

// HasBudget reports whether any budget limits are configured (either policy or agent).
func (bm *BudgetManager) HasBudget() bool {
	eff := bm.EffectiveBudget()
	return !eff.IsZero()
}

// Start initializes the budget tracking with a shutdown callback.
// The callback is invoked (at most once) when a budget is exhausted.
func (bm *BudgetManager) Start(onShutdown func(reason string)) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bm.startTime = time.Now()
	bm.onShutdown = onShutdown
	bm.shutdownOnce = sync.Once{}
	bm.shutdownReason = ""
	bm.requestCount.Store(0)

	bm.resetDurationTimerLocked()
}

// RecordRequest increments the request counter and checks the budget.
// Returns true if the request is allowed, false if the budget is exhausted.
func (bm *BudgetManager) RecordRequest() bool {
	count := bm.requestCount.Add(1)

	eff := bm.EffectiveBudget()
	if eff.MaxTotalRequests > 0 && count > eff.MaxTotalRequests {
		bm.triggerShutdown(fmt.Sprintf("request budget exhausted: %d/%d requests", count, eff.MaxTotalRequests))
		return false
	}
	return true
}

// RequestCount returns the current request count.
func (bm *BudgetManager) RequestCount() int64 {
	return bm.requestCount.Load()
}

// ShutdownReason returns the reason the proxy was shut down, or empty if still running.
func (bm *BudgetManager) ShutdownReason() string {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return bm.shutdownReason
}

// TriggerShutdown triggers a shutdown with the given reason.
// This is used by the plugin shutdown API.
func (bm *BudgetManager) TriggerShutdown(reason string) {
	bm.triggerShutdown(reason)
}

// Stop cancels the duration timer and cleans up resources.
func (bm *BudgetManager) Stop() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if bm.durationTimer != nil {
		bm.durationTimer.Stop()
		bm.durationTimer = nil
	}
}

// triggerShutdown records the reason and calls the shutdown callback once.
func (bm *BudgetManager) triggerShutdown(reason string) {
	bm.shutdownOnce.Do(func() {
		bm.mu.Lock()
		bm.shutdownReason = reason
		cb := bm.onShutdown
		bm.mu.Unlock()

		if cb != nil {
			cb(reason)
		}
	})
}

// validateAgentBudgetLocked checks that agent limits don't exceed policy limits.
// Must be called with bm.mu held.
func (bm *BudgetManager) validateAgentBudgetLocked(cfg BudgetConfig) error {
	// If policy has a request limit, agent's limit must not exceed it.
	if bm.policyConfig.MaxTotalRequests > 0 && cfg.MaxTotalRequests > 0 {
		if cfg.MaxTotalRequests > bm.policyConfig.MaxTotalRequests {
			return fmt.Errorf("agent max_total_requests (%d) exceeds policy limit (%d)",
				cfg.MaxTotalRequests, bm.policyConfig.MaxTotalRequests)
		}
	}

	// If policy has a duration limit, agent's limit must not exceed it.
	if bm.policyConfig.MaxDuration > 0 && cfg.MaxDuration > 0 {
		if cfg.MaxDuration > bm.policyConfig.MaxDuration {
			return fmt.Errorf("agent max_duration (%s) exceeds policy limit (%s)",
				cfg.MaxDuration, bm.policyConfig.MaxDuration)
		}
	}

	return nil
}

// resetDurationTimerLocked resets the duration timer based on the current effective budget.
// Must be called with bm.mu held.
func (bm *BudgetManager) resetDurationTimerLocked() {
	if bm.durationTimer != nil {
		bm.durationTimer.Stop()
		bm.durationTimer = nil
	}

	eff := BudgetConfig{
		MaxTotalRequests: effectiveBudgetInt64(bm.policyConfig.MaxTotalRequests, bm.agentConfig.MaxTotalRequests),
		MaxDuration:      effectiveBudgetDuration(bm.policyConfig.MaxDuration, bm.agentConfig.MaxDuration),
	}

	if eff.MaxDuration > 0 && !bm.startTime.IsZero() {
		elapsed := time.Since(bm.startTime)
		remaining := eff.MaxDuration - elapsed
		if remaining <= 0 {
			// Already expired.
			go bm.triggerShutdown(fmt.Sprintf("duration budget exhausted: %s elapsed, limit %s", elapsed.Round(time.Second), eff.MaxDuration))
		} else {
			bm.durationTimer = time.AfterFunc(remaining, func() {
				bm.triggerShutdown(fmt.Sprintf("duration budget exhausted: limit %s reached", eff.MaxDuration))
			})
		}
	}
}

// effectiveBudgetInt64 returns the stricter (lower non-zero) of two int64 values.
func effectiveBudgetInt64(policyVal, agentVal int64) int64 {
	if policyVal == 0 && agentVal == 0 {
		return 0
	}
	if policyVal == 0 {
		return agentVal
	}
	if agentVal == 0 {
		return policyVal
	}
	if agentVal < policyVal {
		return agentVal
	}
	return policyVal
}

// effectiveBudgetDuration returns the stricter (lower non-zero) of two durations.
func effectiveBudgetDuration(policyVal, agentVal time.Duration) time.Duration {
	if policyVal == 0 && agentVal == 0 {
		return 0
	}
	if policyVal == 0 {
		return agentVal
	}
	if agentVal == 0 {
		return policyVal
	}
	if agentVal < policyVal {
		return agentVal
	}
	return policyVal
}

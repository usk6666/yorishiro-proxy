//go:build legacy

package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// ScopeStep enforces target scope rules. It checks whether the Exchange's
// target URL is allowed by the configured TargetScope. Only Send-direction
// Exchanges with a non-nil URL are checked; all others pass through.
//
// When blocked, ScopeStep records a "BlockedBy" key in Exchange.Metadata
// and returns Drop.
type ScopeStep struct {
	scope *proxy.TargetScope
}

// NewScopeStep creates a ScopeStep backed by the given TargetScope.
// If scope is nil, the Step always returns Continue.
func NewScopeStep(scope *proxy.TargetScope) *ScopeStep {
	return &ScopeStep{scope: scope}
}

// Process checks the Exchange's URL against the TargetScope rules.
// Returns Drop if the target is blocked, Continue otherwise.
func (s *ScopeStep) Process(_ context.Context, ex *exchange.Exchange) Result {
	if ex.Direction != exchange.Send {
		return Result{}
	}
	if ex.URL == nil {
		return Result{}
	}
	if s.scope == nil || !s.scope.HasRules() {
		return Result{}
	}

	allowed, reason := s.scope.CheckURL(ex.URL)
	if !allowed {
		if ex.Metadata == nil {
			ex.Metadata = make(map[string]any)
		}
		ex.Metadata["BlockedBy"] = "target_scope"
		ex.Metadata["BlockedReason"] = reason
		return Result{Action: Drop}
	}
	return Result{}
}

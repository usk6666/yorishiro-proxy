//go:build legacy

package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// RateLimitStep enforces rate limiting. It checks whether the Exchange's
// target hostname is within the configured rate limits. Only Send-direction
// Exchanges with a non-nil URL are checked; all others pass through.
//
// When rate limited, RateLimitStep records denial details in Exchange.Metadata
// and returns Drop.
type RateLimitStep struct {
	limiter *proxy.RateLimiter
}

// NewRateLimitStep creates a RateLimitStep backed by the given RateLimiter.
// If limiter is nil, the Step always returns Continue.
func NewRateLimitStep(limiter *proxy.RateLimiter) *RateLimitStep {
	return &RateLimitStep{limiter: limiter}
}

// Process checks the Exchange's target hostname against the RateLimiter.
// Returns Drop if the request is rate limited, Continue otherwise.
func (s *RateLimitStep) Process(_ context.Context, ex *exchange.Exchange) Result {
	if ex.Direction != envelope.Send {
		return Result{}
	}
	if ex.URL == nil {
		return Result{}
	}
	if s.limiter == nil || !s.limiter.HasLimits() {
		return Result{}
	}

	denial := s.limiter.Check(ex.URL.Hostname())
	if denial != nil {
		if ex.Metadata == nil {
			ex.Metadata = make(map[string]any)
		}
		ex.Metadata["BlockedBy"] = "rate_limit"
		for k, v := range denial.Tags() {
			ex.Metadata[k] = v
		}
		return Result{Action: Drop}
	}
	return Result{}
}

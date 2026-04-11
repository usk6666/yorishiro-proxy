package proxy

// This file is a backward-compatibility shim. The real RateLimiter type
// lives in internal/connector/. The aliases here keep existing
// internal/proxy/ handlers and tests compiling during the M36-M44
// architecture rewrite; both the aliases and the legacy proxy package are
// scheduled for deletion in M44.

import (
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// RateLimitDenial is an alias for connector.RateLimitDenial.
type RateLimitDenial = connector.RateLimitDenial

// RateLimitConfig is an alias for connector.RateLimitConfig.
type RateLimitConfig = connector.RateLimitConfig

// RateLimiter is an alias for connector.RateLimiter.
type RateLimiter = connector.RateLimiter

// NewRateLimiter creates a new RateLimiter with no limits configured.
// Delegates to connector.NewRateLimiter.
func NewRateLimiter() *RateLimiter {
	return connector.NewRateLimiter()
}

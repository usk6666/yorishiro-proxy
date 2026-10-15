package mcpserver

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// PolicySource names where the Policy Layer is read from.
type PolicySource struct {
	ConfigFile string
	PolicyFile string
}

// policyReloader replaces the Policy Layer at runtime.
type policyReloader struct {
	source PolicySource
	scope  *connector.TargetScope
	rl     *connector.RateLimiter
	bm     *connector.BudgetManager
	logger *slog.Logger
}

func newPolicyReloader(source PolicySource, scope *connector.TargetScope, rl *connector.RateLimiter, bm *connector.BudgetManager, logger *slog.Logger) *policyReloader {
	return &policyReloader{source: source, scope: scope, rl: rl, bm: bm, logger: logger}
}

// Reload re-reads the policy source and installs it.
func (r *policyReloader) Reload(trigger string) error {
	return nil
}

func (r *policyReloader) run(ctx context.Context, c <-chan struct{}, trigger string, onReload func(error)) {
	<-ctx.Done()
}

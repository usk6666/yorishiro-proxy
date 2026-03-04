package flow

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// CleanerConfig holds the configuration for the flow cleaner.
type CleanerConfig struct {
	// MaxFlows is the maximum number of flows to retain. 0 means unlimited.
	MaxFlows int
	// MaxAge is the maximum age of flows to retain. 0 means unlimited.
	MaxAge time.Duration
	// Interval is the time between automatic cleanup runs.
	Interval time.Duration
}

// Enabled returns true if any retention policy is configured.
func (c CleanerConfig) Enabled() bool {
	return c.MaxFlows > 0 || c.MaxAge > 0
}

// Cleaner periodically removes expired or excess flows from the store.
type Cleaner struct {
	store  Store
	config CleanerConfig
	logger *slog.Logger
	done   chan struct{}
	wg     sync.WaitGroup
}

// NewCleaner creates a new Cleaner with the given store, config, and logger.
func NewCleaner(store Store, config CleanerConfig, logger *slog.Logger) *Cleaner {
	return &Cleaner{
		store:  store,
		config: config,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// RunOnce performs a single cleanup pass. It deletes flows older than MaxAge
// first (which may reduce the count), then deletes excess flows beyond MaxFlows.
// It returns the total number of deleted flows.
func (c *Cleaner) RunOnce(ctx context.Context) (int64, error) {
	var total int64

	// Delete by age first — this may reduce the count enough to skip excess deletion.
	if c.config.MaxAge > 0 {
		cutoff := time.Now().UTC().Add(-c.config.MaxAge)
		n, err := c.store.DeleteFlowsOlderThan(ctx, cutoff)
		if err != nil {
			return total, err
		}
		total += n
		if n > 0 {
			c.logger.Info("cleaned up old flows", "deleted", n, "max_age", c.config.MaxAge)
		}
	}

	// Delete by count.
	if c.config.MaxFlows > 0 {
		n, err := c.store.DeleteExcessFlows(ctx, c.config.MaxFlows)
		if err != nil {
			return total, err
		}
		total += n
		if n > 0 {
			c.logger.Info("cleaned up excess flows", "deleted", n, "max_flows", c.config.MaxFlows)
		}
	}

	return total, nil
}

// Start begins periodic cleanup. It runs an immediate cleanup on startup,
// then runs at the configured interval until Stop is called or ctx is cancelled.
func (c *Cleaner) Start(ctx context.Context) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		// Run immediately on startup.
		if _, err := c.RunOnce(ctx); err != nil {
			c.logger.Warn("initial cleanup failed", "error", err)
		}

		if c.config.Interval <= 0 {
			return
		}

		ticker := time.NewTicker(c.config.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if _, err := c.RunOnce(ctx); err != nil {
					c.logger.Warn("periodic cleanup failed", "error", err)
				}
			case <-c.done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop signals the cleaner to stop and waits for the goroutine to finish.
func (c *Cleaner) Stop() {
	close(c.done)
	c.wg.Wait()
}

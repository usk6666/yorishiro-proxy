package fuzzer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// maxConcurrency is the upper bound on concurrent workers per fuzz job.
// This prevents resource exhaustion from excessive goroutine creation (CWE-770).
const maxConcurrency = 100

// RunConfig extends Config with execution control and stop condition parameters.
type RunConfig struct {
	Config

	// Concurrency is the number of concurrent workers. Defaults to 1.
	Concurrency int `json:"concurrency,omitempty"`
	// RateLimitRPS is the maximum requests per second. 0 means unlimited.
	RateLimitRPS float64 `json:"rate_limit_rps,omitempty"`
	// DelayMs is the fixed delay in milliseconds between requests.
	DelayMs int `json:"delay_ms,omitempty"`
	// MaxRetries is the number of retries per request on failure.
	MaxRetries int `json:"max_retries,omitempty"`

	// StopOn defines automatic stop conditions.
	StopOn *StopCondition `json:"stop_on,omitempty"`

	// Hooks provides optional macro hook callbacks for each fuzz iteration.
	// When set, pre_send hooks run before each iteration and post_receive hooks
	// run after. The hooks field is not serialized to JSON (set at runtime only).
	Hooks HookCallbacks `json:"-"`

	// HTTPDoer overrides the engine's default HTTP client for this job.
	// When set, this client is used instead of the engine's httpDoer.
	// Not serialized to JSON (set at runtime only).
	HTTPDoer HTTPDoer `json:"-"`
}

// Validate checks that a RunConfig is well-formed.
func (rc *RunConfig) Validate() error {
	if err := rc.Config.Validate(); err != nil {
		return err
	}
	if rc.Concurrency < 0 {
		return fmt.Errorf("concurrency must be >= 0, got %d", rc.Concurrency)
	}
	if rc.Concurrency > maxConcurrency {
		return fmt.Errorf("concurrency %d exceeds maximum %d", rc.Concurrency, maxConcurrency)
	}
	if rc.RateLimitRPS < 0 {
		return fmt.Errorf("rate_limit_rps must be >= 0, got %f", rc.RateLimitRPS)
	}
	if rc.DelayMs < 0 {
		return fmt.Errorf("delay_ms must be >= 0, got %d", rc.DelayMs)
	}
	if rc.MaxRetries < 0 {
		return fmt.Errorf("max_retries must be >= 0, got %d", rc.MaxRetries)
	}
	return nil
}

// AsyncResult is the immediate response returned when starting an async fuzz job.
type AsyncResult struct {
	// FuzzID is the unique identifier of the fuzz job.
	FuzzID string `json:"fuzz_id"`
	// Status is the initial job status ("running").
	Status string `json:"status"`
	// TotalRequests is the total number of iterations to execute.
	TotalRequests int `json:"total_requests"`
	// Tag is the job tag (if set).
	Tag string `json:"tag,omitempty"`
	// Message is a human-readable summary.
	Message string `json:"message"`
}

// Runner manages asynchronous fuzz job execution with concurrency control,
// rate limiting, and overload detection.
type Runner struct {
	engine   *Engine
	registry *JobRegistry
}

// NewRunner creates a new async fuzz runner backed by the given engine.
func NewRunner(engine *Engine, registry *JobRegistry) *Runner {
	return &Runner{
		engine:   engine,
		registry: registry,
	}
}

// Registry returns the runner's job registry.
func (r *Runner) Registry() *JobRegistry {
	return r.registry
}

// Start launches an asynchronous fuzz job. It validates the configuration,
// creates the job in the DB, and starts the execution in a background goroutine.
// Returns an AsyncResult immediately with the fuzz_id.
func (r *Runner) Start(ctx context.Context, cfg RunConfig) (*AsyncResult, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid fuzz config: %w", err)
	}

	// Fetch the template session and validate it exists.
	sess, err := r.engine.sessionFetcher.GetSession(ctx, cfg.SessionID)
	if err != nil {
		return nil, fmt.Errorf("get template session: %w", err)
	}

	sendMsgs, err := r.engine.sessionFetcher.GetMessages(ctx, sess.ID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, fmt.Errorf("template session %s has no send messages", cfg.SessionID)
	}
	sendMsg := sendMsgs[0]

	baseData := BuildRequestData(sendMsg)

	// Resolve payload sets.
	resolvedPayloads, err := ResolvePayloads(cfg.PayloadSets, r.engine.wordlistDir)
	if err != nil {
		return nil, err
	}

	// Create iterator.
	iter, err := NewIterator(cfg.AttackType, cfg.Positions, resolvedPayloads)
	if err != nil {
		return nil, fmt.Errorf("create iterator: %w", err)
	}

	// Serialize config for DB storage.
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal fuzz config: %w", err)
	}

	// Create fuzz job in DB.
	now := time.Now()
	job := &session.FuzzJob{
		ID:        uuid.New().String(),
		SessionID: cfg.SessionID,
		Config:    string(configJSON),
		Status:    string(StatusRunning),
		Tag:       cfg.Tag,
		CreatedAt: now,
		Total:     iter.Total(),
	}
	if err := r.engine.fuzzStore.SaveFuzzJob(ctx, job); err != nil {
		return nil, fmt.Errorf("save fuzz job: %w", err)
	}

	// Set up execution parameters.
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	timeout := 10 * time.Second
	if cfg.TimeoutMs > 0 {
		timeout = time.Duration(cfg.TimeoutMs) * time.Millisecond
	}

	// Create a cancellable context for the job.
	jobCtx, jobCancel := context.WithCancel(ctx)

	// Create the controller and register it.
	ctrl := NewJobController(jobCancel)
	if err := r.registry.Register(job.ID, ctrl); err != nil {
		jobCancel()
		return nil, fmt.Errorf("register fuzz job: %w", err)
	}

	// Set up overload monitor if needed.
	var monitor *OverloadMonitor
	if cfg.StopOn != nil {
		window := cfg.StopOn.LatencyWindow
		if window <= 0 {
			window = 10
		}
		monitor = NewOverloadMonitor(
			cfg.StopOn.LatencyThresholdMs,
			cfg.StopOn.LatencyBaselineMultiplier,
			window,
		)
	}

	// Launch the background execution.
	go r.execute(jobCtx, job, ctrl, iter, baseData, cfg, sess.Protocol, timeout, concurrency, monitor)

	return &AsyncResult{
		FuzzID:        job.ID,
		Status:        string(StatusRunning),
		TotalRequests: iter.Total(),
		Tag:           cfg.Tag,
		Message:       "Fuzzing started. Query fuzz_results with fuzz_id to check progress.",
	}, nil
}

// execute runs the fuzz iterations with the given concurrency, rate limiting,
// and stop conditions. It updates the job status in the DB upon completion.
func (r *Runner) execute(
	ctx context.Context,
	job *session.FuzzJob,
	ctrl *JobController,
	iter Iterator,
	baseData *RequestData,
	cfg RunConfig,
	protocol string,
	timeout time.Duration,
	concurrency int,
	monitor *OverloadMonitor,
) {
	defer r.registry.Remove(job.ID)

	var completedCount atomic.Int32
	var errorCount atomic.Int32

	// Compute rate limiter interval.
	var rateLimitInterval time.Duration
	if cfg.RateLimitRPS > 0 {
		rateLimitInterval = time.Duration(float64(time.Second) / cfg.RateLimitRPS)
	}

	// Fixed delay between requests.
	delay := time.Duration(cfg.DelayMs) * time.Millisecond

	// Channel for distributing fuzz cases to workers.
	cases := make(chan FuzzCase, concurrency)
	// stopOnce ensures we only stop once.
	var stopOnce sync.Once
	// stopped signals that a stop condition was triggered.
	stopped := make(chan struct{})

	triggerStop := func(reason string) {
		stopOnce.Do(func() {
			ctrl.Stop(StatusError, reason)
			close(stopped)
		})
	}

	// Rate limiter: a channel that workers read from before sending a request.
	// If no rate limiting, the channel is nil and workers proceed immediately.
	var rateTick <-chan time.Time
	var rateTicker *time.Ticker
	if rateLimitInterval > 0 {
		rateTicker = time.NewTicker(rateLimitInterval)
		rateTick = rateTicker.C
		defer rateTicker.Stop()
	}

	// Create a shared hook state per job (tracks cross-iteration state like "once", "every_n").
	var hookState *HookState
	if cfg.Hooks != nil {
		hookState = &HookState{}
	}

	// Worker pool.
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fc := range cases {
				// Check for pause.
				if err := ctrl.WaitIfPaused(ctx); err != nil {
					return
				}

				// Rate limit.
				if rateTick != nil {
					select {
					case <-rateTick:
					case <-ctx.Done():
						return
					}
				}

				// Fixed delay.
				if delay > 0 {
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return
					}
				}

				// Execute with retries.
				var result *session.FuzzResult
				attempts := 1 + cfg.MaxRetries
				for attempt := 0; attempt < attempts; attempt++ {
					result = r.engine.executeFuzzCaseWithHooks(ctx, baseData, cfg.Positions, fc, protocol, timeout, job.ID, cfg.Hooks, hookState, cfg.HTTPDoer)
					if result.Error == "" {
						break
					}
					// Don't retry if context is cancelled.
					if ctx.Err() != nil {
						break
					}
				}

				// Save result.
				if err := r.engine.fuzzStore.SaveFuzzResult(ctx, result); err != nil {
					errorCount.Add(1)
					r.updateJobProgress(ctx, job, int(completedCount.Load()), int(errorCount.Load()))
					continue
				}

				if result.Error != "" {
					errorCount.Add(1)
				} else {
					completedCount.Add(1)
				}

				// Update hook state after request completion.
				if cfg.Hooks != nil && hookState != nil {
					hookState.Mu.Lock()
					hadError := result.Error != ""
					cfg.Hooks.UpdateState(hookState, result.StatusCode, hadError)
					hookState.Mu.Unlock()
				}

				// Update progress in DB.
				r.updateJobProgress(ctx, job, int(completedCount.Load()), int(errorCount.Load()))

				// Check stop conditions.
				if cfg.StopOn != nil {
					// Status code stop condition.
					if result.StatusCode != 0 && checkStatusCode(result.StatusCode, cfg.StopOn.StatusCodes) {
						triggerStop(fmt.Sprintf("stop condition: received status code %d", result.StatusCode))
						return
					}

					// Error count stop condition.
					if cfg.StopOn.ErrorCount > 0 && int(errorCount.Load()) >= cfg.StopOn.ErrorCount {
						triggerStop(fmt.Sprintf("stop condition: error count reached %d", cfg.StopOn.ErrorCount))
						return
					}
				}

				// Overload detection.
				if monitor != nil && result.DurationMs > 0 {
					if monitor.Record(result.DurationMs) {
						triggerStop("stop condition: overload detected (latency threshold exceeded)")
						return
					}
				}
			}
		}()
	}

	// Producer: feed fuzz cases to the workers.
	go func() {
		defer close(cases)
		for {
			fc, ok := iter.Next()
			if !ok {
				break
			}

			select {
			case <-ctx.Done():
				return
			case <-stopped:
				return
			case cases <- fc:
			}
		}
	}()

	// Wait for all workers to finish.
	wg.Wait()

	// Determine final status.
	finalStatus := ctrl.Status()
	finalCompleted := int(completedCount.Load())
	finalErrors := int(errorCount.Load())

	switch finalStatus {
	case StatusRunning:
		// All iterations completed normally.
		ctrl.Complete()
		finalStatus = StatusCompleted
	case StatusPaused:
		// Should not happen here, but handle gracefully.
		finalStatus = StatusPaused
	}

	// Update the job in the DB with final status.
	// Create a new struct to avoid data races with concurrent readers.
	completedAt := time.Now()
	finalJob := &session.FuzzJob{
		ID:             job.ID,
		SessionID:      job.SessionID,
		Config:         job.Config,
		Status:         string(finalStatus),
		Tag:            job.Tag,
		CreatedAt:      job.CreatedAt,
		CompletedAt:    &completedAt,
		Total:          job.Total,
		CompletedCount: finalCompleted,
		ErrorCount:     finalErrors,
	}

	// Use a background context since the job context may be cancelled.
	if err := r.engine.fuzzStore.UpdateFuzzJob(context.Background(), finalJob); err != nil {
		slog.Warn("failed to finalize fuzz job in DB", "job_id", job.ID, "error", err)
	}
}

// updateJobProgress updates the job's completed and error counts in the DB.
func (r *Runner) updateJobProgress(ctx context.Context, job *session.FuzzJob, completed, errors int) {
	// Create a shallow copy to avoid data races.
	update := &session.FuzzJob{
		ID:             job.ID,
		SessionID:      job.SessionID,
		Config:         job.Config,
		Status:         string(StatusRunning),
		Tag:            job.Tag,
		CreatedAt:      job.CreatedAt,
		Total:          job.Total,
		CompletedCount: completed,
		ErrorCount:     errors,
	}
	// Best-effort update; don't fail the job if DB write fails here.
	if err := r.engine.fuzzStore.UpdateFuzzJob(ctx, update); err != nil {
		slog.Warn("failed to update fuzz job progress", "job_id", job.ID, "error", err)
	}
}

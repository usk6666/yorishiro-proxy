package fuzzer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// maxConcurrency is the upper bound on concurrent workers per fuzz job.
// This prevents resource exhaustion from excessive goroutine creation (CWE-770).
// maxTimeoutMs is the upper bound on per-request timeout in milliseconds (10 minutes).
// This matches the proxy's maxTimeoutMs and prevents goroutine blocking (CWE-400).
const (
	maxConcurrency = 100
	maxTimeoutMs   = 600000
)

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

	// TargetScopeChecker validates a URL against target scope rules before
	// sending each fuzz request. This is called after position application
	// and KV Store template expansion to prevent SSRF via payload injection.
	// When nil, no target scope check is performed (open mode).
	// Not serialized to JSON (set at runtime only).
	TargetScopeChecker func(u *url.URL) error `json:"-"`

	// SafetyInputChecker validates request body, URL, and headers against
	// safety filter rules before sending each fuzz request. This is called
	// after position application to prevent destructive payloads via fuzz
	// injection. When a payload is blocked, that iteration is skipped with
	// an error but the fuzz job continues.
	// When nil, no safety input check is performed.
	// Not serialized to JSON (set at runtime only).
	SafetyInputChecker func(body []byte, rawURL string, headers []exchange.KeyValue) error `json:"-"`
}

// Validate checks that a RunConfig is well-formed.
func (rc *RunConfig) Validate() error {
	if err := rc.Config.Validate(); err != nil {
		return err
	}
	if rc.TimeoutMs < 0 {
		return fmt.Errorf("timeout_ms must be >= 0, got %d", rc.TimeoutMs)
	}
	if rc.TimeoutMs > maxTimeoutMs {
		return fmt.Errorf("timeout_ms %d exceeds maximum %d", rc.TimeoutMs, maxTimeoutMs)
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

	// Fetch the template flow and validate it exists.
	fl, err := r.engine.flowFetcher.GetFlow(ctx, cfg.FlowID)
	if err != nil {
		return nil, fmt.Errorf("get template flow: %w", err)
	}

	sendMsgs, err := r.engine.flowFetcher.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, fmt.Errorf("template flow %s has no send messages", cfg.FlowID)
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
	job := &flow.FuzzJob{
		ID:        uuid.New().String(),
		FlowID:    cfg.FlowID,
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
	go r.execute(jobCtx, executeParams{
		job:         job,
		ctrl:        ctrl,
		iter:        iter,
		baseData:    baseData,
		cfg:         cfg,
		protocol:    fl.Protocol,
		timeout:     timeout,
		concurrency: concurrency,
		monitor:     monitor,
	})

	return &AsyncResult{
		FuzzID:        job.ID,
		Status:        string(StatusRunning),
		TotalRequests: iter.Total(),
		Tag:           cfg.Tag,
		Message:       "Fuzzing started. Query fuzz_results with fuzz_id to check progress.",
	}, nil
}

// executeParams bundles the parameters for a fuzz job execution.
type executeParams struct {
	job         *flow.FuzzJob
	ctrl        *JobController
	iter        Iterator
	baseData    *RequestData
	cfg         RunConfig
	protocol    string
	timeout     time.Duration
	concurrency int
	monitor     *OverloadMonitor
}

// execute runs the fuzz iterations with the given concurrency, rate limiting,
// and stop conditions. It updates the job status in the DB upon completion.
func (r *Runner) execute(ctx context.Context, p executeParams) {
	defer r.registry.Remove(p.job.ID)

	var completedCount atomic.Int32
	var errorCount atomic.Int32

	// Channel for distributing fuzz cases to workers.
	cases := make(chan FuzzCase, p.concurrency)
	// stopOnce ensures we only stop once.
	var stopOnce sync.Once
	// stopped signals that a stop condition was triggered.
	stopped := make(chan struct{})

	triggerStop := func(reason string) {
		stopOnce.Do(func() {
			p.ctrl.Stop(StatusError, reason)
			close(stopped)
		})
	}

	rateTick, rateTicker := r.setupRateLimiter(p.cfg)
	if rateTicker != nil {
		defer rateTicker.Stop()
	}

	// Create a shared hook state per job (tracks cross-iteration state like "once", "every_n").
	var hookState *HookState
	if p.cfg.Hooks != nil {
		hookState = &HookState{}
	}

	delay := time.Duration(p.cfg.DelayMs) * time.Millisecond

	// Worker pool.
	var wg sync.WaitGroup
	for i := 0; i < p.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.workerLoop(ctx, p, cases, rateTick, delay, hookState, &completedCount, &errorCount, triggerStop)
		}()
	}

	// Producer: feed fuzz cases to the workers.
	r.startProducer(ctx, p.iter, cases, stopped)

	// Wait for all workers to finish.
	wg.Wait()

	r.finalizeJob(p.job, p.ctrl, int(completedCount.Load()), int(errorCount.Load()))
}

// setupRateLimiter creates a rate limiter ticker based on the config.
// Returns a nil channel and nil ticker if no rate limiting is configured.
func (r *Runner) setupRateLimiter(cfg RunConfig) (<-chan time.Time, *time.Ticker) {
	if cfg.RateLimitRPS <= 0 {
		return nil, nil
	}
	interval := time.Duration(float64(time.Second) / cfg.RateLimitRPS)
	if interval <= 0 {
		return nil, nil
	}
	ticker := time.NewTicker(interval)
	return ticker.C, ticker
}

// workerLoop processes fuzz cases from the cases channel, applying rate limiting,
// delays, retries, stop conditions, and overload detection.
func (r *Runner) workerLoop(
	ctx context.Context,
	p executeParams,
	cases <-chan FuzzCase,
	rateTick <-chan time.Time,
	delay time.Duration,
	hookState *HookState,
	completedCount, errorCount *atomic.Int32,
	triggerStop func(string),
) {
	for fc := range cases {
		// Check for pause.
		if err := p.ctrl.WaitIfPaused(ctx); err != nil {
			return
		}

		if !r.waitForRateAndDelay(ctx, rateTick, delay) {
			return
		}

		result := r.executeWithRetries(ctx, p, fc, hookState)

		if !r.saveAndUpdateProgress(ctx, p.job, p.ctrl, result, completedCount, errorCount) {
			continue
		}

		// Update hook state after request completion.
		if p.cfg.Hooks != nil && hookState != nil {
			hookState.Mu.Lock()
			hadError := result.Error != ""
			p.cfg.Hooks.UpdateState(hookState, result.StatusCode, hadError)
			hookState.Mu.Unlock()
		}

		// Update progress in DB.
		r.updateJobProgress(ctx, p.job, p.ctrl, int(completedCount.Load()), int(errorCount.Load()))

		if r.checkStopConditions(result, p.cfg.StopOn, p.monitor, errorCount, triggerStop) {
			return
		}
	}
}

// waitForRateAndDelay waits for the rate limiter and fixed delay.
// Returns false if the context was cancelled.
func (r *Runner) waitForRateAndDelay(ctx context.Context, rateTick <-chan time.Time, delay time.Duration) bool {
	if rateTick != nil {
		select {
		case <-rateTick:
		case <-ctx.Done():
			return false
		}
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return false
		}
	}
	return true
}

// executeWithRetries executes a fuzz case with the configured number of retries.
func (r *Runner) executeWithRetries(ctx context.Context, p executeParams, fc FuzzCase, hookState *HookState) *flow.FuzzResult {
	var result *flow.FuzzResult
	attempts := 1 + p.cfg.MaxRetries
	for attempt := 0; attempt < attempts; attempt++ {
		result = r.engine.executeFuzzCaseWithHooks(ctx, p.baseData, p.cfg.Positions, fc, p.protocol, p.timeout, p.job.ID, p.cfg.Hooks, hookState, p.cfg.HTTPDoer, p.cfg.TargetScopeChecker, p.cfg.SafetyInputChecker)
		if result.Error == "" {
			break
		}
		// Don't retry if context is cancelled.
		if ctx.Err() != nil {
			break
		}
	}
	return result
}

// saveAndUpdateProgress saves the fuzz result and updates counters.
// Returns false if saving failed (caller should continue to next case).
func (r *Runner) saveAndUpdateProgress(ctx context.Context, job *flow.FuzzJob, ctrl *JobController, result *flow.FuzzResult, completedCount, errorCount *atomic.Int32) bool {
	if err := r.engine.fuzzStore.SaveFuzzResult(ctx, result); err != nil {
		errorCount.Add(1)
		r.updateJobProgress(ctx, job, ctrl, int(completedCount.Load()), int(errorCount.Load()))
		return false
	}
	if result.Error != "" {
		errorCount.Add(1)
	} else {
		completedCount.Add(1)
	}
	return true
}

// checkStopConditions evaluates stop conditions and overload detection.
// Returns true if the worker should stop.
func (r *Runner) checkStopConditions(result *flow.FuzzResult, stopOn *StopCondition, monitor *OverloadMonitor, errorCount *atomic.Int32, triggerStop func(string)) bool {
	if stopOn != nil {
		if result.StatusCode != 0 && checkStatusCode(result.StatusCode, stopOn.StatusCodes) {
			triggerStop(fmt.Sprintf("stop condition: received status code %d", result.StatusCode))
			return true
		}
		if stopOn.ErrorCount > 0 && int(errorCount.Load()) >= stopOn.ErrorCount {
			triggerStop(fmt.Sprintf("stop condition: error count reached %d", stopOn.ErrorCount))
			return true
		}
	}
	if monitor != nil && result.DurationMs > 0 {
		if monitor.Record(result.DurationMs) {
			triggerStop("stop condition: overload detected (latency threshold exceeded)")
			return true
		}
	}
	return false
}

// startProducer feeds fuzz cases from the iterator to the workers channel.
func (r *Runner) startProducer(ctx context.Context, iter Iterator, cases chan<- FuzzCase, stopped <-chan struct{}) {
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
}

// finalizeJob determines the final job status and persists it to the DB.
func (r *Runner) finalizeJob(job *flow.FuzzJob, ctrl *JobController, completed, errors int) {
	finalStatus := ctrl.Status()

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
	finalJob := &flow.FuzzJob{
		ID:             job.ID,
		FlowID:         job.FlowID,
		Config:         job.Config,
		Status:         string(finalStatus),
		Tag:            job.Tag,
		CreatedAt:      job.CreatedAt,
		CompletedAt:    &completedAt,
		Total:          job.Total,
		CompletedCount: completed,
		ErrorCount:     errors,
	}

	// Use a background context since the job context may be cancelled.
	if err := r.engine.fuzzStore.UpdateFuzzJob(context.Background(), finalJob); err != nil {
		slog.Warn("failed to finalize fuzz job in DB", "job_id", job.ID, "error", err)
	}
}

// updateJobProgress updates the job's completed and error counts in the DB.
// It reads the current status from the JobController so that pause/resume
// transitions are correctly reflected in the database.
func (r *Runner) updateJobProgress(ctx context.Context, job *flow.FuzzJob, ctrl *JobController, completed, errors int) {
	// Create a shallow copy to avoid data races.
	update := &flow.FuzzJob{
		ID:             job.ID,
		FlowID:         job.FlowID,
		Config:         job.Config,
		Status:         string(ctrl.Status()),
		Tag:            job.Tag,
		CreatedAt:      job.CreatedAt,
		Total:          job.Total,
		CompletedCount: completed,
		ErrorCount:     errors,
	}
	// Best-effort update; don't fail the job if DB write fails here.
	if err := r.engine.fuzzStore.UpdateFuzzJob(ctx, update); err != nil {
		slog.Debug("failed to update fuzz job progress", "job_id", job.ID, "error", err)
	}
}

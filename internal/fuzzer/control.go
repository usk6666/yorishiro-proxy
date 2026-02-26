package fuzzer

import (
	"context"
	"fmt"
	"sync"
)

// JobStatus represents the lifecycle state of a fuzz job.
type JobStatus string

const (
	// StatusRunning indicates the job is actively executing.
	StatusRunning JobStatus = "running"
	// StatusPaused indicates the job is temporarily suspended.
	StatusPaused JobStatus = "paused"
	// StatusCompleted indicates the job finished all iterations.
	StatusCompleted JobStatus = "completed"
	// StatusCancelled indicates the job was cancelled by the user.
	StatusCancelled JobStatus = "cancelled"
	// StatusError indicates the job was stopped due to an error or stop condition.
	StatusError JobStatus = "error"
)

// JobController manages the lifecycle of a single fuzz job, providing
// pause, resume, and cancel operations. It uses a channel-based approach
// for pause/resume to avoid busy-waiting.
type JobController struct {
	mu     sync.Mutex
	status JobStatus

	// cancel cancels the job's context, stopping all work.
	cancel context.CancelFunc

	// pauseCh is closed when the job is paused. Workers select on this
	// channel and block when it's not closed. When resumed, a new channel
	// is created.
	pauseCh chan struct{}

	// stopReason is the reason the job was stopped (for error/stop condition cases).
	stopReason string
}

// NewJobController creates a controller for a running job.
// The cancel func should cancel the context passed to the runner goroutine.
func NewJobController(cancel context.CancelFunc) *JobController {
	return &JobController{
		status:  StatusRunning,
		cancel:  cancel,
		pauseCh: make(chan struct{}),
	}
}

// Status returns the current job status.
func (jc *JobController) Status() JobStatus {
	jc.mu.Lock()
	defer jc.mu.Unlock()
	return jc.status
}

// StopReason returns the reason the job was stopped, if any.
func (jc *JobController) StopReason() string {
	jc.mu.Lock()
	defer jc.mu.Unlock()
	return jc.stopReason
}

// Pause transitions the job from running to paused state.
// Returns an error if the job is not in the running state.
func (jc *JobController) Pause() error {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	if jc.status != StatusRunning {
		return fmt.Errorf("cannot pause job in %q state", jc.status)
	}

	jc.status = StatusPaused
	// pauseCh stays open; WaitIfPaused will check status
	return nil
}

// Resume transitions the job from paused to running state.
// Returns an error if the job is not in the paused state.
func (jc *JobController) Resume() error {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	if jc.status != StatusPaused {
		return fmt.Errorf("cannot resume job in %q state", jc.status)
	}

	jc.status = StatusRunning
	// Close the old pauseCh so any blocked workers wake up.
	close(jc.pauseCh)
	// Create a new channel for future pauses.
	jc.pauseCh = make(chan struct{})
	return nil
}

// Cancel transitions the job to the cancelled state and cancels its context.
// Can be called from any active state (running or paused).
func (jc *JobController) Cancel() error {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	if jc.status != StatusRunning && jc.status != StatusPaused {
		return fmt.Errorf("cannot cancel job in %q state", jc.status)
	}

	wasPaused := jc.status == StatusPaused
	jc.status = StatusCancelled
	jc.cancel()

	// If paused, wake up any blocked workers so they can observe the cancellation.
	if wasPaused {
		close(jc.pauseCh)
		jc.pauseCh = make(chan struct{})
	}

	return nil
}

// Stop transitions the job to the given terminal state with a reason.
// Used internally by the runner when a stop condition is triggered.
func (jc *JobController) Stop(status JobStatus, reason string) {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	if jc.status != StatusRunning && jc.status != StatusPaused {
		return // already terminal
	}

	jc.status = status
	jc.stopReason = reason
	jc.cancel()
}

// Complete marks the job as completed.
// Used internally by the runner when all iterations finish successfully.
func (jc *JobController) Complete() {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	if jc.status != StatusRunning {
		return
	}
	jc.status = StatusCompleted
}

// WaitIfPaused blocks until the job is no longer paused.
// Returns the job's context error if the context is cancelled while paused.
// Returns nil if the job is resumed or was not paused.
func (jc *JobController) WaitIfPaused(ctx context.Context) error {
	for {
		jc.mu.Lock()
		status := jc.status
		ch := jc.pauseCh
		jc.mu.Unlock()

		if status != StatusPaused {
			return nil
		}

		// Wait until either resumed (ch closed) or context cancelled.
		select {
		case <-ch:
			// Channel closed — either resumed or cancelled. Loop to recheck status.
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// JobRegistry manages active fuzz job controllers, keyed by fuzz ID.
type JobRegistry struct {
	mu   sync.RWMutex
	jobs map[string]*JobController
}

// NewJobRegistry creates a new empty job registry.
func NewJobRegistry() *JobRegistry {
	return &JobRegistry{
		jobs: make(map[string]*JobController),
	}
}

// Register adds a job controller to the registry.
func (r *JobRegistry) Register(fuzzID string, ctrl *JobController) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jobs[fuzzID] = ctrl
}

// Get retrieves a job controller by fuzz ID. Returns nil if not found.
func (r *JobRegistry) Get(fuzzID string) *JobController {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.jobs[fuzzID]
}

// Remove removes a job controller from the registry.
func (r *JobRegistry) Remove(fuzzID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.jobs, fuzzID)
}

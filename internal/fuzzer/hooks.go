package fuzzer

import (
	"context"
	"sync"
)

// HookCallbacks provides hook execution points for fuzz iterations.
// The MCP layer implements this interface to integrate macro hooks with fuzzing.
// Each callback receives a fresh context for the iteration.
// Implementations must be safe for concurrent use when Concurrency > 1.
type HookCallbacks interface {
	// PreSend is called before each fuzz iteration sends its request.
	// It returns a KV Store map for template expansion on override parameters.
	// The iterationIndex is the 0-based index of the current iteration.
	// The state tracks execution state across iterations (e.g., for "once", "every_n").
	// Returns nil map if no hook is configured or the hook's run_interval skips this iteration.
	// Callers must hold state.Mu for the full read-execute-writeback cycle.
	PreSend(ctx context.Context, state *HookState) (kvStore map[string]string, err error)

	// PostSend is called after each fuzz iteration receives its response.
	// It passes the response status code and body to the post_receive hook.
	// The state tracks execution state across iterations.
	// Callers must hold state.Mu for the full read-execute-writeback cycle.
	PostSend(ctx context.Context, state *HookState, statusCode int, responseBody []byte) error

	// UpdateState updates the hook state after a request completes.
	// This is called after each iteration to track status codes, errors, etc.
	// Callers must hold state.Mu before calling this method.
	UpdateState(state *HookState, statusCode int, hadError bool)
}

// HookState tracks the execution state of hooks across fuzz iterations.
// A new HookState is created for each fuzz job to ensure iteration independence
// while allowing run_interval tracking (e.g., "once", "every_n").
// All fields must be accessed while holding Mu when shared across goroutines.
type HookState struct {
	// Mu protects all fields below from concurrent access by worker goroutines.
	Mu sync.Mutex
	// PreSendExecuted tracks whether the pre_send hook has been executed (for "once").
	PreSendExecuted bool
	// RequestCount tracks the total number of main requests sent (for "every_n").
	RequestCount int
	// LastStatusCode is the status code from the previous main request (for "on_error").
	LastStatusCode int
	// LastError indicates whether the previous main request had an error (for "on_error").
	LastError bool
}

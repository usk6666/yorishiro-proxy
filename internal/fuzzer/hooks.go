package fuzzer

import "context"

// HookCallbacks provides hook execution points for fuzz iterations.
// The MCP layer implements this interface to integrate macro hooks with fuzzing.
// Each callback receives a fresh context for the iteration.
type HookCallbacks interface {
	// PreSend is called before each fuzz iteration sends its request.
	// It returns a KV Store map for template expansion on override parameters.
	// The iterationIndex is the 0-based index of the current iteration.
	// The state tracks execution state across iterations (e.g., for "once", "every_n").
	// Returns nil map if no hook is configured or the hook's run_interval skips this iteration.
	PreSend(ctx context.Context, state *HookState) (kvStore map[string]string, err error)

	// PostSend is called after each fuzz iteration receives its response.
	// It passes the response status code and body to the post_receive hook.
	// The state tracks execution state across iterations.
	PostSend(ctx context.Context, state *HookState, statusCode int, responseBody []byte) error

	// UpdateState updates the hook state after a request completes.
	// This is called after each iteration to track status codes, errors, etc.
	UpdateState(state *HookState, statusCode int, hadError bool)
}

// HookState tracks the execution state of hooks across fuzz iterations.
// A new HookState is created for each fuzz job to ensure iteration independence
// while allowing run_interval tracking (e.g., "once", "every_n").
type HookState struct {
	// PreSendExecuted tracks whether the pre_send hook has been executed (for "once").
	PreSendExecuted bool
	// RequestCount tracks the total number of main requests sent (for "every_n").
	RequestCount int
	// LastStatusCode is the status code from the previous main request (for "on_error").
	LastStatusCode int
	// LastError indicates whether the previous main request had an error (for "on_error").
	LastError bool
}

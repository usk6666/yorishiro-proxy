package mcp

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
)

// fuzzHookCallbacks implements fuzzer.HookCallbacks by delegating to the
// MCP layer's hookExecutor. It bridges the fuzzer package's hook interface
// with the macro execution infrastructure.
type fuzzHookCallbacks struct {
	d     *deps
	hooks *hooksInput
}

// newFuzzHookCallbacks creates a new fuzzHookCallbacks instance.
func newFuzzHookCallbacks(d *deps, hooks *hooksInput) *fuzzHookCallbacks {
	return &fuzzHookCallbacks{
		d:     d,
		hooks: hooks,
	}
}

// PreSend implements fuzzer.HookCallbacks.
// It creates a hookExecutor with the fuzzer's hook state and executes the pre_send hook.
func (f *fuzzHookCallbacks) PreSend(ctx context.Context, state *fuzzer.HookState) (map[string]string, error) {
	if f.hooks == nil || f.hooks.PreSend == nil {
		return nil, nil
	}

	// Convert fuzzer.HookState to internal hookState.
	hs := fuzzStateToHookState(state)
	executor := newHookExecutor(f.d, f.hooks, hs)

	kvStore, err := executor.executePreSend(ctx)
	if err != nil {
		return nil, err
	}

	// Copy back state changes (e.g., preSendExecuted for "once").
	hookStateToFuzzState(hs, state)

	return kvStore, nil
}

// PostSend implements fuzzer.HookCallbacks.
// It creates a hookExecutor and executes the post_receive hook.
// The kvStore parameter carries KV Store values from the preceding PreSend call,
// enabling post_receive hooks to access values produced by pre_send.
func (f *fuzzHookCallbacks) PostSend(ctx context.Context, state *fuzzer.HookState, statusCode int, responseBody []byte, kvStore map[string]string) error {
	if f.hooks == nil || f.hooks.PostReceive == nil {
		return nil
	}

	hs := fuzzStateToHookState(state)
	executor := newHookExecutor(f.d, f.hooks, hs)

	return executor.executePostReceive(ctx, statusCode, responseBody, kvStore)
}

// UpdateState implements fuzzer.HookCallbacks.
// It updates the fuzzer's hook state after a request completes.
func (f *fuzzHookCallbacks) UpdateState(state *fuzzer.HookState, statusCode int, hadError bool) {
	state.RequestCount++
	state.LastStatusCode = statusCode
	state.LastError = hadError
}

// fuzzStateToHookState converts a fuzzer.HookState to the internal hookState.
func fuzzStateToHookState(fs *fuzzer.HookState) *hookState {
	return &hookState{
		preSendExecuted: fs.PreSendExecuted,
		requestCount:    fs.RequestCount,
		lastStatusCode:  fs.LastStatusCode,
		lastError:       fs.LastError,
	}
}

// hookStateToFuzzState copies hook state changes back to the fuzzer's HookState.
func hookStateToFuzzState(hs *hookState, fs *fuzzer.HookState) {
	fs.PreSendExecuted = hs.preSendExecuted
	// requestCount, lastStatusCode, lastError are updated by UpdateState.
}

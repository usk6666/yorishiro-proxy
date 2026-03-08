package plugin

// txCtxKey is the data map key for the transaction context dict.
const txCtxKey = "ctx"

// NewTxCtx creates a new empty transaction context dict.
// The returned map is shared across all hook invocations within a single
// transaction (e.g., one HTTP request-response pair). Plugins can read and
// write arbitrary key-value pairs to pass data between hooks.
func NewTxCtx() map[string]any {
	return make(map[string]any)
}

// InjectTxCtx sets the transaction context into the hook data map.
// Call this before each Dispatch to ensure the ctx is available to plugins.
func InjectTxCtx(data map[string]any, txCtx map[string]any) {
	data[txCtxKey] = txCtx
}

// ExtractTxCtx reads the transaction context from a hook result's data map
// and merges any changes back into the provided txCtx. This must be called
// after Dispatch to capture modifications made by plugins.
//
// If the result or its Data is nil, txCtx is returned unchanged.
func ExtractTxCtx(result *HookResult, txCtx map[string]any) map[string]any {
	if result == nil || result.Data == nil {
		return txCtx
	}
	raw, ok := result.Data[txCtxKey]
	if !ok {
		return txCtx
	}
	updated, ok := raw.(map[string]any)
	if !ok {
		return txCtx
	}
	// Merge updated values into txCtx so the same map reference is reused.
	for k, v := range updated {
		txCtx[k] = v
	}
	return txCtx
}

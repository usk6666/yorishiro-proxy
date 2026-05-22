package macro

import "strings"

// ReservedKeyPrefix is the prefix marking yorishiro-reserved KV Store
// variables. Reserved keys are populated by the runtime (per-iteration
// nonce, iteration counter, ...) and MUST NOT be overwritten by
// user-supplied macros, hook results, or input vars.
//
// Callers that merge user-controlled maps into a shared KVStore (the Job
// runner's mergeKVStore, MCP per-iteration injection sites) filter such
// writes via IsReservedKey so a malicious or careless macro cannot
// shadow runtime state like §__nonce§ that downstream template
// expansion relies on.
const ReservedKeyPrefix = "__"

// IsReservedKey reports whether key is a yorishiro-reserved KV Store
// variable (prefix "__"). Callers performing KV Store merges with
// user-controlled inputs MUST skip keys for which this returns true.
func IsReservedKey(key string) bool {
	return strings.HasPrefix(key, ReservedKeyPrefix)
}

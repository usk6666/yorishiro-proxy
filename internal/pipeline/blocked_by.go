package pipeline

// BlockedBy values populated by Pipeline Steps when emitting a Drop Action.
// These constants mirror the strings accepted by the MCP query tool's
// `blocked_by` filter (see internal/mcp/query_tool.go validFilterBlockedBy)
// so audit Streams written from session-side recording line up with what
// the operator can filter on.
//
// "rate_limit" is not emitted by any Pipeline Step today: the
// connection-level gates' refusal recorder writes it (like "capacity"). The
// session-side recorder also accepts it, so a future RateLimitStep that
// emits `Result{Action: Drop, BlockedBy: BlockedByRateLimit}` participates
// in the audit pipeline without further wiring.
const (
	// BlockedByTargetScope attributes a Drop to a TargetScope deny rule.
	// Emitted by HostScopeStep (connection-level host check) and
	// HTTPScopeStep (request-level scheme/authority/path check).
	BlockedByTargetScope = "target_scope"

	// BlockedBySafetyFilter attributes a Drop to a Safety rule violation.
	// Emitted by SafetyStep on Send-direction envelopes that match an
	// input safety rule, and forwarded by InterceptStep when the
	// modify_and_forward defense-in-depth re-check fires.
	BlockedBySafetyFilter = "safety_filter"

	// BlockedByInterceptDrop attributes a Drop to an explicit user
	// `drop` action against a held envelope, including a hold timeout
	// under auto_drop. A plugin action.DROP is BlockedByPlugin and the
	// context-cancelled hold path is BlockedByInterceptCancelled.
	BlockedByInterceptDrop = "intercept_drop"

	// BlockedByInterceptCancelled attributes a Drop to an intercept hold
	// whose ctx ended before any action resolved it — proxy_stop, session
	// teardown, or a failure in the peer direction (USK-1193). Emitted by
	// InterceptStep so the held envelope is recorded as an audit Stream
	// instead of vanishing from both the queue and the flow store.
	BlockedByInterceptCancelled = "intercept_cancelled"

	// BlockedByRateLimit attributes an audit Stream to a connection a
	// connection-level gate refused because a Policy / Agent rate limit
	// was exceeded: the transparent listener (USK-1374), tcp_forwards and
	// the CONNECT / plain-HTTP forward / SOCKS5 gates (USK-1381). No
	// Pipeline Step emits it: the connection is refused at admission,
	// before any Layer or Pipeline exists, and proxybuild's
	// blockedConnRecorder writes it directly
	// (connector.TransparentBlockedByRateLimit and
	// connector.GateRefusalBlockedByRateLimit mirror this value). The
	// session-side recorder also accepts it for a future RateLimitStep.
	BlockedByRateLimit = "rate_limit"

	// BlockedByBudget attributes a Drop to a BudgetManager exhaustion
	// (MaxTotalRequests or MaxDuration). Emitted by BudgetStep on
	// Send-direction envelopes when the underlying
	// connector.BudgetManager.RecordRequest reports the request as
	// over-budget. The audit Stream lets operators see exactly which
	// request tripped the limit (USK-818).
	BlockedByBudget = "budget"

	// BlockedByCapacity attributes an audit Stream to a connection the
	// listener refused because max_connections was saturated (USK-1142).
	// No Pipeline Step emits it: the connection is refused before any
	// Layer or Pipeline exists. The proxybuild connection-rejection
	// recorder writes it directly.
	BlockedByCapacity = "capacity"

	// BlockedByPlugin attributes a Drop to a plugin hook returning
	// action.DROP, in either direction and phase (USK-1393). Emitted by
	// PluginStepPre / PluginStepPost together with Result.Record, so the
	// dropped envelope is recorded as a Flow row before the session's
	// OnPipelineDrop recorder marks the Stream state="error". Which plugin
	// and hook dropped it is carried on the Stream's tags (plugin,
	// plugin_hook, plugin_phase), not in this label. A plugin RESPOND is
	// an answer, not a block, and carries no BlockedBy.
	BlockedByPlugin = "plugin"
)

package pipeline

// BlockedBy values populated by Pipeline Steps when emitting a Drop Action.
// These constants mirror the strings accepted by the MCP query tool's
// `blocked_by` filter (see internal/mcp/query_tool.go validFilterBlockedBy)
// so audit Streams written from session-side recording line up with what
// the operator can filter on.
//
// "enabled_protocols" is intentionally not exported here — it is owned by
// the connector peek-time rejection path (proxybuild.buildProtocolRejectedRecorder)
// and is never the result of a Pipeline Step.
//
// "rate_limit" is reserved for a future RateLimitStep. The session-side
// recorder already accepts it; adding a Step that emits
// `Result{Action: Drop, BlockedBy: BlockedByRateLimit}` is sufficient to
// participate in the audit pipeline.
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
	// `drop` action against a held envelope. Plugin ActionDrop and the
	// context-cancelled hold path are intentionally NOT attributed to
	// this label (USK-782 design scope guards).
	BlockedByInterceptDrop = "intercept_drop"

	// BlockedByRateLimit is reserved for a future RateLimitStep; no
	// Pipeline Step emits it today. The session-side recorder accepts
	// the label so future Issues only need to add the Step.
	BlockedByRateLimit = "rate_limit"

	// BlockedByBudget attributes a Drop to a BudgetManager exhaustion
	// (MaxTotalRequests or MaxDuration). Emitted by BudgetStep on
	// Send-direction envelopes when the underlying
	// connector.BudgetManager.RecordRequest reports the request as
	// over-budget. The audit Stream lets operators see exactly which
	// request tripped the limit (USK-818).
	BlockedByBudget = "budget"
)

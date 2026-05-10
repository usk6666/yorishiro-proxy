package pipeline

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// BudgetStep is an Envelope-only Pipeline Step that consults the
// process-singleton connector.BudgetManager on every Send envelope and
// drops the envelope when the configured budget (MaxTotalRequests) is
// exhausted. MaxDuration enforcement is handled asynchronously by
// BudgetManager.Start (it triggers a shutdown callback when the timer
// fires); this Step only handles the per-request counter axis.
//
// Pipeline placement is position #3 — AFTER HostScopeStep / HTTPScopeStep
// (scope rejections are operator-policy and not chargeable to the
// budget), BEFORE SafetyStep / Intercept / Transform / PluginPost /
// Record. Counting at this point matches the user-visible "request"
// granularity (one Send envelope = one request) and short-circuits the
// expensive downstream Steps when over-budget.
//
// Send-only direction filter — Receive envelopes are pass-through. For
// streaming protocols this means the initial Send (HTTP request,
// WebSocket Upgrade, gRPC start frame) counts; subsequent message
// frames or response envelopes do not. This mirrors the "max_total_requests"
// user-facing semantic.
type BudgetStep struct {
	manager *connector.BudgetManager
}

// NewBudgetStep creates a BudgetStep bound to the given BudgetManager.
// A nil manager makes Process a no-op (every envelope continues
// unchanged); the live data path provides a non-nil manager via
// proxybuild.Deps.BudgetManager and the resend/fuzz dispatch helpers
// pass s.misc.budgetManager directly.
func NewBudgetStep(manager *connector.BudgetManager) *BudgetStep {
	return &BudgetStep{manager: manager}
}

// Process consults BudgetManager.RecordRequest on Send envelopes that
// represent a request boundary and returns Drop with BlockedByBudget
// when the call reports the request as over-budget. Receive envelopes
// and non-boundary Send envelopes (gRPC mid-stream Data/End frames,
// WebSocket data frames after the Upgrade) are always Continue.
//
// "Request boundary" is per-protocol:
//
//   - HTTP / HTTP/2 / SOCKS5+HTTP → every HTTPMessage Send is a request
//     (each Send envelope on the live path is one request-response
//     exchange; HTTP/2 streams are decomposed into one Send per stream).
//   - gRPC → only GRPCStartMessage Send counts. GRPCDataMessage and
//     GRPCEndMessage are mid-stream and do NOT increment the counter.
//   - WebSocket → only the upstream Upgrade (an HTTPMessage Send,
//     handled above) counts. WSMessage frames after the Upgrade are
//     mid-stream and do NOT increment.
//   - SSE → only the upstream HTTPMessage Send counts. SSEMessage
//     envelopes are Receive-direction so they are filtered already.
//   - Raw TCP → every RawMessage Send increments. The bytechunk Layer
//     emits one or more Send envelopes per logical "request"; this is
//     a known approximation accepted because Raw has no canonical
//     request boundary.
//
// The current connector.BudgetManager.RecordRequest semantics are
// "increment-then-check": the (max+1)th request is counted-and-blocked.
// This Step preserves those semantics (the existing connector test
// TestBudgetManager_MaxTotalRequests_Policy pins the contract) — the
// blocked envelope's audit Stream is recorded by the session
// OnPipelineDrop callback (live path) or by the inline drop-recorder
// in resend/fuzz dispatch helpers.
func (s *BudgetStep) Process(_ context.Context, env *envelope.Envelope) Result {
	if s.manager == nil {
		return Result{}
	}
	if env == nil || env.Direction != envelope.Send {
		return Result{}
	}
	if !isRequestBoundary(env) {
		return Result{}
	}
	if !s.manager.RecordRequest() {
		return Result{Action: Drop, BlockedBy: BlockedByBudget}
	}
	return Result{}
}

// isRequestBoundary reports whether a Send-direction envelope counts as
// one logical "request" for budget purposes. Mid-stream events on
// streaming protocols (gRPC Data/End, WebSocket frames after Upgrade)
// return false. See BudgetStep.Process docs for the per-protocol rule.
func isRequestBoundary(env *envelope.Envelope) bool {
	switch env.Message.(type) {
	case *envelope.GRPCDataMessage, *envelope.GRPCEndMessage:
		// Mid-stream gRPC. The opening GRPCStartMessage already counted.
		return false
	case *envelope.WSMessage:
		// Post-Upgrade WebSocket frame. The HTTP/1.1 Upgrade Send
		// (HTTPMessage) was the request boundary.
		return false
	}
	return true
}

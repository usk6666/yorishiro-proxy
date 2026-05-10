// Package mcp resend_budget_audit.go centralises the "blocked by budget"
// audit-Stream record used by every resend/fuzz dispatch helper. The live
// data path uses the session OnPipelineDrop callback (wired in
// proxybuild.buildSessionOptions) to persist a state="error" Stream when
// a Pipeline Step returns Drop with a BlockedBy attribution. Resend and
// fuzz tools bypass session.RunSession entirely — they call Pipeline.Run
// (now Pipeline.RunWithBlockedBy) directly — so without a parallel
// recorder a budget-blocked dispatch envelope would generate no audit row.
//
// USK-818: this file is the resend/fuzz mirror of
// proxybuild.buildPipelineDropRecorder. Differences:
//
//   - The resend/fuzz helpers always have a pre-allocated env.StreamID
//     (resend tools generate one before calling pipe.Run; fuzz allocates
//     one per variant). buildPipelineDropRecorder generates a fresh UUID
//     when the live path's envelope has none — that branch is unnecessary
//     here.
//
//   - Resend Streams are stamped with flow.OriginResend by RecordStep, but
//     the budget Drop fires BEFORE RecordStep, so the audit Stream
//     written here also stamps Origin so the query tool's resend filter
//     keeps seeing budget-blocked resend audit rows under the resend
//     origin (USK-786 contract).
//
//   - Flow rows are never written. Identical to the live path: blocked
//     envelopes are recorded for audit, not for replay.
package mcp

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// errBudgetExhausted is the sentinel error returned by every resend /
// fuzz dispatch helper when the BudgetStep drops the dispatch envelope
// with BlockedBy="budget". Mirrors the live data path's blocked-by
// semantics — the request never reached the wire and the audit Stream
// has been recorded separately. Callers (the resend / fuzz tool
// handlers) wrap this error with a per-tool prefix; the
// finalizeResendStream call after dispatch sees it as just "any
// non-nil err" and does the normal state="error" UpdateStream — the
// blocked_by attribution survives because UpdateStream only writes
// non-empty fields (USK-818).
var errBudgetExhausted = errors.New("request blocked: budget exhausted")

// budgetCheckResendUpgrade is the WS / SSE / raw equivalent of the
// pipeline-driven BudgetStep check. The resend_ws handler synthesises a
// WSMessage Send envelope which BudgetStep filters out as "post-Upgrade",
// so the pipeline-only path would never count a resend_ws invocation
// toward the budget — yet from the operator's perspective each
// resend_ws call is one request. This helper closes that gap by calling
// BudgetManager.RecordRequest directly before the upstream Upgrade
// runs; on exhaustion it records a state="error" + blocked_by="budget"
// audit Stream and returns errBudgetExhausted.
//
// budgetManager may be nil — Server.finalizeDefaults() always installs
// a default in production, but tests that bypass NewServer (e.g.
// mkServerFromLegacyDeps) may leave it unset. The helper degrades to
// a no-op in that case.
//
// streamID is the per-resend Stream identifier the dispatch will use
// for its (would-be) RecordStep rows; the audit Stream reuses it so
// the operator can correlate the blocked attempt with the user-supplied
// tag and timeout context.
//
// origin is stamped on the audit Stream for the same reason
// recordBudgetBlockedStream stamps it — so the query tool's `origin`
// filter buckets blocked rows alongside their successful siblings.
func (s *Server) budgetCheckResendUpgrade(ctx context.Context, env *envelope.Envelope, streamID string, origin flow.Origin) error {
	bm := s.misc.budgetManager
	if bm == nil {
		return nil
	}
	if bm.RecordRequest() {
		return nil
	}
	recordBudgetBlockedStream(ctx, s.flowStore.store, env, streamID, origin)
	return errBudgetExhausted
}

// recordBudgetBlockedStream persists a state="error", blocked_by="budget"
// Stream for a resend / fuzz envelope dropped by BudgetStep. Safe to call
// with a nil store (no-op) or empty streamID (no-op). Errors are logged
// at slog.Warn — the dispatch path will still surface a budget-exhaustion
// error to the caller; this audit row is best-effort observability.
//
// origin is the flow.Origin tag stamped on the audit Stream. Pass
// flow.OriginResend for resend dispatches and flow.OriginFuzz for fuzz
// dispatches so the query tool's `origin` filter buckets blocked rows
// alongside their successful siblings (USK-786).
func recordBudgetBlockedStream(ctx context.Context, store flow.StreamWriter, env *envelope.Envelope, streamID string, origin flow.Origin) {
	if store == nil || env == nil || streamID == "" {
		return
	}
	st := &flow.Stream{
		ID:        streamID,
		Protocol:  string(env.Protocol),
		State:     "error",
		BlockedBy: "budget",
		Origin:    origin,
		Timestamp: time.Now(),
	}
	// Project HTTP-typed identity fields when available — mirrors
	// proxybuild.buildPipelineDropRecorder's Scheme stamping. Non-HTTP
	// envelopes leave the field empty (the wire-fidelity principle: do
	// not invent values that were not on the wire).
	if msg, ok := env.Message.(*envelope.HTTPMessage); ok && msg != nil {
		if msg.Scheme != "" {
			st.Scheme = msg.Scheme
		}
	}

	// Use a background-derived context with a short timeout so a
	// cancelled handler ctx (e.g. user-supplied timeout_ms expired
	// concurrently) does not abort the audit record. Matches
	// proxybuild.buildPipelineDropRecorder.
	recordCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.SaveStream(recordCtx, st); err == nil {
		return
	}
	// Fallback: update an already-existing Stream row with the audit
	// attribution. Resend/fuzz writes a fresh streamID per dispatch so
	// the SaveStream path is the common case; this branch handles the
	// edge case where a prior Send already created the row before the
	// budget Drop fired (e.g. a future mid-stream BudgetStep variant).
	// Log only when BOTH writes fail — mirrors
	// proxybuild.buildPipelineDropRecorder: a successful UpdateStream
	// fallback is the "audit row recorded via the streaming-Drop path"
	// case and is not log-worthy.
	if uerr := store.UpdateStream(recordCtx, streamID, flow.StreamUpdate{
		State:     "error",
		BlockedBy: "budget",
	}); uerr != nil {
		slog.WarnContext(ctx, "resend: budget-blocked stream save failed",
			"stream_id", streamID,
			"error", uerr,
		)
	}
}

// Package mcp resend_finalize.go closes the Stream-state lifecycle hole
// inherent to the resend code path. The proxy data path drives Stream-state
// finalisation through session.RunSession's OnComplete callback (wired in
// proxybuild.buildSessionOptions): once both client/upstream goroutines
// terminate, OnComplete writes State="complete" (or "error" with a
// classified FailureReason) to the flow store. Resend tools bypass
// RunSession entirely — they call Pipeline.Run directly on synthesised
// envelopes and orchestrate the dial/send/receive themselves — so the
// terminal UpdateStream that proxy-path traffic gets for free never
// fires. The Streams that resend's RecordStep creates would otherwise
// stay pinned at State="active" forever (USK-789).
//
// finalizeResendStream is the per-call hook every resend handler invokes
// after runResend* returns. It mirrors the OnComplete contract used by
// proxybuild.buildSessionOptions:
//
//   - nil err  → State="complete", FailureReason untouched
//   - err != nil → State="error",   FailureReason = session.ClassifyError(err)
//
// session.ClassifyError extracts the *layer.StreamError code when the
// failure carries one (typed RST_STREAM-class errors); other failure
// shapes — dial errors, context cancellations, parse errors — surface as
// FailureReason="" exactly as they do on the proxy path. The empty
// FailureReason is a deliberate "we don't know — see logs" rather than a
// best-effort string we'd have to maintain in two places.
package mcp

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// finalizeResendStream marks the Stream identified by streamID as
// terminal in the flow store. Safe to call with a nil store (no-op),
// empty streamID (no-op), or after the Stream was already finalised by
// a different code path (StreamUpdate is partial-update so non-State
// fields stay intact; State just overwrites).
//
// Callers should invoke this exactly once per runResend* invocation —
// both on the success path and on every error path — so the Stream
// transitions out of State="active" before the MCP handler returns its
// result. The proxy-path equivalent (proxybuild.buildSessionOptions
// OnComplete) is wired into RunSession's deferred g.Wait(); the resend
// path does not run RunSession so the handler is responsible for the
// equivalent terminal write.
//
// Logging: success path is slog.Debug (resend completion is a normal-flow
// detail per CLAUDE.md log-level guidance); store write failures are
// slog.Warn since the data is already on disk via RecordStep — only the
// terminal state attribute is missing — and the proxy can continue.
func finalizeResendStream(ctx context.Context, store flow.StreamWriter, streamID string, runErr error) {
	if store == nil || streamID == "" {
		return
	}
	state := "complete"
	failureReason := ""
	if runErr != nil {
		state = "error"
		failureReason = session.ClassifyError(runErr)
	}
	update := flow.StreamUpdate{
		State:         state,
		FailureReason: failureReason,
	}
	if err := store.UpdateStream(ctx, streamID, update); err != nil {
		slog.WarnContext(ctx, "resend: stream finalize update failed",
			"stream_id", streamID,
			"state", state,
			"error", err,
		)
		return
	}
	slog.DebugContext(ctx, "resend: stream finalized",
		"stream_id", streamID,
		"state", state,
	)
}

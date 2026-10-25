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
//   - nil err  → State="complete", FailureReason untouched, no tags["error"]
//   - err != nil → State="error",   FailureReason = session.ClassifyError(err),
//     tags["error"] = flow.TruncateErrorTag(err.Error()) merged via
//     AppendTags so tags written earlier (RecordStep etc.) survive
//     (USK-1350; same text and 1 KiB cap as the proxy path)
//   - tag != "" → tags["tag"] = tag on both paths, merged via the same
//     AppendTags write (USK-1362), so a failed attempt carries the
//     user's tag next to tags["error"] and earlier tags survive. An
//     empty tag writes no "tag" key.
//
// session.ClassifyError extracts the *layer.StreamError code when the
// failure carries one (typed RST_STREAM-class errors); other failure
// shapes — dial errors, context cancellations, parse errors — surface as
// FailureReason="" exactly as they do on the proxy path. The empty
// FailureReason is a deliberate "we don't know — see logs" rather than a
// best-effort string we'd have to maintain in two places; the full
// message lives in tags["error"].
//
// Deliberate divergences from the proxy-path OnComplete predicate
// (USK-1350):
//
//   - No io.EOF / session.ErrClientGoneAcked → "complete" carve-out.
//     ErrClientGoneAcked is only produced inside session.RunSession, which
//     no resend / fuzz runner calls. An io.EOF after a successful exchange
//     never reaches this function: the raw / gRPC receive loops convert it
//     to nil, and the HTTP / WS runners return on the final response. The
//     only EOF that does arrive is wrapped ("upstream receive: EOF", e.g.
//     resend_ws when the upstream closes before replying; the HTTP/1.x
//     layer reclassifies the same close as an aborted StreamError) and
//     marks a genuine pre-response failure for which the tool returns
//     IsError — copying the live predicate would record it as "complete".
//   - errBudgetExhausted is tagged like any other error. The live path
//     skips OnComplete for budget-blocked Streams; here the blocked audit
//     Stream additionally receives tags["error"] next to its blocked_by.
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
// tag is the user-supplied resend / fuzz `tag` argument, merged into
// Stream.Tags["tag"] (never replacing other keys) on success and error
// alike; pass "" when the caller supplied none.
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
func finalizeResendStream(ctx context.Context, store flow.StreamWriter, streamID, tag string, runErr error) {
	if store == nil || streamID == "" {
		return
	}
	state := "complete"
	failureReason := ""
	if runErr != nil {
		state = "error"
		failureReason = session.ClassifyError(runErr)
	}
	// USK-1347: stamp Duration = time.Since(Stream.Timestamp) like the
	// proxy-path OnComplete does. RecordStep stamps Timestamp when it
	// creates the Stream from the send envelope, so this is the elapsed
	// time from send to completion (or failure). Every caller passes a
	// flow.Store, which embeds StreamReader; a store without it — or a
	// lookup miss — yields 0, the "do not update" sentinel, so the
	// existing Duration is preserved.
	reader, _ := store.(flow.StreamReader)
	update := flow.StreamUpdate{
		State:         state,
		FailureReason: failureReason,
		Duration:      flow.StreamElapsed(ctx, reader, streamID),
	}
	// USK-1350: keep the error text on the Stream like the proxy path's
	// OnComplete does, so `query flows` shows why the resend / fuzz
	// Stream failed. USK-1362: the user's tag rides the same write, on
	// success and failure alike, so failed attempts stay selectable via
	// `query flows filter.tag`. AppendTags merges rather than replaces,
	// preserving tags RecordStep and friends wrote earlier and keeping
	// tags["error"] and tags["tag"] side by side.
	if tag != "" || runErr != nil {
		update.AppendTags = make(map[string]string, 2)
		if tag != "" {
			update.AppendTags["tag"] = tag
		}
		if runErr != nil {
			update.AppendTags["error"] = flow.TruncateErrorTag(runErr.Error())
		}
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

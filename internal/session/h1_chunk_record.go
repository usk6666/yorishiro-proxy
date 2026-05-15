// Package session — HTTP/1.x chunk-boundary envelope recording for the
// SSE-over-h1-chunked streaming detach path (USK-895).
//
// SSE over HTTP/1.1 with Transfer-Encoding: chunked is the common SSE
// wire shape. Pre-USK-895 only the dechunked event bytes reached the
// recorder — the chunk-size line, chunk-extension, and trailing CRLF
// were observable only as part of the parent http1 response envelope's
// RawBody (which is bounded by MaxRawCaptureSize and lost after the
// streaming-body detach). USK-883's hex-prefix bug was diagnosed late
// because of exactly this gap.
//
// This file installs the recovery path: a record-only Pipeline + a
// chunk-record callback wired into http1.Layer.DetachStreamingBody via
// the new WithChunkRecordCallback option.
//
// Design summary (USK-893 design review lock-in):
//
//   - Naming: <protocol>-<unit> flat, value = "h1-chunk" (per-protocol
//     canonical, not "sse-chunk" — the chunk mechanism is HTTP/1.x's).
//   - API: per-Layer ad-hoc Option mirroring USK-889's
//     WithFrameRecordCallback shape. Common WireLevelTap interface
//     deferred to Rule of Three.
//   - Pipeline: record-only via h2FrameRecordPipeline (already wire-
//     level-agnostic — it strips Safety / PluginPre / Intercept /
//     Transform / PluginPost and leaves HostScope / HTTPScope / Budget /
//     Record). Reusing the helper avoids cloning identical
//     p.Without(...) logic.
//   - Cap: RecordStep.WithHTTP1ChunkMaxPerStream (default 10000, USK-802
//     LRU shared). proxybuild.Deps.RecordHTTP1ChunkMaxPerStream wires
//     it through.
//   - Per-chunk wire-bytes cap: MaxRawCaptureSize is enforced inside
//     the parser (Principle #5 / USK-893 fitness check defence against
//     a 4 GiB malicious chunk). Over-cap chunks emit no envelope.

package session

import (
	"context"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// h1ChunkRecordCallback constructs the per-chunk record callback
// installed via http1.Layer.DetachStreamingBody(WithChunkRecordCallback(...)).
//
// The returned function receives the full on-wire chunk bytes
// (chunk-size line + chunk-extension + chunk-data + trailing CRLF; for
// the terminal "0\r\n…\r\n" chunk this includes any trailer section).
// The callback builds an envelope.Envelope carrying:
//
//   - Protocol = envelope.ProtocolHTTP (not a new ProtocolHTTP1Chunk
//     value — the chunk syntax is part of HTTP/1.x by spec).
//   - Message = nil. Chunk envelopes are pure wire-byte records — there
//     is no L7 structured view to derive. RecordStep's envelopeToFlow
//     handles a nil Message by recording the envelope as a Flow with
//     empty Headers/Body/Metadata (the wire bytes land in RawBytes).
//   - Raw = the full chunk wire bytes copied from the parser.
//   - Context.WireLevel = flow.WireLevelHTTP1Chunk (stamped by
//     wireLevelRecordCallback via flowCtx).
//
// The closure delegates to wireLevelRecordCallback (the USK-889 helper
// generalised for USK-895) for identity rewrite + Pipeline dispatch.
// We wrap that delegate with a constructor function that takes the raw
// chunk bytes the parser gives us and builds the envelope, because the
// parser's callback shape is `func([]byte)` rather than
// `func(*envelope.Envelope)`.
//
// firstResp is the wire-observed response envelope captured by
// UpgradeStep when it latched Pending=UpgradeSSE. When non-nil it
// supplies the post-swap session-scope StreamID and Context. When nil
// (test paths that drive runUpgradeSSE without UpgradeStep), the caller
// supplies the fallback StreamID via sessionStreamID.
func h1ChunkRecordCallback(
	ctx context.Context,
	recPipeline *pipeline.Pipeline,
	sessionStreamID string,
	flowCtx envelope.EnvelopeContext,
) func(chunkRaw []byte) {
	if recPipeline == nil {
		return nil
	}

	// SSE is half-duplex (RFC 8895 §6): chunked responses flow
	// upstream→client only. The chunk-record callback fires on the
	// Receive direction by construction.
	envelopeCB := wireLevelRecordCallback(
		ctx,
		recPipeline,
		sessionStreamID,
		envelope.Receive,
		flowCtx,
		flow.WireLevelHTTP1Chunk,
	)
	if envelopeCB == nil {
		return nil
	}

	return func(chunkRaw []byte) {
		if len(chunkRaw) == 0 {
			return
		}
		// Defensive copy not needed here — the parser already produced a
		// fresh slice via dechunkedReader.emitChunkRecord's defensive
		// copy. The slice's lifetime extends past the envelope's
		// Pipeline.Run because the recorder either stashes RawBytes into
		// SQLite synchronously (today) or, in a hypothetical future
		// async path, owns its own copy by the time it returns.
		env := &envelope.Envelope{
			// StreamID / FlowID / Sequence / Direction / Context are
			// rewritten by wireLevelRecordCallback below; we leave them
			// at the zero value so any leakage of pre-rewrite state is
			// visible in a stack trace.
			FlowID:   uuid.NewString(),
			Protocol: envelope.ProtocolHTTP,
			Raw:      chunkRaw,
			// Message intentionally nil — see godoc.
		}
		envelopeCB(env)
	}
}

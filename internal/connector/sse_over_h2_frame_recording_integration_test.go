//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestFullListener_CONNECT_SSE_OverH2_FrameRecording exercises USK-889:
// after the sse-over-h2 swap, every H2 DATA frame on the detached
// upstream-side stream surfaces as its own flow row with
// wire_level="h2-frame" + direction="receive". The client-side detach
// is for the writer only (RFC 8895 §6 half-duplex); no client-side
// frame rows are expected.
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: 3 SSE events flow end-to-end (reuses the
//     harness used by TestFullListener_CONNECT_SSE_OverH2_HappyPath).
//   - Flow recording: in addition to the semantic SSEMessage envelopes
//     (wire_level="semantic", recorded by sse.Layer), the per-stream
//     sub-stack overlay produces h2-frame rows on the upstream side
//     only. Both groups share the same StreamID.
//   - Half-duplex: there must be NO send-direction h2-frame rows. The
//     proxy never observes client→server DATA frames after the SSE
//     swap (the client-side detach is for the writer only).
//   - Raw bytes recording: h2-frame rows carry non-empty RawBytes.
func TestFullListener_CONNECT_SSE_OverH2_FrameRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamShutdown := startSSEOverH2Upstream(t)
	defer upstreamShutdown()

	proxyAddr, store, wg := startFullListenerProxyWithH2(t, ctx)
	wg.Add(1)

	if err := driveSSEOverH2ThroughProxy(proxyAddr, upstreamAddr, 3); err != nil {
		t.Fatalf("sse-over-h2 through FullListener: %v", err)
	}
	waitSessionDone(t, wg)

	// --- Receive side: h2-frame rows MUST exist. ---
	frameRecv := flowsByWireLevel(store.allFlows(), flow.WireLevelH2Frame, "receive")
	if len(frameRecv) == 0 {
		t.Fatalf("no wire_level=h2-frame receive flow recorded; SSE-over-h2 upstream-only frame recording must produce at least one h2-frame row per DATA frame")
	}

	// --- Send side: NO h2-frame rows (half-duplex). ---
	frameSend := flowsByWireLevel(store.allFlows(), flow.WireLevelH2Frame, "send")
	if len(frameSend) != 0 {
		t.Errorf("unexpected send-direction h2-frame rows: %d. SSE is half-duplex (RFC 8895 §6); the client side carries no DATA frames after the swap.", len(frameSend))
	}

	// --- L4-capable: at least one h2-frame row carries non-empty Raw
	// bytes. Empty payloads are legitimate END_STREAM-only DATA frames.
	if !anyNonEmptyRaw(frameRecv) {
		t.Errorf("no wire_level=h2-frame receive flow with non-empty RawBytes (L4-capable principle violated); flows=%d", len(frameRecv))
	}

	// --- Same StreamID linkage: frame and semantic Receive rows share
	// the post-swap session-scope StreamID.
	semanticRecv := flowsByWireLevel(store.allFlows(), flow.WireLevelSemantic, "receive")
	if len(semanticRecv) == 0 {
		t.Fatalf("no semantic Receive rows recorded; SSE events should produce per-event SSEMessage envelopes")
	}
	if !sharesStreamID(semanticRecv, frameRecv) {
		t.Errorf("semantic SSE and h2-frame Receive rows do not share a StreamID\n  semantic IDs=%v\n  frame IDs=%v",
			streamIDs(semanticRecv), streamIDs(frameRecv))
	}
}

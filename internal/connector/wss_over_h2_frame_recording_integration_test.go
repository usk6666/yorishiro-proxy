//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestFullListener_CONNECT_WSS_OverH2_FrameRecording exercises USK-889:
// after the wss-over-h2 swap, every H2 DATA frame on the detached
// stream surfaces as its own flow row with wire_level="h2-frame", on
// BOTH sides (symmetric per RFC 8441 §5 full-duplex).
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: hi-ws echo round-trip succeeds (reuses
//     the harness used by TestFullListener_CONNECT_WSS_OverH2_MITM).
//   - Flow recording: in addition to the semantic WS frame envelopes
//     (wire_level="semantic", recorded by ws.Layer), the per-stream
//     sub-stack overlay produces h2-frame rows. Both groups share the
//     same StreamID (AC literal "同一 StreamID で紐付き").
//   - Raw bytes recording: h2-frame rows MUST carry non-empty
//     RawBytes (the L4-capable principle is the entire reason USK-889
//     exists).
func TestFullListener_CONNECT_WSS_OverH2_FrameRecording(t *testing.T) {
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		t.Skip("requires GODEBUG=http2xconnect=1 (Makefile test-e2e sets it; run via `make test-e2e` or export the env var)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamShutdown := startWSSOverH2Upstream(t)
	defer upstreamShutdown()

	proxyAddr, store, wg := startFullListenerProxyWithH2(t, ctx)
	wg.Add(1)

	if err := driveWSSOverH2EchoThroughProxy(proxyAddr, upstreamAddr, "hi-ws"); err != nil {
		t.Fatalf("wss-over-h2 echo through FullListener: %v", err)
	}
	waitSessionDone(t, wg)

	// --- Frame recording: per-side h2-frame envelopes must exist. ---
	frameSend := flowsByWireLevel(store.allFlows(), flow.WireLevelH2Frame, "send")
	frameRecv := flowsByWireLevel(store.allFlows(), flow.WireLevelH2Frame, "receive")
	if len(frameSend) == 0 {
		t.Errorf("no wire_level=h2-frame send flow recorded; WS-over-h2 is symmetric and the proxy MUST record client-side DATA frames")
	}
	if len(frameRecv) == 0 {
		t.Errorf("no wire_level=h2-frame receive flow recorded; WS-over-h2 is symmetric and the proxy MUST record upstream-side DATA frames")
	}

	// --- L4-capable: at least one h2-frame row per direction MUST carry
	// non-empty Raw payload bytes. Empty payloads are legitimate —
	// END_STREAM-only DATA frames carry zero payload by spec; those
	// rows also record (they preserve the END_STREAM signal on the
	// typed *H2DataEvent.EndStream field) but they cannot satisfy the
	// "non-empty RawBytes" check.
	if !anyNonEmptyRaw(frameSend) {
		t.Errorf("no wire_level=h2-frame send flow with non-empty RawBytes (L4-capable principle violated); flows=%d", len(frameSend))
	}
	if !anyNonEmptyRaw(frameRecv) {
		t.Errorf("no wire_level=h2-frame receive flow with non-empty RawBytes (L4-capable principle violated); flows=%d", len(frameRecv))
	}

	// --- Same StreamID linkage: frame envelopes and semantic envelopes
	// share the post-swap session-scope StreamID.
	semanticRecv := flowsByWireLevel(store.allFlows(), flow.WireLevelSemantic, "receive")
	if len(semanticRecv) == 0 || len(frameRecv) == 0 {
		t.Fatalf("missing recv side rows: semantic=%d frame=%d", len(semanticRecv), len(frameRecv))
	}
	if !sharesStreamID(semanticRecv, frameRecv) {
		t.Errorf("semantic and h2-frame Receive rows do not share a StreamID; AC literal '同一 StreamID で紐付き' violated\n  semantic IDs=%v\n  frame IDs=%v",
			streamIDs(semanticRecv), streamIDs(frameRecv))
	}
}

// Wire-level helpers (anyNonEmptyRaw / flowsByWireLevel / sharesStreamID /
// streamIDs) moved to wire_level_test_helpers_test.go under plain
// `//go:build e2e` so the USK-895 smoke-tier test (h1-chunk) can share
// them without forcing the exhaustive-tier h2-frame tests into smoke.

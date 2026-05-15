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

// anyNonEmptyRaw reports whether any flow in flows carries non-empty
// RawBytes.
func anyNonEmptyRaw(flows []*flow.Flow) bool {
	for _, f := range flows {
		if f == nil {
			continue
		}
		if len(f.RawBytes) > 0 {
			return true
		}
	}
	return false
}

// flowsByWireLevel filters flows by wire_level + direction.
func flowsByWireLevel(flows []*flow.Flow, wireLevel, direction string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range flows {
		if f == nil {
			continue
		}
		// Empty WireLevel reads as the semantic default for backward
		// compatibility with pre-schemaV14 stores.
		fl := f.WireLevel
		if fl == "" {
			fl = flow.WireLevelSemantic
		}
		if fl != wireLevel {
			continue
		}
		if direction != "" && f.Direction != direction {
			continue
		}
		out = append(out, f)
	}
	return out
}

// sharesStreamID reports whether at least one row from a and one row
// from b share the same StreamID.
func sharesStreamID(a, b []*flow.Flow) bool {
	seen := make(map[string]struct{}, len(a))
	for _, f := range a {
		if f == nil {
			continue
		}
		seen[f.StreamID] = struct{}{}
	}
	for _, f := range b {
		if f == nil {
			continue
		}
		if _, ok := seen[f.StreamID]; ok {
			return true
		}
	}
	return false
}

// streamIDs collects the StreamID values from flows for diagnostic logs.
func streamIDs(flows []*flow.Flow) []string {
	out := make([]string, 0, len(flows))
	for _, f := range flows {
		if f == nil {
			continue
		}
		out = append(out, f.StreamID)
	}
	return out
}

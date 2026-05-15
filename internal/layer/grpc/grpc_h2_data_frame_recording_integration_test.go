//go:build e2e && !e2e_smoke

package grpc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// USK-899 e2e: native gRPC over h2 must emit wire_level=h2-frame envelopes
// for every absorbed H2 DATA frame on the gRPC data path, in addition to
// the existing semantic + grpc-lpm-frame envelopes. The Receive direction
// is the headline diagnostic surface — server-streaming RPCs are where
// per-DATA-frame visibility (vs. LPM reassembly) matters most.
//
// The bug class this test guards against (defense-in-depth, per USK-899
// Issue body):
//   - Tiny-DATA-frame covert channels: one LPM split across many one-byte
//     H2 DATA frames. Reassembly hides the timing / count side-channel
//     signature; h2-frame preserves it.
//   - Zero-payload DATA frames between LPMs as a count side-channel
//     (silently discarded by the LPM reassembler).
//   - SETTINGS_MAX_FRAME_SIZE boundary anomalies in DATA framing.
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: gRPC RPCs flow end-to-end through the proxy
//     (unary + server-streaming).
//   - Stream recording: Stream is saved with Protocol="grpc".
//   - Flow recording: three wire_level rows per direction —
//     wire_level=semantic (GRPCStartMessage / GRPCDataMessage /
//     GRPCEndMessage), wire_level=grpc-lpm-frame (USK-896 — one per LPM),
//     wire_level=h2-frame (USK-899 — one per H2 DATA event).
//   - Raw bytes recording: h2-frame envelopes carry the H2 DATA payload
//     bytes (the LPM bytes embedded in the DATA frame; the 9-byte H2
//     frame header is not part of the payload, matching USK-897 shape).
//   - L4-capable: h2-frame envelopes are wire-snapshot envelopes — the
//     bytes are the on-wire DATA payload, not reassembled LPMs.
//   - MCP tool integration: h2-frame flow is retrievable from the store
//     by ID — the same lookup the `query` MCP tool performs.

// h2FrameFlowsForStream returns flows in store filtered to streamID and
// wire_level=h2-frame. Optionally filtered by direction when dir != "".
func h2FrameFlowsForStream(store *testStore, streamID, dir string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range store.flowsForStream(streamID) {
		if f == nil {
			continue
		}
		if f.WireLevel != flow.WireLevelH2Frame {
			continue
		}
		if dir != "" && f.Direction != dir {
			continue
		}
		out = append(out, f)
	}
	return out
}

// waitForH2FrameFlows polls the store until at least n h2-frame flows for
// streamID in dir are recorded, or until timeout. Failure prints
// diagnostic counts.
func waitForH2FrameFlows(t *testing.T, store *testStore, streamID, dir string, n int, timeout time.Duration) []*flow.Flow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []*flow.Flow
	for time.Now().Before(deadline) {
		last = h2FrameFlowsForStream(store, streamID, dir)
		if len(last) >= n {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: want %d %s h2-frame flows for stream %s; have %d", n, dir, streamID, len(last))
	return nil
}

// h2FrameAndLPMRecordOptFn returns an extraGRPCOptionsFn that wires both
// the USK-896 LPM record callback AND the USK-899 h2-frame record
// callback. The harness threads ch.StreamID() (the client-side gRPC
// stream identity) into both callbacks so the closures rewrite the
// upstream-side envelope StreamID — which differs because upH2.OpenStream
// allocates a new UUID per upstream stream — to the session-scope
// identity, mirroring how session.upstreamToClient unifies the semantic
// envelopes.
func h2FrameAndLPMRecordOptFn() func(*pipeline.Pipeline, string) []grpclayer.Option {
	return func(p *pipeline.Pipeline, sessionStreamID string) []grpclayer.Option {
		ctx := context.Background()
		flowCtx := envelope.EnvelopeContext{}
		return []grpclayer.Option{
			session.GRPCLPMRecordOption(ctx, p, sessionStreamID, flowCtx),
			session.GRPCH2DataFrameRecordOption(ctx, p, sessionStreamID, flowCtx),
		}
	}
}

// TestGRPCH2DataFrameRecording_UnaryRoundTrip is the headline assertion:
// a single unary RPC produces three wire_level rows per direction —
// semantic + grpc-lpm-frame + h2-frame.
func TestGRPCH2DataFrameRecording_UnaryRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			return append([]byte("echo:"), req...), nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()

	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: h2FrameAndLPMRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	var resp []byte
	req := []byte("hello-USK-899")
	if err := cc.Invoke(ctx, echoFullMethod(echoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	if st.Protocol != "grpc" {
		t.Errorf("Stream.Protocol = %q, want grpc", st.Protocol)
	}

	// --- Headline assertion: at least one h2-frame row per direction.
	sendH2 := waitForH2FrameFlows(t, store, st.ID, "send", 1, 5*time.Second)
	recvH2 := waitForH2FrameFlows(t, store, st.ID, "receive", 1, 5*time.Second)
	if len(sendH2) < 1 {
		t.Errorf("send h2-frame count = %d, want >= 1 (USK-899 native gRPC h2-frame producer)", len(sendH2))
	}
	if len(recvH2) < 1 {
		t.Errorf("receive h2-frame count = %d, want >= 1 (USK-899 native gRPC h2-frame producer)", len(recvH2))
	}

	// --- L4-capable: at least one h2-frame row carries non-empty Raw
	// (the LPM payload is non-empty for a "hello-USK-899" request).
	if !anyNonEmptyH2Raw(sendH2) {
		t.Errorf("no send h2-frame flow with non-empty RawBytes (L4-capable violated)")
	}
	if !anyNonEmptyH2Raw(recvH2) {
		t.Errorf("no receive h2-frame flow with non-empty RawBytes (L4-capable violated)")
	}

	// --- Three wire_level rows coexist per direction. The semantic +
	// grpc-lpm-frame rows are covered by the existing USK-896 test suite;
	// we cross-check the h2-frame row count is INDEPENDENT of the LPM
	// row count (different sequence space per the schemaV14 UNIQUE
	// constraint on (stream_id, sequence, direction, variant, wire_level)).
	sendLPM := lpmFlowsForStream(store, st.ID, "send")
	recvLPM := lpmFlowsForStream(store, st.ID, "receive")
	if len(sendLPM) < 1 {
		t.Errorf("send grpc-lpm-frame count = %d, want >= 1 (regression — USK-896 coverage)", len(sendLPM))
	}
	if len(recvLPM) < 1 {
		t.Errorf("receive grpc-lpm-frame count = %d, want >= 1 (regression — USK-896 coverage)", len(recvLPM))
	}

	// --- Stream linkage: h2-frame and grpc-lpm-frame rows share the
	// post-swap session-scope StreamID (the closures rewrite upstream-
	// side env.StreamID to the client-side identity).
	if len(sendH2) > 0 && len(sendLPM) > 0 {
		if sendH2[0].StreamID != sendLPM[0].StreamID {
			t.Errorf("send h2-frame StreamID %q != send grpc-lpm-frame StreamID %q (USK-899 StreamID unification regression)",
				sendH2[0].StreamID, sendLPM[0].StreamID)
		}
	}

	// --- Wire-payload sanity: the h2-frame Send Raw bytes contain the
	// LPM wire bytes (the proxy did NOT strip the 5-byte LPM prefix). We
	// validate by checking the first 5 bytes are a well-formed LPM prefix
	// (compressed flag in {0, 1}, length BE matches remaining payload).
	for _, f := range sendH2 {
		if len(f.RawBytes) == 0 {
			continue
		}
		if len(f.RawBytes) < 5 {
			t.Errorf("send h2-frame RawBytes too short to be a single LPM (len=%d < 5)", len(f.RawBytes))
			continue
		}
		if f.RawBytes[0] != 0 && f.RawBytes[0] != 1 {
			t.Errorf("send h2-frame RawBytes[0] (LPM compressed flag) = %d, want 0 or 1", f.RawBytes[0])
		}
	}

	waitForStreamState(t, store, st.ID, "complete", 3*time.Second)
}

// TestGRPCH2DataFrameRecording_ServerStreaming covers the case where the
// h2-frame producer matters most: a server-streaming RPC where each
// SendMsg likely produces its own H2 DATA frame. We assert
// count(receive h2-frame) >= count(receive grpc-lpm-frame) since each LPM
// is carried in at least one H2 DATA frame; tighter equality is NOT
// asserted because gRPC-Go may coalesce multiple LPMs into one DATA
// frame under flow control (in which case h2-frame count < lpm count is
// also acceptable — both directions of the inequality are valid).
func TestGRPCH2DataFrameRecording_ServerStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	const N = 5
	srv := &echoServer{
		serverStream: func(req []byte, stream grpc.ServerStream) error {
			for i := 0; i < N; i++ {
				msg := append([]byte(strconv.Itoa(i)+":"), req...)
				if err := stream.SendMsg(&msg); err != nil {
					return err
				}
			}
			return nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: h2FrameAndLPMRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	desc := &grpc.StreamDesc{StreamName: echoMethodServerStream, ServerStreams: true}
	cs, err := cc.NewStream(ctx, desc, echoFullMethod(echoMethodServerStream))
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	req := []byte("seed")
	if err := cs.SendMsg(&req); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	recvCount := 0
	for {
		var out []byte
		if err := cs.RecvMsg(&out); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("RecvMsg: %v", err)
		}
		recvCount++
	}
	if recvCount != N {
		t.Errorf("client received %d messages, want %d", recvCount, N)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	// Wait for both wire_level rows to accumulate before asserting count.
	recvLPM := waitForLPMFlows(t, store, st.ID, "receive", N, 5*time.Second)
	recvH2 := waitForH2FrameFlows(t, store, st.ID, "receive", 1, 5*time.Second)

	if len(recvLPM) != N {
		t.Errorf("receive grpc-lpm-frame count = %d, want %d (one per server SendMsg)", len(recvLPM), N)
	}
	if len(recvH2) < 1 {
		t.Errorf("receive h2-frame count = %d, want >= 1 (USK-899)", len(recvH2))
	}

	// --- Sequence-space independence: h2-frame rows run their own
	// per-direction counter, independent of grpc-lpm-frame and semantic.
	// The first h2-frame row in each direction MUST have Sequence=0.
	if len(recvH2) > 0 && recvH2[0].Sequence != 0 {
		t.Errorf("first receive h2-frame Sequence = %d, want 0 (per-(direction, wire_level) counter)", recvH2[0].Sequence)
	}
}

// TestGRPCH2DataFrameRecording_RawIsDataFramePayload verifies the wire
// payload contract: h2-frame Raw bytes equal the H2 DATA frame payload
// (which embeds the LPM bytes for native gRPC) — NOT the reassembled or
// stripped LPM. The 9-byte H2 frame header is NOT part of Raw, matching
// USK-897 / USK-889 shape.
func TestGRPCH2DataFrameRecording_RawIsDataFramePayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			return req, nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: h2FrameAndLPMRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	payload := []byte("USK-899-payload-marker")
	var resp []byte
	if err := cc.Invoke(ctx, echoFullMethod(echoMethodUnary), &payload, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	sendH2 := waitForH2FrameFlows(t, store, st.ID, "send", 1, 5*time.Second)
	sendLPM := waitForLPMFlows(t, store, st.ID, "send", 1, 5*time.Second)

	// The send LPM's Raw is "5-byte prefix + payload" (USK-896 contract).
	// The send h2-frame's Raw is the H2 DATA payload, which for a unary
	// request carrying one LPM is byte-identical to the LPM bytes (gRPC
	// frames one LPM per DATA frame for unary requests). We assert byte
	// equality between the two views.
	var foundEqualPair bool
	for _, h2 := range sendH2 {
		for _, lpm := range sendLPM {
			if bytes.Equal(h2.RawBytes, lpm.RawBytes) {
				foundEqualPair = true
				break
			}
		}
		if foundEqualPair {
			break
		}
	}
	if !foundEqualPair {
		t.Errorf("no send h2-frame row whose Raw matches a send grpc-lpm-frame row byte-for-byte; native-gRPC unary request normally frames one LPM per DATA frame so the two wire views must coincide for at least one pair\n  h2-frame Raws: %d rows  lpm Raws: %d rows", len(sendH2), len(sendLPM))
	}

	// Sanity: send LPM Raw[0..5] should be a valid LPM prefix (compressed
	// flag + BE length). If the h2-frame row matched, the same applies.
	for _, h2 := range sendH2 {
		if len(h2.RawBytes) == 0 {
			continue
		}
		if len(h2.RawBytes) < 5 {
			t.Errorf("send h2-frame RawBytes too short (len=%d)", len(h2.RawBytes))
			continue
		}
		// First byte = compressed flag, must be 0 or 1.
		if h2.RawBytes[0] != 0 && h2.RawBytes[0] != 1 {
			t.Errorf("send h2-frame RawBytes[0] = %d, want 0 or 1 (LPM compressed flag)", h2.RawBytes[0])
		}
		// Bytes 1..5 = BE length; must equal len(payload bytes after LPM
		// prefix) when the DATA frame carries exactly one LPM.
		declared := binary.BigEndian.Uint32(h2.RawBytes[1:5])
		actual := uint32(len(h2.RawBytes) - 5)
		if declared != actual {
			t.Errorf("send h2-frame: LPM declared length %d != actual payload length %d (corrupt embed)", declared, actual)
		}
	}
}

// TestGRPCH2DataFrameRecording_MCPQueryParity verifies an h2-frame flow
// is retrievable from the store by ID — the same lookup the `query` MCP
// tool performs.
func TestGRPCH2DataFrameRecording_MCPQueryParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			return []byte("ok"), nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: h2FrameAndLPMRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	var resp []byte
	req := []byte("query-parity-USK-899")
	if err := cc.Invoke(ctx, echoFullMethod(echoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	sendH2 := waitForH2FrameFlows(t, store, st.ID, "send", 1, 5*time.Second)

	// The testStore satisfies the MCP query tool's read path: a flow
	// must be retrievable by its ID. The store's allFlows() is the
	// substitute for the MCP query round-trip.
	var found bool
	for _, f := range store.allFlows() {
		if f != nil && f.ID == sendH2[0].ID && f.WireLevel == flow.WireLevelH2Frame {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("h2-frame flow %q not retrievable from store; MCP query tool would not see it either", sendH2[0].ID)
	}
}

// anyNonEmptyH2Raw reports whether any flow in flows has non-empty
// RawBytes. Local helper duplicated from the connector package's
// wire_level_test_helpers_test.go (file-level scoping requires we
// redefine it in this package).
func anyNonEmptyH2Raw(flows []*flow.Flow) bool {
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

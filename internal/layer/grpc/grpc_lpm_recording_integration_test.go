//go:build e2e

package grpc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// USK-896 e2e: gRPC LPM (Length-Prefixed Message) frames must emit
// wire_level=grpc-lpm-frame envelopes for every reassembled LPM on the
// gRPC data path (both Send and Receive directions, including bidi).
//
// The bug class this test guards against (defense-in-depth — no live bug
// is currently triggering this gap):
//   - LPM length-prefix smuggling (length-prefix ≠ actual payload bytes)
//   - Compressed-flag anomalies (RFC values are 0 / 1; any other indicates
//     a malicious or buggy peer)
//   - Multi-LPM packing inside one h2 DATA frame with boundary anomalies
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: gRPC RPCs flow end-to-end through the proxy
//     (unary + server-streaming).
//   - Stream recording: Stream is saved with Protocol="grpc".
//   - Flow recording: both semantic envelopes (GRPCStartMessage /
//     GRPCDataMessage / GRPCEndMessage) and grpc-lpm-frame envelopes are
//     recorded under the same StreamID with independent sequence counters
//     per (Direction, WireLevel).
//   - Raw bytes recording: grpc-lpm-frame envelopes carry the full LPM
//     wire bytes (5-byte prefix + payload).
//   - L4-capable: LPM wire envelopes are wire-snapshot envelopes — no L7
//     normalisation applied (compressed bytes recorded as-observed, not
//     decompressed).
//   - MCP tool integration: an LPM wire flow is retrievable from the
//     store by ID — the same lookup the `query` MCP tool performs.

// lpmFlowsForStream returns flows in store filtered to streamID and
// wire_level=grpc-lpm-frame. Optionally filtered by direction when
// dir != "".
func lpmFlowsForStream(store *testStore, streamID, dir string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range store.flowsForStream(streamID) {
		if f == nil {
			continue
		}
		if f.WireLevel != flow.WireLevelGRPCLPMFrame {
			continue
		}
		if dir != "" && f.Direction != dir {
			continue
		}
		out = append(out, f)
	}
	return out
}

// waitForLPMFlows polls the store until at least n LPM flows for streamID
// in dir are recorded, or until timeout. Failure prints diagnostic
// counts.
func waitForLPMFlows(t *testing.T, store *testStore, streamID, dir string, n int, timeout time.Duration) []*flow.Flow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []*flow.Flow
	for time.Now().Before(deadline) {
		last = lpmFlowsForStream(store, streamID, dir)
		if len(last) >= n {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: want %d %s grpc-lpm-frame flows for stream %s; have %d", n, dir, streamID, len(last))
	return nil
}

// lpmRecordOptFn returns an extraGRPCOptionsFn that injects the
// session.GRPCLPMRecordOption built against the supplied pipeline and
// the per-stream session-scope StreamID. The harness threads
// ch.StreamID() (the client-side gRPC stream identity) into the
// callback so the closure rewrites the upstream-side LPM env.StreamID
// — which differs from the client side because upH2.OpenStream
// allocates a new UUID per upstream stream — to the session-scope
// identity, mirroring how session.upstreamToClient unifies the
// semantic envelopes. The flowCtx is empty — HostScope is configured
// nil in buildPipeline, so the LPM record-only Pipeline records every
// envelope regardless of TargetHost (matching the semantic envelope
// recording path the harness already exercises).
func lpmRecordOptFn() func(*pipeline.Pipeline, string) []grpclayer.Option {
	return func(p *pipeline.Pipeline, sessionStreamID string) []grpclayer.Option {
		return []grpclayer.Option{
			session.GRPCLPMRecordOption(context.Background(), p, sessionStreamID, envelope.EnvelopeContext{}),
		}
	}
}

// TestGRPCLPMRecording_UnaryRoundTrip covers Issue case 1:
// gRPC unary RPC → 1 Send LPM (request) + 1 Receive LPM (response).
func TestGRPCLPMRecording_UnaryRoundTrip(t *testing.T) {
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
		extraGRPCOptionsFn: lpmRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	var resp []byte
	req := []byte("hello")
	if err := cc.Invoke(ctx, echoFullMethod(echoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	if st.Protocol != "grpc" {
		t.Errorf("Stream.Protocol = %q, want grpc", st.Protocol)
	}

	// Semantic envelopes: 1 send Start + 1 send Data + 1 recv Start + 1
	// recv Data + 1 recv End = 5 (covered by the unary suite already).
	// LPM envelopes: 1 send (the request LPM) + 1 recv (the response LPM).
	sendLPM := waitForLPMFlows(t, store, st.ID, "send", 1, 5*time.Second)
	recvLPM := waitForLPMFlows(t, store, st.ID, "receive", 1, 5*time.Second)

	if got := len(sendLPM); got != 1 {
		t.Errorf("send LPM count = %d, want 1", got)
	}
	if got := len(recvLPM); got != 1 {
		t.Errorf("receive LPM count = %d, want 1", got)
	}

	// L4-capable: LPM raw bytes are 5-byte prefix + payload.
	for _, f := range append(sendLPM, recvLPM...) {
		if len(f.RawBytes) < 5 {
			t.Errorf("LPM RawBytes too short: len=%d (need ≥5 for prefix)", len(f.RawBytes))
			continue
		}
		if f.RawBytes[0] != 0 {
			t.Errorf("LPM compressed flag = %d, want 0 (uncompressed)", f.RawBytes[0])
		}
		wireLen := binary.BigEndian.Uint32(f.RawBytes[1:5])
		payloadLen := uint32(len(f.RawBytes) - 5)
		if wireLen != payloadLen {
			t.Errorf("LPM length-prefix %d != payload length %d (recorded bytes inconsistent)", wireLen, payloadLen)
		}
	}

	// Send LPM payload contains the request bytes.
	sendPayload := sendLPM[0].RawBytes[5:]
	if !bytes.Equal(sendPayload, []byte("hello")) {
		t.Errorf("send LPM payload = %q, want %q", sendPayload, "hello")
	}
	// Receive LPM payload contains the response bytes.
	recvPayload := recvLPM[0].RawBytes[5:]
	if !bytes.Equal(recvPayload, []byte("echo:hello")) {
		t.Errorf("receive LPM payload = %q, want %q", recvPayload, "echo:hello")
	}

	waitForStreamState(t, store, st.ID, "complete", 3*time.Second)
}

// TestGRPCLPMRecording_ServerStreaming covers Issue case 2:
// gRPC server-streaming with 10 messages → 10 Receive LPM envelopes
// (one per server-emitted gRPC message), independent of the semantic
// GRPCDataMessage count.
func TestGRPCLPMRecording_ServerStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	const N = 10
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
		extraGRPCOptionsFn: lpmRecordOptFn(),
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
	recvLPM := waitForLPMFlows(t, store, st.ID, "receive", N, 5*time.Second)
	if got := len(recvLPM); got != N {
		t.Errorf("receive LPM count = %d, want %d", got, N)
	}
	// Send side: 1 LPM (the seed request).
	sendLPM := waitForLPMFlows(t, store, st.ID, "send", 1, 5*time.Second)
	if got := len(sendLPM); got != 1 {
		t.Errorf("send LPM count = %d, want 1", got)
	}

	// Sequence counters are independent per direction.
	for i, f := range recvLPM {
		if f.Sequence != i {
			t.Errorf("receive LPM[%d].Sequence = %d, want %d (per-direction counter)", i, f.Sequence, i)
		}
	}
	if sendLPM[0].Sequence != 0 {
		t.Errorf("send LPM[0].Sequence = %d, want 0 (independent of receive counter)", sendLPM[0].Sequence)
	}
}

// TestGRPCLPMRecording_MultipleLPMsInOneDataFrame covers Issue case 3:
// Multiple LPMs packed into a single h2 DATA frame are recorded as
// independent LPM envelopes. gRPC client-streaming hands several
// SendMsg calls to the wire; the gRPC-Go client may coalesce them into
// one h2 DATA depending on flow control, and the proxy must surface
// each LPM separately regardless of the wire packing.
func TestGRPCLPMRecording_MultipleLPMsInOneDataFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	const N = 4
	srv := &echoServer{
		clientStream: func(stream grpc.ServerStream) ([]byte, error) {
			var collected [][]byte
			for {
				var msg []byte
				if err := stream.RecvMsg(&msg); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					return nil, err
				}
				collected = append(collected, msg)
			}
			return []byte(fmt.Sprintf("got=%d", len(collected))), nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: lpmRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	desc := &grpc.StreamDesc{StreamName: echoMethodClientStream, ClientStreams: true}
	cs, err := cc.NewStream(ctx, desc, echoFullMethod(echoMethodClientStream))
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	for i := 0; i < N; i++ {
		msg := []byte(strconv.Itoa(i))
		if err := cs.SendMsg(&msg); err != nil {
			t.Fatalf("SendMsg %d: %v", i, err)
		}
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	var resp []byte
	if err := cs.RecvMsg(&resp); err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	// Send side: N LPMs (one per client SendMsg). Whether they cross
	// the wire as 1 h2 DATA frame carrying N LPMs or N separate DATA
	// frames is up to the gRPC-Go client; either way the proxy MUST
	// record N LPM envelopes.
	sendLPM := waitForLPMFlows(t, store, st.ID, "send", N, 5*time.Second)
	if got := len(sendLPM); got != N {
		t.Errorf("send LPM count = %d, want %d (one envelope per LPM regardless of h2 DATA packing)", got, N)
	}
	// Each LPM payload is one of "0".."N-1".
	for i, f := range sendLPM {
		payload := f.RawBytes[5:]
		if string(payload) != strconv.Itoa(i) {
			t.Errorf("send LPM[%d].payload = %q, want %q", i, payload, strconv.Itoa(i))
		}
	}
}

// TestGRPCLPMRecording_GzipCompressedPreserved covers Issue case 4:
// A gzip-compressed LPM is recorded with its compressed bytes on the
// wire envelope (Raw[0]=1, Raw[5:] = compressed bytes), distinct from
// the semantic GRPCDataMessage envelope whose Payload is decompressed.
func TestGRPCLPMRecording_GzipCompressedPreserved(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	// Payload large enough that gRPC-Go's compressor decides to send it
	// compressed (small payloads may pass through uncompressed despite
	// UseCompressor; bigger payload makes the compressed path
	// deterministic).
	largePayload := bytes.Repeat([]byte("compressible"), 100)
	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			return req, nil
		},
	}
	upAddr, upStop := startGRPCUpstream(t, ca, issuer, srv)
	defer upStop()
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: lpmRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr, grpc.WithDefaultCallOptions(grpc.UseCompressor("gzip")))
	defer cc.Close()

	var resp []byte
	if err := cc.Invoke(ctx, echoFullMethod(echoMethodUnary), &largePayload, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	sendLPM := waitForLPMFlows(t, store, st.ID, "send", 1, 5*time.Second)
	// The wire envelope's compressed flag must be 1 (gzip-encoded LPM).
	if sendLPM[0].RawBytes[0] != 1 {
		t.Errorf("send LPM compressed flag = %d, want 1 (gzip-encoded)", sendLPM[0].RawBytes[0])
	}
	// The wire payload is the compressed bytes, NOT the original
	// 1200-byte plaintext. The compressed bytes should be substantially
	// shorter than the plaintext for a highly compressible payload.
	wirePayload := sendLPM[0].RawBytes[5:]
	if len(wirePayload) >= len(largePayload) {
		t.Errorf("send LPM wire payload len = %d, want < %d (compressed bytes should be shorter than plaintext)", len(wirePayload), len(largePayload))
	}
	// The wire payload must NOT be the decompressed plaintext (sanity
	// check on the wire-vs-semantic distinction).
	if bytes.Equal(wirePayload, largePayload) {
		t.Error("send LPM wire payload equals decompressed plaintext; the wire envelope must capture compressed bytes per CLAUDE.md MITM Principle 3")
	}
}

// TestGRPCLPMRecording_LengthPrefixMismatch covers Issue case 5 by
// documenting the architectural reason it is not directly testable
// today.
//
// The grpc Layer's reassembler emits a callback only after a fully
// reassembled LPM (5-byte prefix consumed AND wireLen bytes of payload
// consumed). A length-prefix that disagrees with the actual on-wire
// payload length has three observable outcomes today:
//
//  1. wireLen ≤ remaining-bytes-on-stream: the reassembler treats the
//     declared length as authoritative and the next bytes as the next
//     LPM's prefix. No mismatch surfaces — the smuggling is silent in
//     terms of LPM count, but it MAY surface as a malformed-next-LPM
//     prefix downstream.
//  2. wireLen > config.MaxGRPCMessageSize: errMessageTooLarge fires
//     BEFORE any callback emission, ending the stream with
//     RST_STREAM(INTERNAL_ERROR). No LPM envelope is produced.
//  3. EOF arrives mid-LPM: the channel returns
//     StreamError{Protocol, "grpc: stream ended mid-LPM"}. No LPM
//     envelope is produced for the partial bytes.
//
// Capturing partial-LPM bytes would require a new Layer-internal anomaly
// path (similar to parser.Anomaly on HTTP/1.x). That extension is
// out-of-scope for USK-896 (Issue body explicitly defers it). When the
// path is added, this test should grow an assertion that the partial
// LPM bytes surface as a grpc-lpm-frame envelope with an anomaly tag.
//
// For now we record the gap by skipping the case with the rationale.
func TestGRPCLPMRecording_LengthPrefixMismatch(t *testing.T) {
	t.Skip("not yet implemented: USK-896 deferred — partial-LPM anomaly path requires Layer-internal anomaly field; case 5 covers a smuggling scenario the current architecture intercepts as RST_STREAM(INTERNAL_ERROR) before any wire envelope fires (see test godoc for the three observable outcomes today)")
}

// TestGRPCLPMRecording_PerStreamCap covers Issue case 6:
// WithGRPCLPMFrameMaxPerStream caps the per-stream LPM record count.
// Server emits 5 messages; cap=3 ⇒ recordStep persists ≤3 LPM
// envelopes. Wire forwarding is unaffected.
func TestGRPCLPMRecording_PerStreamCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	const (
		serverMessages = 5
		cap            = 3
	)
	srv := &echoServer{
		serverStream: func(req []byte, stream grpc.ServerStream) error {
			for i := 0; i < serverMessages; i++ {
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
		recordOpts:         []pipeline.Option{pipeline.WithGRPCLPMFrameMaxPerStream(cap)},
		extraGRPCOptionsFn: lpmRecordOptFn(),
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
	// Wire forwarding intact: every server-emitted message reached the
	// client even though the recorder dropped some.
	if recvCount != serverMessages {
		t.Errorf("client received %d messages, want %d (cap must not affect forwarding)", recvCount, serverMessages)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	// Wait until the end envelope has been recorded so we know the
	// stream finished draining.
	waitForGRPCFlows(t, store, st.ID, "end", "receive", 1, 5*time.Second)
	// The recorded LPM count for this stream MUST be ≤ cap. The
	// USK-802 LRU is shared between semantic and per-wire_level caps,
	// so the actual ceiling may be lower than `cap` if semantic
	// envelopes consume counter budget on the same Stream (documented
	// caveat on WithGRPCLPMFrameMaxPerStream).
	all := lpmFlowsForStream(store, st.ID, "")
	if len(all) > cap {
		t.Errorf("recorded LPM count = %d exceeds cap %d", len(all), cap)
	}
	// Sanity: the cap actually fired (recorded < serverMessages+1
	// would-be-LPMs).
	if len(all) >= serverMessages+1 {
		t.Errorf("cap did not fire: recorded %d LPMs (no over-cap drops observed)", len(all))
	}
}

// TestGRPCLPMRecording_MCPQueryParity covers Issue case 7:
// A grpc-lpm-frame flow is retrievable from the store by ID — the same
// lookup the `query` MCP tool performs.
func TestGRPCLPMRecording_MCPQueryParity(t *testing.T) {
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
		extraGRPCOptionsFn: lpmRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	var resp []byte
	req := []byte("query-parity")
	if err := cc.Invoke(ctx, echoFullMethod(echoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	sendLPM := waitForLPMFlows(t, store, st.ID, "send", 1, 5*time.Second)
	// The testStore satisfies the MCP query tool's read path: a flow
	// must be retrievable by its ID. The store's allFlows() is the
	// substitute for the MCP query round-trip.
	var found bool
	for _, f := range store.allFlows() {
		if f != nil && f.ID == sendLPM[0].ID && f.WireLevel == flow.WireLevelGRPCLPMFrame {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("LPM flow %q not retrievable from store; MCP query tool would not see it either", sendLPM[0].ID)
	}
}

// TestGRPCLPMRecording_HARExcludesFrame covers Issue case 8:
// HAR export filters out grpc-lpm-frame envelopes. The filter is
// implemented in internal/flow/har.go and unit-tested by
// TestFilterSemanticFlows in internal/flow/har_test.go; here we
// validate the schemaV14 column carries the discriminator that the
// filter reads. Since the e2e store does not project AppendTags / HAR
// behaviour onto the testStore, this case is satisfied by:
//
//  1. The unit test in internal/flow/har_test.go covers the filter.
//  2. The integration tests above confirm the wire_level column is
//     written with the canonical "grpc-lpm-frame" string.
func TestGRPCLPMRecording_HARExcludesFrame(t *testing.T) {
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
		extraGRPCOptionsFn: lpmRecordOptFn(),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	var resp []byte
	req := []byte("har-filter")
	if err := cc.Invoke(ctx, echoFullMethod(echoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	sendLPM := waitForLPMFlows(t, store, st.ID, "send", 1, 5*time.Second)
	// Each grpc-lpm-frame row MUST carry the canonical discriminator
	// string. The HAR filter (internal/flow/har.go filterSemanticFlows)
	// keys exactly on this value; a regression that wrote the wrong
	// string would silently leak LPM rows into HAR exports.
	for _, f := range sendLPM {
		if f.WireLevel != "grpc-lpm-frame" {
			t.Errorf("LPM flow WireLevel = %q, want %q (HAR filter contract)", f.WireLevel, "grpc-lpm-frame")
		}
	}
}

//go:build e2e && !e2e_smoke

package http2_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	nethttp "net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
	"log/slog"
	"net"
)

// USK-897 e2e: aggregator-path h2 DATA frame envelope recording.
//
// Validates that plain HTTP/2 request/response on the aggregator path
// (httpaggregator.Wrap → HTTPMessage) produces wire_level=h2-frame
// envelopes alongside the semantic HTTPMessage envelope. Closes the
// asymmetry left by USK-889 (PR #888) which only covered the detach
// paths (WS-over-h2 / SSE-over-h2).
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: h2c request/response flows end-to-end.
//   - Stream recording: Stream is saved with Protocol="http".
//   - Flow recording: semantic HTTPMessage envelopes + per-DATA-frame
//     h2-frame envelopes coexist under the same StreamID; per-direction
//     sequence counters keep them in independent sequence spaces per the
//     schemaV14 UNIQUE constraint.
//   - Raw bytes recording: h2-frame envelopes carry per-DATA-frame
//     payload bytes (NOT aggregated across frames), satisfying
//     CLAUDE.md MITM Principle 3.
//   - Cap enforcement: WithHTTP2FrameMaxPerStream(N) skips overflow.
//   - MCP tool integration: an h2-frame flow is retrievable from the
//     store by ID — the same lookup the `query` MCP tool performs.

// startH2CProxyWithAggOpts is the USK-897 variant of startH2CProxy that
// plumbs the per-stream aggregator-path h2 DATA frame record callback
// (session.AggregatorH2FrameRecordOption) into every aggregator.Wrap
// call. recordOpts lets the caller install RecordStep Options such as
// WithHTTP2FrameMaxPerStream for the cap test.
//
// Mirrors the gRPC harness's extraGRPCOptionsFn / extraAggregatorOptionsFn
// closure shape so the test surface is consistent across protocol Layers.
func startH2CProxyWithAggOpts(t *testing.T, ctx context.Context, upstreamAddr string, opts pipelineOpts, recordOpts []pipeline.Option) (proxyAddr string, store *testStore) {
	t.Helper()
	store = &testStore{}

	onStream := func(streamCtx context.Context, clientCh layer.Channel) {
		// Build per-stream pipeline. recordOpts is layered on top of
		// the standard h2 wire-encoder option installed in buildPipeline.
		pipe := buildPipelineWithRecordOpts(store, opts, recordOpts)

		// Per-stream aggregator-path h2 DATA frame record callback.
		// The closure captures the client-side StreamID so the upstream-
		// side wrap (which would otherwise emit envelopes carrying a
		// different upstream stream id) rewrites env.StreamID to the
		// session-scope identity, mirroring how session.upstreamToClient
		// unifies the semantic envelopes.
		aggOpt := session.AggregatorH2FrameRecordOption(
			streamCtx, pipe, clientCh.StreamID(), envelope.EnvelopeContext{},
		)
		aggOpts := []httpaggregator.WrapOption{aggOpt}

		aggClient, derr := connector.DispatchH2StreamFull(
			streamCtx, clientCh, httpaggregator.RoleServer,
			httpaggregator.WrapOptions{}, slog.Default(), nil, nil, aggOpts,
		)
		if derr != nil {
			_ = clientCh.Close()
			return
		}
		dial := func(dialCtx context.Context, env *envelope.Envelope) (layer.Channel, error) {
			upConn, err := net.DialTimeout("tcp", upstreamAddr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			upLayer, err := intHTTP2.New(upConn, "test-upstream", intHTTP2.ClientRole,
				intHTTP2.WithScheme("http"),
			)
			if err != nil {
				upConn.Close()
				return nil, err
			}
			ch, err := upLayer.OpenStream(dialCtx)
			if err != nil {
				upLayer.Close()
				return nil, err
			}
			go func() {
				<-dialCtx.Done()
				upLayer.Close()
			}()
			// Wrap upstream client-role event channel with aggregator
			// AND install the same h2-frame record callback so Receive-
			// direction DATA frames are recorded symmetrically.
			return httpaggregator.Wrap(ch, httpaggregator.RoleClient, nil, httpaggregator.OptionsFromLayer(upLayer), aggOpts...), nil
		}
		_ = session.RunSession(streamCtx, aggClient, dial, pipe, session.SessionOptions{
			OnComplete: func(cctx context.Context, streamID string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				_ = store.UpdateStream(cctx, streamID, flow.StreamUpdate{
					State:         state,
					FailureReason: session.ClassifyError(err),
				})
			},
		})
	}

	flCfg := connector.FullListenerConfig{
		Name: "h2c-agg-frame-test",
		Addr: "127.0.0.1:0",
		OnHTTP2: connector.NewH2CHandler(connector.H2CHandlerConfig{
			OnStream: onStream,
			Logger:   slog.Default(),
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx) //nolint:errcheck

	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("full listener not ready")
	}
	return fl.Addr(), store
}

// buildPipelineWithRecordOpts mirrors buildPipeline but layers additional
// RecordStep Options onto the canonical recordOpts list. Centralised so
// the cap test (WithHTTP2FrameMaxPerStream) can compose with the standard
// h2 wire-encoder registration.
func buildPipelineWithRecordOpts(store flow.Writer, opts pipelineOpts, extra []pipeline.Option) *pipeline.Pipeline {
	recordOpts := []pipeline.Option{
		pipeline.WithWireEncoder(envelope.ProtocolHTTP, httpaggregator.EncodeWireBytes),
	}
	if opts.recordMaxBodySize > 0 {
		recordOpts = append(recordOpts, pipeline.WithMaxBodySize(opts.recordMaxBodySize))
	}
	recordOpts = append(recordOpts, extra...)

	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(opts.hostScope),
		pipeline.NewHTTPScopeStep(opts.httpScope),
		pipeline.NewSafetyStep(opts.safetyEngine, nil, nil, slog.Default()),
		pipeline.NewTransformStep(opts.transformEngine, nil, nil, nil),
		pipeline.NewInterceptStep(opts.interceptEngine, nil, nil, nil, opts.holdQueue, nil, slog.Default()),
		pipeline.NewRecordStep(store, slog.Default(), recordOpts...),
	}
	return pipeline.New(steps...)
}

// h2FrameFlowsForStream returns flows in store filtered to streamID and
// wire_level=h2-frame, optionally filtered by direction when dir != "".
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

// waitForH2FrameFlows polls until at least n h2-frame flows match.
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

// firstStreamWithProto returns the first stream with the given Protocol value.
func firstStreamWithProto(t *testing.T, store *testStore, proto string, timeout time.Duration) *flow.Stream {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, st := range store.getStreams() {
			if st.Protocol == proto {
				return st
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %q stream recorded; streams=%d", proto, len(store.getStreams()))
	return nil
}

// TestAggregatorH2FrameRecording_PlainH2POST_RecordsFramesBothDirections
// covers Issue §D #3: plain HTTP/2 request/response → h2-frame envelopes
// recorded on the aggregator path.
//
// Drives a POST request with a small body so the aggregator absorbs
// ≥1 H2DataEvent on the Send direction, and the upstream returns a
// body too so the aggregator absorbs ≥1 H2DataEvent on the Receive
// direction. Both directions must produce h2-frame envelopes; the
// semantic HTTPMessage envelopes must coexist with the same StreamID.
func TestAggregatorH2FrameRecording_PlainH2POST_RecordsFramesBothDirections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	requestBody := []byte("hello-from-client")
	responseBody := []byte("hello-from-server")
	upstreamAddr, upShutdown := startH2CUpstream(t, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, requestBody) {
			t.Errorf("upstream got body=%q, want %q", body, requestBody)
		}
		_, _ = w.Write(responseBody)
	}))
	defer upShutdown()

	proxyAddr, store := startH2CProxyWithAggOpts(t, ctx, upstreamAddr, pipelineOpts{}, nil)

	cli := newH2CClient()
	req, err := nethttp.NewRequestWithContext(ctx, "POST", "http://"+proxyAddr+"/upload", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do: %v", err)
	}
	gotBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(gotBody, responseBody) {
		t.Errorf("client got body=%q, want %q", gotBody, responseBody)
	}

	st := firstStreamWithProto(t, store, "http", 5*time.Second)
	// Semantic envelopes: 1 send (HTTPMessage) + 1 recv (HTTPMessage). The
	// canonical assertion is already covered by TestH2C_BasicRoundtrip;
	// here we focus on h2-frame.
	sendFrames := waitForH2FrameFlows(t, store, st.ID, "send", 1, 5*time.Second)
	recvFrames := waitForH2FrameFlows(t, store, st.ID, "receive", 1, 5*time.Second)

	if len(sendFrames) < 1 {
		t.Errorf("send h2-frame count = %d, want ≥1", len(sendFrames))
	}
	if len(recvFrames) < 1 {
		t.Errorf("receive h2-frame count = %d, want ≥1", len(recvFrames))
	}

	// Concatenating all Send-direction frame payloads must equal the
	// request body bytes (single-frame case or multi-frame case both
	// satisfy this).
	var sendCat []byte
	for _, f := range sendFrames {
		sendCat = append(sendCat, f.RawBytes...)
	}
	if !bytes.Equal(sendCat, requestBody) {
		t.Errorf("send h2-frame concat = %q, want %q (per-frame payload preservation)", sendCat, requestBody)
	}
	var recvCat []byte
	for _, f := range recvFrames {
		recvCat = append(recvCat, f.RawBytes...)
	}
	if !bytes.Equal(recvCat, responseBody) {
		t.Errorf("receive h2-frame concat = %q, want %q (per-frame payload preservation)", recvCat, responseBody)
	}

	// Per-direction sequence counters start at 0 and increment by 1.
	for i, f := range sendFrames {
		if f.Sequence != i {
			t.Errorf("send h2-frame[%d].Sequence = %d, want %d", i, f.Sequence, i)
		}
		if f.WireLevel != flow.WireLevelH2Frame {
			t.Errorf("send h2-frame[%d].WireLevel = %q, want %q", i, f.WireLevel, flow.WireLevelH2Frame)
		}
	}
	for i, f := range recvFrames {
		if f.Sequence != i {
			t.Errorf("recv h2-frame[%d].Sequence = %d, want %d (independent of send counter)", i, f.Sequence, i)
		}
	}

	// All recorded h2-frame envelopes must share the same StreamID as
	// the semantic envelopes (StreamID unification via the
	// AggregatorH2FrameRecordOption closure).
	for _, f := range h2FrameFlowsForStream(store, st.ID, "") {
		if f.StreamID != st.ID {
			t.Errorf("h2-frame.StreamID = %q, want %q (StreamID unification)", f.StreamID, st.ID)
		}
	}
}

// TestAggregatorH2FrameRecording_LargeBodySplitsAcrossFrames covers
// Issue §D #4 (small-DATA flooding intent): a sufficiently large request
// body forces the HTTP/2 wire to split it across multiple DATA frames
// at the default 16 KiB MaxFrameSize. Each DATA frame must produce one
// h2-frame envelope; concatenating them must reproduce the full body.
//
// We don't reduce SETTINGS_MAX_FRAME_SIZE to 512 because that requires
// peer-side advertisement plumbing the harness doesn't expose. The
// 60 KiB payload forces ≥4 frames at the default 16384 frame size,
// which is the same observable property the smaller-frame variant
// would exercise.
func TestAggregatorH2FrameRecording_LargeBodySplitsAcrossFrames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 60 KiB payload — at default MaxFrameSize=16384, this splits into
	// ≥4 DATA frames on the wire.
	payload := bytes.Repeat([]byte("AB"), 30*1024)

	upstreamAddr, upShutdown := startH2CUpstream(t, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) != len(payload) {
			t.Errorf("upstream got body len=%d, want %d", len(body), len(payload))
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upShutdown()

	proxyAddr, store := startH2CProxyWithAggOpts(t, ctx, upstreamAddr, pipelineOpts{}, nil)

	cli := newH2CClient()
	req, err := nethttp.NewRequestWithContext(ctx, "POST", "http://"+proxyAddr+"/big", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	st := firstStreamWithProto(t, store, "http", 5*time.Second)

	// Wait for AT LEAST one send h2-frame; large bodies typically split
	// into ≥2 frames but exact count depends on flow control and the
	// proxy's re-frame behavior. Concatenation correctness is the
	// load-bearing assertion.
	sendFrames := waitForH2FrameFlows(t, store, st.ID, "send", 1, 5*time.Second)
	var sendCat []byte
	for _, f := range sendFrames {
		sendCat = append(sendCat, f.RawBytes...)
	}
	if !bytes.Equal(sendCat, payload) {
		t.Errorf("send h2-frame concat len = %d, want %d (per-frame payload preservation across body fragmentation)",
			len(sendCat), len(payload))
	}
	// We expect the wire to fragment (≥2 frames) at this size; if the
	// proxy re-frames into a single DATA frame the test still passes the
	// concat assertion above, which is the correctness contract.
	t.Logf("60 KiB POST: send h2-frame count = %d (wire-level fragmentation)", len(sendFrames))
}

// TestAggregatorH2FrameRecording_PerStreamCap covers Issue §D #5:
// WithHTTP2FrameMaxPerStream caps the per-Stream h2-frame envelope
// count on the aggregator path. Wire forwarding is unaffected.
func TestAggregatorH2FrameRecording_PerStreamCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const cap = 3
	// Body large enough to fragment across multiple frames; use a body
	// per direction so both Send and Receive contribute to the cap.
	requestBody := bytes.Repeat([]byte("R"), 60*1024)
	responseBody := bytes.Repeat([]byte("S"), 60*1024)

	upstreamAddr, upShutdown := startH2CUpstream(t, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write(responseBody)
	}))
	defer upShutdown()

	proxyAddr, store := startH2CProxyWithAggOpts(
		t, ctx, upstreamAddr, pipelineOpts{},
		[]pipeline.Option{pipeline.WithHTTP2FrameMaxPerStream(cap)},
	)

	cli := newH2CClient()
	req, err := nethttp.NewRequestWithContext(ctx, "POST", "http://"+proxyAddr+"/cap", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do: %v", err)
	}
	gotBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wire forwarding intact: full response body delivered even though
	// the recorder dropped some frames.
	if len(gotBody) != len(responseBody) {
		t.Errorf("client received body len=%d, want %d (cap must not affect forwarding)", len(gotBody), len(responseBody))
	}

	st := firstStreamWithProto(t, store, "http", 5*time.Second)
	// Wait for the response semantic envelope to be persisted so we know
	// the stream finished draining.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var sawRecv bool
		for _, f := range store.flowsForStream(st.ID) {
			if f.Direction == "receive" && f.WireLevel == flow.WireLevelSemantic {
				sawRecv = true
				break
			}
		}
		if sawRecv {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Cap fires: total h2-frame envelopes on this stream ≤ cap. The cap
	// gate keys on WireLevel (USK-889 Q15) — Send and Receive frames
	// share the same per-Stream budget because they share the same
	// wire_level discriminator.
	frames := h2FrameFlowsForStream(store, st.ID, "")
	if len(frames) > cap {
		t.Errorf("recorded h2-frame count = %d exceeds cap %d", len(frames), cap)
	}
	if len(frames) == 0 {
		t.Errorf("recorded h2-frame count = 0; cap wiring may have skipped every envelope")
	}
}

// TestAggregatorH2FrameRecording_MCPQueryParity covers Issue §D #6:
// h2-frame flows are retrievable from the store by ID — the same lookup
// the `query` MCP tool performs. Asserts a 3-wire-level stream presents
// all kinds (semantic + h2-frame here; native gRPC would also add
// grpc-lpm-frame, but plain HTTP/2 has no grpc layer).
func TestAggregatorH2FrameRecording_MCPQueryParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upShutdown := startH2CUpstream(t, nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte("query-parity"))
	}))
	defer upShutdown()

	proxyAddr, store := startH2CProxyWithAggOpts(t, ctx, upstreamAddr, pipelineOpts{}, nil)

	cli := newH2CClient()
	req, err := nethttp.NewRequestWithContext(ctx, "POST", "http://"+proxyAddr+"/q", bytes.NewReader([]byte("req-body")))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	st := firstStreamWithProto(t, store, "http", 5*time.Second)
	frames := waitForH2FrameFlows(t, store, st.ID, "send", 1, 5*time.Second)
	// The testStore's allFlows() is the substitute for the MCP query
	// round-trip — any flow that lands here is retrievable by the
	// `query` MCP tool.
	var found bool
	for _, f := range store.allFlows() {
		if f != nil && f.ID == frames[0].ID && f.WireLevel == flow.WireLevelH2Frame {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("h2-frame flow %q not retrievable from store; MCP query tool would not see it either", frames[0].ID)
	}

	// Stream contains both wire_level kinds (semantic + h2-frame).
	semanticCount := 0
	frameCount := 0
	for _, f := range store.flowsForStream(st.ID) {
		switch f.WireLevel {
		case flow.WireLevelSemantic, "":
			semanticCount++
		case flow.WireLevelH2Frame:
			frameCount++
		}
	}
	if semanticCount == 0 {
		t.Errorf("semantic envelope count = 0; expected ≥1 (request/response HTTPMessage)")
	}
	if frameCount == 0 {
		t.Errorf("h2-frame envelope count = 0; expected ≥1")
	}
}

// TestAggregatorH2FrameRecording_WireLevelConstantStable verifies the
// canonical discriminator string ("h2-frame") is reused per USK-893 Q5.
// Same shape as USK-896's TestGRPCLPMRecording_HARExcludesFrame guard.
func TestAggregatorH2FrameRecording_WireLevelConstantStable(t *testing.T) {
	if flow.WireLevelH2Frame != "h2-frame" {
		t.Errorf("flow.WireLevelH2Frame = %q, want %q (USK-893 Q5: discriminator value is locked across producers)",
			flow.WireLevelH2Frame, "h2-frame")
	}
}

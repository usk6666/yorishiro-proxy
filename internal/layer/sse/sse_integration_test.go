//go:build e2e

// Package sse_test contains e2e tests for the SSE Layer / Channel that drive
// the Channel + Pipeline + RunSession integration without depending on the
// http1 streaming-body detach primitive.
//
// Scope rationale (USK-653 / USK-643 D1 deferral):
//
// The original USK-653 spec asks for a full-chain "Content-Type:
// text/event-stream detection → Receive-side Layer swap → byte-loss-free
// passthrough" e2e test. That path is BLOCKED in production today because
// http1.channel.Next drains the response body before returning the response
// envelope, which means the swap orchestration in
// session.runUpgradeSSE never sees a streaming body to wrap. The blocker is
// documented as deferred item D1 in the USK-643 PR description.
//
// Until D1 lands, we provide direct-Wrap integration tests that exercise
// sse.Wrap → Pipeline.Run → RunSession without involving RunStackSession
// or any http1 → SSE swap. They cover the recording projection (Stream/
// Flow rows + sse_event/sse_id/sse_retry_ms metadata), the Send-sentinel
// programmer-error contract, the MaxEventSize StreamError + OnComplete
// error-path projection, and parser anomaly emission (sse_anomaly_*
// metadata). The full-chain swap test remains t.Skip until D1 lands.
package sse_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// testStore implements flow.Writer for capturing recorded streams and flows.
// Mirrors the testStore in internal/layer/http1/mitm_integration_test.go;
// kept inline so the SSE e2e file is self-contained and we do not pollute
// the http1 _test.go namespace from across packages.
type testStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
}

func (s *testStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *testStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if st.ID == id {
			if update.State != "" {
				st.State = update.State
			}
			if update.FailureReason != "" {
				st.FailureReason = update.FailureReason
			}
		}
	}
	return nil
}

func (s *testStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append(s.flows, f)
	return nil
}

func (s *testStore) getStreams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

func (s *testStore) flowsByDirection(dir string) []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*flow.Flow
	for _, f := range s.flows {
		if f.Direction == dir {
			out = append(out, f)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// stub Channels
// ---------------------------------------------------------------------------

// seedClientChannel emits a single Send envelope (the "seed") on the first
// Next, then reports io.EOF. It records envelopes the session passes to
// Send so the test can verify what the Receive-path eventually pushed back
// to the client. It never blocks: simulating a half-duplex SSE client that
// has already issued the GET and is now only reading events.
//
// The seed envelope is constructed with Protocol=ProtocolSSE so RecordStep
// projects Stream.Protocol = "sse" on the first Send. This is the
// "synthesize the seed with explicit Protocol" approach decided in the
// USK-653 scope notes; it sidesteps the need to thread a real http1
// request → SSE swap, which is blocked by D1.
type seedClientChannel struct {
	streamID string
	seed     *envelope.Envelope

	mu        sync.Mutex
	emitted   bool
	sent      []*envelope.Envelope
	closed    chan struct{}
	closeOnce sync.Once
}

func newSeedClientChannel(streamID string, seed *envelope.Envelope) *seedClientChannel {
	return &seedClientChannel{
		streamID: streamID,
		seed:     seed,
		closed:   make(chan struct{}),
	}
}

func (c *seedClientChannel) StreamID() string { return c.streamID }

func (c *seedClientChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	c.mu.Lock()
	if !c.emitted {
		c.emitted = true
		out := c.seed
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()
	// After the seed, mimic a half-closed client: block until ctx cancels
	// or the channel is explicitly closed, then return io.EOF. RunSession
	// treats io.EOF as normal termination on the Send side.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, io.EOF
	}
}

func (c *seedClientChannel) Send(_ context.Context, env *envelope.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, env)
	return nil
}

func (c *seedClientChannel) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *seedClientChannel) Closed() <-chan struct{} { return c.closed }
func (c *seedClientChannel) Err() error              { return nil }

// innerStub is the layer.Channel given to sse.Wrap as the "inner" handle.
// sse.Wrap only uses StreamID() and Close() on the inner channel; Next/Send
// are never invoked. We track Close calls for cascade verification.
type innerStub struct {
	streamID string
	closed   chan struct{}
	once     sync.Once
}

func newInnerStub(streamID string) *innerStub {
	return &innerStub{streamID: streamID, closed: make(chan struct{})}
}

func (s *innerStub) StreamID() string                                   { return s.streamID }
func (s *innerStub) Next(_ context.Context) (*envelope.Envelope, error) { return nil, io.EOF }
func (s *innerStub) Send(_ context.Context, _ *envelope.Envelope) error {
	return errors.New("inner stub: Send not used")
}
func (s *innerStub) Close() error            { s.once.Do(func() { close(s.closed) }); return nil }
func (s *innerStub) Closed() <-chan struct{} { return s.closed }
func (s *innerStub) Err() error              { return nil }

// makeSSEFirstResponse builds the firstResponse envelope sse.Wrap needs.
// It mirrors what http1.channel.Next would produce for a 200/text/event-stream
// response, except we leave Body empty (the body bytes are supplied to Wrap
// as a separate io.Reader).
func makeSSEFirstResponse(streamID string, seq int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "sse-first-resp",
		Sequence:  seq,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
			Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "text/event-stream"},
			},
		},
	}
}

// makeSSESeedRequest builds the seed Send envelope used to drive
// clientToUpstream's first iteration. Protocol is set to ProtocolSSE so
// RecordStep projects Stream.Protocol = "sse" on Stream creation. The
// envelope carries an HTTPMessage shape (the wire form for an SSE
// subscribe request is a plain GET) so RecordStep's HTTPMessage projection
// produces a meaningful Method/URL row for the seed Flow.
func makeSSESeedRequest(streamID string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "sse-seed-req",
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolSSE,
		Raw:       []byte("GET /events HTTP/1.1\r\nHost: example.test\r\nAccept: text/event-stream\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/events",
			Authority: "example.test",
			Scheme:    "https",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.test"},
				{Name: "Accept", Value: "text/event-stream"},
			},
		},
	}
}

// buildPipeline assembles a minimal Pipeline with just RecordStep, which is
// the only Step the SSE recording assertions exercise. Other Steps (Scope,
// Safety, Transform, Intercept) are out of scope for the SSE projection
// assertions.
//
// The seed Send envelope flows through Continue so RunSession lazily dials
// the SSE upstream and the Receive-side goroutine starts. Forwarding the
// Send envelope to the SSE upstream's Send is suppressed by the upstream
// adapter (sseUpstreamAdapter.Send swallows the call), not by a Drop in the
// Pipeline — the Pipeline's job is to record, not to gate dispatch.
func buildPipeline(store flow.Writer) *pipeline.Pipeline {
	return pipeline.New(
		pipeline.NewRecordStep(store, slog.Default()),
	)
}

// sseUpstreamAdapter wraps an sse.Wrap-ed Channel so that Send is a no-op
// instead of returning sse.ErrSendUnsupported. RunSession's
// dispatchClientAction unconditionally calls upstream.Send for Continue
// envelopes; in the production runUpgradeSSE path the client side is a
// drained Channel that emits no envelopes, so upstream.Send is never
// reached. Our test deliberately drives a synthetic Send seed (to fire
// Stream creation with Protocol="sse" via RecordStep), which means we must
// neutralize the upstream Send. The wrapped Channel still exposes the real
// Next/Closed/Err behaviour driven by sse.Wrap.
type sseUpstreamAdapter struct {
	inner layer.Channel
}

func (a *sseUpstreamAdapter) StreamID() string { return a.inner.StreamID() }
func (a *sseUpstreamAdapter) Next(ctx context.Context) (*envelope.Envelope, error) {
	return a.inner.Next(ctx)
}
func (a *sseUpstreamAdapter) Send(_ context.Context, _ *envelope.Envelope) error { return nil }
func (a *sseUpstreamAdapter) Close() error                                       { return a.inner.Close() }
func (a *sseUpstreamAdapter) Closed() <-chan struct{}                            { return a.inner.Closed() }
func (a *sseUpstreamAdapter) Err() error                                         { return a.inner.Err() }

// ---------------------------------------------------------------------------
// Active tests
// ---------------------------------------------------------------------------

// TestSSE_DirectChannelThroughPipelineRecordsThreeEvents exercises the SSE
// recording projection end-to-end:
//
//  1. A seed Send envelope (synthetic GET /events, Protocol=ProtocolSSE)
//     drives Stream creation with Protocol="sse".
//  2. The dial returns an sse.Wrap-ed Channel whose body io.Reader carries
//     three identical SSE events (event/data/id/retry).
//  3. RunSession drives upstream.Next which produces 1 first-response
//     envelope (re-shaped) + 3 SSEMessage envelopes + io.EOF.
//  4. RecordStep projects each SSEMessage into a Receive flow row whose
//     Body is the parsed Data, RawBytes equals the wire bytes incl. the
//     trailing blank line, and Metadata carries sse_event / sse_id /
//     sse_retry_ms.
//
// This test does NOT cover the http1 → SSE swap; it drives sse.Wrap
// directly, sidestepping D1.
func TestSSE_DirectChannelThroughPipelineRecordsThreeEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const streamID = "sse-stream-1"
	const event = "event: ping\ndata: 1\nid: 1\nretry: 3000\n\n"
	wire := strings.Repeat(event, 3)

	store := &testStore{}

	seed := makeSSESeedRequest(streamID)
	clientCh := newSeedClientChannel(streamID, seed)

	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 1)
	body := strings.NewReader(wire)
	upstreamCh := sse.Wrap(inner, first, body)

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &sseUpstreamAdapter{inner: upstreamCh}, nil
	}

	p := buildPipeline(store)

	done := make(chan error, 1)
	go func() {
		done <- session.RunSession(ctx, clientCh, dial, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, sid string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if sid != "" {
					_ = store.UpdateStream(cctx, sid, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
	}()

	// The first SSEMessage upstream envelope is the wrapped first response;
	// subsequent envelopes drive parser.Next over the body. After 3 events
	// the parser hits io.EOF, upstream.Next returns nil, RunSession's
	// Receive-side goroutine returns nil. The Send-side goroutine is still
	// blocked waiting on client.Next; close the client channel to unblock.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recvCount := len(store.flowsByDirection("receive"))
		if recvCount >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = clientCh.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunSession returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunSession did not return")
	}

	// --- Stream recording ---
	streams := store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	if streams[0].Protocol != "sse" {
		t.Errorf("Stream.Protocol = %q, want %q", streams[0].Protocol, "sse")
	}
	if streams[0].State != "complete" {
		t.Errorf("Stream.State = %q, want %q", streams[0].State, "complete")
	}

	// --- Send flow (seed) ---
	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) != 1 {
		t.Fatalf("got %d send flows, want 1", len(sendFlows))
	}

	// --- Receive flows (1 first-response + 3 SSEMessage events) ---
	recvFlows := store.flowsByDirection("receive")
	// The first-response Receive envelope produced by sse.Wrap carries an
	// HTTPMessage; only the 3 subsequent envelopes carry SSEMessage. So we
	// expect 4 receive flows total: 1 HTTP first-response + 3 SSE events.
	if len(recvFlows) != 4 {
		t.Fatalf("got %d receive flows, want 4 (1 first-response + 3 events)", len(recvFlows))
	}

	// Filter to the SSE-event flows (those carry sse_event metadata).
	var sseFlows []*flow.Flow
	for _, f := range recvFlows {
		if f.Metadata != nil && f.Metadata["sse_event"] != "" {
			sseFlows = append(sseFlows, f)
		}
	}
	if len(sseFlows) != 3 {
		t.Fatalf("got %d SSE event flows (with sse_event metadata), want 3", len(sseFlows))
	}

	for i, f := range sseFlows {
		if f.Metadata["sse_event"] != "ping" {
			t.Errorf("flow %d sse_event = %q, want %q", i, f.Metadata["sse_event"], "ping")
		}
		if f.Metadata["sse_id"] != "1" {
			t.Errorf("flow %d sse_id = %q, want %q", i, f.Metadata["sse_id"], "1")
		}
		if f.Metadata["sse_retry_ms"] != "3000" {
			t.Errorf("flow %d sse_retry_ms = %q, want %q", i, f.Metadata["sse_retry_ms"], "3000")
		}
		if string(f.Body) != "1" {
			t.Errorf("flow %d Body = %q, want %q", i, string(f.Body), "1")
		}
		if string(f.RawBytes) != event {
			t.Errorf("flow %d RawBytes = %q, want %q (byte-exact wire incl. trailing blank line)",
				i, string(f.RawBytes), event)
		}
	}
}

// TestSSE_DirectChannelSendReturnsSentinel confirms that the wrapped SSE
// Channel's Send method is a programmer-error sentinel:
//
//   - errors.Is(err, sse.ErrSendUnsupported) — true
//   - errors.As(err, &*layer.StreamError{}) — false
//
// SSE is half-duplex (server → client per RFC 8895 / N7 D23). A caller that
// reaches Send on the SSE Channel has a logic bug; we surface that as a
// plain sentinel rather than a stream-level abort.
func TestSSE_DirectChannelSendReturnsSentinel(t *testing.T) {
	const streamID = "sse-stream-2"
	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 0)
	ch := sse.Wrap(inner, first, strings.NewReader(""))
	defer ch.Close()

	err := ch.Send(context.Background(), &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolSSE,
	})
	if err == nil {
		t.Fatal("Send returned nil error; want sse.ErrSendUnsupported")
	}
	if !errors.Is(err, sse.ErrSendUnsupported) {
		t.Errorf("errors.Is(err, sse.ErrSendUnsupported) = false, err = %v", err)
	}
	var se *layer.StreamError
	if errors.As(err, &se) {
		t.Errorf("Send returned *layer.StreamError (%v); want plain sentinel", se)
	}
}

// TestSSE_DirectChannelOversizeProducesStreamError feeds an event larger
// than the WithMaxEventSize cap and asserts:
//
//   - upstream.Next surfaces *layer.StreamError with Code=ErrorInternalError
//   - RunSession exits with that wrapped error
//   - SessionOptions.OnComplete fires with non-EOF err
//   - session.ClassifyError(err) == "internal_error"
//   - The OnComplete projection updates Stream.State to "error" and
//     Stream.FailureReason to "internal_error"
func TestSSE_DirectChannelOversizeProducesStreamError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const streamID = "sse-stream-3"
	huge := strings.Repeat("x", 4096)
	wire := "data: " + huge + "\n\n"

	store := &testStore{}

	seed := makeSSESeedRequest(streamID)
	clientCh := newSeedClientChannel(streamID, seed)

	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 1)
	body := strings.NewReader(wire)
	upstreamCh := sse.Wrap(inner, first, body, sse.WithMaxEventSize(64))

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &sseUpstreamAdapter{inner: upstreamCh}, nil
	}

	p := buildPipeline(store)

	var (
		completeErr  error
		completeOnce sync.Once
		completeCh   = make(chan struct{})
	)

	done := make(chan error, 1)
	go func() {
		done <- session.RunSession(ctx, clientCh, dial, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, sid string, err error) {
				completeOnce.Do(func() {
					completeErr = err
					close(completeCh)
				})
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if sid != "" {
					_ = store.UpdateStream(cctx, sid, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
	}()

	// Wait for OnComplete (it always fires once both goroutines exit).
	select {
	case <-completeCh:
	case <-time.After(5 * time.Second):
		_ = clientCh.Close()
		t.Fatal("OnComplete did not fire")
	}

	// RunSession itself should have returned by now (OnComplete fires
	// after g.Wait()), but the Send-side goroutine may still be parked on
	// client.Next. Close the client channel to unblock it. The Receive-
	// side error already cancelled the errgroup ctx, but client.Next on
	// our stub does NOT honor ctx cancel via blockNext semantics. Closing
	// is the safe path.
	_ = clientCh.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunSession did not return after OnComplete")
	}

	// --- OnComplete error ---
	if completeErr == nil {
		t.Fatal("OnComplete err = nil; want non-nil error wrapping *layer.StreamError")
	}
	if errors.Is(completeErr, io.EOF) {
		t.Fatalf("OnComplete err = %v; want non-EOF error", completeErr)
	}
	var se *layer.StreamError
	if !errors.As(completeErr, &se) {
		t.Fatalf("OnComplete err = %v; expected to wrap *layer.StreamError", completeErr)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want ErrorInternalError", se.Code)
	}
	if got := session.ClassifyError(completeErr); got != "internal_error" {
		t.Errorf("ClassifyError = %q, want %q", got, "internal_error")
	}

	// --- Stream State / FailureReason projection via OnComplete ---
	streams := store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	if streams[0].State != "error" {
		t.Errorf("Stream.State = %q, want %q", streams[0].State, "error")
	}
	if streams[0].FailureReason != "internal_error" {
		t.Errorf("Stream.FailureReason = %q, want %q", streams[0].FailureReason, "internal_error")
	}
}

// ---------------------------------------------------------------------------
// Skipped placeholders
// ---------------------------------------------------------------------------

// TestSSE_FullChainSwapEndToEnd is the full http1 → SSE swap e2e test
// originally specified in USK-653. It is currently skipped because
// http1.channel.Next drains the response body before returning the response
// envelope; production SSE streaming requires an http1 streaming-body
// detach primitive (D1, see USK-643 PR description).
//
// Acceptance criteria that activate when D1 lands:
//
//  1. A real upstream serves a 200 text/event-stream response and emits
//     three events.
//  2. The request flows through MITM as HTTP/1.x; the response triggers
//     UpgradeStep + UpgradeNotice with Pending() == UpgradeSSE.
//  3. RunStackSession.runUpgradeSSE detaches the upstream http1 wire,
//     constructs sse.Wrap on the body, and recursively re-runs RunSession.
//  4. The client receives all three events byte-for-byte.
//  5. Recording shows exactly one Stream (Protocol="sse") with the
//     pre-swap Send flow and three post-swap Receive flows.
//  6. No envelope is recorded twice across the swap (no double-recording
//     of the first response envelope).
func TestSSE_FullChainSwapEndToEnd(t *testing.T) {
	t.Skip("not yet implemented: http1 streaming-body detach for SSE — D1 follow-up issue, see USK-643 PR description")
}

// errReader wraps an io.Reader and returns a chosen non-EOF error after
// the underlying reader is exhausted. Used to drive AnomalySSETruncated
// through the integration stack.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, e.err
	}
	return n, err
}

// TestSSE_MalformedEventAnomaly drives three malformed events through the
// SSE Channel + Pipeline integration and asserts that recoverable parser
// anomalies project to flow.Flow.Metadata under stable per-type keys
// (sse_anomaly_missing_data, sse_anomaly_duplicate_id,
// sse_anomaly_truncated). Stream-terminating problems (oversize event)
// are out of scope for this test — they remain *layer.StreamError per the
// USK-656 non-goals.
func TestSSE_MalformedEventAnomaly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const streamID = "sse-stream-anomaly"
	const evMissingData = "event: ping\nid: m\n\n"   // no data: line
	const evDupID = "id: 1\nid: 2\ndata: dup\n\n"    // duplicate id:
	const evTruncated = "event: tail\ndata: partial" // no trailing blank line; reader returns non-EOF error

	wantConnReset := errors.New("connection reset by peer")
	body := &errReader{
		r:   strings.NewReader(evMissingData + evDupID + evTruncated),
		err: wantConnReset,
	}

	store := &testStore{}

	seed := makeSSESeedRequest(streamID)
	clientCh := newSeedClientChannel(streamID, seed)

	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 1)
	upstreamCh := sse.Wrap(inner, first, body)

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &sseUpstreamAdapter{inner: upstreamCh}, nil
	}

	p := buildPipeline(store)

	done := make(chan error, 1)
	go func() {
		done <- session.RunSession(ctx, clientCh, dial, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, sid string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if sid != "" {
					_ = store.UpdateStream(cctx, sid, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recv := store.flowsByDirection("receive")
		// 1 first-response + 3 SSE event flows = 4
		if len(recv) >= 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = clientCh.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunSession returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunSession did not return")
	}

	streams := store.getStreams()
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	if streams[0].Protocol != "sse" {
		t.Errorf("Stream.Protocol = %q, want %q", streams[0].Protocol, "sse")
	}

	// Filter to SSE-event flows by presence of any sse_* metadata key set
	// by the parser. The first-response Receive carries an HTTPMessage and
	// will not match.
	var sseFlows []*flow.Flow
	for _, f := range store.flowsByDirection("receive") {
		if f.Metadata == nil {
			continue
		}
		if f.Metadata["sse_event"] != "" || f.Metadata["sse_id"] != "" ||
			f.Metadata["sse_anomaly_missing_data"] != "" ||
			f.Metadata["sse_anomaly_duplicate_id"] != "" ||
			f.Metadata["sse_anomaly_truncated"] != "" {
			sseFlows = append(sseFlows, f)
		}
	}
	if len(sseFlows) != 3 {
		t.Fatalf("got %d SSE event flows, want 3", len(sseFlows))
	}

	// flow[0] — missing-data event.
	if got := sseFlows[0].Metadata["sse_anomaly_missing_data"]; got == "" {
		t.Errorf("flow[0] missing sse_anomaly_missing_data, got Metadata=%v", sseFlows[0].Metadata)
	}
	if got := sseFlows[0].Metadata["sse_anomaly_duplicate_id"]; got != "" {
		t.Errorf("flow[0] should not have sse_anomaly_duplicate_id, got %q", got)
	}
	if got := sseFlows[0].Metadata["sse_event"]; got != "ping" {
		t.Errorf("flow[0] sse_event = %q, want %q", got, "ping")
	}

	// flow[1] — duplicate-id event.
	if got := sseFlows[1].Metadata["sse_anomaly_duplicate_id"]; got == "" {
		t.Errorf("flow[1] missing sse_anomaly_duplicate_id, got Metadata=%v", sseFlows[1].Metadata)
	}
	if got := sseFlows[1].Metadata["sse_id"]; got != "2" {
		t.Errorf("flow[1] sse_id = %q, want %q (last value wins)", got, "2")
	}
	if string(sseFlows[1].Body) != "dup" {
		t.Errorf("flow[1] Body = %q, want %q", string(sseFlows[1].Body), "dup")
	}

	// flow[2] — truncated event (non-EOF read error mid-event).
	trunc := sseFlows[2].Metadata["sse_anomaly_truncated"]
	if trunc == "" {
		t.Errorf("flow[2] missing sse_anomaly_truncated, got Metadata=%v", sseFlows[2].Metadata)
	}
	if !strings.Contains(trunc, wantConnReset.Error()) {
		t.Errorf("flow[2] sse_anomaly_truncated = %q, want substring %q", trunc, wantConnReset.Error())
	}
	if string(sseFlows[2].Body) != "partial" {
		t.Errorf("flow[2] Body = %q, want %q", string(sseFlows[2].Body), "partial")
	}
}

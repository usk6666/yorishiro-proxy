package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// mockChannel is a test double for layer.Channel.
// nextEnvelopes are returned by Next() in order, followed by io.EOF.
// Envelopes passed to Send() are recorded in sent.
type mockChannel struct {
	mu            sync.Mutex
	streamID      string
	nextEnvelopes []*envelope.Envelope
	nextIdx       int
	nextErr       error // if set, returned instead of io.EOF after envelopes are exhausted
	sent          []*envelope.Envelope
	closed        bool
	closeCalls    int
	blockNext     chan struct{} // if non-nil, Next blocks until closed or ctx done
	sendErr       error         // if set, Send returns this error
	nextGate      chan struct{} // if non-nil, Next waits for a value before each return

	// Terminal-state tracking exposed via Closed/Err. A test can call
	// fireTerminated(err) to model a post-EOF terminal event (e.g., a
	// RST_STREAM that arrives after the peer already half-closed). The
	// backing channel is lazy-initialized so existing literal constructions
	// remain valid — no shared-state surprises because every access funnels
	// through ensureTerm.
	termInit sync.Once
	termMu   sync.Mutex
	termErr  error
	termOnce sync.Once
	termDone chan struct{}
}

func (m *mockChannel) ensureTerm() {
	m.termInit.Do(func() { m.termDone = make(chan struct{}) })
}

func (m *mockChannel) StreamID() string {
	return m.streamID
}

func (m *mockChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	if m.blockNext != nil {
		select {
		case <-m.blockNext:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.nextGate != nil {
		select {
		case <-m.nextGate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nextIdx >= len(m.nextEnvelopes) {
		if m.nextErr != nil {
			return nil, m.nextErr
		}
		return nil, io.EOF
	}
	env := m.nextEnvelopes[m.nextIdx]
	m.nextIdx++
	return env, nil
}

func (m *mockChannel) Send(_ context.Context, env *envelope.Envelope) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, env)
	return nil
}

func (m *mockChannel) Close() error {
	m.mu.Lock()
	m.closeCalls++
	alreadyClosed := m.closed
	m.closed = true
	block := m.blockNext
	m.mu.Unlock()
	if alreadyClosed {
		// Already closed — keep Close idempotent like real Channels.
		return nil
	}
	// If a blocked Next is waiting on blockNext, release it so the Next call
	// returns (io.EOF by default once m.closed is observed). This models the
	// real HTTP/2 channel.Close behavior where Close tears down the receive
	// side and unblocks any pending Next.
	if block != nil {
		select {
		case <-block:
			// Already closed by the test.
		default:
			close(block)
		}
	}
	// Local Close counts as normal (EOF) termination; it must not be
	// misread as a late peer cancel by the session watcher.
	m.fireTerminated(io.EOF)
	return nil
}

// Closed returns the Channel's terminal-state signal.
func (m *mockChannel) Closed() <-chan struct{} {
	m.ensureTerm()
	return m.termDone
}

// Err returns the terminal error captured when Closed fired.
func (m *mockChannel) Err() error {
	m.termMu.Lock()
	defer m.termMu.Unlock()
	return m.termErr
}

// fireTerminated records err (first-writer-wins) and closes termDone
// exactly once. In-package helper used by tests to simulate terminal
// events.
func (m *mockChannel) fireTerminated(err error) {
	m.ensureTerm()
	m.termMu.Lock()
	if m.termErr == nil {
		m.termErr = err
	}
	m.termMu.Unlock()
	m.termOnce.Do(func() { close(m.termDone) })
}

func (m *mockChannel) getCloseCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeCalls
}

func (m *mockChannel) getSent() []*envelope.Envelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*envelope.Envelope, len(m.sent))
	copy(out, m.sent)
	return out
}

func (m *mockChannel) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// passStep is a Pipeline Step that always continues.
type passStep struct{}

func (passStep) Process(_ context.Context, _ *envelope.Envelope) pipeline.Result {
	return pipeline.Result{Action: pipeline.Continue}
}

// dropStep drops all Envelopes.
type dropStep struct{}

func (dropStep) Process(_ context.Context, _ *envelope.Envelope) pipeline.Result {
	return pipeline.Result{Action: pipeline.Drop}
}

// respondStep responds with a fixed Envelope for Send-direction messages.
type respondStep struct {
	resp *envelope.Envelope
}

func (s respondStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if env.Direction == envelope.Send {
		return pipeline.Result{Action: pipeline.Respond, Response: s.resp}
	}
	return pipeline.Result{Action: pipeline.Continue}
}

// capturedEnv is a snapshot of the fields a captureStep observed on one
// envelope, used to assert what the Pipeline saw without holding a reference
// to a mutating live envelope.
type capturedEnv struct {
	direction envelope.Direction
	streamID  string
	sequence  int
}

// captureStep records every envelope the Pipeline dispatches to it. Used to
// verify session-layer transformations (e.g., StreamID rewriting) that
// happen before the Pipeline runs.
type captureStep struct {
	mu   *sync.Mutex
	seen *[]capturedEnv
}

func (c *captureStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	c.mu.Lock()
	*c.seen = append(*c.seen, capturedEnv{
		direction: env.Direction,
		streamID:  env.StreamID,
		sequence:  env.Sequence,
	})
	c.mu.Unlock()
	return pipeline.Result{Action: pipeline.Continue}
}

func findCaptured(seen []capturedEnv, dir envelope.Direction) *capturedEnv {
	for i := range seen {
		if seen[i].direction == dir {
			return &seen[i]
		}
	}
	return nil
}

func makeEnvelope(dir envelope.Direction, seq int) *envelope.Envelope {
	return &envelope.Envelope{
		Direction: dir,
		Sequence:  seq,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("test-data"),
		Message:   &envelope.RawMessage{Bytes: []byte("test-data")},
	}
}

func makeEnvelopeWithStreamID(dir envelope.Direction, seq int, streamID string) *envelope.Envelope {
	env := makeEnvelope(dir, seq)
	env.StreamID = streamID
	return env
}

func TestRunSession_Unary(t *testing.T) {
	req := makeEnvelope(envelope.Send, 0)
	resp := makeEnvelope(envelope.Receive, 1)

	clientCh := &mockChannel{
		streamID:      "client-stream",
		nextEnvelopes: []*envelope.Envelope{req},
	}
	upstreamCh := &mockChannel{
		streamID:      "upstream-stream",
		nextEnvelopes: []*envelope.Envelope{resp},
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCh, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	// Upstream should have received the request.
	upSent := upstreamCh.getSent()
	if len(upSent) != 1 {
		t.Fatalf("upstream.Send called %d times, want 1", len(upSent))
	}
	if upSent[0].Direction != envelope.Send {
		t.Errorf("upstream received direction %v, want Send", upSent[0].Direction)
	}

	// Client should have received the response.
	clientSent := clientCh.getSent()
	if len(clientSent) != 1 {
		t.Fatalf("client.Send called %d times, want 1", len(clientSent))
	}
	if clientSent[0].Direction != envelope.Receive {
		t.Errorf("client received direction %v, want Receive", clientSent[0].Direction)
	}

	// Both channels should be closed.
	if !clientCh.isClosed() {
		t.Error("client channel not closed")
	}
	if !upstreamCh.isClosed() {
		t.Error("upstream channel not closed")
	}
}

func TestRunSession_Stream(t *testing.T) {
	var clientEnvelopes []*envelope.Envelope
	var upstreamEnvelopes []*envelope.Envelope
	for i := 0; i < 3; i++ {
		clientEnvelopes = append(clientEnvelopes, makeEnvelope(envelope.Send, i))
		upstreamEnvelopes = append(upstreamEnvelopes, makeEnvelope(envelope.Receive, i))
	}

	gate := make(chan struct{}, len(upstreamEnvelopes)+1)
	for i := 0; i < len(upstreamEnvelopes)+1; i++ {
		gate <- struct{}{}
	}

	clientCh := &mockChannel{
		streamID:      "stream",
		nextEnvelopes: clientEnvelopes,
	}
	upstreamCh := &mockChannel{
		streamID:      "upstream",
		nextEnvelopes: upstreamEnvelopes,
		nextGate:      gate,
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCh, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	upSent := upstreamCh.getSent()
	if len(upSent) != 3 {
		t.Fatalf("upstream.Send called %d times, want 3", len(upSent))
	}

	clientSent := clientCh.getSent()
	if len(clientSent) != 3 {
		t.Fatalf("client.Send called %d times, want 3", len(clientSent))
	}
}

func TestRunSession_PipelineDrop(t *testing.T) {
	req := makeEnvelope(envelope.Send, 0)

	clientCh := &mockChannel{
		streamID:      "stream",
		nextEnvelopes: []*envelope.Envelope{req},
	}

	dialCalled := false
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		dialCalled = true
		return &mockChannel{}, nil
	}

	p := pipeline.New(dropStep{})

	err := RunSession(context.Background(), clientCh, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if dialCalled {
		t.Error("dial should not be called when all envelopes are dropped")
	}

	if !clientCh.isClosed() {
		t.Error("client channel not closed")
	}
}

func TestRunSession_PipelineRespond(t *testing.T) {
	req := makeEnvelope(envelope.Send, 0)
	customResp := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("blocked"),
		Message:   &envelope.RawMessage{Bytes: []byte("blocked")},
	}

	clientCh := &mockChannel{
		streamID:      "stream",
		nextEnvelopes: []*envelope.Envelope{req},
	}

	dialCalled := false
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		dialCalled = true
		return &mockChannel{}, nil
	}

	p := pipeline.New(respondStep{resp: customResp})

	err := RunSession(context.Background(), clientCh, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if dialCalled {
		t.Error("dial should not be called when pipeline responds directly")
	}

	clientSent := clientCh.getSent()
	if len(clientSent) != 1 {
		t.Fatalf("client.Send called %d times, want 1", len(clientSent))
	}
	if string(clientSent[0].Raw) != "blocked" {
		t.Errorf("client received raw %q, want %q", clientSent[0].Raw, "blocked")
	}
}

func TestRunSession_DialFailure(t *testing.T) {
	req := makeEnvelope(envelope.Send, 0)

	clientCh := &mockChannel{
		streamID:      "stream",
		nextEnvelopes: []*envelope.Envelope{req},
	}

	dialErr := errors.New("connection refused")
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return nil, dialErr
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCh, dial, p)
	if err == nil {
		t.Fatal("RunSession should return error on dial failure")
	}
	if !errors.Is(err, dialErr) {
		t.Errorf("error %v does not wrap %v", err, dialErr)
	}

	if !clientCh.isClosed() {
		t.Error("client channel not closed after dial failure")
	}
}

func TestRunSession_ContextCancel(t *testing.T) {
	clientCh := &mockChannel{
		streamID:  "stream",
		blockNext: make(chan struct{}),
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &mockChannel{}, nil
	}
	p := pipeline.New(passStep{})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, clientCh, dial, p)
	}()

	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunSession did not terminate after context cancellation")
	}

	if !clientCh.isClosed() {
		t.Error("client channel not closed after context cancellation")
	}
}

func TestRunSession_ClientNextError(t *testing.T) {
	clientErr := fmt.Errorf("read error")
	clientCh := &mockChannel{
		streamID: "stream",
		nextErr:  clientErr,
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &mockChannel{}, nil
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCh, dial, p)
	if err == nil {
		t.Fatal("RunSession should return error on client.Next failure")
	}
	if !errors.Is(err, clientErr) {
		t.Errorf("error %v does not wrap %v", err, clientErr)
	}
}

func TestRunSession_UpstreamSendError(t *testing.T) {
	req := makeEnvelope(envelope.Send, 0)
	clientCh := &mockChannel{
		streamID:      "stream",
		nextEnvelopes: []*envelope.Envelope{req},
	}

	sendErr := fmt.Errorf("write error")
	upstreamCh := &mockChannel{
		streamID: "upstream",
		sendErr:  sendErr,
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCh, dial, p)
	if err == nil {
		t.Fatal("RunSession should return error on upstream.Send failure")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("error %v does not wrap %v", err, sendErr)
	}
}

func TestRunSession_ClientSendRespondError(t *testing.T) {
	req := makeEnvelope(envelope.Send, 0)
	customResp := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolRaw,
	}

	sendErr := fmt.Errorf("client send error")
	clientCh := &mockChannel{
		streamID:      "stream",
		nextEnvelopes: []*envelope.Envelope{req},
		sendErr:       sendErr,
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &mockChannel{}, nil
	}
	p := pipeline.New(respondStep{resp: customResp})

	err := RunSession(context.Background(), clientCh, dial, p)
	if err == nil {
		t.Fatal("RunSession should return error on client.Send failure during respond")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("error %v does not wrap %v", err, sendErr)
	}
}

func TestRunSession_NoUpstreamCloseOnNil(t *testing.T) {
	req := makeEnvelope(envelope.Send, 0)
	clientCh := &mockChannel{
		streamID:      "stream",
		nextEnvelopes: []*envelope.Envelope{req},
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &mockChannel{}, nil
	}
	p := pipeline.New(dropStep{})

	// Should not panic.
	err := RunSession(context.Background(), clientCh, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}
}

func TestRunSession_OnComplete_NormalEOF(t *testing.T) {
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "stream-1")
	resp := makeEnvelopeWithStreamID(envelope.Receive, 1, "stream-1")

	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{req},
	}
	upstreamCh := &mockChannel{
		streamID:      "upstream",
		nextEnvelopes: []*envelope.Envelope{resp},
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	var gotStreamID string
	var gotErr error
	called := false

	opts := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, err error) {
			called = true
			gotStreamID = streamID
			gotErr = err
		},
	}

	err := RunSession(context.Background(), clientCh, dial, p, opts)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if !called {
		t.Fatal("OnComplete was not called")
	}
	if gotStreamID != "stream-1" {
		t.Errorf("OnComplete streamID = %q, want %q", gotStreamID, "stream-1")
	}
	if gotErr != nil {
		t.Errorf("OnComplete err = %v, want nil", gotErr)
	}
}

func TestRunSession_OnComplete_Error(t *testing.T) {
	sendErr := fmt.Errorf("upstream write error")
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "stream-err")

	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{req},
	}
	upstreamCh := &mockChannel{
		streamID: "upstream",
		sendErr:  sendErr,
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	var gotStreamID string
	var gotErr error
	called := false

	opts := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, err error) {
			called = true
			gotStreamID = streamID
			gotErr = err
		},
	}

	err := RunSession(context.Background(), clientCh, dial, p, opts)
	if err == nil {
		t.Fatal("RunSession should return error")
	}

	if !called {
		t.Fatal("OnComplete was not called on error")
	}
	if gotStreamID != "stream-err" {
		t.Errorf("OnComplete streamID = %q, want %q", gotStreamID, "stream-err")
	}
	if !errors.Is(gotErr, sendErr) {
		t.Errorf("OnComplete err = %v, want wrapping %v", gotErr, sendErr)
	}
}

func TestRunSession_OnComplete_Nil(t *testing.T) {
	req := makeEnvelope(envelope.Send, 0)
	resp := makeEnvelope(envelope.Receive, 1)

	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{req},
	}
	upstreamCh := &mockChannel{
		streamID:      "upstream",
		nextEnvelopes: []*envelope.Envelope{resp},
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	// No opts at all — backward compatible.
	err := RunSession(context.Background(), clientCh, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	// Explicit nil OnComplete.
	err = RunSession(context.Background(),
		&mockChannel{
			streamID:      "client2",
			nextEnvelopes: []*envelope.Envelope{makeEnvelope(envelope.Send, 0)},
		},
		func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return &mockChannel{
				streamID:      "upstream2",
				nextEnvelopes: []*envelope.Envelope{makeEnvelope(envelope.Receive, 1)},
			}, nil
		},
		pipeline.New(passStep{}),
		SessionOptions{OnComplete: nil},
	)
	if err != nil {
		t.Fatalf("RunSession returned error with nil OnComplete: %v", err)
	}
}

func TestRunSession_OnComplete_StreamIDFromFirstEnvelope(t *testing.T) {
	env1 := makeEnvelopeWithStreamID(envelope.Send, 0, "first-stream")
	env2 := makeEnvelopeWithStreamID(envelope.Send, 1, "second-stream")

	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{env1, env2},
	}
	upstreamCh := &mockChannel{streamID: "upstream"}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	var gotStreamID string
	opts := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, _ error) {
			gotStreamID = streamID
		},
	}

	_ = RunSession(context.Background(), clientCh, dial, p, opts)

	if gotStreamID != "first-stream" {
		t.Errorf("OnComplete streamID = %q, want %q", gotStreamID, "first-stream")
	}
}

// TestRunSession_UnifiesReceiveStreamID verifies that when the upstream
// Channel yields an envelope with a StreamID different from the one stamped
// by the client Channel, RunSession rewrites the receive-direction envelope
// to carry the client-side StreamID before the Pipeline runs. This is the
// invariant that USK-615 restores: one logical exchange = one flow.Stream,
// with both Send and Receive flows linked by the same identifier.
func TestRunSession_UnifiesReceiveStreamID(t *testing.T) {
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "client-uuid")
	resp := makeEnvelopeWithStreamID(envelope.Receive, 0, "upstream-uuid")

	clientCh := &mockChannel{
		streamID:      "client-conn",
		nextEnvelopes: []*envelope.Envelope{req},
	}
	upstreamCh := &mockChannel{
		streamID:      "upstream-conn",
		nextEnvelopes: []*envelope.Envelope{resp},
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}

	var (
		mu   sync.Mutex
		seen []capturedEnv
	)
	capture := &captureStep{mu: &mu, seen: &seen}
	p := pipeline.New(capture)

	if err := RunSession(context.Background(), clientCh, dial, p); err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("Pipeline saw %d envelopes, want 2", len(seen))
	}

	// Send-direction envelope should retain the client-side StreamID as-is.
	sendSeen := findCaptured(seen, envelope.Send)
	if sendSeen == nil {
		t.Fatal("no send envelope seen by Pipeline")
	}
	if sendSeen.streamID != "client-uuid" {
		t.Errorf("send StreamID seen by Pipeline = %q, want client-uuid", sendSeen.streamID)
	}

	// Receive-direction envelope must be rewritten to the client-side StreamID
	// BEFORE the Pipeline runs. Before USK-615 this would be "upstream-uuid".
	recvSeen := findCaptured(seen, envelope.Receive)
	if recvSeen == nil {
		t.Fatal("no receive envelope seen by Pipeline")
	}
	if recvSeen.streamID != "client-uuid" {
		t.Errorf("receive StreamID seen by Pipeline = %q, want client-uuid (unified from upstream-uuid)", recvSeen.streamID)
	}
}

// TestRunSession_UnifyReceiveStreamID_EmptyClientStreamID covers the defensive
// branch where the client-side StreamID is empty (e.g., the Channel produced
// an envelope without stamping one). In that case the rewrite is skipped —
// we do not want to clobber the upstream value with an empty string.
func TestRunSession_UnifyReceiveStreamID_EmptyClientStreamID(t *testing.T) {
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "")
	resp := makeEnvelopeWithStreamID(envelope.Receive, 0, "upstream-kept")

	clientCh := &mockChannel{
		streamID:      "client-conn",
		nextEnvelopes: []*envelope.Envelope{req},
	}
	upstreamCh := &mockChannel{
		streamID:      "upstream-conn",
		nextEnvelopes: []*envelope.Envelope{resp},
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}

	var (
		mu   sync.Mutex
		seen []capturedEnv
	)
	capture := &captureStep{mu: &mu, seen: &seen}
	p := pipeline.New(capture)

	if err := RunSession(context.Background(), clientCh, dial, p); err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	recvSeen := findCaptured(seen, envelope.Receive)
	if recvSeen == nil {
		t.Fatal("no receive envelope seen by Pipeline")
	}
	if recvSeen.streamID != "upstream-kept" {
		t.Errorf("receive StreamID seen by Pipeline = %q, want upstream-kept (no rewrite when client-side empty)", recvSeen.streamID)
	}
}

func TestRunSession_OnComplete_ContextNotCancelled(t *testing.T) {
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "ctx-test")
	resp := makeEnvelopeWithStreamID(envelope.Receive, 1, "ctx-test")

	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{req},
	}
	upstreamCh := &mockChannel{
		streamID:      "upstream",
		nextEnvelopes: []*envelope.Envelope{resp},
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	var ctxErr error
	opts := SessionOptions{
		OnComplete: func(ctx context.Context, _ string, _ error) {
			ctxErr = ctx.Err()
		},
	}

	err := RunSession(context.Background(), clientCh, dial, p, opts)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if ctxErr != nil {
		t.Errorf("OnComplete context was cancelled: %v", ctxErr)
	}
}

// TestRunSession_CascadeCloseOnClientError verifies that when
// clientToUpstream returns a non-EOF error (e.g., client-side RST_STREAM), the
// upstream Channel is actively closed so upstreamToClient's pending Next
// unblocks promptly. Before USK-616 the errgroup context cancel did not
// reliably unblock Next on all Channel implementations, causing OnComplete to
// never fire and flow.Stream.State to remain "active" even for canceled
// streams.
func TestRunSession_CascadeCloseOnClientError(t *testing.T) {
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "cascade-stream")
	streamErr := &layer.StreamError{Code: layer.ErrorCanceled, Reason: "client canceled"}

	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{req},
		// After the first envelope is delivered, the next Next call returns
		// a StreamError to simulate an abnormal client exit (e.g.,
		// RST_STREAM(CANCEL)).
		nextErr: streamErr,
	}

	// Upstream mock: Next blocks until Close is called. Close will unblock
	// the pending Next by closing blockNext, and then Next returns io.EOF
	// (because nextErr is unset). This models the HTTP/2 channel.Close
	// behavior where Close closes the recv queue and any pending Next
	// unblocks promptly.
	upstreamCh := &mockChannel{
		streamID:  "upstream",
		blockNext: make(chan struct{}),
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	var (
		called       bool
		gotStreamID  string
		gotErr       error
		onCompleteMu sync.Mutex
	)
	opts := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, err error) {
			onCompleteMu.Lock()
			defer onCompleteMu.Unlock()
			called = true
			gotStreamID = streamID
			gotErr = err
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, clientCh, dial, p, opts)
	}()

	select {
	case err := <-done:
		// Session should return the wrapped StreamError.
		if err == nil {
			t.Fatal("RunSession should return error")
		}
		if !errors.Is(err, streamErr) {
			t.Errorf("RunSession err = %v, want wrapping %v", err, streamErr)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("RunSession did not terminate within 1.5s — upstream cascade close did not unblock response goroutine")
	}

	// Upstream must have been closed at least twice:
	//   1. the cascade close triggered by the new defer in clientToUpstream
	//   2. the outer defer in RunSession that closes uh.ch
	// Real Channel implementations (and our mock) are idempotent, so the
	// second call is observed but is a no-op on the underlying state. A count
	// of 2 indicates the cascade fired; a count of 1 would indicate only the
	// outer defer ran, which means the cascade is missing.
	if got := upstreamCh.getCloseCalls(); got < 2 {
		t.Errorf("upstream Close calls = %d, want >= 2 (cascade close missing — only outer defer ran)", got)
	}

	// OnComplete must have fired with the StreamError.
	onCompleteMu.Lock()
	defer onCompleteMu.Unlock()
	if !called {
		t.Fatal("OnComplete was not called")
	}
	if gotStreamID != "cascade-stream" {
		t.Errorf("OnComplete streamID = %q, want %q", gotStreamID, "cascade-stream")
	}
	if gotErr == nil {
		t.Fatal("OnComplete err = nil, want StreamError")
	}
	var se *layer.StreamError
	if !errors.As(gotErr, &se) {
		t.Fatalf("OnComplete err = %v, want unwrappable to *layer.StreamError", gotErr)
	}
	if se.Code != layer.ErrorCanceled {
		t.Errorf("OnComplete StreamError.Code = %v, want %v", se.Code, layer.ErrorCanceled)
	}
}

// TestRunSession_NoCascadeOnNormalEOF verifies that on normal EOF from the
// client (err == nil from clientToUpstream), the upstream Channel is NOT
// prematurely closed by the new cascade-close defer. This preserves HTTP/1.x
// single-request semantics where the client half-closes after the request
// and the response is still being delivered.
//
// The critical invariant: the response envelope must round-trip successfully
// before the outer RunSession defer closes the upstream. If the cascade
// defer fired on nil err, the upstream would be closed prematurely and the
// response would be lost.
func TestRunSession_NoCascadeOnNormalEOF(t *testing.T) {
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "normal-stream")
	resp := makeEnvelopeWithStreamID(envelope.Receive, 0, "normal-stream")

	// Client: first call returns req, second returns io.EOF (normal termination).
	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{req},
	}

	// Upstream: two Next calls. First returns the response after ~50ms delay
	// (so the client-side goroutine exits with EOF first, testing that the
	// response goroutine still gets its envelope); second returns io.EOF.
	// We implement the delay via nextGate.
	gate := make(chan struct{}, 2)
	go func() {
		// Let the first Next return after a short delay so clientToUpstream
		// has time to see EOF and hit its defer without the cascade firing.
		time.Sleep(50 * time.Millisecond)
		gate <- struct{}{}
		// Second call returns io.EOF immediately.
		gate <- struct{}{}
	}()
	upstreamCh := &mockChannel{
		streamID:      "upstream",
		nextEnvelopes: []*envelope.Envelope{resp},
		nextGate:      gate,
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	var (
		called       bool
		gotErr       error
		onCompleteMu sync.Mutex
	)
	opts := SessionOptions{
		OnComplete: func(_ context.Context, _ string, err error) {
			onCompleteMu.Lock()
			defer onCompleteMu.Unlock()
			called = true
			gotErr = err
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, clientCh, dial, p, opts)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunSession returned error on normal EOF: %v", err)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("RunSession did not terminate within 1.5s")
	}

	// Upstream Close must have been called exactly once — by the outer defer
	// in RunSession. The cascade defer in clientToUpstream must NOT fire on
	// nil err (EOF path).
	if got := upstreamCh.getCloseCalls(); got != 1 {
		t.Errorf("upstream Close calls = %d, want 1 (cascade fired on nil err: %v)", got, got > 1)
	}

	// The response envelope must have reached the client BEFORE upstream was
	// closed. Verify by checking client.Send was called with the receive envelope.
	sent := clientCh.getSent()
	if len(sent) != 1 {
		t.Fatalf("client.Send called %d times, want 1 (response lost due to premature cascade close?)", len(sent))
	}
	if sent[0].Direction != envelope.Receive {
		t.Errorf("client received direction %v, want Receive", sent[0].Direction)
	}

	// OnComplete must have fired with nil err.
	onCompleteMu.Lock()
	defer onCompleteMu.Unlock()
	if !called {
		t.Fatal("OnComplete was not called")
	}
	if gotErr != nil {
		t.Errorf("OnComplete err = %v, want nil (normal EOF)", gotErr)
	}
}

// TestRunSession_LateClientErrorCascadesToUpstream verifies that an error
// that arrives on the client Channel AFTER clientToUpstream has already
// returned io.EOF still causes the upstream Channel to be closed and the
// session to terminate with an error result. This models the HTTP/2
// scenario where the client sends HEADERS(endStream=true) followed by a
// late RST_STREAM — the cascade-close defer in clientToUpstream misses the
// late error (Next already returned EOF), so the late-error watcher must
// pick it up.
func TestRunSession_LateClientErrorCascadesToUpstream(t *testing.T) {
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "late-err-stream")
	streamErr := &layer.StreamError{Code: layer.ErrorCanceled, Reason: "late cancel"}

	// Client: first Next returns req; subsequent Next calls return EOF.
	// The test fires fireTerminated(streamErr) to model a late RST_STREAM
	// arriving after the client half-closed — the watcher observes it via
	// Closed()/Err() instead of driving Next.
	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{req},
	}

	// Upstream: blocks on Next until Close is called (Close unblocks via
	// blockNext, then Next returns io.EOF). This mirrors the real upstream
	// HTTP/2 Channel: Close emits RST_STREAM and closes the recv side.
	upstreamCh := &mockChannel{
		streamID:  "upstream",
		blockNext: make(chan struct{}),
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(passStep{})

	var (
		called       bool
		gotErr       error
		onCompleteMu sync.Mutex
	)
	opts := SessionOptions{
		OnComplete: func(_ context.Context, _ string, err error) {
			onCompleteMu.Lock()
			defer onCompleteMu.Unlock()
			called = true
			gotErr = err
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, clientCh, dial, p, opts)
	}()

	// Give the session a moment to forward the request and reach the
	// post-EOF waiting state, then fire the late-error signal on the
	// client Channel. 50ms is ample — the watcher parks on Closed()
	// without polling.
	time.Sleep(50 * time.Millisecond)
	clientCh.fireTerminated(streamErr)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunSession should return error when late client cancel is detected")
		}
		if !errors.Is(err, streamErr) {
			t.Errorf("RunSession err = %v, want wrapping %v", err, streamErr)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("RunSession did not terminate after late client error injection")
	}

	// Upstream must have been closed at least once (by the watcher). The
	// outer RunSession defer also closes it, so we expect >= 2.
	if got := upstreamCh.getCloseCalls(); got < 2 {
		t.Errorf("upstream Close calls = %d, want >= 2 (watcher cascade missing)", got)
	}

	// OnComplete must have fired with the late error surfaced.
	onCompleteMu.Lock()
	defer onCompleteMu.Unlock()
	if !called {
		t.Fatal("OnComplete was not called")
	}
	var se *layer.StreamError
	if !errors.As(gotErr, &se) {
		t.Fatalf("OnComplete err = %v, want unwrappable to *layer.StreamError", gotErr)
	}
	if se.Code != layer.ErrorCanceled {
		t.Errorf("OnComplete StreamError.Code = %v, want %v", se.Code, layer.ErrorCanceled)
	}
}

func TestRunSession_OnComplete_AllDropped(t *testing.T) {
	req := makeEnvelopeWithStreamID(envelope.Send, 0, "dropped-stream")

	clientCh := &mockChannel{
		streamID:      "client",
		nextEnvelopes: []*envelope.Envelope{req},
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &mockChannel{}, nil
	}
	p := pipeline.New(dropStep{})

	var gotStreamID string
	var gotErr error
	called := false

	opts := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, err error) {
			called = true
			gotStreamID = streamID
			gotErr = err
		},
	}

	err := RunSession(context.Background(), clientCh, dial, p, opts)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if !called {
		t.Fatal("OnComplete was not called when all envelopes dropped")
	}
	if gotStreamID != "dropped-stream" {
		t.Errorf("OnComplete streamID = %q, want %q", gotStreamID, "dropped-stream")
	}
	if gotErr != nil {
		t.Errorf("OnComplete err = %v, want nil", gotErr)
	}
}

// TestClassifyError covers the USK-620 helper that OnComplete closures use
// to project a *layer.StreamError's code into flow.StreamUpdate.FailureReason.
// The helper must traverse %w wrapping (session.RunSession wraps dial errors
// as "dial: %w") and return the empty string for unclassified errors so the
// FailureReason column remains empty when no protocol-level classification
// applies.
func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"refused", &layer.StreamError{Code: layer.ErrorRefused, Reason: "GOAWAY received"}, "refused"},
		{"canceled", &layer.StreamError{Code: layer.ErrorCanceled}, "canceled"},
		{"aborted", &layer.StreamError{Code: layer.ErrorAborted}, "aborted"},
		{"internal_error", &layer.StreamError{Code: layer.ErrorInternalError}, "internal_error"},
		{"protocol_error", &layer.StreamError{Code: layer.ErrorProtocol}, "protocol_error"},
		{
			"wrapped refused",
			fmt.Errorf("dial: %w", &layer.StreamError{Code: layer.ErrorRefused, Reason: "layer shutdown"}),
			"refused",
		},
		{
			"double-wrapped canceled",
			fmt.Errorf("upstream.Next: %w", fmt.Errorf("inner: %w", &layer.StreamError{Code: layer.ErrorCanceled})),
			"canceled",
		},
		{"plain ctx cancel", context.Canceled, ""},
		{"plain ctx deadline", context.DeadlineExceeded, ""},
		{"unclassified error", errors.New("something else"), ""},
		{"io.EOF", io.EOF, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyError(tc.err)
			if got != tc.want {
				t.Errorf("ClassifyError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// --- USK-634: session body-buffer backstop -----------------------------------
//
// The backstop exists because Pipeline.Run's variant-snapshot Clone calls
// HTTPMessage.CloneMessage, which calls BodyBuffer.Retain. The snapshot is
// reachable only through the ctx threaded into Run; once Run returns that ctx
// goes out of scope, and Go's GC will happily reclaim the snapshot struct
// without decrementing the BodyBuffer's refcount. Without the backstop the
// temp file would leak on every exchange where Pipeline.Run saw a
// BodyBuffer — i.e. every disk-backed-body request or response.
//
// These tests model the Layer's refcount ownership by constructing buffers at
// refCount=1 (bodybuf.NewFile's default, matching what a Layer assembler would
// produce) and asserting the outcome the session observes. For pass-through
// paths the test issues a final manual Release after the session returns, to
// mirror the channel.Send zero-copy / channel.Close Release a real Layer would
// perform. The file-count assertion then checks that backstop + Layer-sim
// Release together drop the refcount to zero.
//
// For Transform-style paths the Step itself Releases one ref (the Layer's
// ref, in the real system), so the post-session state is already refCount=0
// and the test must not issue another Release (which would panic under the
// sync.WaitGroup.Done()-style contract of bodybuf.Release on a zero refcount).

// bodyBufSpillPrefix matches config.BodySpillPrefix. Hardcoded to avoid an
// import cycle via internal/config.
const bodyBufSpillPrefix = "yorishiro-body-"

// makeHTTPEnvelopeWithBuf constructs an HTTPMessage envelope carrying a
// freshly allocated file-backed BodyBuffer at refCount=1. The buffer is
// pre-populated with payload so its temp file exists on disk.
func makeHTTPEnvelopeWithBuf(t *testing.T, dir string, dir_ envelope.Direction, seq int, payload []byte) *envelope.Envelope {
	t.Helper()
	buf, err := bodybuf.NewFile(dir, bodyBufSpillPrefix, 1<<20)
	if err != nil {
		t.Fatalf("bodybuf.NewFile: %v", err)
	}
	if _, err := buf.Write(payload); err != nil {
		t.Fatalf("bodybuf.Write: %v", err)
	}
	return &envelope.Envelope{
		Direction: dir_,
		Sequence:  seq,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       append([]byte(nil), payload...),
		Message: &envelope.HTTPMessage{
			Method:     "POST",
			Path:       "/",
			BodyBuffer: buf,
		},
	}
}

// countSpillFiles returns the number of yorishiro-body-*- files in dir.
func countSpillFiles(t *testing.T, dir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, bodyBufSpillPrefix+"*"))
	if err != nil {
		t.Fatalf("filepath.Glob: %v", err)
	}
	return len(matches)
}

// envelopeBuf extracts the BodyBuffer pointer from an HTTPMessage envelope.
func envelopeBuf(t *testing.T, env *envelope.Envelope) *bodybuf.BodyBuffer {
	t.Helper()
	m, ok := env.Message.(*envelope.HTTPMessage)
	if !ok || m == nil {
		t.Fatalf("envelope is not HTTPMessage: %#v", env.Message)
	}
	return m.BodyBuffer
}

// transformReleaseStep models rules/http.TransformEngine's ReplaceBody commit:
// it Releases the current envelope's BodyBuffer and nils the pointer. The
// snapshot taken at Pipeline.Run entry still holds its own Retain'd reference,
// which only the session backstop can Release.
type transformReleaseStep struct{}

func (transformReleaseStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if m, ok := env.Message.(*envelope.HTTPMessage); ok && m != nil && m.BodyBuffer != nil {
		_ = m.BodyBuffer.Release()
		m.BodyBuffer = nil
		m.Body = []byte("transformed")
	}
	return pipeline.Result{Action: pipeline.Continue}
}

// TestRunSession_BodyBufferBackstop_ContinuePath verifies that the backstop
// Releases both outstanding Retains on a disk-backed body at session end:
// the Layer-owned Retain from bodybuf.NewFile plus the Pipeline.Run variant-
// snapshot Retain. No manual Release is issued — any additional Release would
// panic with Release-below-zero, which is itself a useful assertion that the
// accounting is exact.
func TestRunSession_BodyBufferBackstop_ContinuePath(t *testing.T) {
	dir := t.TempDir()
	req := makeHTTPEnvelopeWithBuf(t, dir, envelope.Send, 0, []byte("request"))
	resp := makeHTTPEnvelopeWithBuf(t, dir, envelope.Receive, 0, []byte("response"))
	reqBuf := envelopeBuf(t, req)
	respBuf := envelopeBuf(t, resp)

	if got := countSpillFiles(t, dir); got != 2 {
		t.Fatalf("setup: spill files = %d, want 2", got)
	}

	clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{req}}
	upstreamCh := &mockChannel{streamID: "u", nextEnvelopes: []*envelope.Envelope{resp}}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) { return upstreamCh, nil }

	if err := RunSession(context.Background(), clientCh, dial, pipeline.New(passStep{})); err != nil {
		t.Fatalf("RunSession: %v", err)
	}

	// Both req and resp buffers should have been fully released by drain.
	// Probe: Bytes() errors on a released buffer.
	if _, err := reqBuf.Bytes(context.Background()); err == nil {
		t.Error("expected reqBuf Bytes() to error after full teardown")
	}
	if _, err := respBuf.Bytes(context.Background()); err == nil {
		t.Error("expected respBuf Bytes() to error after full teardown")
	}

	if got := countSpillFiles(t, dir); got != 0 {
		t.Errorf("after session: spill files = %d, want 0 (backstop must release both Retains)", got)
	}
}

// TestRunSession_BodyBufferBackstop_DropPath covers the Drop branch of
// Pipeline.Run where the envelope is discarded before Send. The backstop must
// release BOTH the Layer Retain and the snapshot Retain (drop doesn't consume
// the buffer anywhere downstream).
func TestRunSession_BodyBufferBackstop_DropPath(t *testing.T) {
	dir := t.TempDir()
	req := makeHTTPEnvelopeWithBuf(t, dir, envelope.Send, 0, []byte("drop-me"))
	reqBuf := envelopeBuf(t, req)

	clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{req}}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		t.Error("dial should not be called on Drop path")
		return &mockChannel{}, nil
	}

	if err := RunSession(context.Background(), clientCh, dial, pipeline.New(dropStep{})); err != nil {
		t.Fatalf("RunSession: %v", err)
	}

	if _, err := reqBuf.Bytes(context.Background()); err == nil {
		t.Error("expected reqBuf Bytes() to error after drop session teardown")
	}
	if got := countSpillFiles(t, dir); got != 0 {
		t.Errorf("after drop session: spill files = %d, want 0", got)
	}
}

// TestRunSession_BodyBufferBackstop_RespondPath covers the Respond branch,
// where the Step synthesizes a response envelope that is sent back to the
// client without touching the upstream. Both the original request's
// BodyBuffer (snapshot Retain) AND the synthetic response's BodyBuffer must
// be tracked. No current Step populates resp.Message.BodyBuffer, but the
// backstop registers it defensively — any future plugin or rule that
// synthesizes a body-carrying response must not leak its buffer.
func TestRunSession_BodyBufferBackstop_RespondPath(t *testing.T) {
	dir := t.TempDir()
	req := makeHTTPEnvelopeWithBuf(t, dir, envelope.Send, 0, []byte("blocked-request"))
	customResp := makeHTTPEnvelopeWithBuf(t, dir, envelope.Receive, 0, []byte("custom-response"))
	reqBuf := envelopeBuf(t, req)
	respBuf := envelopeBuf(t, customResp)

	if got := countSpillFiles(t, dir); got != 2 {
		t.Fatalf("setup: spill files = %d, want 2", got)
	}

	clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{req}}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		t.Error("dial should not be called on Respond path")
		return &mockChannel{}, nil
	}

	p := pipeline.New(respondStep{resp: customResp})
	if err := RunSession(context.Background(), clientCh, dial, p); err != nil {
		t.Fatalf("RunSession: %v", err)
	}

	// req: Layer Retain (+1) + Pipeline.Run snapshot Retain (+1) = 2. Drain
	// Releases both (Respond path keeps msg.BodyBuffer == pre, so the backstop
	// owns the Layer Retain). No manual Release — would panic.
	// customResp: Layer Retain = 1, tracked by reg.trackEnvelope(resp), drain
	// Releases once → refcount 0 → file removed. An additional Release would
	// panic; assert via file count + Bytes() error instead.
	if got := countSpillFiles(t, dir); got != 0 {
		t.Errorf("after respond session: spill files = %d, want 0", got)
	}

	if _, err := reqBuf.Bytes(context.Background()); err == nil {
		t.Error("expected reqBuf Bytes() to error after session teardown")
	}
	if _, err := respBuf.Bytes(context.Background()); err == nil {
		t.Error("expected respBuf Bytes() to error after session teardown")
	}
}

// TestRunSession_BodyBufferBackstop_DialFailure covers the error-exit path
// where upstream dial fails after Pipeline.Run completed. The snapshot Retain
// is outstanding at the moment the goroutine returns the dial error; the
// backstop must still run.
func TestRunSession_BodyBufferBackstop_DialFailure(t *testing.T) {
	dir := t.TempDir()
	req := makeHTTPEnvelopeWithBuf(t, dir, envelope.Send, 0, []byte("req"))
	reqBuf := envelopeBuf(t, req)

	clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{req}}
	dialErr := errors.New("connection refused")
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return nil, dialErr
	}

	err := RunSession(context.Background(), clientCh, dial, pipeline.New(passStep{}))
	if !errors.Is(err, dialErr) {
		t.Fatalf("RunSession err = %v, want wrap of %v", err, dialErr)
	}

	// Dial failure means no channel.Send ever ran — the backstop must release
	// both Retains (Layer + snapshot) so the temp file is unlinked. No manual
	// Release — would panic on the zero refcount.
	if _, err := reqBuf.Bytes(context.Background()); err == nil {
		t.Error("expected reqBuf Bytes() to error after dial-failure teardown")
	}
	if got := countSpillFiles(t, dir); got != 0 {
		t.Errorf("after dial failure: spill files = %d, want 0", got)
	}
}

// TestRunSession_BodyBufferBackstop_TransformCommit verifies that when a Step
// Releases its own reference to a BodyBuffer (rules/http.TransformEngine's
// ReplaceBody commit contract, USK-633), the session backstop cleanly
// releases the snapshot's Retain without panicking on a double-Release.
// This is the load-bearing refcount invariant for USK-634.
func TestRunSession_BodyBufferBackstop_TransformCommit(t *testing.T) {
	dir := t.TempDir()
	req := makeHTTPEnvelopeWithBuf(t, dir, envelope.Send, 0, []byte("original-body"))
	reqBuf := envelopeBuf(t, req)

	if got := countSpillFiles(t, dir); got != 1 {
		t.Fatalf("setup: spill files = %d, want 1", got)
	}

	clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{req}}
	upstreamCh := &mockChannel{streamID: "u"}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) { return upstreamCh, nil }

	// transformReleaseStep: msg.BodyBuffer.Release() + msg.BodyBuffer=nil.
	// Starting refCount=1; Pipeline.Run Retain → 2; Step Release → 1;
	// session drain Release → 0 → teardown. No test-side Release — that
	// would panic because refcount is already zero.
	if err := RunSession(context.Background(), clientCh, dial, pipeline.New(transformReleaseStep{})); err != nil {
		t.Fatalf("RunSession: %v", err)
	}

	if _, err := reqBuf.Bytes(context.Background()); err == nil {
		t.Error("expected reqBuf Bytes() to error after full teardown")
	}
	if got := countSpillFiles(t, dir); got != 0 {
		t.Errorf("after transform commit session: spill files = %d, want 0", got)
	}
}

// TestRunSession_BodyBufferBackstop_ClientNextError covers the path where no
// envelope is ever received — the backstop registry is empty and drain is a
// no-op.
func TestRunSession_BodyBufferBackstop_ClientNextError(t *testing.T) {
	dir := t.TempDir()
	clientErr := errors.New("read error")
	clientCh := &mockChannel{streamID: "s", nextErr: clientErr}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &mockChannel{}, nil
	}

	err := RunSession(context.Background(), clientCh, dial, pipeline.New(passStep{}))
	if !errors.Is(err, clientErr) {
		t.Fatalf("RunSession err = %v, want wrap of %v", err, clientErr)
	}
	if got := countSpillFiles(t, dir); got != 0 {
		t.Errorf("no-envelope session: spill files = %d, want 0", got)
	}
}

// TestRunSession_BodyBufferBackstop_NonHTTPEnvelope verifies the backstop is
// a no-op for non-HTTP envelopes (Raw, WS, gRPC, SSE). These protocols do not
// use HTTPMessage.BodyBuffer today; the type-switch must skip them cleanly
// without allocating tracker slots.
func TestRunSession_BodyBufferBackstop_NonHTTPEnvelope(t *testing.T) {
	dir := t.TempDir()
	// RawMessage envelope — no BodyBuffer field, no tracking expected.
	req := makeEnvelope(envelope.Send, 0)
	resp := makeEnvelope(envelope.Receive, 0)

	clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{req}}
	upstreamCh := &mockChannel{streamID: "u", nextEnvelopes: []*envelope.Envelope{resp}}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) { return upstreamCh, nil }

	if err := RunSession(context.Background(), clientCh, dial, pipeline.New(passStep{})); err != nil {
		t.Fatalf("RunSession: %v", err)
	}
	if got := countSpillFiles(t, dir); got != 0 {
		t.Errorf("non-HTTP session: spill files = %d, want 0", got)
	}
}

// TestRunSession_BodyBufferBackstop_MultipleEnvelopes covers the streaming
// case where a single session processes many envelopes with disk-backed
// bodies. Registry append must accumulate every snapshot Retain and release
// all of them at drain time; a bounded-size optimization that dropped older
// entries would silently leak.
func TestRunSession_BodyBufferBackstop_MultipleEnvelopes(t *testing.T) {
	dir := t.TempDir()
	const n = 5
	reqs := make([]*envelope.Envelope, n)
	bufs := make([]*bodybuf.BodyBuffer, n)
	for i := 0; i < n; i++ {
		reqs[i] = makeHTTPEnvelopeWithBuf(t, dir, envelope.Send, i, []byte(fmt.Sprintf("req-%d", i)))
		bufs[i] = envelopeBuf(t, reqs[i])
	}
	if got := countSpillFiles(t, dir); got != n {
		t.Fatalf("setup: spill files = %d, want %d", got, n)
	}

	clientCh := &mockChannel{streamID: "s", nextEnvelopes: reqs}
	upstreamCh := &mockChannel{streamID: "u"}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) { return upstreamCh, nil }

	if err := RunSession(context.Background(), clientCh, dial, pipeline.New(passStep{})); err != nil {
		t.Fatalf("RunSession: %v", err)
	}

	// Backstop releases Layer+snapshot for every envelope; file count must
	// drop to zero purely from drain. An additional manual Release would
	// panic on the zero refcount.
	for i, b := range bufs {
		if _, err := b.Bytes(context.Background()); err == nil {
			t.Errorf("bufs[%d] Bytes() succeeded post-drain; expected released", i)
		}
	}
	if got := countSpillFiles(t, dir); got != 0 {
		t.Errorf("after streaming session: spill files = %d, want 0", got)
	}
}

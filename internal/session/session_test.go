package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
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
	blockNext     chan struct{} // if non-nil, Next blocks until closed or ctx done
	sendErr       error         // if set, Send returns this error
	nextGate      chan struct{} // if non-nil, Next waits for a value before each return
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
	defer m.mu.Unlock()
	m.closed = true
	return nil
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

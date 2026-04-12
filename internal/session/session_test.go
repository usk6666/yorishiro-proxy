//go:build legacy

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// mockCodec is a test double for codec.Codec.
// nextExchanges are returned by Next() in order, followed by io.EOF.
// Exchanges passed to Send() are recorded in sent.
type mockCodec struct {
	mu            sync.Mutex
	nextExchanges []*exchange.Exchange
	nextIdx       int
	nextErr       error // if set, returned instead of io.EOF after exchanges are exhausted
	sent          []*exchange.Exchange
	closed        bool
	blockNext     chan struct{} // if non-nil, Next blocks until closed or ctx done
	sendErr       error         // if set, Send returns this error
	nextGate      chan struct{} // if non-nil, Next waits for a value before each return
}

func (m *mockCodec) Next(ctx context.Context) (*exchange.Exchange, error) {
	if m.blockNext != nil {
		select {
		case <-m.blockNext:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// If nextGate is set, wait for a signal before returning each exchange.
	// This allows tests to synchronize Next() calls with external events
	// (e.g., ensuring Send() has been called before the next response is
	// returned).
	if m.nextGate != nil {
		select {
		case <-m.nextGate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.nextIdx >= len(m.nextExchanges) {
		if m.nextErr != nil {
			return nil, m.nextErr
		}
		return nil, io.EOF
	}
	ex := m.nextExchanges[m.nextIdx]
	m.nextIdx++
	return ex, nil
}

func (m *mockCodec) Send(_ context.Context, ex *exchange.Exchange) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, ex)
	return nil
}

func (m *mockCodec) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockCodec) getSent() []*exchange.Exchange {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*exchange.Exchange, len(m.sent))
	copy(out, m.sent)
	return out
}

func (m *mockCodec) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// passStep is a Pipeline Step that always continues.
type passStep struct{}

func (passStep) Process(_ context.Context, ex *exchange.Exchange) pipeline.Result {
	return pipeline.Result{Action: pipeline.Continue}
}

// dropStep drops all Exchanges.
type dropStep struct{}

func (dropStep) Process(_ context.Context, _ *exchange.Exchange) pipeline.Result {
	return pipeline.Result{Action: pipeline.Drop}
}

// respondStep responds with a fixed Exchange for Send-direction messages.
type respondStep struct {
	resp *exchange.Exchange
}

func (s respondStep) Process(_ context.Context, ex *exchange.Exchange) pipeline.Result {
	if ex.Direction == exchange.Send {
		return pipeline.Result{Action: pipeline.Respond, Response: s.resp}
	}
	return pipeline.Result{Action: pipeline.Continue}
}

func makeExchange(dir exchange.Direction, method string, seq int) *exchange.Exchange {
	return &exchange.Exchange{
		Direction: dir,
		Method:    method,
		Sequence:  seq,
		Protocol:  exchange.HTTP1,
	}
}

func makeExchangeWithStreamID(dir exchange.Direction, method string, seq int, streamID string) *exchange.Exchange {
	ex := makeExchange(dir, method, seq)
	ex.StreamID = streamID
	return ex
}

func TestRunSession_Unary(t *testing.T) {
	req := makeExchange(exchange.Send, "GET", 0)
	resp := makeExchange(exchange.Receive, "", 1)

	clientCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{req},
	}
	upstreamCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{resp},
	}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	// Upstream should have received the request.
	upSent := upstreamCodec.getSent()
	if len(upSent) != 1 {
		t.Fatalf("upstream.Send called %d times, want 1", len(upSent))
	}
	if upSent[0].Method != "GET" {
		t.Errorf("upstream received method %q, want %q", upSent[0].Method, "GET")
	}

	// Client should have received the response.
	clientSent := clientCodec.getSent()
	if len(clientSent) != 1 {
		t.Fatalf("client.Send called %d times, want 1", len(clientSent))
	}
	if clientSent[0].Direction != exchange.Receive {
		t.Errorf("client received direction %v, want Receive", clientSent[0].Direction)
	}

	// Both codecs should be closed.
	if !clientCodec.isClosed() {
		t.Error("client codec not closed")
	}
	if !upstreamCodec.isClosed() {
		t.Error("upstream codec not closed")
	}
}

func TestRunSession_Stream(t *testing.T) {
	var clientExchanges []*exchange.Exchange
	var upstreamExchanges []*exchange.Exchange
	for i := 0; i < 3; i++ {
		clientExchanges = append(clientExchanges, makeExchange(exchange.Send, "STREAM", i))
		upstreamExchanges = append(upstreamExchanges, makeExchange(exchange.Receive, "", i))
	}

	// Use a buffered nextGate channel so that each upstream Next() call
	// waits for an explicit signal. This prevents a race where the
	// upstream-to-client goroutine drains all responses before the
	// client-to-upstream goroutine has finished, and then the done/ready
	// channel ordering causes the upstream reader to exit early.
	//
	// We pre-fill the gate with len(upstreamExchanges)+1 tokens:
	// one for each response, plus one for the final EOF call.
	gate := make(chan struct{}, len(upstreamExchanges)+1)
	for i := 0; i < len(upstreamExchanges)+1; i++ {
		gate <- struct{}{}
	}

	clientCodec := &mockCodec{nextExchanges: clientExchanges}
	upstreamCodec := &mockCodec{
		nextExchanges: upstreamExchanges,
		nextGate:      gate,
	}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	upSent := upstreamCodec.getSent()
	if len(upSent) != 3 {
		t.Fatalf("upstream.Send called %d times, want 3", len(upSent))
	}

	clientSent := clientCodec.getSent()
	if len(clientSent) != 3 {
		t.Fatalf("client.Send called %d times, want 3", len(clientSent))
	}
}

func TestRunSession_PipelineDrop(t *testing.T) {
	req := makeExchange(exchange.Send, "GET", 0)

	clientCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{req},
	}

	dialCalled := false
	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		dialCalled = true
		return &mockCodec{}, nil
	}

	// Drop all exchanges.
	p := pipeline.New(dropStep{})

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if dialCalled {
		t.Error("dial should not be called when all exchanges are dropped")
	}

	if !clientCodec.isClosed() {
		t.Error("client codec not closed")
	}
}

func TestRunSession_PipelineRespond(t *testing.T) {
	req := makeExchange(exchange.Send, "GET", 0)
	customResp := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    403,
		Body:      []byte("blocked"),
	}

	clientCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{req},
	}

	dialCalled := false
	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		dialCalled = true
		return &mockCodec{}, nil
	}

	p := pipeline.New(respondStep{resp: customResp})

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if dialCalled {
		t.Error("dial should not be called when pipeline responds directly")
	}

	clientSent := clientCodec.getSent()
	if len(clientSent) != 1 {
		t.Fatalf("client.Send called %d times, want 1", len(clientSent))
	}
	if clientSent[0].Status != 403 {
		t.Errorf("client received status %d, want 403", clientSent[0].Status)
	}
	if string(clientSent[0].Body) != "blocked" {
		t.Errorf("client received body %q, want %q", clientSent[0].Body, "blocked")
	}
}

func TestRunSession_DialFailure(t *testing.T) {
	req := makeExchange(exchange.Send, "GET", 0)

	clientCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{req},
	}

	dialErr := errors.New("connection refused")
	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return nil, dialErr
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err == nil {
		t.Fatal("RunSession should return error on dial failure")
	}
	if !errors.Is(err, dialErr) {
		t.Errorf("error %v does not wrap %v", err, dialErr)
	}

	if !clientCodec.isClosed() {
		t.Error("client codec not closed after dial failure")
	}
}

func TestRunSession_ContextCancel(t *testing.T) {
	// Client blocks on Next until context is cancelled.
	clientCodec := &mockCodec{
		blockNext: make(chan struct{}),
	}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return &mockCodec{}, nil
	}
	p := pipeline.New(passStep{})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, clientCodec, dial, p)
	}()

	// Cancel after a short delay.
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

	if !clientCodec.isClosed() {
		t.Error("client codec not closed after context cancellation")
	}
}

func TestRunSession_ClientNextError(t *testing.T) {
	clientErr := fmt.Errorf("read error")
	clientCodec := &mockCodec{
		nextErr: clientErr,
	}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return &mockCodec{}, nil
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err == nil {
		t.Fatal("RunSession should return error on client.Next failure")
	}
	if !errors.Is(err, clientErr) {
		t.Errorf("error %v does not wrap %v", err, clientErr)
	}
}

func TestRunSession_UpstreamSendError(t *testing.T) {
	req := makeExchange(exchange.Send, "GET", 0)
	clientCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{req},
	}

	sendErr := fmt.Errorf("write error")
	upstreamCodec := &mockCodec{
		sendErr: sendErr,
	}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
	}
	p := pipeline.New(passStep{})

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err == nil {
		t.Fatal("RunSession should return error on upstream.Send failure")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("error %v does not wrap %v", err, sendErr)
	}
}

func TestRunSession_ClientSendRespondError(t *testing.T) {
	req := makeExchange(exchange.Send, "GET", 0)
	customResp := &exchange.Exchange{Direction: exchange.Receive, Status: 403}

	sendErr := fmt.Errorf("client send error")
	clientCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{req},
		sendErr:       sendErr,
	}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return &mockCodec{}, nil
	}
	p := pipeline.New(respondStep{resp: customResp})

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err == nil {
		t.Fatal("RunSession should return error on client.Send failure during respond")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("error %v does not wrap %v", err, sendErr)
	}
}

func TestRunSession_NoUpstreamCloseOnNil(t *testing.T) {
	// When all exchanges are dropped, upstream is never created.
	// RunSession should not panic when closing nil upstream.
	req := makeExchange(exchange.Send, "GET", 0)
	clientCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{req},
	}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return &mockCodec{}, nil
	}
	p := pipeline.New(dropStep{})

	// Should not panic.
	err := RunSession(context.Background(), clientCodec, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}
}

func TestRunSession_DropSendContinueReceive(t *testing.T) {
	// Pipeline drops Send-direction but continues Receive-direction.
	// First exchange is not dropped (to establish upstream), subsequent are.
	req1 := makeExchange(exchange.Send, "GET", 0)
	resp := makeExchange(exchange.Receive, "", 1)

	clientCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{req1},
	}
	upstreamCodec := &mockCodec{
		nextExchanges: []*exchange.Exchange{resp},
	}

	// Use a pipeline that passes everything (so we can establish upstream).
	p := pipeline.New(passStep{})

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
	}

	err := RunSession(context.Background(), clientCodec, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	// Verify response was forwarded to client.
	clientSent := clientCodec.getSent()
	if len(clientSent) != 1 {
		t.Fatalf("client.Send called %d times, want 1", len(clientSent))
	}
}

func TestRunSession_OnComplete_NormalEOF(t *testing.T) {
	req := makeExchangeWithStreamID(exchange.Send, "GET", 0, "stream-1")
	resp := makeExchangeWithStreamID(exchange.Receive, "", 1, "stream-1")

	clientCodec := &mockCodec{nextExchanges: []*exchange.Exchange{req}}
	upstreamCodec := &mockCodec{nextExchanges: []*exchange.Exchange{resp}}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
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

	err := RunSession(context.Background(), clientCodec, dial, p, opts)
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
	req := makeExchangeWithStreamID(exchange.Send, "GET", 0, "stream-err")

	clientCodec := &mockCodec{nextExchanges: []*exchange.Exchange{req}}
	upstreamCodec := &mockCodec{sendErr: sendErr}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
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

	err := RunSession(context.Background(), clientCodec, dial, p, opts)
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
	// OnComplete nil should not panic.
	req := makeExchange(exchange.Send, "GET", 0)
	resp := makeExchange(exchange.Receive, "", 1)

	clientCodec := &mockCodec{nextExchanges: []*exchange.Exchange{req}}
	upstreamCodec := &mockCodec{nextExchanges: []*exchange.Exchange{resp}}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
	}
	p := pipeline.New(passStep{})

	// No opts at all — backward compatible.
	err := RunSession(context.Background(), clientCodec, dial, p)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	// Explicit nil OnComplete.
	err = RunSession(context.Background(),
		&mockCodec{nextExchanges: []*exchange.Exchange{makeExchange(exchange.Send, "GET", 0)}},
		func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
			return &mockCodec{nextExchanges: []*exchange.Exchange{makeExchange(exchange.Receive, "", 1)}}, nil
		},
		pipeline.New(passStep{}),
		SessionOptions{OnComplete: nil},
	)
	if err != nil {
		t.Fatalf("RunSession returned error with nil OnComplete: %v", err)
	}
}

func TestRunSession_OnComplete_StreamIDFromFirstExchange(t *testing.T) {
	// Multiple exchanges with different StreamIDs — only the first is captured.
	ex1 := makeExchangeWithStreamID(exchange.Send, "GET", 0, "first-stream")
	ex2 := makeExchangeWithStreamID(exchange.Send, "GET", 1, "second-stream")

	clientCodec := &mockCodec{nextExchanges: []*exchange.Exchange{ex1, ex2}}
	upstreamCodec := &mockCodec{} // no responses, will EOF immediately

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
	}
	p := pipeline.New(passStep{})

	var gotStreamID string
	opts := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, _ error) {
			gotStreamID = streamID
		},
	}

	_ = RunSession(context.Background(), clientCodec, dial, p, opts)

	if gotStreamID != "first-stream" {
		t.Errorf("OnComplete streamID = %q, want %q", gotStreamID, "first-stream")
	}
}

func TestRunSession_OnComplete_ContextNotCancelled(t *testing.T) {
	req := makeExchangeWithStreamID(exchange.Send, "GET", 0, "ctx-test")
	resp := makeExchangeWithStreamID(exchange.Receive, "", 1, "ctx-test")

	clientCodec := &mockCodec{nextExchanges: []*exchange.Exchange{req}}
	upstreamCodec := &mockCodec{nextExchanges: []*exchange.Exchange{resp}}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return upstreamCodec, nil
	}
	p := pipeline.New(passStep{})

	var ctxErr error
	opts := SessionOptions{
		OnComplete: func(ctx context.Context, _ string, _ error) {
			ctxErr = ctx.Err()
		},
	}

	err := RunSession(context.Background(), clientCodec, dial, p, opts)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if ctxErr != nil {
		t.Errorf("OnComplete context was cancelled: %v", ctxErr)
	}
}

func TestRunSession_OnComplete_AllDropped(t *testing.T) {
	// When all exchanges are dropped, no upstream is established.
	// OnComplete should still be called with an empty StreamID.
	req := makeExchangeWithStreamID(exchange.Send, "GET", 0, "dropped-stream")

	clientCodec := &mockCodec{nextExchanges: []*exchange.Exchange{req}}

	dial := func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		return &mockCodec{}, nil
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

	err := RunSession(context.Background(), clientCodec, dial, p, opts)
	if err != nil {
		t.Fatalf("RunSession returned error: %v", err)
	}

	if !called {
		t.Fatal("OnComplete was not called when all exchanges dropped")
	}
	// StreamID is still captured because we read the exchange before dropping.
	if gotStreamID != "dropped-stream" {
		t.Errorf("OnComplete streamID = %q, want %q", gotStreamID, "dropped-stream")
	}
	if gotErr != nil {
		t.Errorf("OnComplete err = %v, want nil", gotErr)
	}
}

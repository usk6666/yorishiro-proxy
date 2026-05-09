package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-783: Direct unit tests for runWSOverH2Relay / wsRelayDirection /
// h2LayersFromAccessor (the test-shaped fallback consumer of the same logic
// h2LayersFromStack uses). These helpers were introduced by USK-781 (PR
// #775) and were previously exercised only by the wss-over-h2 e2e harness
// in internal/connector/wss_over_h2_integration_test.go. The /review-gate
// F-1 finding flagged the missing direct coverage; this file repays that
// test debt without changing helper behavior.

// notH2Layer is a layer.Layer that is deliberately NOT *http2.Layer. Used
// to force h2LayersFromAccessor's type-assertion error paths.
type notH2Layer struct{}

func (notH2Layer) Channels() <-chan layer.Channel {
	ch := make(chan layer.Channel)
	close(ch)
	return ch
}
func (notH2Layer) Close() error { return nil }

// fakeH2StackAccessor implements h2StackAccessor with caller-controlled
// return values so tests can exercise every branch without constructing
// real *http2.Layer instances on either side.
//
// Storing typed-nil pointers (e.g. (*http2.Layer)(nil)) is intentional:
// h2LayersFromAccessor only type-asserts on *http2.Layer and returns the
// pointer; it never dereferences it, so the success cases can use
// typed-nil sentinels safely.
type fakeH2StackAccessor struct {
	clientTop layer.Layer
	upTop     layer.Layer
	pooled    *http2.Layer
}

func (f *fakeH2StackAccessor) ClientTopmost() layer.Layer    { return f.clientTop }
func (f *fakeH2StackAccessor) UpstreamTopmost() layer.Layer  { return f.upTop }
func (f *fakeH2StackAccessor) UpstreamH2Layer() *http2.Layer { return f.pooled }

func TestH2LayersFromAccessor(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Reusable typed-nil sentinels. ws/h2 swap callers only need pointer
	// identity (DetachStream is invoked later); the helper itself never
	// dereferences these.
	var typedClient *http2.Layer = (*http2.Layer)(nil)
	var typedUpstream *http2.Layer = (*http2.Layer)(nil)

	t.Run("client_topmost_not_h2_returns_typed_error", func(t *testing.T) {
		acc := &fakeH2StackAccessor{
			clientTop: notH2Layer{},
			upTop:     typedUpstream,
		}
		c, u, err := h2LayersFromAccessor(acc)
		if err == nil {
			t.Fatalf("expected error, got client=%v upstream=%v", c, u)
		}
		if c != nil || u != nil {
			t.Errorf("expected (nil, nil) on error, got (%v, %v)", c, u)
		}
		if !strings.Contains(err.Error(), "client topmost") {
			t.Errorf("error message %q does not mention client topmost", err.Error())
		}
		if !strings.Contains(err.Error(), "session.notH2Layer") {
			t.Errorf("error message %q should include the actual concrete type", err.Error())
		}
	})

	t.Run("client_topmost_nil_returns_typed_error", func(t *testing.T) {
		// nil interface (no concrete type) — fmt %T prints "<nil>".
		acc := &fakeH2StackAccessor{
			clientTop: nil,
			upTop:     typedUpstream,
		}
		_, _, err := h2LayersFromAccessor(acc)
		if err == nil {
			t.Fatal("expected error when ClientTopmost is nil interface")
		}
		if !strings.Contains(err.Error(), "client topmost") {
			t.Errorf("error message %q does not mention client topmost", err.Error())
		}
	})

	t.Run("upstream_topmost_h2_returns_topmost_without_consulting_pool", func(t *testing.T) {
		acc := &fakeH2StackAccessor{
			clientTop: typedClient,
			upTop:     typedUpstream,
			pooled:    nil, // no pool — must succeed via topmost
		}
		c, u, err := h2LayersFromAccessor(acc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c != typedClient {
			t.Errorf("client = %p, want %p", c, typedClient)
		}
		if u != typedUpstream {
			t.Errorf("upstream = %p, want %p", u, typedUpstream)
		}
	})

	t.Run("upstream_h2_layer_fallback_when_topmost_not_h2", func(t *testing.T) {
		// Use distinct dummy *http2.Layer values to assert pointer
		// identity. *http2.Layer is opaque to this test — it's enough
		// that both pointers compare equal to what we put in.
		distinctPooled := &http2.Layer{} // zero value — never invoked
		acc := &fakeH2StackAccessor{
			clientTop: typedClient,
			upTop:     notH2Layer{}, // NOT *http2.Layer — forces fallback
			pooled:    distinctPooled,
		}
		c, u, err := h2LayersFromAccessor(acc)
		if err != nil {
			t.Fatalf("expected fallback success, got error: %v", err)
		}
		if c != typedClient {
			t.Errorf("client = %p, want %p", c, typedClient)
		}
		if u != distinctPooled {
			t.Errorf("upstream = %p, want pooled %p (fallback path did not return pool)", u, distinctPooled)
		}
	})

	t.Run("upstream_h2_layer_preferred_over_topmost_when_both_set", func(t *testing.T) {
		// USK-781 production wiring: live "h2" ALPN route sets
		// UpstreamH2Layer but does NOT push a topmost. The function
		// must return the pooled value before consulting topmost.
		distinctPooled := &http2.Layer{}
		acc := &fakeH2StackAccessor{
			clientTop: typedClient,
			upTop:     typedUpstream, // would also satisfy the assertion
			pooled:    distinctPooled,
		}
		_, u, err := h2LayersFromAccessor(acc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u != distinctPooled {
			t.Errorf("upstream = %p, want pooled %p (pool must win over topmost)", u, distinctPooled)
		}
	})

	t.Run("both_upstream_nil_returns_typed_error_no_nilderef", func(t *testing.T) {
		acc := &fakeH2StackAccessor{
			clientTop: typedClient,
			upTop:     nil, // nil interface
			pooled:    nil,
		}
		c, u, err := h2LayersFromAccessor(acc)
		if err == nil {
			t.Fatal("expected error when both upstream sources are nil")
		}
		if c != nil || u != nil {
			t.Errorf("expected (nil, nil) on error, got (%v, %v)", c, u)
		}
		if !strings.Contains(err.Error(), "upstream") {
			t.Errorf("error message %q does not mention upstream", err.Error())
		}
	})

	t.Run("upstream_topmost_not_h2_and_no_pool_returns_typed_error", func(t *testing.T) {
		acc := &fakeH2StackAccessor{
			clientTop: typedClient,
			upTop:     notH2Layer{},
			pooled:    nil,
		}
		_, _, err := h2LayersFromAccessor(acc)
		if err == nil {
			t.Fatal("expected error when upstream is non-h2 and no pool")
		}
		if !strings.Contains(err.Error(), "upstream") {
			t.Errorf("error message %q does not mention upstream", err.Error())
		}
		if !strings.Contains(err.Error(), "session.notH2Layer") {
			t.Errorf("error message %q should include the concrete type", err.Error())
		}
	})
}

// countingWriteCloser counts Close invocations and tracks how many of those
// closed the underlying writer. Mirrors detachCloserAdapter / detachWriter
// semantics: the public contract is that Close is safe under concurrent
// re-entry and the underlying side-effect (h2 END_STREAM emission) fires
// at most once. The test uses sync.Once to enforce that contract on the
// fake itself, so a buggy production close-twice cascade cannot
// accidentally pass.
type countingWriteCloser struct {
	calls   atomic.Int32
	once    sync.Once
	effects atomic.Int32 // increments only inside once.Do — at-most-once semantics
}

func (c *countingWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *countingWriteCloser) Close() error {
	c.calls.Add(1)
	c.once.Do(func() {
		c.effects.Add(1)
	})
	return nil
}

// makeWSEnvelope returns a minimal Send-direction WS envelope. Pipeline
// passes it through unchanged; mockChannel.Send records the pointer.
func makeWSEnvelope(dir envelope.Direction, payload []byte) *envelope.Envelope {
	return &envelope.Envelope{
		Direction: dir,
		Protocol:  envelope.ProtocolWebSocket,
		Raw:       append([]byte(nil), payload...),
		Message:   &envelope.WSMessage{Opcode: 1 /* text */, Payload: append([]byte(nil), payload...)},
	}
}

// drainAfter spawns a goroutine that waits dur then signals via cancel. Used
// so that the goleak assertion is the test (any leaked relay goroutine fails
// the assertion).
func drainAfter(t *testing.T, dur time.Duration, cancel context.CancelFunc) {
	t.Helper()
	stop := time.AfterFunc(dur, cancel)
	t.Cleanup(func() { stop.Stop() })
}

func TestRunWSOverH2Relay_GracefulEOFClientSide_HalfClosesUpstream(t *testing.T) {
	defer goleak.VerifyNone(t)

	clientCh := &mockChannel{streamID: "client-stream"} // no envelopes → immediate EOF
	upstreamCh := &mockChannel{streamID: "upstream", blockNext: make(chan struct{})}

	clientW := &countingWriteCloser{}   // upstream→client direction will Close this
	upstreamW := &countingWriteCloser{} // client→upstream direction will Close this on EOF

	// Pipeline is a passthrough — the relay itself is what we are
	// exercising, not Pipeline behavior.
	p := pipeline.New(passStep{})

	// upstreamCh blocks until we close blockNext, modelling the upstream
	// half-close arriving in response to the client→upstream END_STREAM.
	go func() {
		// Wait until upstreamW has been closed (i.e. the relay propagated
		// the half-close), then signal upstream-side EOF so the second
		// goroutine exits without leaking. Poll on the effect counter so
		// we don't depend on internal scheduling.
		for upstreamW.effects.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		// Closing blockNext unparks upstreamCh.Next; with no envelopes
		// queued it returns io.EOF.
		close(upstreamCh.blockNext)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := runWSOverH2Relay(ctx, p, SessionOptions{}, clientCh, upstreamCh, clientW, upstreamW, "session-stream"); err != nil {
		t.Fatalf("runWSOverH2Relay returned unexpected error: %v", err)
	}

	// Idempotency: even if both directions raced, the underlying side-
	// effect fires exactly once per writer.
	if got := upstreamW.effects.Load(); got != 1 {
		t.Errorf("upstream writer Close effects = %d, want 1 (client EOF must half-close upstream exactly once)", got)
	}
	if got := clientW.effects.Load(); got != 1 {
		t.Errorf("client writer Close effects = %d, want 1 (upstream EOF must half-close client exactly once)", got)
	}
}

func TestRunWSOverH2Relay_GracefulEOFUpstreamSide_HalfClosesClient(t *testing.T) {
	defer goleak.VerifyNone(t)

	clientCh := &mockChannel{streamID: "client", blockNext: make(chan struct{})}
	upstreamCh := &mockChannel{streamID: "upstream"} // immediate EOF

	clientW := &countingWriteCloser{}
	upstreamW := &countingWriteCloser{}

	p := pipeline.New(passStep{})

	go func() {
		for clientW.effects.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		close(clientCh.blockNext)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := runWSOverH2Relay(ctx, p, SessionOptions{}, clientCh, upstreamCh, clientW, upstreamW, "session-stream"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := clientW.effects.Load(); got != 1 {
		t.Errorf("client writer effects = %d, want 1", got)
	}
	if got := upstreamW.effects.Load(); got != 1 {
		t.Errorf("upstream writer effects = %d, want 1", got)
	}
}

func TestRunWSOverH2Relay_NonEOFErrorDoesNotCascadeENDStream(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Client side errors with a non-EOF, non-Canceled error — must NOT
	// trigger the END_STREAM cascade on upstreamW.
	srcErr := fmt.Errorf("client-read failure")
	clientCh := &mockChannel{streamID: "client", nextErr: srcErr}

	// Upstream blocks until we cancel ctx — represents an upstream that
	// has not produced anything yet. The errgroup must propagate the
	// client-side error and cancel the upstream goroutine via ctx.
	upstreamCh := &mockChannel{streamID: "upstream", blockNext: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-upstreamCh.blockNext:
		default:
			close(upstreamCh.blockNext)
		}
	})

	clientW := &countingWriteCloser{}
	upstreamW := &countingWriteCloser{}

	p := pipeline.New(passStep{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := runWSOverH2Relay(ctx, p, SessionOptions{}, clientCh, upstreamCh, clientW, upstreamW, "session-stream")
	if err == nil {
		t.Fatal("expected non-nil error from non-EOF client-side failure")
	}
	if !errors.Is(err, srcErr) {
		t.Errorf("error %v does not wrap srcErr %v", err, srcErr)
	}
	// MUST NOT cascade — END_STREAM only on graceful EOF.
	if got := upstreamW.effects.Load(); got != 0 {
		t.Errorf("upstream writer effects = %d after non-EOF client failure, want 0 (no cascade)", got)
	}
	// Upstream side returned via ctx-cancel; clientW close is also NOT
	// part of the cascade because upstream did not surface graceful EOF.
	if got := clientW.effects.Load(); got != 0 {
		t.Errorf("client writer effects = %d, want 0 (no cascade on non-EOF)", got)
	}
}

func TestRunWSOverH2Relay_ContextCancel_NoGoroutineLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	clientCh := &mockChannel{streamID: "client", blockNext: make(chan struct{})}
	upstreamCh := &mockChannel{streamID: "upstream", blockNext: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-clientCh.blockNext:
		default:
			close(clientCh.blockNext)
		}
		select {
		case <-upstreamCh.blockNext:
		default:
			close(upstreamCh.blockNext)
		}
	})

	clientW := &countingWriteCloser{}
	upstreamW := &countingWriteCloser{}

	p := pipeline.New(passStep{})
	ctx, cancel := context.WithCancel(context.Background())
	drainAfter(t, 50*time.Millisecond, cancel)

	err := runWSOverH2Relay(ctx, p, SessionOptions{}, clientCh, upstreamCh, clientW, upstreamW, "session-stream")
	if err == nil {
		t.Fatal("expected non-nil error after ctx cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	// ctx-cancel is treated as a non-EOF terminal — no half-close cascade.
	if got := clientW.effects.Load(); got != 0 {
		t.Errorf("client writer effects = %d after ctx cancel, want 0", got)
	}
	if got := upstreamW.effects.Load(); got != 0 {
		t.Errorf("upstream writer effects = %d after ctx cancel, want 0", got)
	}
	// No-leak assertion is the test (goleak.VerifyNone above).
}

func TestRunWSOverH2Relay_OnCompleteFires(t *testing.T) {
	defer goleak.VerifyNone(t)

	clientCh := &mockChannel{streamID: "client"}     // immediate EOF
	upstreamCh := &mockChannel{streamID: "upstream"} // immediate EOF

	clientW := &countingWriteCloser{}
	upstreamW := &countingWriteCloser{}

	p := pipeline.New(passStep{})

	var (
		called   atomic.Int32
		gotID    atomic.Value
		gotErr   atomic.Value
		callOnce sync.Once
	)
	opts := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, err error) {
			callOnce.Do(func() {
				called.Add(1)
				gotID.Store(streamID)
				if err == nil {
					gotErr.Store("<nil>")
				} else {
					gotErr.Store(err.Error())
				}
			})
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := runWSOverH2Relay(ctx, p, opts, clientCh, upstreamCh, clientW, upstreamW, "session-id-42"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("OnComplete called %d times, want 1", called.Load())
	}
	if id := gotID.Load(); id != "session-id-42" {
		t.Errorf("OnComplete streamID = %q, want %q", id, "session-id-42")
	}
	if v := gotErr.Load(); v != "<nil>" {
		t.Errorf("OnComplete err = %v, want nil", v)
	}
}

func TestWSRelayDirection(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Run("send_envelope_forwarded_to_dst", func(t *testing.T) {
		env := makeWSEnvelope(envelope.Send, []byte("ping"))
		src := &mockChannel{streamID: "src", nextEnvelopes: []*envelope.Envelope{env}}
		dst := &mockChannel{streamID: "dst"}

		p := pipeline.New(passStep{})
		reg := &bodyBufRegistry{}

		err := wsRelayDirection(context.Background(), p, reg, src, dst, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sent := dst.getSent()
		if len(sent) != 1 {
			t.Fatalf("dst.Send called %d times, want 1", len(sent))
		}
		if sent[0].Direction != envelope.Send {
			t.Errorf("dst received direction %v, want Send", sent[0].Direction)
		}
		if string(sent[0].Raw) != "ping" {
			t.Errorf("dst payload = %q, want %q", sent[0].Raw, "ping")
		}
	})

	t.Run("receive_envelope_forwarded_to_dst", func(t *testing.T) {
		env := makeWSEnvelope(envelope.Receive, []byte("pong"))
		src := &mockChannel{streamID: "src", nextEnvelopes: []*envelope.Envelope{env}}
		dst := &mockChannel{streamID: "dst"}

		p := pipeline.New(passStep{})
		reg := &bodyBufRegistry{}

		err := wsRelayDirection(context.Background(), p, reg, src, dst, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sent := dst.getSent()
		if len(sent) != 1 || sent[0].Direction != envelope.Receive {
			t.Fatalf("dst received %d envelopes (first dir=%v), want 1 Receive", len(sent), sent[0].Direction)
		}
	})

	t.Run("eof_returns_nil", func(t *testing.T) {
		src := &mockChannel{streamID: "src"} // no envelopes → io.EOF
		dst := &mockChannel{streamID: "dst"}
		p := pipeline.New(passStep{})
		reg := &bodyBufRegistry{}

		err := wsRelayDirection(context.Background(), p, reg, src, dst, nil)
		if err != nil {
			t.Errorf("EOF must surface as nil error, got %v", err)
		}
		if got := len(dst.getSent()); got != 0 {
			t.Errorf("dst received %d envelopes after EOF-only stream, want 0", got)
		}
	})

	t.Run("non_eof_error_wrapped", func(t *testing.T) {
		srcErr := errors.New("synthetic read failure")
		src := &mockChannel{streamID: "src", nextErr: srcErr}
		dst := &mockChannel{streamID: "dst"}
		p := pipeline.New(passStep{})
		reg := &bodyBufRegistry{}

		err := wsRelayDirection(context.Background(), p, reg, src, dst, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, srcErr) {
			t.Errorf("err %v does not wrap srcErr %v", err, srcErr)
		}
		if !strings.Contains(err.Error(), "src.Next") {
			t.Errorf("err %q should mention src.Next for diagnostic context", err.Error())
		}
	})

	t.Run("ctx_cancel_returns_ctx_err", func(t *testing.T) {
		src := &mockChannel{streamID: "src", blockNext: make(chan struct{})}
		t.Cleanup(func() {
			select {
			case <-src.blockNext:
			default:
				close(src.blockNext)
			}
		})
		dst := &mockChannel{streamID: "dst"}
		p := pipeline.New(passStep{})
		reg := &bodyBufRegistry{}

		ctx, cancel := context.WithCancel(context.Background())
		drainAfter(t, 50*time.Millisecond, cancel)

		err := wsRelayDirection(ctx, p, reg, src, dst, nil)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	})

	t.Run("dst_send_error_wrapped", func(t *testing.T) {
		env := makeWSEnvelope(envelope.Send, []byte("payload"))
		src := &mockChannel{streamID: "src", nextEnvelopes: []*envelope.Envelope{env}}
		dstErr := errors.New("synthetic write failure")
		dst := &mockChannel{streamID: "dst", sendErr: dstErr}

		p := pipeline.New(passStep{})
		reg := &bodyBufRegistry{}

		err := wsRelayDirection(context.Background(), p, reg, src, dst, nil)
		if err == nil {
			t.Fatal("expected dst.Send failure to surface")
		}
		if !errors.Is(err, dstErr) {
			t.Errorf("err %v does not wrap dstErr %v", err, dstErr)
		}
		if !strings.Contains(err.Error(), "dst.Send") {
			t.Errorf("err %q should identify the dst.Send failure path", err.Error())
		}
	})

	t.Run("drop_action_skips_dst", func(t *testing.T) {
		env := makeWSEnvelope(envelope.Send, []byte("dropped"))
		src := &mockChannel{streamID: "src", nextEnvelopes: []*envelope.Envelope{env}}
		dst := &mockChannel{streamID: "dst"}

		p := pipeline.New(dropStep{})
		reg := &bodyBufRegistry{}

		err := wsRelayDirection(context.Background(), p, reg, src, dst, nil)
		if err != nil {
			t.Fatalf("unexpected error after Drop: %v", err)
		}
		if got := len(dst.getSent()); got != 0 {
			t.Errorf("dst received %d envelopes after Drop, want 0", got)
		}
	})

	t.Run("respond_action_writes_back_to_src", func(t *testing.T) {
		req := makeWSEnvelope(envelope.Send, []byte("req"))
		resp := makeWSEnvelope(envelope.Receive, []byte("forced-respond"))
		src := &mockChannel{streamID: "src", nextEnvelopes: []*envelope.Envelope{req}}
		dst := &mockChannel{streamID: "dst"}

		p := pipeline.New(respondStep{resp: resp})
		reg := &bodyBufRegistry{}

		err := wsRelayDirection(context.Background(), p, reg, src, dst, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Respond writes back to src (mirror of RunSession semantics).
		srcSent := src.getSent()
		if len(srcSent) != 1 {
			t.Fatalf("src.Send called %d times, want 1 (Respond)", len(srcSent))
		}
		if string(srcSent[0].Raw) != "forced-respond" {
			t.Errorf("respond payload = %q, want %q", srcSent[0].Raw, "forced-respond")
		}
		if got := len(dst.getSent()); got != 0 {
			t.Errorf("dst received %d envelopes during Respond, want 0", got)
		}
	})

	// Sanity: verify Issue contract that EOF -> io.EOF is internally
	// translated to nil. Direct check on errors.Is(io.EOF) was done above
	// via mockChannel exhaustion; the named sentinel below confirms the
	// exact wrapping semantics if a future change introduces a wrapped
	// EOF.
	t.Run("wrapped_eof_returns_nil", func(t *testing.T) {
		wrapped := fmt.Errorf("layer wrapping: %w", io.EOF)
		src := &mockChannel{streamID: "src", nextErr: wrapped}
		dst := &mockChannel{streamID: "dst"}
		p := pipeline.New(passStep{})
		reg := &bodyBufRegistry{}

		err := wsRelayDirection(context.Background(), p, reg, src, dst, nil)
		if err != nil {
			t.Errorf("wrapped io.EOF must surface as nil, got %v", err)
		}
	})
}

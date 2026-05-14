package httpaggregator

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestAggregator_SSEResponseOverH2_EmitsWithoutBody is the USK-888
// regression gate. A 2xx response on an HTTP/2 stream with
// Content-Type: text/event-stream MUST emit the HEADERS as a complete
// bodyless HTTPMessage immediately. Pre-fix the aggregator parked in
// phaseCollectingBody waiting for END_STREAM (which never arrives for
// SSE) or hit MaxBodySize after accumulating enough event payload —
// either way no SSE event envelope ever reached the Pipeline.
//
// After the short-circuit, the aggregator:
//   - emits the response HEADERS as `done=true` HTTPMessage,
//   - resets phase to phaseIdle,
//   - latches tunnelExchangeDone so subsequent Next() calls park,
//
// so the post-emit runUpgradeSSEOverH2 orchestrator can DetachStream the
// per-stream DATA frames without contention.
func TestAggregator_SSEResponseOverH2_EmitsWithoutBody(t *testing.T) {
	inner := newFakeChannel()
	// 2xx response, no END_STREAM, Content-Type=text/event-stream.
	inner.queue(&envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Status: 200,
			Headers: []envelope.KeyValue{
				{Name: "content-type", Value: "text/event-stream"},
				{Name: "cache-control", Value: "no-cache"},
			},
			EndStream: false,
		},
	})

	// RoleClient = upstream-side aggregator (Next=>Receive/responses).
	ch := Wrap(inner, RoleClient, nil, WrapOptions{})

	envResp, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next (sse response): %v", err)
	}
	respMsg, ok := envResp.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("response Message = %T, want *HTTPMessage", envResp.Message)
	}
	if respMsg.Status != 200 {
		t.Errorf("response Status = %d, want 200", respMsg.Status)
	}
	if envResp.Direction != envelope.Receive {
		t.Errorf("response Direction = %v, want Receive", envResp.Direction)
	}
	// Header order/casing must be preserved (MITM Principle #1).
	if len(respMsg.Headers) != 2 ||
		respMsg.Headers[0].Name != "content-type" ||
		respMsg.Headers[0].Value != "text/event-stream" {
		t.Errorf("Headers preservation broken; got %+v", respMsg.Headers)
	}
}

// TestAggregator_SSEResponseOverH2_ParksAfterEmit verifies the second
// invariant of the USK-888 short-circuit: after the SSE HEADERS emit, the
// aggregator must park on Next() so post-emit DATA frames flow into
// http2.Layer.DetachStream rather than getting consumed (and probably
// rejected as "DATA in phase 0") by the aggregator.
func TestAggregator_SSEResponseOverH2_ParksAfterEmit(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Status: 200,
			Headers: []envelope.KeyValue{
				{Name: "content-type", Value: "text/event-stream; charset=utf-8"},
			},
		},
	})

	ch := Wrap(inner, RoleClient, nil, WrapOptions{})

	// First Next pulls the SSE response.
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next: %v", err)
	}

	// Second Next MUST park until ctx cancel rather than greedy-pulling
	// the next inner event. We park with a short ctx timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	env, err := ch.Next(ctx)
	if env != nil {
		t.Errorf("post-emit Next returned envelope %+v, want park", env)
	}
	if err != context.DeadlineExceeded {
		t.Errorf("post-emit Next err = %v, want context.DeadlineExceeded (parked)", err)
	}
}

// TestAggregator_SSEResponseOverH2_NonSSEPathUnchanged checks that the
// short-circuit does not fire for non-SSE 2xx responses. A regular
// application/json response continues to enter phaseCollectingBody and
// is reassembled once DATA + END_STREAM arrive.
func TestAggregator_SSEResponseOverH2_NonSSEPathUnchanged(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Status: 200,
			Headers: []envelope.KeyValue{
				{Name: "content-type", Value: "application/json"},
			},
			EndStream: false,
		},
	})
	inner.queue(&envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2DataEvent{
			Payload:   []byte(`{"k":"v"}`),
			EndStream: true,
		},
	})

	ch := Wrap(inner, RoleClient, nil, WrapOptions{})
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message = %T, want *HTTPMessage", env.Message)
	}
	if string(msg.Body) != `{"k":"v"}` {
		t.Errorf("Body = %q, want JSON payload (non-SSE path unchanged)", string(msg.Body))
	}
}

// TestAggregator_SSEResponseOverH2_NonReceiveDirectionUnchanged ensures
// the short-circuit only fires on Receive direction so a hypothetical
// "Send-side SSE response" (test fixture / Layer reuse) does not
// inadvertently short-circuit.
func TestAggregator_SSEResponseOverH2_NonReceiveDirectionUnchanged(t *testing.T) {
	inner := newFakeChannel()
	inner.queue(&envelope.Envelope{
		Direction: envelope.Send, // intentional misdirection
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Status: 200,
			Headers: []envelope.KeyValue{
				{Name: "content-type", Value: "text/event-stream"},
			},
			EndStream: true, // pretend bodyless so the path completes
		},
	})

	// RoleServer parks differently (tunnelled flag). Use RoleClient for
	// uniformity; the short-circuit gate is the Direction guard, not Role.
	ch := Wrap(inner, RoleClient, nil, WrapOptions{})
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	// Without the short-circuit firing, the bodyless END_STREAM path emits
	// the HTTPMessage normally — proving the short-circuit did not trigger
	// on Send direction. (If it had, we would still get an envelope, but
	// the subsequent Next() would park instead of returning EOF on the
	// underlying empty channel.)
	if env == nil {
		t.Fatal("Next returned nil envelope, want HTTPMessage")
	}
	// Subsequent Next() should NOT park (no tunnelExchangeDone latch).
	// fakeChannel.Next returns io.EOF when its queue is empty; that EOF
	// proves we are NOT in the post-SSE parking branch.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err2 := ch.Next(ctx)
	if err2 == nil {
		t.Fatal("subsequent Next returned nil err, want io.EOF")
	}
	if err2 == context.DeadlineExceeded {
		t.Fatalf("subsequent Next parked (got %v); short-circuit fired on Send direction (bug)", err2)
	}
}

// TestIsSSEResponseHeaders_Cases is the unit test for the helper
// predicate guarding the absorbHeaders short-circuit.
func TestIsSSEResponseHeaders_Cases(t *testing.T) {
	mkEnv := func(dir envelope.Direction) *envelope.Envelope {
		return &envelope.Envelope{Direction: dir, Protocol: envelope.ProtocolHTTP}
	}
	cases := []struct {
		name string
		env  *envelope.Envelope
		evt  *http2.H2HeadersEvent
		want bool
	}{
		{
			name: "200 + text/event-stream on Receive",
			env:  mkEnv(envelope.Receive),
			evt:  &http2.H2HeadersEvent{Status: 200, Headers: []envelope.KeyValue{{Name: "content-type", Value: "text/event-stream"}}},
			want: true,
		},
		{
			name: "206 + text/event-stream; charset=utf-8",
			env:  mkEnv(envelope.Receive),
			evt:  &http2.H2HeadersEvent{Status: 206, Headers: []envelope.KeyValue{{Name: "Content-Type", Value: "text/event-stream; charset=utf-8"}}},
			want: true,
		},
		{
			name: "Send direction must not match",
			env:  mkEnv(envelope.Send),
			evt:  &http2.H2HeadersEvent{Status: 200, Headers: []envelope.KeyValue{{Name: "content-type", Value: "text/event-stream"}}},
			want: false,
		},
		{
			name: "404 + text/event-stream",
			env:  mkEnv(envelope.Receive),
			evt:  &http2.H2HeadersEvent{Status: 404, Headers: []envelope.KeyValue{{Name: "content-type", Value: "text/event-stream"}}},
			want: false,
		},
		{
			name: "200 + application/json",
			env:  mkEnv(envelope.Receive),
			evt:  &http2.H2HeadersEvent{Status: 200, Headers: []envelope.KeyValue{{Name: "content-type", Value: "application/json"}}},
			want: false,
		},
		{
			name: "200 missing content-type",
			env:  mkEnv(envelope.Receive),
			evt:  &http2.H2HeadersEvent{Status: 200, Headers: []envelope.KeyValue{}},
			want: false,
		},
		{
			name: "nil envelope",
			env:  nil,
			evt:  &http2.H2HeadersEvent{Status: 200},
			want: false,
		},
		{
			name: "nil event",
			env:  mkEnv(envelope.Receive),
			evt:  nil,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSSEResponseHeaders(tc.env, tc.evt); got != tc.want {
				t.Errorf("isSSEResponseHeaders = %v, want %v", got, tc.want)
			}
		})
	}
}

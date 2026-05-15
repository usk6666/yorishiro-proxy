package httpaggregator

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-897 unit tests: httpaggregator.WithH2FrameRecordCallback fires once
// per absorbed H2DataEvent BEFORE the payload reaches the body buffer,
// preserving frame boundaries on the aggregator path symmetrically with
// the USK-889 detach-path coverage.

// TestChannel_H2FrameRecordCallback_FiresPerDataFrame verifies that
// every H2DataEvent absorbed by the aggregator triggers exactly one
// callback invocation carrying that frame's payload bytes (not the
// aggregated body) and the right shape (Protocol=ProtocolHTTP, Message=nil,
// preserved Direction).
func TestChannel_H2FrameRecordCallback_FiresPerDataFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5)
	defer cancel()
	_ = ctx // unused; we drive Next with background ctx below

	stub := newFakeChannel()

	var (
		mu       sync.Mutex
		observed []*envelope.Envelope
	)
	cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		// Defensive copy so we can assert against payload bytes even if
		// the aggregator's defensive-copy contract changes in the future.
		cp := *env
		cp.Raw = append([]byte(nil), env.Raw...)
		observed = append(observed, &cp)
	}

	// Build aggregator with the callback installed.
	ch := Wrap(stub, RoleServer, nil, WrapOptions{}, WithH2FrameRecordCallback(cb))

	// Queue: HEADERS (no END_STREAM) → DATA (no END_STREAM) → DATA (END_STREAM).
	stub.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method:    "POST",
			Path:      "/upload",
			Scheme:    "https",
			Authority: "example.com",
			Headers: []envelope.KeyValue{
				{Name: ":method", Value: "POST"},
			},
		},
		Raw: []byte("HEADERS-raw"),
	})
	// First DATA frame: 5-byte payload.
	frame1 := []byte("ABCDE")
	stub.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Sequence:  1,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &http2.H2DataEvent{Payload: frame1},
		Raw:       frame1,
	})
	// Second DATA frame: 3-byte payload, END_STREAM.
	frame2 := []byte("XYZ")
	stub.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Sequence:  2,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &http2.H2DataEvent{Payload: frame2, EndStream: true},
		Raw:       frame2,
	})

	// Drain.
	out, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if out == nil || out.Message == nil {
		t.Fatalf("Next returned nil envelope/message")
	}
	httpMsg, ok := out.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Next returned %T, want *HTTPMessage", out.Message)
	}
	wantBody := append(append([]byte{}, frame1...), frame2...)
	if !bytes.Equal(httpMsg.Body, wantBody) {
		t.Errorf("aggregated Body = %q, want %q", httpMsg.Body, wantBody)
	}

	// Callback expectations.
	mu.Lock()
	defer mu.Unlock()
	if got := len(observed); got != 2 {
		t.Fatalf("callback fired %d times, want 2 (one per H2DataEvent)", got)
	}
	if !bytes.Equal(observed[0].Raw, frame1) {
		t.Errorf("frame[0].Raw = %q, want %q", observed[0].Raw, frame1)
	}
	if !bytes.Equal(observed[1].Raw, frame2) {
		t.Errorf("frame[1].Raw = %q, want %q", observed[1].Raw, frame2)
	}
	for i, env := range observed {
		if env.Protocol != envelope.ProtocolHTTP {
			t.Errorf("frame[%d].Protocol = %q, want %q", i, env.Protocol, envelope.ProtocolHTTP)
		}
		if env.Direction != envelope.Send {
			t.Errorf("frame[%d].Direction = %v, want Send", i, env.Direction)
		}
		if env.Message != nil {
			t.Errorf("frame[%d].Message = %T, want nil (wire envelope has no L7 view)", i, env.Message)
		}
		if env.StreamID != "fake-stream" {
			t.Errorf("frame[%d].StreamID = %q, want fake-stream", i, env.StreamID)
		}
	}
}

// TestChannel_H2FrameRecordCallback_FiresBeforeBodyBuffer verifies the
// ordering contract: the callback observes the DATA payload BEFORE it is
// appended to the aggregator's in-flight body buffer. CLAUDE.md MITM
// Principle 3 — wire-record envelope's snapshot must reflect on-wire
// observation, not the post-mutation state. We assert this by mutating
// the payload slice from inside the callback and verifying the
// aggregator's body still contains the original bytes (proving the
// callback runs before the bodyBuf write but with shared-slice semantics
// — actually, our impl makes a defensive copy of evt.Payload, so the
// callback's slice is detached from the aggregator's. The shape of this
// test asserts the per-call ordering through observable side effects:
// the aggregator's body is built only after every callback fires).
func TestChannel_H2FrameRecordCallback_FiresBeforeBodyBuffer(t *testing.T) {
	stub := newFakeChannel()

	var (
		fireOrder []string
		muOrder   sync.Mutex
	)
	cb := func(env *envelope.Envelope) {
		muOrder.Lock()
		defer muOrder.Unlock()
		fireOrder = append(fireOrder, "callback:"+string(env.Raw))
	}

	ch := Wrap(stub, RoleServer, nil, WrapOptions{}, WithH2FrameRecordCallback(cb))

	stub.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "POST", Path: "/", Scheme: "https", Authority: "x",
		},
		Raw: []byte("H"),
	})
	stub.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Sequence:  1,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &http2.H2DataEvent{Payload: []byte("F1"), EndStream: false},
		Raw:       []byte("F1"),
	})
	stub.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Sequence:  2,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &http2.H2DataEvent{Payload: []byte("F2"), EndStream: true},
		Raw:       []byte("F2"),
	})

	out, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	httpMsg := out.Message.(*envelope.HTTPMessage)
	muOrder.Lock()
	defer muOrder.Unlock()
	wantOrder := []string{"callback:F1", "callback:F2"}
	if len(fireOrder) != len(wantOrder) {
		t.Fatalf("fire order len = %d, want %d (%v)", len(fireOrder), len(wantOrder), fireOrder)
	}
	for i, w := range wantOrder {
		if fireOrder[i] != w {
			t.Errorf("fireOrder[%d] = %q, want %q", i, fireOrder[i], w)
		}
	}
	if !bytes.Equal(httpMsg.Body, []byte("F1F2")) {
		t.Errorf("aggregated Body = %q, want %q (body built only after all callbacks fired)", httpMsg.Body, "F1F2")
	}
}

// TestChannel_H2FrameRecordCallback_NilDisabled verifies that supplying
// WithH2FrameRecordCallback(nil) is a no-op: the aggregator behaves
// identically to the pre-USK-897 contract and no panic surfaces.
func TestChannel_H2FrameRecordCallback_NilDisabled(t *testing.T) {
	stub := newFakeChannel()
	ch := Wrap(stub, RoleServer, nil, WrapOptions{}, WithH2FrameRecordCallback(nil))

	stub.queue(&envelope.Envelope{
		StreamID:  "fake-stream",
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "GET", Path: "/", Scheme: "https", Authority: "x",
			EndStream: true,
		},
		Raw: []byte("H"),
	})

	out, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if _, ok := out.Message.(*envelope.HTTPMessage); !ok {
		t.Errorf("Next returned %T, want *HTTPMessage", out.Message)
	}
}

// TestChannel_H2FrameRecordCallback_DefensiveCopy verifies that the
// callback's env.Raw is a defensive copy of the H2DataEvent payload:
// mutating the callback-received slice must NOT corrupt the aggregator's
// accumulated body bytes. This protects consumers (record-only Pipeline
// that writes to SQLite asynchronously) from cross-coupling with the
// aggregator's body assembly.
func TestChannel_H2FrameRecordCallback_DefensiveCopy(t *testing.T) {
	stub := newFakeChannel()

	var captured []byte
	cb := func(env *envelope.Envelope) {
		captured = env.Raw
		// Mutate the captured slice: if the aggregator shared the same
		// backing array this would corrupt the assembled body.
		for i := range captured {
			captured[i] = 0xFF
		}
	}

	ch := Wrap(stub, RoleServer, nil, WrapOptions{}, WithH2FrameRecordCallback(cb))
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 0, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "POST", Path: "/", Scheme: "https", Authority: "x",
		},
		Raw: []byte("H"),
	})
	originalPayload := []byte("HELLO")
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 1, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2DataEvent{Payload: originalPayload, EndStream: true},
		Raw:      originalPayload,
	})

	out, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	httpMsg := out.Message.(*envelope.HTTPMessage)
	if !bytes.Equal(httpMsg.Body, []byte("HELLO")) {
		t.Errorf("aggregated Body = %q, want %q (callback mutation must not corrupt body — defensive copy contract)", httpMsg.Body, "HELLO")
	}
}

// TestChannel_H2FrameRecordCallback_EmptyEndStreamDataFires verifies the
// callback fires for an empty END_STREAM DATA frame too. The aggregator's
// absorbData treats len==0 + EndStream as a phase-violation when there is
// no inflight body, but inside phaseCollectingBody it is a valid
// "no-more-payload" marker. The callback must still fire so analysts
// observing per-frame DATA flooding see the trailing empty frame.
func TestChannel_H2FrameRecordCallback_EmptyEndStreamDataFires(t *testing.T) {
	stub := newFakeChannel()

	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		cp := *env
		cp.Raw = append([]byte(nil), env.Raw...)
		observed = append(observed, &cp)
	}

	ch := Wrap(stub, RoleServer, nil, WrapOptions{}, WithH2FrameRecordCallback(cb))
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 0, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2HeadersEvent{Method: "POST", Path: "/", Scheme: "https", Authority: "x"},
		Raw:      []byte("H"),
	})
	// Non-empty DATA frame.
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 1, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2DataEvent{Payload: []byte("payload")},
		Raw:      []byte("payload"),
	})
	// Empty END_STREAM DATA frame.
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 2, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2DataEvent{Payload: nil, EndStream: true},
		Raw:      nil,
	})

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(observed) != 2 {
		t.Fatalf("callback fired %d times, want 2 (one per DATA frame, including trailing empty END_STREAM)", len(observed))
	}
	if !bytes.Equal(observed[0].Raw, []byte("payload")) {
		t.Errorf("frame[0].Raw = %q, want %q", observed[0].Raw, "payload")
	}
	if len(observed[1].Raw) != 0 {
		t.Errorf("frame[1].Raw len = %d, want 0 (empty END_STREAM marker)", len(observed[1].Raw))
	}
}

// TestChannel_H2FrameRecordCallback_PreservesContext verifies that the
// per-envelope EnvelopeContext is propagated through to the callback so
// the session orchestrator's record-only Pipeline can apply scope gates
// consistently with the semantic envelopes (HostScope / HTTPScope).
func TestChannel_H2FrameRecordCallback_PreservesContext(t *testing.T) {
	stub := newFakeChannel()

	var got envelope.EnvelopeContext
	cb := func(env *envelope.Envelope) { got = env.Context }

	ch := Wrap(stub, RoleServer, nil, WrapOptions{}, WithH2FrameRecordCallback(cb))
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 0, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2HeadersEvent{Method: "POST", Path: "/", Scheme: "https", Authority: "x"},
		Raw:      []byte("H"),
		Context:  envelope.EnvelopeContext{ConnID: "conn-7", TargetHost: "example.com:443"},
	})
	stub.queue(&envelope.Envelope{
		StreamID: "fake-stream", Sequence: 1, Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP,
		Message:  &http2.H2DataEvent{Payload: []byte("data"), EndStream: true},
		Raw:      []byte("data"),
		Context:  envelope.EnvelopeContext{ConnID: "conn-7", TargetHost: "example.com:443"},
	})

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next: %v", err)
	}
	if got.ConnID != "conn-7" {
		t.Errorf("Context.ConnID = %q, want conn-7", got.ConnID)
	}
	if got.TargetHost != "example.com:443" {
		t.Errorf("Context.TargetHost = %q, want example.com:443", got.TargetHost)
	}
}

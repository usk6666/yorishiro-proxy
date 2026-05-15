package grpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// USK-899 unit tests: grpc.WithH2DataFrameRecordCallback fires once per
// absorbed H2DataEvent BEFORE LPM reassembly, preserving H2 DATA frame
// boundaries on the native-gRPC path symmetrically with the USK-897
// aggregator-path coverage.
//
// Shape mirrors USK-896's lpm_record_callback_test.go — stub inner channel,
// drainNext helper, mu-guarded observed slice for parallel-test safety.

// TestChannel_H2DataFrameRecordCallback_FiresPerDataFrame verifies that
// every H2DataEvent absorbed by the gRPC channel triggers exactly one
// callback invocation carrying that frame's payload bytes (not the
// reassembled LPM payload) and the right shape (Protocol=ProtocolHTTP,
// Message=nil, preserved Direction).
func TestChannel_H2DataFrameRecordCallback_FiresPerDataFrame(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))

	// Two LPMs packed into a single H2 DATA frame on the wire.
	a := makeLPM(false, []byte("aaaa"))
	b := makeLPM(false, []byte("bbbb"))
	frame1 := append(append([]byte{}, a...), b...)
	stub.pushData(envelope.Send, frame1, false)
	// Second H2 DATA frame: one LPM split-prefix style? simpler: another
	// payload carrying one LPM.
	c := makeLPM(false, []byte("cccc"))
	stub.pushData(envelope.Send, c, true)

	var mu sync.Mutex
	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		// Defensive copy of the observed envelope so a future change to
		// the channel's defensive-copy contract surfaces here.
		cp := *env
		cp.Raw = append([]byte(nil), env.Raw...)
		observed = append(observed, &cp)
	}

	ch := Wrap(stub, nil, RoleServer, WithH2DataFrameRecordCallback(cb))
	defer ch.Close()

	// Drain: 1 Start + 3 Data envelopes = 4 total.
	_ = drainNext(t, ch, 4)

	mu.Lock()
	defer mu.Unlock()
	if got := len(observed); got != 2 {
		t.Fatalf("callback fired %d times, want 2 (one per H2DataEvent, NOT per LPM)", got)
	}
	if !bytes.Equal(observed[0].Raw, frame1) {
		t.Errorf("observed[0].Raw = %x, want %x (frame1 = LPM-a+LPM-b)", observed[0].Raw, frame1)
	}
	if !bytes.Equal(observed[1].Raw, c) {
		t.Errorf("observed[1].Raw = %x, want %x (frame2 = LPM-c)", observed[1].Raw, c)
	}
	for i, env := range observed {
		if env.Protocol != envelope.ProtocolHTTP {
			t.Errorf("observed[%d].Protocol = %q, want %q (h2 DATA frame wire envelope is per the H2DataEvent provenance, NOT ProtocolGRPC)", i, env.Protocol, envelope.ProtocolHTTP)
		}
		if env.Direction != envelope.Send {
			t.Errorf("observed[%d].Direction = %v, want Send", i, env.Direction)
		}
		if env.Message != nil {
			t.Errorf("observed[%d].Message = %T, want nil (h2 DATA wire envelope has no L7 view)", i, env.Message)
		}
		if env.StreamID != "stream-1" {
			t.Errorf("observed[%d].StreamID = %q, want stream-1", i, env.StreamID)
		}
	}
}

// TestChannel_H2DataFrameRecordCallback_FiresBeforeLPMAndSemantic verifies
// the ordering contract (CLAUDE.md MITM Principle 3 applied per framing
// layer): the h2-frame wire-record callback fires BEFORE the LPM
// wire-record callback, and both fire BEFORE the GRPCDataMessage envelope
// is queued for emission to the consumer's Next.
//
// We exercise this with both callbacks installed and a marker recorded by
// each, then assert the order in which markers were appended.
func TestChannel_H2DataFrameRecordCallback_FiresBeforeLPMAndSemantic(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, makeLPM(false, []byte("only")), true)

	var muOrder sync.Mutex
	var fireOrder []string
	h2cb := func(env *envelope.Envelope) {
		muOrder.Lock()
		defer muOrder.Unlock()
		fireOrder = append(fireOrder, "h2-frame")
	}
	lpmcb := func(env *envelope.Envelope) {
		muOrder.Lock()
		defer muOrder.Unlock()
		fireOrder = append(fireOrder, "grpc-lpm")
	}

	ch := Wrap(stub, nil, RoleServer,
		WithH2DataFrameRecordCallback(h2cb),
		WithLPMFrameRecordCallback(lpmcb),
	)
	defer ch.Close()

	// First Next consumes the Start envelope; neither callback has fired
	// yet (Start is HEADERS, not DATA).
	startEnv, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #1 (Start): %v", err)
	}
	if _, ok := startEnv.Message.(*envelope.GRPCStartMessage); !ok {
		t.Fatalf("Next #1 Message = %T, want GRPCStartMessage", startEnv.Message)
	}
	muOrder.Lock()
	if len(fireOrder) != 0 {
		t.Errorf("callback fired before Next yielded Data; got %v, want []", fireOrder)
	}
	muOrder.Unlock()

	// Second Next: absorbData triggers BOTH callbacks BEFORE queuing the
	// GRPCDataMessage envelope.
	dataEnv, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #2 (Data): %v", err)
	}
	if _, ok := dataEnv.Message.(*envelope.GRPCDataMessage); !ok {
		t.Fatalf("Next #2 Message = %T, want GRPCDataMessage", dataEnv.Message)
	}

	muOrder.Lock()
	defer muOrder.Unlock()
	want := []string{"h2-frame", "grpc-lpm"}
	if len(fireOrder) != len(want) {
		t.Fatalf("fireOrder len = %d, want %d (%v)", len(fireOrder), len(want), fireOrder)
	}
	for i, w := range want {
		if fireOrder[i] != w {
			t.Errorf("fireOrder[%d] = %q, want %q (h2-frame must fire before grpc-lpm per CLAUDE.md MITM Principle 3 — wire-record top-down by framing layer)", i, fireOrder[i], w)
		}
	}
}

// TestChannel_H2DataFrameRecordCallback_NilDisabled verifies that the
// Option installed with nil callback is a no-op — the channel works
// identically to one wrapped without the Option.
func TestChannel_H2DataFrameRecordCallback_NilDisabled(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, makeLPM(false, []byte("only")), true)

	ch := Wrap(stub, nil, RoleServer, WithH2DataFrameRecordCallback(nil))
	defer ch.Close()

	// The channel must function identically to the no-Option case:
	// Next yields Start + Data without panic.
	envs := drainNext(t, ch, 2)
	if _, ok := envs[0].Message.(*envelope.GRPCStartMessage); !ok {
		t.Errorf("envs[0].Message = %T, want GRPCStartMessage", envs[0].Message)
	}
	if _, ok := envs[1].Message.(*envelope.GRPCDataMessage); !ok {
		t.Errorf("envs[1].Message = %T, want GRPCDataMessage", envs[1].Message)
	}
}

// TestChannel_H2DataFrameRecordCallback_DefensiveCopy verifies that the
// callback's env.Raw is a defensive copy of evt.Payload: mutating the
// callback-received slice must NOT corrupt the channel's LPM reassembly
// or the semantic GRPCDataMessage envelope's payload.
func TestChannel_H2DataFrameRecordCallback_DefensiveCopy(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	original := []byte("data")
	stub.pushData(envelope.Send, makeLPM(false, original), true)

	var captured []byte
	cb := func(env *envelope.Envelope) {
		captured = env.Raw
		// Mutate the captured slice: if the channel shared the same
		// backing array this would corrupt the reassembled LPM payload.
		for i := range captured {
			captured[i] = 0xFF
		}
	}

	ch := Wrap(stub, nil, RoleServer, WithH2DataFrameRecordCallback(cb))
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	dm := envs[1].Message.(*envelope.GRPCDataMessage)
	if string(dm.Payload) != "data" {
		t.Errorf("semantic envelope Payload = %q, want %q (callback mutation must not corrupt LPM payload — defensive copy contract)", dm.Payload, "data")
	}
}

// TestChannel_H2DataFrameRecordCallback_EmptyEndStreamDataFires verifies
// the callback fires for an empty END_STREAM DATA frame too. The gRPC
// client emitted by gRPC-Go closes a unary call with
// DATA(payload=msg) then DATA(payload=, END_STREAM=1); the proxy must
// surface the trailing empty frame as an independent h2-frame envelope
// so analysts observe per-frame DATA flooding even on graceful close
// sequences.
func TestChannel_H2DataFrameRecordCallback_EmptyEndStreamDataFires(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	// Non-empty DATA frame carrying one LPM.
	stub.pushData(envelope.Send, makeLPM(false, []byte("payload")), false)
	// Empty END_STREAM DATA frame (no LPM bytes).
	stub.pushData(envelope.Send, nil, true)

	var mu sync.Mutex
	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		cp := *env
		cp.Raw = append([]byte(nil), env.Raw...)
		observed = append(observed, &cp)
	}

	ch := Wrap(stub, nil, RoleServer, WithH2DataFrameRecordCallback(cb))
	defer ch.Close()

	// Drain: Start + Data + synthetic end-marker Data = 3 envelopes.
	_ = drainNext(t, ch, 3)

	mu.Lock()
	defer mu.Unlock()
	if len(observed) != 2 {
		t.Fatalf("callback fired %d times, want 2 (one per H2DataEvent, including trailing empty END_STREAM)", len(observed))
	}
	if !bytes.Equal(observed[0].Raw, makeLPM(false, []byte("payload"))) {
		t.Errorf("observed[0].Raw = %x, want LPM-wrapped payload", observed[0].Raw)
	}
	if len(observed[1].Raw) != 0 {
		t.Errorf("observed[1].Raw len = %d, want 0 (empty END_STREAM marker frame)", len(observed[1].Raw))
	}
}

// TestChannel_H2DataFrameRecordCallback_TinyDataFrames covers the
// USK-899 headline diagnostic value: tiny-DATA-frame covert channels.
// One LPM is split across many one-byte H2 DATA frames; the proxy must
// surface count(h2-frame) >> count(LPM) so the side-channel signature is
// observable.
func TestChannel_H2DataFrameRecordCallback_TinyDataFrames(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))

	// One LPM split across 9 single-byte H2 DATA frames (5-byte prefix +
	// 4-byte payload).
	wire := makeLPM(false, []byte("abcd"))
	for i, b := range wire {
		stub.pushData(envelope.Send, []byte{b}, i == len(wire)-1)
	}

	var h2Count, lpmCount int
	var mu sync.Mutex
	h2cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		h2Count++
	}
	lpmcb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		lpmCount++
	}

	ch := Wrap(stub, nil, RoleServer,
		WithH2DataFrameRecordCallback(h2cb),
		WithLPMFrameRecordCallback(lpmcb),
	)
	defer ch.Close()

	// Drain Start + 1 reassembled Data = 2.
	_ = drainNext(t, ch, 2)

	mu.Lock()
	defer mu.Unlock()
	if h2Count != 9 {
		t.Errorf("h2-frame callback fired %d times, want 9 (one per single-byte DATA frame)", h2Count)
	}
	if lpmCount != 1 {
		t.Errorf("grpc-lpm callback fired %d times, want 1 (LPM reassembly hides the per-frame boundaries the h2-frame view preserves)", lpmCount)
	}
	if h2Count <= lpmCount {
		t.Errorf("expected count(h2-frame) > count(grpc-lpm) for tiny-DATA-frame covert channel, got h2=%d lpm=%d", h2Count, lpmCount)
	}
}

// TestChannel_H2DataFrameRecordCallback_PreservesContext verifies that
// the per-envelope EnvelopeContext is propagated through to the callback
// so the session orchestrator's record-only Pipeline can apply scope
// gates consistently with the semantic envelopes (HostScope / HTTPScope).
func TestChannel_H2DataFrameRecordCallback_PreservesContext(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, makeLPM(false, []byte("data")), true)
	// pushData does not populate Context; patch the latest queued envelope
	// in place so the DATA event the channel observes carries a non-zero
	// EnvelopeContext.
	stub.mu.Lock()
	stub.recv[len(stub.recv)-1].Context = envelope.EnvelopeContext{
		ConnID:     "conn-7",
		TargetHost: "example.com:443",
	}
	stub.mu.Unlock()

	var got envelope.EnvelopeContext
	cb := func(env *envelope.Envelope) { got = env.Context }

	ch := Wrap(stub, nil, RoleServer, WithH2DataFrameRecordCallback(cb))
	defer ch.Close()

	_ = drainNext(t, ch, 2) // Start + Data

	if got.ConnID != "conn-7" {
		t.Errorf("Context.ConnID = %q, want conn-7", got.ConnID)
	}
	if got.TargetHost != "example.com:443" {
		t.Errorf("Context.TargetHost = %q, want example.com:443", got.TargetHost)
	}
}

// TestChannel_H2DataFrameRecordCallback_FiresOnLPMCapTrip verifies the
// F-1 fix from /review-gate code review of USK-899: when the LPM
// reassembler rejects an oversized declared length (errMessageTooLarge),
// the H2 DATA frame WAS observed on the wire — and that exact scenario
// is one of the smuggling / attack signatures the wire_level=h2-frame
// view was designed to make observable. The callback MUST fire even
// though the absorbData call returns *layer.StreamError without queuing
// any GRPCDataMessage envelope.
//
// Mirrors USK-897's aggregator-path behavior — the aggregator's
// h2-frame callback fires BEFORE the MaxBodySize gate.
func TestChannel_H2DataFrameRecordCallback_FiresOnLPMCapTrip(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-cap-trip")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	// Declare a 200-byte LPM. Tightened cap (below) rejects.
	prefix := make([]byte, lpmPrefixLen)
	binary.BigEndian.PutUint32(prefix[1:5], 200)
	stub.pushData(envelope.Send, prefix, false)

	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		observed = append(observed, env)
	}

	ch := Wrap(stub, nil, RoleServer,
		WithH2DataFrameRecordCallback(cb),
		WithMaxMessageSize(100),
	)
	defer ch.Close()

	// Start envelope first; no h2-frame callback yet (Start is HEADERS).
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next Start: %v", err)
	}
	if got := len(observed); got != 0 {
		t.Fatalf("callback fired %d times before DATA; want 0", got)
	}

	// Second Next consumes the oversized-LPM DATA event and returns
	// *layer.StreamError{ErrorInternalError}. The callback must still
	// have fired exactly once for this H2DataEvent.
	_, err := ch.Next(context.Background())
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: got %v, want *layer.StreamError (LPM cap trip)", err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want ErrorInternalError", se.Code)
	}
	if got := len(observed); got != 1 {
		t.Fatalf("callback fired %d times on LPM-cap-trip DATA; want 1 (the wire frame WAS observed; recording smuggling/attack signatures is the whole point of wire_level=h2-frame)", got)
	}
	if !bytes.Equal(observed[0].Raw, prefix) {
		t.Errorf("observed.Raw = %x, want %x (the oversized-LPM prefix as observed on the wire)", observed[0].Raw, prefix)
	}
	if observed[0].Direction != envelope.Send {
		t.Errorf("observed.Direction = %v, want Send", observed[0].Direction)
	}
}

// TestChannel_H2DataFrameRecordCallback_FiresOnMidLPMEndStream verifies
// the F-1 fix from /review-gate code review of USK-899: when an empty
// END_STREAM DATA frame arrives mid-LPM (the reassembler still holds a
// partial prefix or partial payload), absorbData returns
// *layer.StreamError{ErrorProtocol} without queuing any GRPCDataMessage.
// The H2 DATA frame WAS observed on the wire, so the h2-frame callback
// MUST fire for both the first (partial) DATA frame AND the
// END_STREAM-mid-LPM frame.
func TestChannel_H2DataFrameRecordCallback_FiresOnMidLPMEndStream(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-mid-lpm")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	// First DATA: only 3 of the 5 prefix bytes — reassembler stays in
	// phaseWaitingPrefix with prefBuf non-empty.
	stub.pushData(envelope.Send, []byte{0, 0, 0}, false)
	// Second DATA: empty, END_STREAM=1. absorbData rejects with
	// ErrorProtocol because dir.reasm.prefBuf is non-empty.
	stub.pushData(envelope.Send, nil, true)

	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		observed = append(observed, env)
	}

	ch := Wrap(stub, nil, RoleServer, WithH2DataFrameRecordCallback(cb))
	defer ch.Close()

	// Consume Start.
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next Start: %v", err)
	}
	// First DATA absorbs cleanly (no LPM yet — reassembler holds 3 prefix
	// bytes). Next() loops back without yielding a semantic envelope.
	// Second DATA triggers the mid-LPM error. We surface the error from
	// the second Next call.
	_, err := ch.Next(context.Background())
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: got %v, want *layer.StreamError (mid-LPM EOS)", err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("StreamError.Code = %v, want ErrorProtocol", se.Code)
	}
	if got := len(observed); got != 2 {
		t.Fatalf("callback fired %d times; want 2 (one per H2DataEvent, including the END_STREAM-mid-LPM frame)", got)
	}
	if !bytes.Equal(observed[0].Raw, []byte{0, 0, 0}) {
		t.Errorf("observed[0].Raw = %x, want %x (3-byte partial prefix)", observed[0].Raw, []byte{0, 0, 0})
	}
	if len(observed[1].Raw) != 0 {
		t.Errorf("observed[1].Raw len = %d, want 0 (empty END_STREAM marker frame)", len(observed[1].Raw))
	}
}

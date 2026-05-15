package grpcweb

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestChannel_EncodedFormRecordCallback_FiresOnTextVariant verifies that
// the WithEncodedFormRecordCallback Option fires the callback exactly
// once per inbound text-variant HTTPMessage, with the on-wire base64
// body bytes on the envelope's Raw field (BEFORE base64-decode). USK-898.
func TestChannel_EncodedFormRecordCallback_FiresOnTextVariant(t *testing.T) {
	t.Parallel()

	payload := []byte("hello-grpcweb-base64")
	binaryBody := EncodeFrame(false, false, payload)
	base64Body := EncodeBase64Body(binaryBody)

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web-text+proto"},
	}
	in := mustHTTPRequestEnv("s1", headers, base64Body, "/pkg.Svc/Method")

	var mu sync.Mutex
	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		observed = append(observed, env)
	}

	mock := newMockChannel("s1", in)
	ch := Wrap(mock, RoleServer, WithEncodedFormRecordCallback(cb))
	defer ch.Close()

	_ = drainEnvelopes(t, ch, 5)

	mu.Lock()
	defer mu.Unlock()
	if len(observed) != 1 {
		t.Fatalf("callback fired %d times, want 1 (one per text body)", len(observed))
	}
	env := observed[0]
	if env.Protocol != envelope.ProtocolGRPCWeb {
		t.Errorf("observed.Protocol = %q, want grpc-web", env.Protocol)
	}
	if env.Direction != envelope.Send {
		t.Errorf("observed.Direction = %v, want Send", env.Direction)
	}
	if env.StreamID != "s1" {
		t.Errorf("observed.StreamID = %q, want s1", env.StreamID)
	}
	if env.Message != nil {
		t.Errorf("observed.Message = %T, want nil", env.Message)
	}
	// Raw must equal the base64-encoded body bytes, NOT the decoded LPM bytes.
	if !bytes.Equal(env.Raw, base64Body) {
		t.Errorf("observed.Raw = %x, want base64 body %x", env.Raw, base64Body)
	}
	if bytes.Equal(env.Raw, binaryBody) {
		t.Error("observed.Raw equals decoded binary body; the wire envelope must capture the base64 form per CLAUDE.md MITM Principle 3")
	}
}

// TestChannel_EncodedFormRecordCallback_NotFiredOnBinaryVariant verifies
// the contract that the callback does NOT fire when the inbound
// content-type is the binary variant (application/grpc-web[+proto]).
// Negative behaviour is the key correctness property — the callback
// site lives inside the isBase64 branch.
func TestChannel_EncodedFormRecordCallback_NotFiredOnBinaryVariant(t *testing.T) {
	t.Parallel()

	payload := []byte("hello-grpcweb-binary")
	body := EncodeFrame(false, false, payload)

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
	}
	in := mustHTTPRequestEnv("s1", headers, body, "/pkg.Svc/Method")

	var fired int
	cb := func(env *envelope.Envelope) {
		fired++
	}

	mock := newMockChannel("s1", in)
	ch := Wrap(mock, RoleServer, WithEncodedFormRecordCallback(cb))
	defer ch.Close()

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) < 2 {
		t.Fatalf("drained %d envelopes; want at least Start + Data", len(envs))
	}

	if fired != 0 {
		t.Errorf("callback fired %d times on binary variant; want 0 (negative test — binary skips base64 decode path)", fired)
	}
}

// TestChannel_EncodedFormRecordCallback_NilDisabled verifies that
// installing a nil callback is a no-op — the channel works identically
// to one wrapped without the Option.
func TestChannel_EncodedFormRecordCallback_NilDisabled(t *testing.T) {
	t.Parallel()

	payload := []byte("ping")
	body := EncodeBase64Body(EncodeFrame(false, false, payload))

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web-text+proto"},
	}
	in := mustHTTPRequestEnv("s1", headers, body, "/pkg.Svc/Method")

	mock := newMockChannel("s1", in)
	ch := Wrap(mock, RoleServer, WithEncodedFormRecordCallback(nil))
	defer ch.Close()

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) < 2 {
		t.Fatalf("drained %d envelopes; want at least Start + Data (nil callback should not break the channel)", len(envs))
	}
	if _, ok := envs[0].Message.(*envelope.GRPCStartMessage); !ok {
		t.Errorf("envs[0].Message = %T, want *GRPCStartMessage", envs[0].Message)
	}
}

// TestChannel_EncodedFormRecordCallback_DefensiveCopy verifies that the
// wire envelope's Raw is a fresh copy of the body bytes — mutating the
// callback's envelope MUST NOT corrupt subsequent semantic envelopes,
// and mutating the inbound HTTPMessage's body MUST NOT corrupt the
// callback's recorded bytes.
func TestChannel_EncodedFormRecordCallback_DefensiveCopy(t *testing.T) {
	t.Parallel()

	payload := []byte("defensive-copy-test")
	binaryBody := EncodeFrame(false, false, payload)
	base64Body := EncodeBase64Body(binaryBody)
	// Allocate an independent slice so we can later mutate the inbound
	// HTTPMessage.Body without affecting our expected-value reference.
	expected := append([]byte(nil), base64Body...)

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web-text+proto"},
	}
	in := mustHTTPRequestEnv("s1", headers, base64Body, "/pkg.Svc/Method")

	var observed *envelope.Envelope
	cb := func(env *envelope.Envelope) { observed = env }

	mock := newMockChannel("s1", in)
	ch := Wrap(mock, RoleServer, WithEncodedFormRecordCallback(cb))
	defer ch.Close()

	_ = drainEnvelopes(t, ch, 5)

	if observed == nil {
		t.Fatal("callback did not fire")
	}
	if !bytes.Equal(observed.Raw, expected) {
		t.Fatalf("initial Raw mismatch:\n got %x\nwant %x", observed.Raw, expected)
	}
	// Mutate the inbound HTTPMessage.Body. The wire envelope must be
	// unaffected — fireEncodedFormRecord made a defensive copy.
	if hm, ok := in.Message.(*envelope.HTTPMessage); ok && len(hm.Body) > 0 {
		hm.Body[0] = 0xFF
	}
	if !bytes.Equal(observed.Raw, expected) {
		t.Error("mutating inbound HTTPMessage.Body corrupted the wire envelope Raw; defensive copy failed")
	}
}

// TestChannel_EncodedFormRecordCallback_ContextPropagation verifies that
// the wire envelope's Context is propagated from the source envelope —
// the orchestrator helper (GRPCWebBase64RecordOption) overrides it
// later, but the channel must thread the source Context so per-stream
// scope filters in record-only Pipelines can match consistently with
// the semantic envelopes.
func TestChannel_EncodedFormRecordCallback_ContextPropagation(t *testing.T) {
	t.Parallel()

	payload := []byte("ctx-propagation")
	body := EncodeBase64Body(EncodeFrame(false, false, payload))

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web-text+proto"},
	}
	in := mustHTTPRequestEnv("s1", headers, body, "/pkg.Svc/Method")
	in.Context = envelope.EnvelopeContext{
		ConnID:     "conn-42",
		TargetHost: "example.test:443",
	}

	var observed *envelope.Envelope
	cb := func(env *envelope.Envelope) { observed = env }

	mock := newMockChannel("s1", in)
	ch := Wrap(mock, RoleServer, WithEncodedFormRecordCallback(cb))
	defer ch.Close()

	_ = drainEnvelopes(t, ch, 5)

	if observed == nil {
		t.Fatal("callback did not fire")
	}
	if observed.Context.ConnID != "conn-42" {
		t.Errorf("observed.Context.ConnID = %q, want %q", observed.Context.ConnID, "conn-42")
	}
	if observed.Context.TargetHost != "example.test:443" {
		t.Errorf("observed.Context.TargetHost = %q, want %q", observed.Context.TargetHost, "example.test:443")
	}
}

// TestChannel_EncodedFormRecordCallback_FiresOnMalformedBase64 verifies
// the anomaly-path contract: the callback fires BEFORE the in-place
// base64 decode runs, so the wire snapshot is preserved even when the
// decode subsequently fails (ErrMalformedBase64). The semantic
// envelope-path latches an AnomalyMalformedGRPCWebBase64 Start envelope,
// but the wire-record path captures the failing bytes.
func TestChannel_EncodedFormRecordCallback_FiresOnMalformedBase64(t *testing.T) {
	t.Parallel()

	// Illegal base64 — characters outside the alphabet break decode.
	malformed := []byte("!!!not-valid-base64@@@")

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web-text+proto"},
	}
	in := mustHTTPRequestEnv("s1", headers, malformed, "/pkg.Svc/Method")

	var observed *envelope.Envelope
	cb := func(env *envelope.Envelope) { observed = env }

	mock := newMockChannel("s1", in)
	ch := Wrap(mock, RoleServer, WithEncodedFormRecordCallback(cb))
	defer ch.Close()

	// Drain — the channel will emit an Anomaly Start envelope and latch
	// EOF on emitAnomalyStart. We just want to confirm the callback
	// fired first.
	_ = drainEnvelopes(t, ch, 5)

	if observed == nil {
		t.Fatal("callback did not fire on malformed-base64 body; wire-record-before-decode contract violated")
	}
	if !bytes.Equal(observed.Raw, malformed) {
		t.Errorf("observed.Raw = %x, want malformed bytes %x", observed.Raw, malformed)
	}
}

// TestChannel_EncodedFormRecordCallback_FiresPerHTTPMessage verifies
// that when the inner Channel emits multiple inbound text-variant
// HTTPMessages (the upstream-side case for a server-streaming-shaped
// gRPC-Web response would still be one HTTPMessage; this test exercises
// the simpler invariant of "one HTTPMessage → one callback"), the
// callback fires once per HTTPMessage.
//
// gRPC-Web's wire shape is request/response (single HTTPMessage per
// direction) by spec, so production traffic does not produce multiple
// HTTPMessages per RPC. The mock pumps two HTTPMessages through anyway
// to assert the callback's per-HTTPMessage invocation contract holds
// independent of any per-RPC special-casing.
func TestChannel_EncodedFormRecordCallback_FiresPerHTTPMessage(t *testing.T) {
	t.Parallel()

	body1 := EncodeBase64Body(EncodeFrame(false, false, []byte("first")))
	body2 := EncodeBase64Body(EncodeFrame(false, false, []byte("second")))

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web-text+proto"},
	}
	in1 := mustHTTPRequestEnv("s1", headers, body1, "/pkg.Svc/Method")
	in2 := mustHTTPRequestEnv("s1", headers, body2, "/pkg.Svc/Method")
	// Stagger the inbound HTTPMessages with sequence so the channel does
	// not collapse them.
	in2.Sequence = 1

	var mu sync.Mutex
	var observed [][]byte
	cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		// Copy to decouple from the channel's internal buffer.
		cp := make([]byte, len(env.Raw))
		copy(cp, env.Raw)
		observed = append(observed, cp)
	}

	mock := newMockChannel("s1", in1, in2)
	ch := Wrap(mock, RoleServer, WithEncodedFormRecordCallback(cb))
	defer ch.Close()

	// Drain until EOF — Start + Data + End is 3 per HTTPMessage in the
	// Send-direction request path.
	_, _ = ch.Next(context.Background()) // Start #1
	_, _ = ch.Next(context.Background()) // Data #1
	_, _ = ch.Next(context.Background()) // End #1
	_, _ = ch.Next(context.Background()) // Start #2
	_, _ = ch.Next(context.Background()) // Data #2
	_, _ = ch.Next(context.Background()) // End #2

	mu.Lock()
	defer mu.Unlock()
	if len(observed) != 2 {
		t.Fatalf("callback fired %d times, want 2 (one per inbound text HTTPMessage)", len(observed))
	}
	if !bytes.Equal(observed[0], body1) {
		t.Errorf("observed[0] = %x, want %x", observed[0], body1)
	}
	if !bytes.Equal(observed[1], body2) {
		t.Errorf("observed[1] = %x, want %x", observed[1], body2)
	}
}

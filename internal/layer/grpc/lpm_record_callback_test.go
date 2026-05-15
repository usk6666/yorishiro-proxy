package grpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestChannel_LPMFrameRecordCallback_FiresPerLPM verifies that the
// WithLPMFrameRecordCallback Option fires the callback exactly once per
// fully reassembled LPM, with the LPM wire bytes (5-byte prefix +
// payload, BEFORE decompression) on the envelope's Raw field. USK-896.
func TestChannel_LPMFrameRecordCallback_FiresPerLPM(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))

	a := makeLPM(false, []byte("aaaa"))
	b := makeLPM(false, []byte("bbbb"))
	c := makeLPM(false, []byte("cccc"))
	all := append(append(append([]byte{}, a...), b...), c...)
	stub.pushData(envelope.Send, all, true)

	var mu sync.Mutex
	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		observed = append(observed, env)
	}

	ch := Wrap(stub, nil, RoleServer, WithLPMFrameRecordCallback(cb))
	defer ch.Close()

	// Drain everything: 1 Start envelope + 3 GRPCDataMessage envelopes.
	_ = drainNext(t, ch, 4)

	mu.Lock()
	defer mu.Unlock()
	if len(observed) != 3 {
		t.Fatalf("callback fired %d times, want 3 (one per LPM)", len(observed))
	}

	wants := [][]byte{a, b, c}
	for i, env := range observed {
		if env.Protocol != envelope.ProtocolGRPC {
			t.Errorf("observed[%d].Protocol = %q, want grpc", i, env.Protocol)
		}
		if env.Direction != envelope.Send {
			t.Errorf("observed[%d].Direction = %v, want Send", i, env.Direction)
		}
		if env.StreamID != "stream-1" {
			t.Errorf("observed[%d].StreamID = %q, want stream-1", i, env.StreamID)
		}
		if env.Message != nil {
			t.Errorf("observed[%d].Message = %T, want nil", i, env.Message)
		}
		if !bytes.Equal(env.Raw, wants[i]) {
			t.Errorf("observed[%d].Raw = %x, want %x", i, env.Raw, wants[i])
		}
		// First byte = compressed flag = 0; bytes 1-4 = big-endian length.
		if env.Raw[0] != 0 {
			t.Errorf("observed[%d].Raw[0] (compressed flag) = %d, want 0", i, env.Raw[0])
		}
		gotLen := binary.BigEndian.Uint32(env.Raw[1:5])
		if int(gotLen) != 4 {
			t.Errorf("observed[%d].Raw length-prefix = %d, want 4", i, gotLen)
		}
	}
}

// TestChannel_LPMFrameRecordCallback_FiresBeforeSemantic verifies the
// ordering contract (CLAUDE.md MITM Principle 3): the LPM wire-record
// callback fires BEFORE the GRPCDataMessage envelope is queued for
// emission to the consumer's Next. We assert this by checking that the
// callback's observed envelope count matches the data-envelope count at
// each Next call boundary.
func TestChannel_LPMFrameRecordCallback_FiresBeforeSemantic(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, makeLPM(false, []byte("only")), true)

	var observedAtCallbackTime int
	cb := func(env *envelope.Envelope) {
		observedAtCallbackTime++
	}

	ch := Wrap(stub, nil, RoleServer, WithLPMFrameRecordCallback(cb))
	defer ch.Close()

	// First Next consumes the Start envelope; callback has not fired
	// because no LPM has been observed yet (Start is HEADERS, not DATA).
	startEnv, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #1 (Start): %v", err)
	}
	if _, ok := startEnv.Message.(*envelope.GRPCStartMessage); !ok {
		t.Fatalf("Next #1 Message = %T, want GRPCStartMessage", startEnv.Message)
	}
	if observedAtCallbackTime != 0 {
		t.Errorf("callback fired %d times before Next yielded Data; want 0", observedAtCallbackTime)
	}

	// Second Next: absorbData triggers callback BEFORE queuing the
	// GRPCDataMessage. By the time Next returns the data envelope, the
	// callback must have already observed the LPM.
	dataEnv, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #2 (Data): %v", err)
	}
	if _, ok := dataEnv.Message.(*envelope.GRPCDataMessage); !ok {
		t.Fatalf("Next #2 Message = %T, want GRPCDataMessage", dataEnv.Message)
	}
	if observedAtCallbackTime != 1 {
		t.Errorf("callback fired %d times by the time Next yielded Data; want 1 (wire-record-before-semantic)", observedAtCallbackTime)
	}
}

// TestChannel_LPMFrameRecordCallback_CompressedFlagPreserved verifies
// the wire envelope captures the LPM compressed flag = 1 verbatim (the
// canonical "gzip-encoded LPM" case). The semantic envelope's Payload
// is decompressed; the wire envelope's Raw is the as-observed
// (compressed) bytes — they intentionally differ.
func TestChannel_LPMFrameRecordCallback_CompressedFlagPreserved(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	hdrs := requestStartHeaders("/svc.S/M",
		envelope.KeyValue{Name: "grpc-encoding", Value: "gzip"},
	)
	stub.pushHeaders(envelope.Send, []byte("HPACK"), hdrs)

	original := []byte("compressed body")
	compressed := gzipCompress(t, original)
	stub.pushData(envelope.Send, makeLPM(true, compressed), true)

	var mu sync.Mutex
	var observed []*envelope.Envelope
	cb := func(env *envelope.Envelope) {
		mu.Lock()
		defer mu.Unlock()
		observed = append(observed, env)
	}

	ch := Wrap(stub, nil, RoleServer, WithLPMFrameRecordCallback(cb))
	defer ch.Close()

	envs := drainNext(t, ch, 2) // Start + Data
	dm := envs[1].Message.(*envelope.GRPCDataMessage)
	if string(dm.Payload) != string(original) {
		t.Errorf("semantic envelope Payload = %q, want %q (decompressed)", dm.Payload, original)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(observed) != 1 {
		t.Fatalf("callback fired %d times, want 1", len(observed))
	}
	rawEnv := observed[0]
	// Wire envelope: 5-byte prefix with compressed flag = 1 + compressed bytes.
	if rawEnv.Raw[0] != 1 {
		t.Errorf("wire Raw[0] (compressed flag) = %d, want 1", rawEnv.Raw[0])
	}
	rawPayload := rawEnv.Raw[lpmPrefixLen:]
	if !bytes.Equal(rawPayload, compressed) {
		t.Errorf("wire Raw payload = %x, want %x (compressed, NOT decompressed)", rawPayload, compressed)
	}
	if bytes.Equal(rawPayload, original) {
		t.Errorf("wire Raw payload = decompressed original; the wire envelope must capture the compressed bytes per CLAUDE.md MITM Principle 3")
	}
}

// TestChannel_LPMFrameRecordCallback_NilDisabled verifies that the
// Option installed with nil callback is a no-op — the channel works
// identically to one wrapped without the Option.
func TestChannel_LPMFrameRecordCallback_NilDisabled(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, makeLPM(false, []byte("only")), true)

	ch := Wrap(stub, nil, RoleServer, WithLPMFrameRecordCallback(nil))
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

// TestChannel_LPMFrameRecordCallback_DefensiveCopy verifies that the
// LPM wire envelope's Raw is a fresh copy independent of the semantic
// GRPCDataMessage envelope's Raw. Mutating one MUST NOT corrupt the
// other.
func TestChannel_LPMFrameRecordCallback_DefensiveCopy(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, makeLPM(false, []byte("data")), true)

	var observed *envelope.Envelope
	cb := func(env *envelope.Envelope) { observed = env }

	ch := Wrap(stub, nil, RoleServer, WithLPMFrameRecordCallback(cb))
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	dataEnv := envs[1]

	if observed == nil {
		t.Fatal("callback did not fire")
	}
	// Different slices: cap or backing array differs.
	if &observed.Raw[0] == &dataEnv.Raw[0] {
		t.Error("LPM wire envelope and semantic envelope share the same Raw backing array; defensive copy missing")
	}
	// Same content though.
	if !bytes.Equal(observed.Raw, dataEnv.Raw) {
		t.Errorf("wire Raw and semantic Raw byte content differ; wire=%x semantic=%x", observed.Raw, dataEnv.Raw)
	}
	// Mutate the semantic envelope's Raw; the wire envelope must be
	// unaffected.
	saved := append([]byte(nil), observed.Raw...)
	dataEnv.Raw[0] = 0xFF
	if !bytes.Equal(observed.Raw, saved) {
		t.Error("mutating semantic envelope Raw corrupted the wire envelope Raw; defensive copy failed")
	}
}

package pipeline

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestWireEncoderRegistry_RegisterAndLookup(t *testing.T) {
	r := NewWireEncoderRegistry()
	if r.Len() != 0 {
		t.Fatalf("Len = %d, want 0", r.Len())
	}

	called := false
	enc := func(env *envelope.Envelope) ([]byte, error) {
		called = true
		return []byte("ok"), nil
	}
	r.Register(envelope.ProtocolHTTP, enc)
	if r.Len() != 1 {
		t.Errorf("Len after register = %d, want 1", r.Len())
	}
	got, ok := r.Lookup(envelope.ProtocolHTTP)
	if !ok {
		t.Fatal("Lookup miss")
	}
	if _, err := got(nil); err != nil {
		t.Fatalf("invoke err = %v", err)
	}
	if !called {
		t.Error("encoder not invoked")
	}
}

func TestWireEncoderRegistry_LookupMiss(t *testing.T) {
	r := NewWireEncoderRegistry()
	if _, ok := r.Lookup(envelope.ProtocolGRPC); ok {
		t.Error("expected miss")
	}
}

func TestWireEncoderRegistry_NilReceiverSafe(t *testing.T) {
	var r *WireEncoderRegistry
	if r.Len() != 0 {
		t.Errorf("nil Len = %d", r.Len())
	}
	if _, ok := r.Lookup(envelope.ProtocolHTTP); ok {
		t.Error("nil Lookup should return false")
	}
	r.Register(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) { return nil, nil })
	// no panic
}

func TestWireEncoderRegistry_NilFnRemoves(t *testing.T) {
	r := NewWireEncoderRegistry()
	r.Register(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) { return nil, nil })
	r.Register(envelope.ProtocolHTTP, nil)
	if _, ok := r.Lookup(envelope.ProtocolHTTP); ok {
		t.Error("nil register should remove")
	}
}

func TestWireEncoderRegistry_ReregisterReplaces(t *testing.T) {
	r := NewWireEncoderRegistry()
	r.Register(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) { return []byte("a"), nil })
	r.Register(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) { return []byte("b"), nil })
	enc, _ := r.Lookup(envelope.ProtocolHTTP)
	got, _ := enc(nil)
	if string(got) != "b" {
		t.Errorf("got = %q, want b", string(got))
	}
}

func TestRecordStep_WithWireEncoderRegistry_Sharing(t *testing.T) {
	// Verify the integration point used by USK-671: the same registry is
	// shared between RecordStep and PluginStepPost.
	reg := NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) { return []byte("encoded"), nil })

	rs := NewRecordStep(nil, nil, WithWireEncoderRegistry(reg))
	if rs.encoders != reg {
		t.Error("RecordStep did not adopt the shared registry")
	}
	post := NewPluginStepPost(nil, reg, nil)
	if post.encoders != reg {
		t.Error("PluginStepPost did not adopt the shared registry")
	}
}

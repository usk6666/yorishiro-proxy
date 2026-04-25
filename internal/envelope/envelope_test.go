package envelope

import (
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

func TestDirection_String(t *testing.T) {
	tests := []struct {
		d    Direction
		want string
	}{
		{Send, "send"},
		{Receive, "receive"},
		{Direction(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("Direction(%d).String() = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestHTTPMessage_Protocol(t *testing.T) {
	m := &HTTPMessage{}
	if got := m.Protocol(); got != ProtocolHTTP {
		t.Errorf("HTTPMessage.Protocol() = %q, want %q", got, ProtocolHTTP)
	}
}

func TestRawMessage_Protocol(t *testing.T) {
	m := &RawMessage{}
	if got := m.Protocol(); got != ProtocolRaw {
		t.Errorf("RawMessage.Protocol() = %q, want %q", got, ProtocolRaw)
	}
}

func TestHTTPMessage_CloneMessage_DeepCopy(t *testing.T) {
	orig := &HTTPMessage{
		Method:       "POST",
		Scheme:       "https",
		Authority:    "example.com",
		Path:         "/api/v1",
		RawQuery:     "foo=bar",
		Status:       200,
		StatusReason: "OK",
		Headers: []KeyValue{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "X-Custom", Value: "value"},
		},
		Trailers: []KeyValue{
			{Name: "Checksum", Value: "abc123"},
		},
		Body: []byte(`{"key":"value"}`),
	}

	cloned := orig.CloneMessage().(*HTTPMessage)

	// Verify values are equal
	if cloned.Method != orig.Method {
		t.Errorf("Method: got %q, want %q", cloned.Method, orig.Method)
	}
	if cloned.Scheme != orig.Scheme {
		t.Errorf("Scheme: got %q, want %q", cloned.Scheme, orig.Scheme)
	}
	if cloned.Authority != orig.Authority {
		t.Errorf("Authority: got %q, want %q", cloned.Authority, orig.Authority)
	}
	if cloned.Path != orig.Path {
		t.Errorf("Path: got %q, want %q", cloned.Path, orig.Path)
	}
	if cloned.RawQuery != orig.RawQuery {
		t.Errorf("RawQuery: got %q, want %q", cloned.RawQuery, orig.RawQuery)
	}
	if cloned.Status != orig.Status {
		t.Errorf("Status: got %d, want %d", cloned.Status, orig.Status)
	}
	if cloned.StatusReason != orig.StatusReason {
		t.Errorf("StatusReason: got %q, want %q", cloned.StatusReason, orig.StatusReason)
	}
	if len(cloned.Headers) != len(orig.Headers) {
		t.Fatalf("Headers length: got %d, want %d", len(cloned.Headers), len(orig.Headers))
	}
	if len(cloned.Trailers) != len(orig.Trailers) {
		t.Fatalf("Trailers length: got %d, want %d", len(cloned.Trailers), len(orig.Trailers))
	}
	if string(cloned.Body) != string(orig.Body) {
		t.Errorf("Body: got %q, want %q", cloned.Body, orig.Body)
	}

	// Verify independence: mutating the clone must not affect the original
	cloned.Headers[0].Name = "MUTATED"
	if orig.Headers[0].Name == "MUTATED" {
		t.Error("Headers are not independent: mutating clone affected original")
	}

	cloned.Trailers[0].Name = "MUTATED"
	if orig.Trailers[0].Name == "MUTATED" {
		t.Error("Trailers are not independent: mutating clone affected original")
	}

	cloned.Body[0] = 'X'
	if orig.Body[0] == 'X' {
		t.Error("Body is not independent: mutating clone affected original")
	}
}

func TestRawMessage_CloneMessage_DeepCopy(t *testing.T) {
	orig := &RawMessage{
		Bytes: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	cloned := orig.CloneMessage().(*RawMessage)

	if string(cloned.Bytes) != string(orig.Bytes) {
		t.Errorf("Bytes: got %q, want %q", cloned.Bytes, orig.Bytes)
	}

	// Verify independence
	cloned.Bytes[0] = 'X'
	if orig.Bytes[0] == 'X' {
		t.Error("Bytes are not independent: mutating clone affected original")
	}
}

func TestRawMessage_CloneMessage_NilBytes(t *testing.T) {
	orig := &RawMessage{Bytes: nil}
	cloned := orig.CloneMessage().(*RawMessage)
	if cloned.Bytes != nil {
		t.Error("CloneMessage of nil Bytes should produce nil, not empty slice")
	}
}

// TestHTTPMessage_CloneMessage_BodyBufferRetained verifies that CloneMessage
// shares the BodyBuffer pointer and calls Retain so the clone and original
// both hold live references. The buffer is fully released only after both
// owners call Release.
func TestHTTPMessage_CloneMessage_BodyBufferRetained(t *testing.T) {
	bb := bodybuf.NewMemory([]byte("shared-body"))
	orig := &HTTPMessage{
		Method:     "POST",
		BodyBuffer: bb,
	}

	cloned := orig.CloneMessage().(*HTTPMessage)

	if cloned.BodyBuffer != orig.BodyBuffer {
		t.Fatal("CloneMessage should share BodyBuffer pointer with original")
	}

	// Release the original owner's reference; Len() must still work because
	// the clone still holds a ref.
	if err := orig.BodyBuffer.Release(); err != nil {
		t.Fatalf("first Release (orig): %v", err)
	}
	if got := cloned.BodyBuffer.Len(); got != int64(len("shared-body")) {
		t.Errorf("clone.BodyBuffer.Len() after orig Release = %d, want %d",
			got, len("shared-body"))
	}

	// Final release: clone drops the last reference; cleanup happens now.
	if err := cloned.BodyBuffer.Release(); err != nil {
		t.Fatalf("second Release (clone): %v", err)
	}
}

func TestHTTPMessage_CloneMessage_NilSlices(t *testing.T) {
	orig := &HTTPMessage{
		Method: "GET",
		// Headers, Trailers, Body all nil
	}
	cloned := orig.CloneMessage().(*HTTPMessage)

	if cloned.Headers != nil {
		t.Error("CloneMessage of nil Headers should produce nil")
	}
	if cloned.Trailers != nil {
		t.Error("CloneMessage of nil Trailers should produce nil")
	}
	if cloned.Body != nil {
		t.Error("CloneMessage of nil Body should produce nil")
	}
}

func TestEnvelope_Clone_DeepCopy(t *testing.T) {
	orig := &Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-1",
		Sequence:  42,
		Direction: Send,
		Protocol:  ProtocolHTTP,
		Raw:       []byte("raw wire bytes"),
		Message: &HTTPMessage{
			Method: "GET",
			Path:   "/test",
			Headers: []KeyValue{
				{Name: "Host", Value: "example.com"},
			},
		},
		Context: EnvelopeContext{
			ConnID:     "conn-1",
			TargetHost: "example.com:443",
			ReceivedAt: time.Now(),
			TLS: &TLSSnapshot{
				SNI:  "example.com",
				ALPN: "h2",
			},
		},
		Opaque: "layer-state",
	}

	cloned := orig.Clone()

	// Identity fields preserved
	if cloned.StreamID != orig.StreamID {
		t.Errorf("StreamID: got %q, want %q", cloned.StreamID, orig.StreamID)
	}
	if cloned.FlowID != orig.FlowID {
		t.Errorf("FlowID: got %q, want %q", cloned.FlowID, orig.FlowID)
	}
	if cloned.Sequence != orig.Sequence {
		t.Errorf("Sequence: got %d, want %d", cloned.Sequence, orig.Sequence)
	}
	if cloned.Direction != orig.Direction {
		t.Errorf("Direction: got %v, want %v", cloned.Direction, orig.Direction)
	}
	if cloned.Protocol != orig.Protocol {
		t.Errorf("Protocol: got %q, want %q", cloned.Protocol, orig.Protocol)
	}

	// Raw bytes independence
	if string(cloned.Raw) != string(orig.Raw) {
		t.Errorf("Raw: got %q, want %q", cloned.Raw, orig.Raw)
	}
	cloned.Raw[0] = 'X'
	if orig.Raw[0] == 'X' {
		t.Error("Raw is not independent: mutating clone affected original")
	}

	// Message deep-copied
	clonedHTTP := cloned.Message.(*HTTPMessage)
	origHTTP := orig.Message.(*HTTPMessage)
	clonedHTTP.Headers[0].Name = "MUTATED"
	if origHTTP.Headers[0].Name == "MUTATED" {
		t.Error("Message.Headers are not independent: mutating clone affected original")
	}

	// Context shallow copy (TLS pointer shared — immutable)
	if cloned.Context.ConnID != orig.Context.ConnID {
		t.Errorf("Context.ConnID: got %q, want %q", cloned.Context.ConnID, orig.Context.ConnID)
	}
	if cloned.Context.TLS != orig.Context.TLS {
		t.Error("Context.TLS should be the same pointer (shared, immutable)")
	}

	// Opaque not cloned
	if cloned.Opaque != nil {
		t.Error("Opaque should be nil in clone (not cloned)")
	}
}

func TestEnvelope_Clone_NilMessage(t *testing.T) {
	orig := &Envelope{
		StreamID: "stream-1",
		Protocol: ProtocolRaw,
		Raw:      []byte("data"),
		// Message is nil
	}

	cloned := orig.Clone()
	if cloned.Message != nil {
		t.Error("Clone of nil Message should produce nil")
	}
	if string(cloned.Raw) != "data" {
		t.Errorf("Raw: got %q, want %q", cloned.Raw, "data")
	}
}

func TestEnvelope_Clone_NilRaw(t *testing.T) {
	orig := &Envelope{
		StreamID: "stream-1",
		Protocol: ProtocolRaw,
		// Raw is nil
		Message: &RawMessage{Bytes: []byte("hello")},
	}

	cloned := orig.Clone()
	if cloned.Raw != nil {
		t.Error("Clone of nil Raw should produce nil")
	}
}

func TestEnvelope_Clone_NilTLS(t *testing.T) {
	orig := &Envelope{
		StreamID: "stream-1",
		Protocol: ProtocolRaw,
		Context: EnvelopeContext{
			ConnID:     "conn-1",
			TargetHost: "example.com",
			// TLS is nil
		},
		Message: &RawMessage{Bytes: []byte("data")},
	}

	// Should not panic
	cloned := orig.Clone()
	if cloned.Context.TLS != nil {
		t.Error("Clone of nil TLS should produce nil")
	}
}

// Compile-time interface compliance checks.
var (
	_ Message = (*HTTPMessage)(nil)
	_ Message = (*RawMessage)(nil)
	_ Message = (*WSMessage)(nil)
	_ Message = (*GRPCStartMessage)(nil)
	_ Message = (*GRPCDataMessage)(nil)
	_ Message = (*GRPCEndMessage)(nil)
	_ Message = (*SSEMessage)(nil)
)

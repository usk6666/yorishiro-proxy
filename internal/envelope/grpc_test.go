package envelope

import (
	"testing"
	"time"
)

func TestGRPCStartMessage_Protocol(t *testing.T) {
	m := &GRPCStartMessage{}
	if got := m.Protocol(); got != ProtocolGRPC {
		t.Errorf("GRPCStartMessage.Protocol() = %q, want %q", got, ProtocolGRPC)
	}
}

func TestGRPCDataMessage_Protocol(t *testing.T) {
	m := &GRPCDataMessage{}
	if got := m.Protocol(); got != ProtocolGRPC {
		t.Errorf("GRPCDataMessage.Protocol() = %q, want %q", got, ProtocolGRPC)
	}
}

func TestGRPCEndMessage_Protocol(t *testing.T) {
	m := &GRPCEndMessage{}
	if got := m.Protocol(); got != ProtocolGRPC {
		t.Errorf("GRPCEndMessage.Protocol() = %q, want %q", got, ProtocolGRPC)
	}
}

func TestGRPCStartMessage_CloneMessage_DeepCopy(t *testing.T) {
	orig := &GRPCStartMessage{
		Service: "example.Greeter",
		Method:  "SayHello",
		Metadata: []KeyValue{
			{Name: "x-request-id", Value: "abc123"},
			{Name: "authorization", Value: "Bearer xyz"},
		},
		Timeout:        5 * time.Second,
		ContentType:    "application/grpc+proto",
		Encoding:       "gzip",
		AcceptEncoding: []string{"gzip", "deflate", "identity"},
	}

	cloned := orig.CloneMessage().(*GRPCStartMessage)

	if cloned.Service != orig.Service {
		t.Errorf("Service: got %q, want %q", cloned.Service, orig.Service)
	}
	if cloned.Method != orig.Method {
		t.Errorf("Method: got %q, want %q", cloned.Method, orig.Method)
	}
	if cloned.Timeout != orig.Timeout {
		t.Errorf("Timeout: got %v, want %v", cloned.Timeout, orig.Timeout)
	}
	if cloned.ContentType != orig.ContentType {
		t.Errorf("ContentType: got %q, want %q", cloned.ContentType, orig.ContentType)
	}
	if cloned.Encoding != orig.Encoding {
		t.Errorf("Encoding: got %q, want %q", cloned.Encoding, orig.Encoding)
	}
	if len(cloned.Metadata) != len(orig.Metadata) {
		t.Fatalf("Metadata length: got %d, want %d", len(cloned.Metadata), len(orig.Metadata))
	}
	if len(cloned.AcceptEncoding) != len(orig.AcceptEncoding) {
		t.Fatalf("AcceptEncoding length: got %d, want %d",
			len(cloned.AcceptEncoding), len(orig.AcceptEncoding))
	}

	// Metadata independence
	cloned.Metadata[0].Name = "MUTATED"
	if orig.Metadata[0].Name == "MUTATED" {
		t.Error("Metadata not independent: mutating clone affected original")
	}

	// AcceptEncoding independence
	cloned.AcceptEncoding[0] = "MUTATED"
	if orig.AcceptEncoding[0] == "MUTATED" {
		t.Error("AcceptEncoding not independent: mutating clone affected original")
	}
}

func TestGRPCStartMessage_CloneMessage_NilSlices(t *testing.T) {
	orig := &GRPCStartMessage{Service: "s", Method: "m"}
	cloned := orig.CloneMessage().(*GRPCStartMessage)
	if cloned.Metadata != nil {
		t.Error("CloneMessage of nil Metadata should produce nil")
	}
	if cloned.AcceptEncoding != nil {
		t.Error("CloneMessage of nil AcceptEncoding should produce nil")
	}
}

func TestGRPCDataMessage_CloneMessage_DeepCopy(t *testing.T) {
	orig := &GRPCDataMessage{
		Service:    "example.Greeter",
		Method:     "SayHello",
		Compressed: true,
		WireLength: 42,
		Payload:    []byte{0x0A, 0x05, 'h', 'e', 'l', 'l', 'o'},
	}

	cloned := orig.CloneMessage().(*GRPCDataMessage)

	if cloned.Service != orig.Service {
		t.Errorf("Service: got %q, want %q", cloned.Service, orig.Service)
	}
	if cloned.Method != orig.Method {
		t.Errorf("Method: got %q, want %q", cloned.Method, orig.Method)
	}
	if cloned.Compressed != orig.Compressed {
		t.Errorf("Compressed: got %v, want %v", cloned.Compressed, orig.Compressed)
	}
	if cloned.WireLength != orig.WireLength {
		t.Errorf("WireLength: got %d, want %d", cloned.WireLength, orig.WireLength)
	}
	if string(cloned.Payload) != string(orig.Payload) {
		t.Errorf("Payload: got %v, want %v", cloned.Payload, orig.Payload)
	}

	// Payload independence
	cloned.Payload[0] = 0xFF
	if orig.Payload[0] == 0xFF {
		t.Error("Payload is not independent: mutating clone affected original")
	}
}

func TestGRPCDataMessage_CloneMessage_NilPayload(t *testing.T) {
	orig := &GRPCDataMessage{Service: "s", Method: "m"}
	cloned := orig.CloneMessage().(*GRPCDataMessage)
	if cloned.Payload != nil {
		t.Error("CloneMessage of nil Payload should produce nil")
	}
}

func TestGRPCEndMessage_CloneMessage_DeepCopy(t *testing.T) {
	orig := &GRPCEndMessage{
		Status:        2, // codes.Unknown
		Message:       "internal error",
		StatusDetails: []byte{0x08, 0x02},
		Trailers: []KeyValue{
			{Name: "x-debug-id", Value: "trace-1"},
		},
	}

	cloned := orig.CloneMessage().(*GRPCEndMessage)

	if cloned.Status != orig.Status {
		t.Errorf("Status: got %d, want %d", cloned.Status, orig.Status)
	}
	if cloned.Message != orig.Message {
		t.Errorf("Message: got %q, want %q", cloned.Message, orig.Message)
	}
	if string(cloned.StatusDetails) != string(orig.StatusDetails) {
		t.Errorf("StatusDetails: got %v, want %v", cloned.StatusDetails, orig.StatusDetails)
	}
	if len(cloned.Trailers) != len(orig.Trailers) {
		t.Fatalf("Trailers length: got %d, want %d", len(cloned.Trailers), len(orig.Trailers))
	}

	// StatusDetails independence
	cloned.StatusDetails[0] = 0xFF
	if orig.StatusDetails[0] == 0xFF {
		t.Error("StatusDetails is not independent: mutating clone affected original")
	}

	// Trailers independence
	cloned.Trailers[0].Name = "MUTATED"
	if orig.Trailers[0].Name == "MUTATED" {
		t.Error("Trailers not independent: mutating clone affected original")
	}
}

func TestGRPCEndMessage_CloneMessage_NilSlices(t *testing.T) {
	orig := &GRPCEndMessage{Status: 0}
	cloned := orig.CloneMessage().(*GRPCEndMessage)
	if cloned.StatusDetails != nil {
		t.Error("CloneMessage of nil StatusDetails should produce nil")
	}
	if cloned.Trailers != nil {
		t.Error("CloneMessage of nil Trailers should produce nil")
	}
}

func TestGRPCMessages_ZeroValue(t *testing.T) {
	// Zero-value behavior: Protocol() still returns ProtocolGRPC and
	// CloneMessage does not panic.
	var (
		start = &GRPCStartMessage{}
		data  = &GRPCDataMessage{}
		end   = &GRPCEndMessage{}
	)
	if start.Protocol() != ProtocolGRPC || data.Protocol() != ProtocolGRPC || end.Protocol() != ProtocolGRPC {
		t.Error("zero-value Protocol() should be ProtocolGRPC for all three gRPC messages")
	}
	_ = start.CloneMessage()
	_ = data.CloneMessage()
	_ = end.CloneMessage()
}

func TestCloneStrings(t *testing.T) {
	tests := []struct {
		name string
		in   []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"one", []string{"gzip"}},
		{"many", []string{"gzip", "deflate", "identity"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := cloneStrings(tt.in)
			if tt.in == nil {
				if out != nil {
					t.Errorf("cloneStrings(nil) = %v, want nil", out)
				}
				return
			}
			if len(out) != len(tt.in) {
				t.Fatalf("length: got %d, want %d", len(out), len(tt.in))
			}
			for i := range tt.in {
				if out[i] != tt.in[i] {
					t.Errorf("element %d: got %q, want %q", i, out[i], tt.in[i])
				}
			}
			// Independence check (only for non-empty slices).
			if len(tt.in) > 0 {
				out[0] = "MUTATED"
				if tt.in[0] == "MUTATED" {
					t.Error("cloneStrings not independent: mutating clone affected original")
				}
			}
		})
	}
}

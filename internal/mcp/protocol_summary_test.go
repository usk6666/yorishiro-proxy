package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestBuildProtocolSummary_CanonicalSpellings verifies the canonical
// Envelope.Protocol values dispatch correctly. Legacy spellings were
// retired in USK-705 (RFC-001 N9 design review Q8).
func TestBuildProtocolSummary_CanonicalSpellings(t *testing.T) {
	t.Run("ws", func(t *testing.T) {
		msgs := []*flow.Flow{
			{Sequence: 0, Direction: "send", Metadata: map[string]string{"opcode": "1"}},
			{Sequence: 1, Direction: "receive", Metadata: map[string]string{"opcode": "8"}},
		}
		summary := buildProtocolSummary("ws", msgs)
		if summary == nil {
			t.Fatal("summary should not be nil for canonical ws")
		}
		if summary["message_count"] != "2" {
			t.Errorf("message_count = %q, want 2", summary["message_count"])
		}
		if summary["last_frame_type"] != "Close" {
			t.Errorf("last_frame_type = %q, want Close", summary["last_frame_type"])
		}
	})

	t.Run("grpc", func(t *testing.T) {
		msgs := []*flow.Flow{
			{Sequence: 0, Direction: "send", Metadata: map[string]string{"service": "S", "method": "M"}},
			{Sequence: 1, Direction: "receive", Metadata: map[string]string{"grpc_status": "0"}},
		}
		summary := buildProtocolSummary("grpc", msgs)
		if summary == nil {
			t.Fatal("summary should not be nil for canonical grpc")
		}
		if summary["service"] != "S" || summary["method"] != "M" || summary["grpc_status"] != "0" {
			t.Errorf("unexpected summary: %+v", summary)
		}
	})

	t.Run("grpc-web", func(t *testing.T) {
		msgs := []*flow.Flow{
			{Sequence: 0, Direction: "send", Metadata: map[string]string{"service": "S", "method": "M"}},
		}
		summary := buildProtocolSummary("grpc-web", msgs)
		if summary == nil {
			t.Fatal("summary should not be nil for canonical grpc-web")
		}
		if summary["service"] != "S" {
			t.Errorf("service = %q, want S", summary["service"])
		}
	})

	t.Run("raw", func(t *testing.T) {
		msgs := []*flow.Flow{
			{Sequence: 0, Direction: "send", Body: []byte("ab")},
			{Sequence: 1, Direction: "receive", Body: []byte("cde")},
		}
		summary := buildProtocolSummary("raw", msgs)
		if summary == nil {
			t.Fatal("summary should not be nil for canonical raw")
		}
		if summary["send_bytes"] != "2" || summary["receive_bytes"] != "3" {
			t.Errorf("unexpected raw summary: %+v", summary)
		}
	})

	t.Run("sse_returns_nil", func(t *testing.T) {
		msgs := []*flow.Flow{{Sequence: 0, Direction: "receive"}}
		if got := buildProtocolSummary("sse", msgs); got != nil {
			t.Errorf("sse summary should be nil (no dedicated builder), got %+v", got)
		}
	})

	t.Run("tls-handshake_returns_nil", func(t *testing.T) {
		if got := buildProtocolSummary("tls-handshake", nil); got != nil {
			t.Errorf("tls-handshake summary should be nil, got %+v", got)
		}
	})

	t.Run("unknown_returns_nil", func(t *testing.T) {
		if got := buildProtocolSummary("nonsense-protocol", nil); got != nil {
			t.Errorf("unknown protocol should yield nil, got %+v", got)
		}
	})
}

func TestWsOpcodeLabel(t *testing.T) {
	tests := []struct {
		opcode string
		want   string
	}{
		{"0", "Continuation"},
		{"1", "Text"},
		{"2", "Binary"},
		{"8", "Close"},
		{"9", "Ping"},
		{"10", "Pong"},
		{"99", "Unknown(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.opcode, func(t *testing.T) {
			got := wsOpcodeLabel(tc.opcode)
			if got != tc.want {
				t.Errorf("wsOpcodeLabel(%q) = %q, want %q", tc.opcode, got, tc.want)
			}
		})
	}
}

func TestGrpcStatusLabel(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"0", "OK"},
		{"1", "CANCELLED"},
		{"2", "UNKNOWN"},
		{"5", "NOT_FOUND"},
		{"13", "INTERNAL"},
		{"16", "UNAUTHENTICATED"},
		{"99", ""},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			got := grpcStatusLabel(tc.status)
			if got != tc.want {
				t.Errorf("grpcStatusLabel(%q) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

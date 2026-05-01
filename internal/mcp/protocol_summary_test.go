package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

func TestBuildProtocolSummary_WebSocket(t *testing.T) {
	msgs := []*flow.Flow{
		{Sequence: 0, Direction: "send", Body: []byte("hello"), Metadata: map[string]string{"opcode": "1"}},
		{Sequence: 1, Direction: "receive", Body: []byte("world"), Metadata: map[string]string{"opcode": "1"}},
		{Sequence: 2, Direction: "send", Body: []byte("bye"), Metadata: map[string]string{"opcode": "8"}},
	}

	summary := buildProtocolSummary("WebSocket", msgs)

	if summary == nil {
		t.Fatal("summary should not be nil for WebSocket")
	}
	if summary["message_count"] != "3" {
		t.Errorf("message_count = %q, want 3", summary["message_count"])
	}
	if summary["last_frame_type"] != "Close" {
		t.Errorf("last_frame_type = %q, want Close", summary["last_frame_type"])
	}
}

func TestBuildProtocolSummary_WebSocket_Empty(t *testing.T) {
	summary := buildProtocolSummary("WebSocket", nil)

	if summary == nil {
		t.Fatal("summary should not be nil")
	}
	if summary["message_count"] != "0" {
		t.Errorf("message_count = %q, want 0", summary["message_count"])
	}
	if _, ok := summary["last_frame_type"]; ok {
		t.Error("last_frame_type should not be present for empty messages")
	}
}

func TestBuildProtocolSummary_HTTP2(t *testing.T) {
	msgs := []*flow.Flow{
		{Sequence: 0, Direction: "send", Method: "GET"},
		{Sequence: 1, Direction: "receive", StatusCode: 200},
	}

	summary := buildProtocolSummary("HTTP/2", msgs)

	if summary == nil {
		t.Fatal("summary should not be nil for HTTP/2")
	}
	if summary["stream_count"] != "1" {
		t.Errorf("stream_count = %q, want 1", summary["stream_count"])
	}
}

func TestBuildProtocolSummary_GRPC(t *testing.T) {
	msgs := []*flow.Flow{
		{Sequence: 0, Direction: "send", Metadata: map[string]string{"service": "UserService", "method": "GetUser"}},
		{Sequence: 1, Direction: "receive", Metadata: map[string]string{"grpc_status": "0"}},
	}

	summary := buildProtocolSummary("gRPC", msgs)

	if summary == nil {
		t.Fatal("summary should not be nil for gRPC")
	}
	if summary["service"] != "UserService" {
		t.Errorf("service = %q, want UserService", summary["service"])
	}
	if summary["method"] != "GetUser" {
		t.Errorf("method = %q, want GetUser", summary["method"])
	}
	if summary["grpc_status"] != "0" {
		t.Errorf("grpc_status = %q, want 0", summary["grpc_status"])
	}
	if summary["grpc_status_name"] != "OK" {
		t.Errorf("grpc_status_name = %q, want OK", summary["grpc_status_name"])
	}
}

func TestBuildProtocolSummary_TCP(t *testing.T) {
	msgs := []*flow.Flow{
		{Sequence: 0, Direction: "send", Body: []byte("hello")},
		{Sequence: 1, Direction: "receive", Body: []byte("world!")},
		{Sequence: 2, Direction: "send", Body: []byte("bye")},
	}

	summary := buildProtocolSummary("TCP", msgs)

	if summary == nil {
		t.Fatal("summary should not be nil for TCP")
	}
	if summary["send_bytes"] != "8" { // "hello" + "bye" = 5 + 3
		t.Errorf("send_bytes = %q, want 8", summary["send_bytes"])
	}
	if summary["receive_bytes"] != "6" { // "world!"
		t.Errorf("receive_bytes = %q, want 6", summary["receive_bytes"])
	}
}

func TestBuildProtocolSummary_HTTP(t *testing.T) {
	msgs := []*flow.Flow{
		{Sequence: 0, Direction: "send"},
		{Sequence: 1, Direction: "receive"},
	}

	summary := buildProtocolSummary("HTTP/1.x", msgs)
	if summary != nil {
		t.Error("summary should be nil for HTTP/1.x")
	}

	summary = buildProtocolSummary("HTTPS", msgs)
	if summary != nil {
		t.Error("summary should be nil for HTTPS")
	}

	// New canonical "http" spelling: HTTPMessage covers both HTTP/1.x and
	// HTTP/2 wire versions; the existing legacy summary is HTTP/2-specific
	// (keyed by literal "HTTP/2"), so generic canonical "http" returns nil
	// — matching the legacy HTTP/1.x/HTTPS path.
	summary = buildProtocolSummary("http", msgs)
	if summary != nil {
		t.Error("summary should be nil for canonical http (no version distinction)")
	}
}

// TestBuildProtocolSummary_NewSpellings verifies that the new lowercase
// canonical Envelope.Protocol values dispatch through canonicalProtocol to
// the same summary builders as the legacy spellings.
func TestBuildProtocolSummary_NewSpellings(t *testing.T) {
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

// TestCanonicalProtocol verifies the inverse-lookup table is consistent with
// the family table and covers every literal we expect to see in the store.
func TestCanonicalProtocol(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// Canonical (new) spellings map to themselves.
		{"http", "http"},
		{"ws", "ws"},
		{"grpc", "grpc"},
		{"grpc-web", "grpc-web"},
		{"sse", "sse"},
		{"raw", "raw"},
		{"tls-handshake", "tls-handshake"},
		// Legacy literals map to their canonical families.
		{"HTTP/1.x", "http"},
		{"HTTPS", "http"},
		{"HTTP/2", "http"},
		{"WebSocket", "ws"},
		{"gRPC", "grpc"},
		{"gRPC-Web", "grpc-web"},
		{"TCP", "raw"},
		// SOCKS5+ variants map to canonical families.
		{"SOCKS5+HTTPS", "http"},
		{"SOCKS5+HTTP/2", "http"},
		{"SOCKS5+WebSocket", "ws"},
		{"SOCKS5+TCP", "raw"},
		// Unknown returns "".
		{"nonsense", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := canonicalProtocol(tc.input); got != tc.want {
				t.Errorf("canonicalProtocol(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
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

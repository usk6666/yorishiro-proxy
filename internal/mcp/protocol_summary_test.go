package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

func TestBuildProtocolSummary_WebSocket(t *testing.T) {
	msgs := []*flow.Message{
		{Sequence: 0, Direction: "send", Body: []byte("hello"), Metadata: map[string]string{"opcode": "1"}},
		{Sequence: 1, Direction: "receive", Body: []byte("world"), Metadata: map[string]string{"opcode": "1"}},
		{Sequence: 2, Direction: "send", Body: []byte("bye"), Metadata: map[string]string{"opcode": "8"}},
	}

	summary := buildProtocolSummary("WebSocket", "bidirectional", msgs)

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
	summary := buildProtocolSummary("WebSocket", "bidirectional", nil)

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
	msgs := []*flow.Message{
		{Sequence: 0, Direction: "send", Method: "GET"},
		{Sequence: 1, Direction: "receive", StatusCode: 200},
	}

	summary := buildProtocolSummary("HTTP/2", "unary", msgs)

	if summary == nil {
		t.Fatal("summary should not be nil for HTTP/2")
	}
	if summary["stream_count"] != "1" {
		t.Errorf("stream_count = %q, want 1", summary["stream_count"])
	}
}

func TestBuildProtocolSummary_GRPC(t *testing.T) {
	msgs := []*flow.Message{
		{Sequence: 0, Direction: "send", Metadata: map[string]string{"service": "UserService", "method": "GetUser"}},
		{Sequence: 1, Direction: "receive", Metadata: map[string]string{"grpc_status": "0"}},
	}

	summary := buildProtocolSummary("gRPC", "unary", msgs)

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
	msgs := []*flow.Message{
		{Sequence: 0, Direction: "send", Body: []byte("hello")},
		{Sequence: 1, Direction: "receive", Body: []byte("world!")},
		{Sequence: 2, Direction: "send", Body: []byte("bye")},
	}

	summary := buildProtocolSummary("TCP", "bidirectional", msgs)

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
	msgs := []*flow.Message{
		{Sequence: 0, Direction: "send"},
		{Sequence: 1, Direction: "receive"},
	}

	summary := buildProtocolSummary("HTTP/1.x", "unary", msgs)
	if summary != nil {
		t.Error("summary should be nil for HTTP/1.x")
	}

	summary = buildProtocolSummary("HTTPS", "unary", msgs)
	if summary != nil {
		t.Error("summary should be nil for HTTPS")
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

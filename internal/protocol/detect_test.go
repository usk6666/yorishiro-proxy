package protocol

import (
	"context"
	"net"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// mockHandler is a test double for proxy.ProtocolHandler.
type mockHandler struct {
	name      string
	canHandle func(peek []byte) bool
}

func (h *mockHandler) Name() string            { return h.name }
func (h *mockHandler) Detect(peek []byte) bool { return h.canHandle(peek) }
func (h *mockHandler) Handle(_ context.Context, _ net.Conn) error {
	return nil
}

// Compile-time check that mockHandler satisfies proxy.ProtocolHandler.
var _ proxy.ProtocolHandler = (*mockHandler)(nil)

func TestDetect(t *testing.T) {
	httpHandler := &mockHandler{
		name: "HTTP",
		canHandle: func(peek []byte) bool {
			return len(peek) >= 3 && string(peek[:3]) == "GET"
		},
	}
	grpcHandler := &mockHandler{
		name: "gRPC",
		canHandle: func(peek []byte) bool {
			// PRI * HTTP/2.0 preface starts with "PRI"
			return len(peek) >= 3 && string(peek[:3]) == "PRI"
		},
	}
	catchAllHandler := &mockHandler{
		name: "raw",
		canHandle: func([]byte) bool {
			return true
		},
	}
	neverMatchHandler := &mockHandler{
		name: "never",
		canHandle: func([]byte) bool {
			return false
		},
	}

	tests := []struct {
		name     string
		handlers []proxy.ProtocolHandler
		peek     []byte
		wantName string // expected handler name, "" means nil
	}{
		{
			name:     "matching handler returns that handler",
			handlers: []proxy.ProtocolHandler{httpHandler},
			peek:     []byte("GET / HTTP/1.1"),
			wantName: "HTTP",
		},
		{
			name:     "first matching handler wins (priority order)",
			handlers: []proxy.ProtocolHandler{httpHandler, catchAllHandler},
			peek:     []byte("GET /index.html"),
			wantName: "HTTP",
		},
		{
			name:     "skips non-matching, returns first match",
			handlers: []proxy.ProtocolHandler{grpcHandler, httpHandler, catchAllHandler},
			peek:     []byte("GET /api"),
			wantName: "HTTP",
		},
		{
			name:     "falls through to catch-all",
			handlers: []proxy.ProtocolHandler{httpHandler, grpcHandler, catchAllHandler},
			peek:     []byte{0x00, 0x01, 0x02},
			wantName: "raw",
		},
		{
			name:     "no handler matches returns nil",
			handlers: []proxy.ProtocolHandler{httpHandler, grpcHandler},
			peek:     []byte{0x00, 0x01, 0x02},
			wantName: "",
		},
		{
			name:     "no handlers registered returns nil",
			handlers: nil,
			peek:     []byte("GET /"),
			wantName: "",
		},
		{
			name:     "empty peek returns nil when no handler matches",
			handlers: []proxy.ProtocolHandler{httpHandler, grpcHandler},
			peek:     []byte{},
			wantName: "",
		},
		{
			name:     "empty peek with catch-all returns catch-all",
			handlers: []proxy.ProtocolHandler{catchAllHandler},
			peek:     []byte{},
			wantName: "raw",
		},
		{
			name:     "nil peek returns nil when no handler matches",
			handlers: []proxy.ProtocolHandler{httpHandler},
			peek:     nil,
			wantName: "",
		},
		{
			name:     "all handlers reject returns nil",
			handlers: []proxy.ProtocolHandler{neverMatchHandler, neverMatchHandler},
			peek:     []byte("some data"),
			wantName: "",
		},
		{
			name:     "gRPC handler matches PRI preface",
			handlers: []proxy.ProtocolHandler{httpHandler, grpcHandler},
			peek:     []byte("PRI * HTTP/2.0"),
			wantName: "gRPC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector(tt.handlers...)
			got := d.Detect(tt.peek)

			if tt.wantName == "" {
				if got != nil {
					t.Errorf("Detect(%q) = %q, want nil", tt.peek, got.Name())
				}
				return
			}
			if got == nil {
				t.Fatalf("Detect(%q) = nil, want %q", tt.peek, tt.wantName)
			}
			if got.Name() != tt.wantName {
				t.Errorf("Detect(%q).Name() = %q, want %q", tt.peek, got.Name(), tt.wantName)
			}
		})
	}
}

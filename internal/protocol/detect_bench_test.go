package protocol

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/usk6666/katashiro-proxy/internal/proxy"
)

// benchHandler is a benchmark-oriented protocol handler stub.
type benchHandler struct {
	name      string
	canHandle func(peek []byte) bool
}

func (h *benchHandler) Name() string                                    { return h.name }
func (h *benchHandler) Detect(peek []byte) bool                         { return h.canHandle(peek) }
func (h *benchHandler) Handle(_ context.Context, _ net.Conn) error      { return nil }

var _ proxy.ProtocolHandler = (*benchHandler)(nil)

func BenchmarkDetect(b *testing.B) {
	httpHandler := &benchHandler{
		name: "HTTP",
		canHandle: func(peek []byte) bool {
			if len(peek) < 3 {
				return false
			}
			switch string(peek[:3]) {
			case "GET", "POS", "PUT", "DEL", "HEA", "OPT", "PAT", "CON":
				return true
			}
			return false
		},
	}
	tlsHandler := &benchHandler{
		name: "TLS",
		canHandle: func(peek []byte) bool {
			return len(peek) >= 1 && peek[0] == 0x16
		},
	}
	catchAllHandler := &benchHandler{
		name: "raw",
		canHandle: func([]byte) bool { return true },
	}

	detector := NewDetector(httpHandler, tlsHandler, catchAllHandler)

	cases := []struct {
		name string
		peek []byte
	}{
		{"HTTP_GET", []byte("GET / HTTP/1.1\r\n")},
		{"HTTP_POST", []byte("POST /api HTTP/1.1\r\n")},
		{"TLS_ClientHello", []byte{0x16, 0x03, 0x01, 0x00, 0x05}},
		{"Unknown_Binary", []byte{0x00, 0x01, 0x02, 0x03, 0x04}},
		{"Empty", []byte{}},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				detector.Detect(tc.peek)
			}
		})
	}
}

func BenchmarkDetect_HandlerCount(b *testing.B) {
	makeHandlers := func(n int) []proxy.ProtocolHandler {
		handlers := make([]proxy.ProtocolHandler, n)
		for i := 0; i < n; i++ {
			handlers[i] = &benchHandler{
				name:      "noop",
				canHandle: func([]byte) bool { return false },
			}
		}
		// Last handler matches everything.
		handlers[n-1] = &benchHandler{
			name:      "catchall",
			canHandle: func([]byte) bool { return true },
		}
		return handlers
	}

	peek := []byte("GET / HTTP/1.1\r\n")
	counts := []int{1, 5, 10, 20}

	for _, n := range counts {
		b.Run(fmt.Sprintf("handlers_%d", n), func(b *testing.B) {
			detector := NewDetector(makeHandlers(n)...)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				detector.Detect(peek)
			}
		})
	}
}

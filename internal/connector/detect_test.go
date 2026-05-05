package connector

import (
	"testing"
)

func TestDetectKind(t *testing.T) {
	tests := []struct {
		name string
		peek []byte
		want ProtocolKind
	}{
		{"empty", []byte{}, ProtocolUnknown},
		{"nil", nil, ProtocolUnknown},

		// SOCKS5: single 0x05 byte.
		{"socks5 single byte", []byte{0x05}, ProtocolSOCKS5},
		{"socks5 with greeting", []byte{0x05, 0x02, 0x00, 0x02}, ProtocolSOCKS5},

		// CONNECT: requires exact prefix with trailing space.
		{"http connect", []byte("CONNECT example.com:443"), ProtocolHTTPConnect},
		{"http connect full", []byte("CONNECT example.com:443 HTTP/1.1\r\n"), ProtocolHTTPConnect},
		{"http connected (negative)", []byte("CONNECTED "), ProtocolTCP},

		// HTTP methods: known methods with trailing space.
		{"get", []byte("GET / HTTP/1.1"), ProtocolHTTP1},
		{"post", []byte("POST /api/x HT"), ProtocolHTTP1},
		{"put", []byte("PUT /foo HTTP/1"), ProtocolHTTP1},
		{"delete", []byte("DELETE /x HTTP/"), ProtocolHTTP1},
		{"head", []byte("HEAD /x HTTP/1.1"), ProtocolHTTP1},
		{"options", []byte("OPTIONS * HTTP/1.1"), ProtocolHTTP1},
		{"patch", []byte("PATCH /x HTTP/1."), ProtocolHTTP1},
		{"trace", []byte("TRACE /x HTTP/1.1"), ProtocolHTTP1},

		// Short HTTP method read that is still consistent — allowed by
		// stage 1 so the listener retries in stage 2.
		{"short get", []byte("GE"), ProtocolHTTP1},
		{"short post", []byte("POS"), ProtocolHTTP1},

		// Unknown method should fall through to TCP.
		{"unknown method", []byte("BREW / HTTP/1.1"), ProtocolTCP},

		// h2c connection preface.
		{"h2c preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), ProtocolHTTP2},
		{"h2c first 8", []byte("PRI * HT"), ProtocolHTTP2},
		{"h2c short 7", []byte("PRI * H"), ProtocolTCP}, // not enough bytes

		// Raw TCP fall-through.
		{"binary", []byte{0xFF, 0xFE, 0xFD, 0x00}, ProtocolTCP},
		{"single letter", []byte{'A'}, ProtocolTCP},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := DetectKind(tt.peek)
			if got != tt.want {
				t.Errorf("DetectKind(%q) = %v, want %v", tt.peek, got, tt.want)
			}
		})
	}
}

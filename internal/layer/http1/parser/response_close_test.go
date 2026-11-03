package parser

import (
	"bufio"
	"strings"
	"testing"
)

// TestParseResponse_Close (USK-1415 T10): RawResponse.Close reports a
// response that makes the connection non-reusable, by the same rule as a
// request's Close: a close token in any Connection header (any casing,
// anywhere in a token list), or HTTP/1.0 without keep-alive.
func TestParseResponse_Close(t *testing.T) {
	tests := []struct {
		name string
		head string
		want bool
	}{
		{"http11 connection close", "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n", true},
		{"mixed case", "HTTP/1.1 413 Payload Too Large\r\nconnection: CLOSE\r\n", true},
		{"token list", "HTTP/1.1 413 Payload Too Large\r\nConnection: keep-alive, close\r\n", true},
		{"second connection header", "HTTP/1.1 413 Payload Too Large\r\nConnection: keep-alive\r\nConnection: Close\r\n", true},
		{"http10 without keep-alive", "HTTP/1.0 413 Payload Too Large\r\n", true},
		{"http10 keep-alive", "HTTP/1.0 413 Payload Too Large\r\nConnection: keep-alive\r\n", false},
		{"http11 default", "HTTP/1.1 413 Payload Too Large\r\n", false},
		{"http11 keep-alive", "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n", false},
		{"close as substring only", "HTTP/1.1 200 OK\r\nConnection: closed\r\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseResponse(bufio.NewReader(strings.NewReader(tt.head + "Content-Length: 0\r\n\r\n")))
			if err != nil {
				t.Fatalf("ParseResponse: %v", err)
			}
			if resp.Close != tt.want {
				t.Errorf("Close = %v, want %v", resp.Close, tt.want)
			}
		})
	}
}

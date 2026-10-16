package parser

import (
	"bufio"
	"strings"
	"testing"
)

// TestParseRequestLine covers the exported request-line-only reader used
// by the connector's capacity-rejection path (USK-1142).
func TestParseRequestLine(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantMethod string
		wantTarget string
		wantProto  string
		wantRest   string
	}{
		{
			name:       "complete line does not consume headers",
			input:      "GET http://h/p HTTP/1.1\r\nHost: h\r\n\r\n",
			wantMethod: "GET",
			wantTarget: "http://h/p",
			wantProto:  "HTTP/1.1",
			wantRest:   "Host: h\r\n\r\n",
		},
		{
			name:       "CONNECT authority casing preserved",
			input:      "CONNECT ExAmPlE.com:443 HTTP/1.1\r\n",
			wantMethod: "CONNECT",
			wantTarget: "ExAmPlE.com:443",
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "partial line at EOF is returned best-effort",
			input:      "CONNECT exa",
			wantMethod: "CONNECT",
			wantTarget: "exa",
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "bare LF terminator",
			input:      "GET / HTTP/1.0\n",
			wantMethod: "GET",
			wantTarget: "/",
			wantProto:  "HTTP/1.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tt.input))
			method, target, proto, err := ParseRequestLine(r)
			if err != nil {
				t.Fatalf("ParseRequestLine() error = %v", err)
			}
			if method != tt.wantMethod || target != tt.wantTarget || proto != tt.wantProto {
				t.Errorf("ParseRequestLine() = (%q, %q, %q), want (%q, %q, %q)",
					method, target, proto, tt.wantMethod, tt.wantTarget, tt.wantProto)
			}
			rest := make([]byte, 64)
			n, _ := r.Read(rest)
			if got := string(rest[:n]); got != tt.wantRest {
				t.Errorf("unread remainder = %q, want %q", got, tt.wantRest)
			}
		})
	}
}

// TestParseRequestLine_EmptyInput returns an error rather than an empty line.
func TestParseRequestLine_EmptyInput(t *testing.T) {
	if _, _, _, err := ParseRequestLine(bufio.NewReader(strings.NewReader(""))); err == nil {
		t.Fatal("ParseRequestLine(empty) error = nil, want non-nil")
	}
}

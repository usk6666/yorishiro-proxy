package http

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

func TestWriteResponseHeaders_AutoContentLengthTrue(t *testing.T) {
	tests := []struct {
		name    string
		headers parser.RawHeaders
		bodyLen int
		want    string
	}{
		{
			name: "replaces CL with actual body length",
			headers: parser.RawHeaders{
				{Name: "Content-Type", Value: "text/html"},
				{Name: "Content-Length", Value: "999"},
			},
			bodyLen: 5,
			want:    "Content-Type: text/html\r\nContent-Length: 5\r\n",
		},
		{
			name: "adds CL when missing",
			headers: parser.RawHeaders{
				{Name: "Content-Type", Value: "text/html"},
			},
			bodyLen: 10,
			want:    "Content-Type: text/html\r\nContent-Length: 10\r\n",
		},
		{
			name: "strips Transfer-Encoding",
			headers: parser.RawHeaders{
				{Name: "Transfer-Encoding", Value: "chunked"},
				{Name: "Content-Type", Value: "text/html"},
			},
			bodyLen: 3,
			want:    "Content-Type: text/html\r\nContent-Length: 3\r\n",
		},
		{
			name: "deduplicates multiple CL headers",
			headers: parser.RawHeaders{
				{Name: "Content-Length", Value: "10"},
				{Name: "Content-Length", Value: "20"},
			},
			bodyLen: 5,
			want:    "Content-Length: 5\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := bufio.NewWriter(&buf)
			if err := writeResponseHeaders(w, tt.headers, tt.bodyLen, true); err != nil {
				t.Fatal(err)
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			got := buf.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteResponseHeaders_AutoContentLengthFalse(t *testing.T) {
	tests := []struct {
		name    string
		headers parser.RawHeaders
		bodyLen int
		want    string
	}{
		{
			name: "preserves original CL value",
			headers: parser.RawHeaders{
				{Name: "Content-Type", Value: "text/html"},
				{Name: "Content-Length", Value: "999"},
			},
			bodyLen: 5,
			want:    "Content-Type: text/html\r\nContent-Length: 999\r\n",
		},
		{
			name: "preserves Transfer-Encoding",
			headers: parser.RawHeaders{
				{Name: "Transfer-Encoding", Value: "chunked"},
				{Name: "Content-Type", Value: "text/html"},
			},
			bodyLen: 3,
			want:    "Transfer-Encoding: chunked\r\nContent-Type: text/html\r\n",
		},
		{
			name: "preserves CL/TE mismatch",
			headers: parser.RawHeaders{
				{Name: "Content-Length", Value: "0"},
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			bodyLen: 100,
			want:    "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
		},
		{
			name: "does not add CL when missing",
			headers: parser.RawHeaders{
				{Name: "Content-Type", Value: "text/html"},
			},
			bodyLen: 10,
			want:    "Content-Type: text/html\r\n",
		},
		{
			name: "preserves duplicate CL headers",
			headers: parser.RawHeaders{
				{Name: "Content-Length", Value: "10"},
				{Name: "Content-Length", Value: "20"},
			},
			bodyLen: 5,
			want:    "Content-Length: 10\r\nContent-Length: 20\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := bufio.NewWriter(&buf)
			if err := writeResponseHeaders(w, tt.headers, tt.bodyLen, false); err != nil {
				t.Fatal(err)
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			got := buf.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWriteRawResponse_AutoContentLength(t *testing.T) {
	tests := []struct {
		name            string
		resp            *parser.RawResponse
		body            []byte
		autoContentLen  bool
		wantCLInOutput  string // expected Content-Length line
		wantTEPreserved bool   // expect Transfer-Encoding in output
	}{
		{
			name: "auto=true recalculates CL",
			resp: &parser.RawResponse{
				Proto:      "HTTP/1.1",
				Status:     "200 OK",
				StatusCode: 200,
				Headers: parser.RawHeaders{
					{Name: "Content-Length", Value: "999"},
				},
			},
			body:           []byte("hello"),
			autoContentLen: true,
			wantCLInOutput: "Content-Length: 5",
		},
		{
			name: "auto=false preserves user CL",
			resp: &parser.RawResponse{
				Proto:      "HTTP/1.1",
				Status:     "200 OK",
				StatusCode: 200,
				Headers: parser.RawHeaders{
					{Name: "Content-Length", Value: "999"},
				},
			},
			body:           []byte("hello"),
			autoContentLen: false,
			wantCLInOutput: "Content-Length: 999",
		},
		{
			name: "auto=false preserves TE",
			resp: &parser.RawResponse{
				Proto:      "HTTP/1.1",
				Status:     "200 OK",
				StatusCode: 200,
				Headers: parser.RawHeaders{
					{Name: "Transfer-Encoding", Value: "chunked"},
					{Name: "Content-Length", Value: "0"},
				},
			},
			body:            []byte("hello"),
			autoContentLen:  false,
			wantCLInOutput:  "Content-Length: 0",
			wantTEPreserved: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()

			done := make(chan string)
			go func() {
				buf := make([]byte, 4096)
				n, _ := server.Read(buf)
				done <- string(buf[:n])
			}()

			err := writeRawResponse(client, tt.resp, tt.body, tt.autoContentLen)
			client.Close()
			if err != nil {
				t.Fatal(err)
			}

			got := <-done
			if !strings.Contains(got, tt.wantCLInOutput) {
				t.Errorf("output should contain %q, got:\n%s", tt.wantCLInOutput, got)
			}
			hasTE := strings.Contains(got, "Transfer-Encoding")
			if tt.wantTEPreserved && !hasTE {
				t.Error("expected Transfer-Encoding to be preserved, but it was removed")
			}
			if !tt.wantTEPreserved && hasTE {
				t.Error("expected Transfer-Encoding to be removed, but it was present")
			}
		})
	}
}

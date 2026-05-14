package sse

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestIsHTTPMessageChunked exercises the helper that runUpgradeSSE uses
// to detect whether the pre-swap response advertised chunked TE on the
// wire.
func TestIsHTTPMessageChunked(t *testing.T) {
	cases := []struct {
		name string
		env  *envelope.Envelope
		want bool
	}{
		{"nil envelope", nil, false},
		{"non-http message", &envelope.Envelope{Message: &envelope.SSEMessage{}}, false},
		{
			name: "no transfer-encoding",
			env: &envelope.Envelope{Message: &envelope.HTTPMessage{
				Headers: []envelope.KeyValue{{Name: "Content-Length", Value: "10"}},
			}},
			want: false,
		},
		{
			name: "chunked exact",
			env: &envelope.Envelope{Message: &envelope.HTTPMessage{
				Headers: []envelope.KeyValue{{Name: "Transfer-Encoding", Value: "chunked"}},
			}},
			want: true,
		},
		{
			name: "chunked mixed case header",
			env: &envelope.Envelope{Message: &envelope.HTTPMessage{
				Headers: []envelope.KeyValue{{Name: "transfer-encoding", Value: "chunked"}},
			}},
			want: true,
		},
		{
			name: "chunked mixed case value",
			env: &envelope.Envelope{Message: &envelope.HTTPMessage{
				Headers: []envelope.KeyValue{{Name: "Transfer-Encoding", Value: "Chunked"}},
			}},
			want: true,
		},
		{
			name: "comma list with chunked",
			env: &envelope.Envelope{Message: &envelope.HTTPMessage{
				Headers: []envelope.KeyValue{{Name: "Transfer-Encoding", Value: "gzip, chunked"}},
			}},
			want: true,
		},
		{
			name: "comma list without chunked",
			env: &envelope.Envelope{Message: &envelope.HTTPMessage{
				Headers: []envelope.KeyValue{{Name: "Transfer-Encoding", Value: "gzip, deflate"}},
			}},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsHTTPMessageChunked(c.env)
			if got != c.want {
				t.Fatalf("IsHTTPMessageChunked = %v, want %v", got, c.want)
			}
		})
	}
}

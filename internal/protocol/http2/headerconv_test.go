package http2

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

func TestHpackToRawHeadersWithHost(t *testing.T) {
	tests := []struct {
		name   string
		fields []hpack.HeaderField
		host   string
		want   parser.RawHeaders
	}{
		{
			name: "basic conversion with host",
			fields: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":path", Value: "/api"},
				{Name: "content-type", Value: "application/json"},
				{Name: "x-custom", Value: "value"},
			},
			host: "example.com",
			want: parser.RawHeaders{
				{Name: "Host", Value: "example.com"},
				{Name: "content-type", Value: "application/json"},
				{Name: "x-custom", Value: "value"},
			},
		},
		{
			name: "skips pseudo-headers",
			fields: []hpack.HeaderField{
				{Name: ":method", Value: "POST"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/"},
				{Name: "accept", Value: "*/*"},
			},
			host: "example.com",
			want: parser.RawHeaders{
				{Name: "Host", Value: "example.com"},
				{Name: "accept", Value: "*/*"},
			},
		},
		{
			name: "removes hop-by-hop headers",
			fields: []hpack.HeaderField{
				{Name: "connection", Value: "keep-alive"},
				{Name: "keep-alive", Value: "timeout=5"},
				{Name: "transfer-encoding", Value: "chunked"},
				{Name: "upgrade", Value: "websocket"},
				{Name: "proxy-connection", Value: "keep-alive"},
				{Name: "x-real", Value: "kept"},
			},
			host: "example.com",
			want: parser.RawHeaders{
				{Name: "Host", Value: "example.com"},
				{Name: "x-real", Value: "kept"},
			},
		},
		{
			name: "te trailers is kept",
			fields: []hpack.HeaderField{
				{Name: "te", Value: "trailers"},
				{Name: "accept", Value: "text/html"},
			},
			host: "example.com",
			want: parser.RawHeaders{
				{Name: "Host", Value: "example.com"},
				{Name: "te", Value: "trailers"},
				{Name: "accept", Value: "text/html"},
			},
		},
		{
			name: "te non-trailers is removed",
			fields: []hpack.HeaderField{
				{Name: "te", Value: "gzip"},
			},
			host: "example.com",
			want: parser.RawHeaders{
				{Name: "Host", Value: "example.com"},
			},
		},
		{
			name: "skips duplicate host from hpack",
			fields: []hpack.HeaderField{
				{Name: "host", Value: "should-be-skipped"},
				{Name: "content-type", Value: "text/plain"},
			},
			host: "example.com",
			want: parser.RawHeaders{
				{Name: "Host", Value: "example.com"},
				{Name: "content-type", Value: "text/plain"},
			},
		},
		{
			name:   "empty host",
			fields: []hpack.HeaderField{{Name: "accept", Value: "*/*"}},
			host:   "",
			want:   parser.RawHeaders{{Name: "accept", Value: "*/*"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hpackToRawHeadersWithHost(tt.fields, tt.host)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d\ngot:  %v\nwant: %v", len(got), len(tt.want), got, tt.want)
			}
			for i := range got {
				if got[i].Name != tt.want[i].Name || got[i].Value != tt.want[i].Value {
					t.Errorf("[%d] = {%q, %q}, want {%q, %q}", i, got[i].Name, got[i].Value, tt.want[i].Name, tt.want[i].Value)
				}
			}
		})
	}
}

func TestRawHeadersToHpackLower(t *testing.T) {
	rh := parser.RawHeaders{
		{Name: "Content-Type", Value: "application/json"},
		{Name: "X-Custom-Header", Value: "value"},
		{Name: "already-lower", Value: "ok"},
	}

	got := rawHeadersToHpackLower(rh)

	want := []hpack.HeaderField{
		{Name: "content-type", Value: "application/json"},
		{Name: "x-custom-header", Value: "value"},
		{Name: "already-lower", Value: "ok"},
	}

	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Name != want[i].Name || got[i].Value != want[i].Value {
			t.Errorf("[%d] = {%q, %q}, want {%q, %q}", i, got[i].Name, got[i].Value, want[i].Name, want[i].Value)
		}
	}
}

func TestSetRawHeader_Replace(t *testing.T) {
	rh := parser.RawHeaders{
		{Name: "Content-Length", Value: "100"},
		{Name: "Content-Type", Value: "text/plain"},
	}

	got := setRawHeader(rh, "content-length", "200")

	if got[0].Value != "200" {
		t.Errorf("Content-Length = %q, want %q", got[0].Value, "200")
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

func TestSetRawHeader_Append(t *testing.T) {
	rh := parser.RawHeaders{
		{Name: "Content-Type", Value: "text/plain"},
	}

	got := setRawHeader(rh, "content-length", "42")

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[1].Name != "content-length" || got[1].Value != "42" {
		t.Errorf("appended header = {%q, %q}, want {%q, %q}", got[1].Name, got[1].Value, "content-length", "42")
	}
}

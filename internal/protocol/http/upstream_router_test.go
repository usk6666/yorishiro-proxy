package http

import (
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

func TestBuildH2Headers(t *testing.T) {
	tests := []struct {
		name     string
		req      *parser.RawRequest
		hostname string
		want     []hpack.HeaderField
	}{
		{
			name: "basic GET",
			req: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/api/v1/data",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "Accept", Value: "application/json"},
					{Name: "User-Agent", Value: "test/1.0"},
				},
			},
			hostname: "example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/api/v1/data"},
				{Name: "accept", Value: "application/json"},
				{Name: "user-agent", Value: "test/1.0"},
			},
		},
		{
			name: "Host header used for authority",
			req: &parser.RawRequest{
				Method:     "POST",
				RequestURI: "/submit",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "api.example.com:8443"},
					{Name: "Content-Type", Value: "application/json"},
				},
			},
			hostname: "fallback.example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "POST"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "api.example.com:8443"},
				{Name: ":path", Value: "/submit"},
				{Name: "content-type", Value: "application/json"},
			},
		},
		{
			name: "fallback to hostname when no Host header",
			req: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Headers:    parser.RawHeaders{},
			},
			hostname: "fallback.example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "fallback.example.com"},
				{Name: ":path", Value: "/"},
			},
		},
		{
			name: "empty RequestURI defaults to /",
			req: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
				},
			},
			hostname: "example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/"},
			},
		},
		{
			name: "hop-by-hop headers are filtered",
			req: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "Connection", Value: "keep-alive"},
					{Name: "Keep-Alive", Value: "timeout=5"},
					{Name: "Transfer-Encoding", Value: "chunked"},
					{Name: "Proxy-Connection", Value: "keep-alive"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "X-Custom", Value: "preserved"},
				},
			},
			hostname: "example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/"},
				{Name: "x-custom", Value: "preserved"},
			},
		},
		{
			name: "te: trailers is preserved",
			req: &parser.RawRequest{
				Method:     "POST",
				RequestURI: "/grpc",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "TE", Value: "trailers"},
					{Name: "Content-Type", Value: "application/grpc"},
				},
			},
			hostname: "example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "POST"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/grpc"},
				{Name: "te", Value: "trailers"},
				{Name: "content-type", Value: "application/grpc"},
			},
		},
		{
			name: "te: non-trailers is filtered",
			req: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "TE", Value: "gzip"},
				},
			},
			hostname: "example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/"},
			},
		},
		{
			name: "headers are lowercased",
			req: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "X-Custom-Header", Value: "value1"},
					{Name: "Content-Type", Value: "text/html"},
				},
			},
			hostname: "example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/"},
				{Name: "x-custom-header", Value: "value1"},
				{Name: "content-type", Value: "text/html"},
			},
		},
		{
			name: "multiple values for same header",
			req: &parser.RawRequest{
				Method:     "GET",
				RequestURI: "/",
				Headers: parser.RawHeaders{
					{Name: "Host", Value: "example.com"},
					{Name: "Accept", Value: "text/html"},
					{Name: "Accept", Value: "application/json"},
				},
			},
			hostname: "example.com",
			want: []hpack.HeaderField{
				{Name: ":method", Value: "GET"},
				{Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":path", Value: "/"},
				{Name: "accept", Value: "text/html"},
				{Name: "accept", Value: "application/json"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildH2Headers(tt.req, tt.hostname)
			if len(got) != len(tt.want) {
				t.Fatalf("buildH2Headers() returned %d headers, want %d\ngot:  %v\nwant: %v", len(got), len(tt.want), got, tt.want)
			}
			for i, g := range got {
				if g.Name != tt.want[i].Name || g.Value != tt.want[i].Value {
					t.Errorf("header[%d] = {%q, %q}, want {%q, %q}", i, g.Name, g.Value, tt.want[i].Name, tt.want[i].Value)
				}
			}
		})
	}
}

func TestH2ResultToRawResponse(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		headers        []hpack.HeaderField
		bodyData       string
		wantStatusCode int
		wantProto      string
		wantHeaders    int // expected number of non-pseudo headers
	}{
		{
			name:       "200 OK response",
			statusCode: 200,
			headers: []hpack.HeaderField{
				{Name: ":status", Value: "200"},
				{Name: "content-type", Value: "application/json"},
				{Name: "x-request-id", Value: "abc123"},
			},
			bodyData:       `{"ok":true}`,
			wantStatusCode: 200,
			wantProto:      "HTTP/2.0",
			wantHeaders:    2,
		},
		{
			name:       "pseudo-headers are filtered from response headers",
			statusCode: 404,
			headers: []hpack.HeaderField{
				{Name: ":status", Value: "404"},
				{Name: ":other", Value: "ignored"},
				{Name: "content-type", Value: "text/plain"},
			},
			bodyData:       "not found",
			wantStatusCode: 404,
			wantProto:      "HTTP/2.0",
			wantHeaders:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h2r := &http2.RoundTripResult{
				StatusCode: tt.statusCode,
				Headers:    tt.headers,
				Body:       strings.NewReader(tt.bodyData),
			}
			resp := h2ResultToRawResponse(h2r)
			if resp.StatusCode != tt.wantStatusCode {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantStatusCode)
			}
			if resp.Proto != tt.wantProto {
				t.Errorf("Proto = %q, want %q", resp.Proto, tt.wantProto)
			}
			if len(resp.Headers) != tt.wantHeaders {
				t.Errorf("len(Headers) = %d, want %d", len(resp.Headers), tt.wantHeaders)
			}
		})
	}
}

func TestIsH2HopByHopHeader(t *testing.T) {
	hopByHop := []string{"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te"}
	for _, h := range hopByHop {
		if !isH2HopByHopHeader(h) {
			t.Errorf("isH2HopByHopHeader(%q) = false, want true", h)
		}
	}

	regular := []string{"content-type", "accept", "authorization", "x-custom", "host"}
	for _, h := range regular {
		if isH2HopByHopHeader(h) {
			t.Errorf("isH2HopByHopHeader(%q) = true, want false", h)
		}
	}
}

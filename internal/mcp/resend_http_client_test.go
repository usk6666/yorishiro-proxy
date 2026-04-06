package mcp

import (
	"context"
	"io"
	"net"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

func TestResendUpstreamRouter_DefaultRouter(t *testing.T) {
	s := &Server{deps: &deps{}}

	router := s.resendUpstreamRouter(resendParams{})
	ur, ok := router.(*protohttp.UpstreamRouter)
	if !ok {
		t.Fatalf("expected *protohttp.UpstreamRouter, got %T", router)
	}
	if ur.H1 == nil {
		t.Error("H1 transport must not be nil")
	}
	if ur.H2 == nil {
		t.Error("H2 transport must not be nil")
	}
	if ur.Pool == nil {
		t.Error("Pool must not be nil")
	}
	if !ur.Pool.AllowH2 {
		t.Error("Pool.AllowH2 must be true to allow h2 ALPN negotiation for gRPC resend")
	}
	if ur.Pool.TLSTransport != nil {
		t.Error("Pool.TLSTransport must be nil when no TLS transport is configured")
	}
}

func TestResendUpstreamRouter_TLSTransportPassthrough(t *testing.T) {
	mock := &mockTLSTransport{}
	s := &Server{deps: &deps{tlsTransport: mock}}

	router := s.resendUpstreamRouter(resendParams{})
	ur, ok := router.(*protohttp.UpstreamRouter)
	if !ok {
		t.Fatalf("expected *protohttp.UpstreamRouter, got %T", router)
	}
	if ur.Pool.TLSTransport != mock {
		t.Error("Pool.TLSTransport must be the configured TLS transport (passed through without restriction)")
	}
}

func TestResendUpstreamRouter_ReplayRouterOverride(t *testing.T) {
	mock := &mockResendRouter{}
	s := &Server{deps: &deps{replayRouter: mock}}

	router := s.resendUpstreamRouter(resendParams{})
	if router != mock {
		t.Error("expected replayRouter to be returned when set")
	}
}

type mockResendRouter struct{}

func (m *mockResendRouter) RoundTrip(_ context.Context, _ *parser.RawRequest, _ string, _ bool, _ string) (*httputil.RoundTripResult, error) {
	return nil, nil
}

type mockTLSTransport struct{}

func (m *mockTLSTransport) TLSConnect(_ context.Context, conn net.Conn, _ string) (net.Conn, string, error) {
	return conn, "h2", nil
}

func TestBuildRawRequest_ContentLengthRecalculation(t *testing.T) {
	s := &Server{deps: &deps{}}
	u, _ := url.Parse("http://example.com/path")

	tests := []struct {
		name     string
		body     []byte
		headers  parser.RawHeaders
		wantCL   string // expected Content-Length value ("" means absent)
		wantNoCL bool   // true if Content-Length should be absent
	}{
		{
			name: "stale Content-Length is recalculated",
			body: []byte("modified body"),
			headers: parser.RawHeaders{
				{Name: "Content-Length", Value: "999"},
				{Name: "X-Custom", Value: "test"},
			},
			wantCL: "13", // len("modified body") == 13
		},
		{
			name: "missing Content-Length is added",
			body: []byte("hello"),
			headers: parser.RawHeaders{
				{Name: "X-Custom", Value: "test"},
			},
			wantCL: "5",
		},
		{
			name:     "empty body removes stale Content-Length",
			body:     nil,
			headers:  parser.RawHeaders{{Name: "Content-Length", Value: "42"}},
			wantNoCL: true,
		},
		{
			name: "Transfer-Encoding chunked is stripped and Content-Length recalculated",
			body: []byte("chunked body"),
			headers: parser.RawHeaders{
				{Name: "Transfer-Encoding", Value: "chunked"},
				{Name: "Content-Length", Value: "999"},
			},
			wantCL: "12", // len("chunked body") == 12; TE removed, CL recalculated
		},
		{
			name: "duplicate Content-Length headers are collapsed to one correct value",
			body: []byte("dup"),
			headers: parser.RawHeaders{
				{Name: "Content-Length", Value: "100"},
				{Name: "X-Between", Value: "separator"},
				{Name: "Content-Length", Value: "200"},
			},
			wantCL: "3", // len("dup") == 3; both stale CLs removed, single correct CL added
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prep := &resendPrepared{
				method:  "POST",
				url:     u,
				body:    tt.body,
				headers: tt.headers,
			}
			req := s.buildRawRequest(prep)

			cl := req.Headers.Get("Content-Length")
			if tt.wantNoCL {
				if cl != "" {
					t.Errorf("expected no Content-Length, got %q", cl)
				}
				return
			}
			if cl != tt.wantCL {
				t.Errorf("Content-Length = %q, want %q", cl, tt.wantCL)
			}

			// Exactly one Content-Length header must remain.
			if n := len(req.Headers.Values("Content-Length")); n != 1 {
				t.Errorf("expected exactly 1 Content-Length header, got %d", n)
			}

			// Transfer-Encoding must always be stripped for structured resends
			// (H1Transport writes body verbatim without chunked encoding).
			if te := req.Headers.Get("Transfer-Encoding"); te != "" {
				t.Errorf("Transfer-Encoding should be stripped, got %q", te)
			}

			// Verify body is readable and matches
			if len(tt.body) > 0 && req.Body != nil {
				data, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("reading body: %v", err)
				}
				if string(data) != string(tt.body) {
					t.Errorf("body = %q, want %q", data, tt.body)
				}
			}
		})
	}
}

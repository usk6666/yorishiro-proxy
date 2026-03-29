package mcp

import (
	"context"
	"io"
	"net/url"
	"testing"

	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
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
	if ur.Pool == nil {
		t.Error("Pool must not be nil")
	}
	if ur.Pool.AllowH2 {
		t.Error("Pool.AllowH2 must be false: resend router has no H2 transport, h2 ALPN would cause a nil dereference panic")
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

func (m *mockResendRouter) RoundTrip(_ context.Context, _ *parser.RawRequest, _ string, _ bool, _ string) (*protohttp.RoundTripResult, error) {
	return nil, nil
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
			name: "Transfer-Encoding chunked preserves no Content-Length",
			body: []byte("chunked body"),
			headers: parser.RawHeaders{
				{Name: "Transfer-Encoding", Value: "chunked"},
				{Name: "Content-Length", Value: "999"},
			},
			wantCL: "999", // not recalculated when Transfer-Encoding is set
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

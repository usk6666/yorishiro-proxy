package mcp

import (
	"context"
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
	if !ur.Pool.AllowH2 {
		t.Error("Pool.AllowH2 must be true to support HTTP/2 via ALPN routing")
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

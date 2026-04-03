package http

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestIsGRPCWebRequest_NilHandler(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())
	// No grpcWebHandler set.

	headers := parser.RawHeaders{
		{Name: "Content-Type", Value: "application/grpc-web+proto"},
	}
	if h.isGRPCWebRequest(headers) {
		t.Error("isGRPCWebRequest should return false when grpcWebHandler is nil")
	}
}

func TestIsGRPCWebRequest_WithHandler(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, testutil.DiscardLogger()))

	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "grpc-web binary",
			contentType: "application/grpc-web",
			want:        true,
		},
		{
			name:        "grpc-web+proto",
			contentType: "application/grpc-web+proto",
			want:        true,
		},
		{
			name:        "grpc-web-text",
			contentType: "application/grpc-web-text",
			want:        true,
		},
		{
			name:        "grpc-web-text+proto",
			contentType: "application/grpc-web-text+proto",
			want:        true,
		},
		{
			name:        "grpc-web with params",
			contentType: "application/grpc-web+proto; charset=utf-8",
			want:        true,
		},
		{
			name:        "regular json",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "regular grpc (not grpc-web)",
			contentType: "application/grpc",
			want:        false,
		},
		{
			name:        "empty content-type",
			contentType: "",
			want:        false,
		},
		{
			name:        "text/html",
			contentType: "text/html",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := parser.RawHeaders{
				{Name: "Content-Type", Value: tt.contentType},
			}
			got := h.isGRPCWebRequest(headers)
			if got != tt.want {
				t.Errorf("isGRPCWebRequest(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

func TestIsGRPCWebRequest_CaseInsensitiveHeaderName(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())
	h.SetGRPCWebHandler(grpcweb.NewHandler(store, testutil.DiscardLogger()))

	// Wire may send mixed-case Content-Type header name.
	headers := parser.RawHeaders{
		{Name: "content-type", Value: "application/grpc-web+proto"},
	}
	if !h.isGRPCWebRequest(headers) {
		t.Error("isGRPCWebRequest should match case-insensitive header name")
	}
}

func TestSetGRPCWebHandler(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, nil, testutil.DiscardLogger())

	if h.grpcWebHandler != nil {
		t.Fatal("grpcWebHandler should be nil initially")
	}

	gwh := grpcweb.NewHandler(store, testutil.DiscardLogger())
	h.SetGRPCWebHandler(gwh)

	if h.grpcWebHandler != gwh {
		t.Error("SetGRPCWebHandler did not set the handler")
	}
}

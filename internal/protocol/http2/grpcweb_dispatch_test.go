package http2

import (
	"log/slog"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/grpcweb"
)

func TestSetGRPCWebHandler(t *testing.T) {
	h := NewHandler(&mockStore{}, slog.Default())

	if h.grpcWebHandler != nil {
		t.Fatal("grpcWebHandler should be nil by default")
	}

	gwh := grpcweb.NewHandler(&mockStore{}, slog.Default())
	h.SetGRPCWebHandler(gwh)

	if h.grpcWebHandler == nil {
		t.Fatal("grpcWebHandler should be set after SetGRPCWebHandler")
	}
}

func TestGRPCWebContentTypeDispatch(t *testing.T) {
	// Verify that isGRPCContentType excludes gRPC-Web and grpcweb.IsGRPCWebContentType
	// correctly identifies gRPC-Web types, ensuring proper dispatch.
	tests := []struct {
		name       string
		ct         string
		wantGRPC   bool
		wantGRPCW  bool
		wantNormal bool
	}{
		{
			name:       "plain gRPC",
			ct:         "application/grpc",
			wantGRPC:   true,
			wantGRPCW:  false,
			wantNormal: false,
		},
		{
			name:       "gRPC with subtype",
			ct:         "application/grpc+proto",
			wantGRPC:   true,
			wantGRPCW:  false,
			wantNormal: false,
		},
		{
			name:       "gRPC-Web binary",
			ct:         "application/grpc-web",
			wantGRPC:   false,
			wantGRPCW:  true,
			wantNormal: false,
		},
		{
			name:       "gRPC-Web binary with subtype",
			ct:         "application/grpc-web+proto",
			wantGRPC:   false,
			wantGRPCW:  true,
			wantNormal: false,
		},
		{
			name:       "gRPC-Web text",
			ct:         "application/grpc-web-text",
			wantGRPC:   false,
			wantGRPCW:  true,
			wantNormal: false,
		},
		{
			name:       "gRPC-Web text with subtype",
			ct:         "application/grpc-web-text+proto",
			wantGRPC:   false,
			wantGRPCW:  true,
			wantNormal: false,
		},
		{
			name:       "gRPC-Web with charset param",
			ct:         "application/grpc-web; charset=utf-8",
			wantGRPC:   false,
			wantGRPCW:  true,
			wantNormal: false,
		},
		{
			name:       "normal JSON",
			ct:         "application/json",
			wantGRPC:   false,
			wantGRPCW:  false,
			wantNormal: true,
		},
		{
			name:       "empty content-type",
			ct:         "",
			wantGRPC:   false,
			wantGRPCW:  false,
			wantNormal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotGRPC := isGRPCContentType(tt.ct)
			gotGRPCWeb := grpcweb.IsGRPCWebContentType(tt.ct)
			gotNormal := !gotGRPC && !gotGRPCWeb

			if gotGRPC != tt.wantGRPC {
				t.Errorf("isGRPCContentType(%q) = %v, want %v", tt.ct, gotGRPC, tt.wantGRPC)
			}
			if gotGRPCWeb != tt.wantGRPCW {
				t.Errorf("IsGRPCWebContentType(%q) = %v, want %v", tt.ct, gotGRPCWeb, tt.wantGRPCW)
			}
			if gotNormal != tt.wantNormal {
				t.Errorf("normal path for %q = %v, want %v", tt.ct, gotNormal, tt.wantNormal)
			}
		})
	}
}

// TestGRPCWebDispatchNilHandler verifies that gRPC-Web dispatch is skipped
// when the grpcWebHandler is nil, even for gRPC-Web Content-Types.
func TestGRPCWebDispatchNilHandler(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, slog.Default())

	// grpcWebHandler is nil — gRPC-Web content should not trigger dispatch.
	ct := "application/grpc-web"
	isGRPC := h.grpcHandler != nil && isGRPCContentType(ct)
	isGRPCWeb := h.grpcWebHandler != nil && grpcweb.IsGRPCWebContentType(ct)

	if isGRPC {
		t.Error("expected isGRPC=false when grpcHandler is nil")
	}
	if isGRPCWeb {
		t.Error("expected isGRPCWeb=false when grpcWebHandler is nil")
	}
}

// TestGRPCWebDispatchEnabled verifies that gRPC-Web dispatch is triggered
// when the grpcWebHandler is set and the Content-Type matches.
func TestGRPCWebDispatchEnabled(t *testing.T) {
	store := &mockStore{}
	h := NewHandler(store, slog.Default())

	gwh := grpcweb.NewHandler(store, slog.Default())
	h.SetGRPCWebHandler(gwh)

	ct := "application/grpc-web"
	isGRPC := h.grpcHandler != nil && isGRPCContentType(ct)
	isGRPCWeb := h.grpcWebHandler != nil && grpcweb.IsGRPCWebContentType(ct)

	if isGRPC {
		t.Error("expected isGRPC=false for gRPC-Web content type")
	}
	if !isGRPCWeb {
		t.Error("expected isGRPCWeb=true for gRPC-Web content type with handler set")
	}
}

// mockStore is defined in handler_test.go.

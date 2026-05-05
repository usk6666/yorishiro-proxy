package connector

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
)

// TestIsGRPCContentType validates the precise native-gRPC content-type
// discriminator introduced in USK-658. The previous prefix-only matcher
// over-matched application/grpc-web*, breaking gRPC-Web routing.
func TestIsGRPCContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{"plain gRPC", "application/grpc", true},
		{"gRPC +proto subtype", "application/grpc+proto", true},
		{"gRPC +json subtype", "application/grpc+json", true},
		{"gRPC with charset param", "application/grpc; charset=utf-8", true},
		{"gRPC +proto with charset", "application/grpc+proto; charset=utf-8", true},
		{"gRPC uppercase", "APPLICATION/GRPC", true},
		{"gRPC with leading space", " application/grpc", true},

		// USK-658 regression guards: gRPC-Web variants must NOT match.
		{"grpc-web binary", "application/grpc-web", false},
		{"grpc-web +proto", "application/grpc-web+proto", false},
		{"grpc-web text", "application/grpc-web-text", false},
		{"grpc-web text +proto", "application/grpc-web-text+proto", false},
		{"grpc-web with charset", "application/grpc-web; charset=utf-8", false},

		// Other non-matches.
		{"application/grpcweb (no separator)", "application/grpcweb", false},
		{"json", "application/json", false},
		{"empty", "", false},
		{"text/plain", "text/plain", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGRPCContentType(tt.ct); got != tt.want {
				t.Errorf("isGRPCContentType(%q) = %v, want %v", tt.ct, got, tt.want)
			}
		})
	}
}

// TestExtractContentType verifies the helper returns the first content-type
// header value (case-insensitive name match), preserving wire case in the
// returned value, and "" when no content-type header is present.
func TestExtractContentType(t *testing.T) {
	tests := []struct {
		name    string
		headers []envelope.KeyValue
		want    string
	}{
		{
			name:    "no content-type header",
			headers: []envelope.KeyValue{{Name: "x-other", Value: "ignore"}},
			want:    "",
		},
		{
			name:    "lowercase content-type",
			headers: []envelope.KeyValue{{Name: "content-type", Value: "application/grpc"}},
			want:    "application/grpc",
		},
		{
			name:    "mixed-case header name",
			headers: []envelope.KeyValue{{Name: "Content-Type", Value: "application/grpc-web"}},
			want:    "application/grpc-web",
		},
		{
			name: "first content-type wins",
			headers: []envelope.KeyValue{
				{Name: "content-type", Value: "application/grpc"},
				{Name: "content-type", Value: "application/grpc-web"},
			},
			want: "application/grpc",
		},
		{
			name: "value case preserved",
			headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "Application/GRPC; CHARSET=UTF-8"},
			},
			want: "Application/GRPC; CHARSET=UTF-8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := &http2.H2HeadersEvent{Headers: tt.headers}
			if got := extractContentType(evt); got != tt.want {
				t.Errorf("extractContentType = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDispatchClassification cross-checks how each test content-type would be
// routed by DispatchH2Stream. The three dispatch buckets are mutually
// exclusive: gRPC-Web wins over native-gRPC by branch order (defense-in-depth);
// the precise discriminator makes order non-load-bearing for correctness.
func TestDispatchClassification(t *testing.T) {
	tests := []struct {
		name        string
		ct          string
		wantGRPC    bool
		wantGRPCWeb bool
	}{
		{"plain gRPC", "application/grpc", true, false},
		{"gRPC +proto", "application/grpc+proto", true, false},
		{"grpc-web binary", "application/grpc-web", false, true},
		{"grpc-web +proto", "application/grpc-web+proto", false, true},
		{"grpc-web text", "application/grpc-web-text", false, true},
		{"grpc-web text +proto", "application/grpc-web-text+proto", false, true},
		{"json", "application/json", false, false},
		{"empty", "", false, false},
		{"application/grpcweb (no separator)", "application/grpcweb", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isGRPC := isGRPCContentType(tt.ct)
			isGRPCWeb := grpcweb.IsGRPCWebContentType(tt.ct)
			if isGRPC != tt.wantGRPC {
				t.Errorf("isGRPCContentType(%q) = %v, want %v", tt.ct, isGRPC, tt.wantGRPC)
			}
			if isGRPCWeb != tt.wantGRPCWeb {
				t.Errorf("grpcweb.IsGRPCWebContentType(%q) = %v, want %v", tt.ct, isGRPCWeb, tt.wantGRPCWeb)
			}
			if isGRPC && isGRPCWeb {
				t.Errorf("classifications must be mutually exclusive; %q matched both", tt.ct)
			}
		})
	}
}

// TestTranslateRoleForGRPCWeb verifies role translation between the
// httpaggregator and grpcweb Role enums. They are independent types; the
// translator makes the coupling explicit.
func TestTranslateRoleForGRPCWeb(t *testing.T) {
	tests := []struct {
		name string
		in   httpaggregator.Role
		want grpcweb.Role
	}{
		{"server", httpaggregator.RoleServer, grpcweb.RoleServer},
		{"client", httpaggregator.RoleClient, grpcweb.RoleClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := translateRoleForGRPCWeb(tt.in); got != tt.want {
				t.Errorf("translateRoleForGRPCWeb(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestTranslateRoleForGRPC mirrors the gRPC-Web role test for the existing
// translator. Keeps both translators covered so a future refactor that
// collapses them into a generic helper still has both directions tested.
func TestTranslateRoleForGRPC(t *testing.T) {
	tests := []struct {
		name string
		in   httpaggregator.Role
		want grpclayer.Role
	}{
		{"server", httpaggregator.RoleServer, grpclayer.RoleServer},
		{"client", httpaggregator.RoleClient, grpclayer.RoleClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := translateRoleForGRPC(tt.in); got != tt.want {
				t.Errorf("translateRoleForGRPC(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

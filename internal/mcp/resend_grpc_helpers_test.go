// Package mcp resend_grpc_helpers_test.go — unit coverage for
// extractResendGRPCStartFields (USK-920).
//
// projectGRPCStart (internal/pipeline/record_step.go) writes grpc_service /
// grpc_method into Flow.Metadata unconditionally, and after USK-920 also
// populates Flow.URL from the request-side pseudo-headers. The recovery
// helper must prefer the URL projection when present and fall back to
// Metadata for already-recorded flows that pre-date the URL projection.
package mcp

import (
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

func TestExtractResendGRPCStartFields(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		flow          *flow.Flow
		wantAuthority string
		wantService   string
		wantMethod    string
		wantScheme    string
	}{
		{
			name: "url_only",
			flow: &flow.Flow{
				URL: &url.URL{
					Scheme: "https",
					Host:   "api.example.com:443",
					Path:   "/hello.HelloService/SayHello",
				},
			},
			wantAuthority: "api.example.com:443",
			wantService:   "hello.HelloService",
			wantMethod:    "SayHello",
			wantScheme:    "https",
		},
		{
			name: "metadata_only_legacy_flow",
			flow: &flow.Flow{
				Metadata: map[string]string{
					"grpc_service": "hello.HelloService",
					"grpc_method":  "SayHello",
				},
			},
			// Authority/scheme unrecoverable for legacy rows that pre-date
			// the URL projection — caller must supply target_addr+scheme.
			wantAuthority: "",
			wantService:   "hello.HelloService",
			wantMethod:    "SayHello",
			wantScheme:    "",
		},
		{
			name: "url_and_metadata_present_url_wins",
			flow: &flow.Flow{
				URL: &url.URL{
					Scheme: "http",
					Host:   "127.0.0.1:9000",
					Path:   "/url.Service/UrlMethod",
				},
				Metadata: map[string]string{
					"grpc_service": "metadata.Service",
					"grpc_method":  "MetadataMethod",
				},
			},
			// URL is authoritative — Metadata only fills in when URL is
			// missing the field.
			wantAuthority: "127.0.0.1:9000",
			wantService:   "url.Service",
			wantMethod:    "UrlMethod",
			wantScheme:    "http",
		},
		{
			name: "url_missing_path_metadata_fills_service_method",
			flow: &flow.Flow{
				URL: &url.URL{
					Scheme: "https",
					Host:   "api.example.com",
				},
				Metadata: map[string]string{
					"grpc_service": "hello.HelloService",
					"grpc_method":  "SayHello",
				},
			},
			wantAuthority: "api.example.com",
			wantService:   "hello.HelloService",
			wantMethod:    "SayHello",
			wantScheme:    "https",
		},
		{
			name:          "neither_url_nor_metadata",
			flow:          &flow.Flow{},
			wantAuthority: "",
			wantService:   "",
			wantMethod:    "",
			wantScheme:    "",
		},
		{
			name:          "nil_flow",
			flow:          nil,
			wantAuthority: "",
			wantService:   "",
			wantMethod:    "",
			wantScheme:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotAuth, gotSvc, gotMethod, gotScheme := extractResendGRPCStartFields(tc.flow)
			if gotAuth != tc.wantAuthority {
				t.Errorf("authority = %q, want %q", gotAuth, tc.wantAuthority)
			}
			if gotSvc != tc.wantService {
				t.Errorf("service = %q, want %q", gotSvc, tc.wantService)
			}
			if gotMethod != tc.wantMethod {
				t.Errorf("method = %q, want %q", gotMethod, tc.wantMethod)
			}
			if gotScheme != tc.wantScheme {
				t.Errorf("scheme = %q, want %q", gotScheme, tc.wantScheme)
			}
		})
	}
}

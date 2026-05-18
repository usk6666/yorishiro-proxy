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

// TestPickGRPCStartFlow_Empty verifies the wrapper returns nil for a nil
// or empty input slice. USK-930 simplification post-condition: callers
// already passed FlowListOptions{WireLevel: flow.WireLevelSemantic} when
// loading these flows, so the wrapper does not need to defend against
// overlay rows.
func TestPickGRPCStartFlow_Empty(t *testing.T) {
	t.Parallel()
	if got := pickGRPCStartFlow(nil); got != nil {
		t.Errorf("pickGRPCStartFlow(nil) = %v, want nil", got)
	}
	if got := pickGRPCStartFlow([]*flow.Flow{}); got != nil {
		t.Errorf("pickGRPCStartFlow(empty) = %v, want nil", got)
	}
}

// TestPickGRPCStartFlow_FirstFlow verifies the wrapper unconditionally
// returns the first element regardless of Metadata (USK-930 lifted the
// defensive Metadata["grpc_event"]=="start" scan now that callers pass
// the semantic wire_level filter, so the GRPCStart envelope is
// guaranteed to be flows[0] by the RecordStep projection invariant).
func TestPickGRPCStartFlow_FirstFlow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		flows []*flow.Flow
	}{
		{
			name: "single_flow_with_start_metadata",
			flows: []*flow.Flow{
				{ID: "first", Metadata: map[string]string{"grpc_event": "start"}},
			},
		},
		{
			name: "single_flow_no_metadata",
			flows: []*flow.Flow{
				{ID: "first"},
			},
		},
		{
			name: "multi_flow_start_first",
			flows: []*flow.Flow{
				{ID: "first", Metadata: map[string]string{"grpc_event": "start"}},
				{ID: "second", Metadata: map[string]string{"grpc_event": "data"}},
			},
		},
		{
			name: "multi_flow_no_metadata_at_all",
			flows: []*flow.Flow{
				{ID: "first"},
				{ID: "second"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pickGRPCStartFlow(tc.flows)
			if got == nil || got.ID != "first" {
				t.Fatalf("pickGRPCStartFlow returned %v, want flow ID 'first'", got)
			}
		})
	}
}

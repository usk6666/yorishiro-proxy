// Package mcp resend_grpc_helpers_test.go — unit coverage for
// extractResendGRPCStartFields (USK-920) and for the Send-side
// pseudo-header projection onto the synthesised Start envelope (USK-1051).
//
// projectGRPCStart (internal/pipeline/record_step.go) writes grpc_service /
// grpc_method into Flow.Metadata unconditionally, and after USK-920 also
// populates Flow.URL from the request-side pseudo-headers. The recovery
// helper must prefer the URL projection when present and fall back to
// Metadata for already-recorded flows that pre-date the URL projection.
package mcp

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
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

// TestBuildResendGRPCStartEnvelope_CarriesAuthorityAndScheme pins USK-1051:
// the gRPC Layer derives :authority / :scheme from the GRPCStartMessage
// overlay alone (no Envelope.Context.TargetHost fallback), and this
// synthetic envelope's Context carries only a ConnID. If the builder stops
// copying plan.authority / plan.scheme onto the message, the HEADERS frame
// goes out with no :authority and grpc-go >=1.83.2 rejects the RPC with
// codes.Internal before the handler ever runs.
//
// fuzz_grpc shares this builder via cloneFuzzGRPCPlan (a by-value struct
// copy that carries both fields), so this one assertion covers both tools.
func TestBuildResendGRPCStartEnvelope_CarriesAuthorityAndScheme(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		plan          *resendGRPCPlan
		wantAuthority string
		wantScheme    string
	}{
		{
			name: "tls_plan",
			plan: &resendGRPCPlan{
				streamID:  "stream-1",
				connID:    "conn-1",
				authority: "api.example.com:443",
				scheme:    "https",
				service:   "hello.HelloService",
				method:    "SayHello",
			},
			wantAuthority: "api.example.com:443",
			wantScheme:    "https",
		},
		{
			name: "h2c_plan",
			plan: &resendGRPCPlan{
				streamID:  "stream-2",
				connID:    "conn-2",
				authority: "127.0.0.1:50051",
				scheme:    "http",
				service:   "hello.HelloService",
				method:    "SayHello",
			},
			wantAuthority: "127.0.0.1:50051",
			wantScheme:    "http",
		},
		{
			name: "authority_differs_from_dial_target",
			// target_addr override: the dial goes to dialAddr but the
			// :authority pseudo-header keeps the canonical vhost.
			plan: &resendGRPCPlan{
				streamID:  "stream-3",
				connID:    "conn-3",
				authority: "vhost.example:8443",
				dialAddr:  "127.0.0.1:9999",
				scheme:    "https",
				service:   "hello.HelloService",
				method:    "SayHello",
			},
			wantAuthority: "vhost.example:8443",
			wantScheme:    "https",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := buildResendGRPCStartEnvelope(tc.plan)
			msg, ok := env.Message.(*envelope.GRPCStartMessage)
			if !ok {
				t.Fatalf("env.Message type = %T, want *envelope.GRPCStartMessage", env.Message)
			}
			if msg.Authority != tc.wantAuthority {
				t.Errorf("GRPCStartMessage.Authority = %q, want %q", msg.Authority, tc.wantAuthority)
			}
			if msg.Scheme != tc.wantScheme {
				t.Errorf("GRPCStartMessage.Scheme = %q, want %q", msg.Scheme, tc.wantScheme)
			}
			// The Context is intentionally ConnID-only: the Layer must not
			// be able to fall back to it for :authority.
			if env.Context.TargetHost != "" {
				t.Errorf("env.Context.TargetHost = %q, want empty (no Layer-side fallback source)", env.Context.TargetHost)
			}
		})
	}
}

// TestBuildResendGRPCPlan_ResolvesAuthorityAndScheme drives the real
// producer — buildResendGRPCPlan — rather than a hand-built plan literal,
// so it proves the `plan.scheme = scheme` / `plan.authority = authority`
// assignments are actually reached (USK-1051 review F-1).
//
// The h2c subtests are the load-bearing ones: schemeForStart's literal
// fallback is "https", so a plan that dropped plan.scheme would still emit
// ":scheme: https" and every https-only assertion would keep passing. Only
// an input that resolves to "http" distinguishes "the assignment ran" from
// "the fallback happened to match".
//
// buildResendGRPCPlan needs no flow store when FlowID is empty: the
// recovery branch is skipped, and populateResendGRPCMessages is
// nil-receiver-safe for the text/base64 body encodings used here.
func TestBuildResendGRPCPlan_ResolvesAuthorityAndScheme(t *testing.T) {
	t.Parallel()

	msgs := []resendGRPCData{{Payload: "hello"}}

	cases := []struct {
		name          string
		input         *resendGRPCInput
		wantScheme    string
		wantAuthority string
		wantUseTLS    bool
	}{
		{
			name: "explicit_http_is_h2c",
			input: &resendGRPCInput{
				TargetAddr: "127.0.0.1:50051",
				Scheme:     "http",
				Service:    "hello.HelloService",
				Method:     "SayHello",
				Messages:   msgs,
			},
			wantScheme:    "http",
			wantAuthority: "127.0.0.1:50051",
			wantUseTLS:    false,
		},
		{
			name: "explicit_https",
			input: &resendGRPCInput{
				TargetAddr: "api.example.com:443",
				Scheme:     "https",
				Service:    "hello.HelloService",
				Method:     "SayHello",
				Messages:   msgs,
			},
			wantScheme:    "https",
			wantAuthority: "api.example.com:443",
			wantUseTLS:    true,
		},
		{
			name: "omitted_scheme_defaults_to_https",
			input: &resendGRPCInput{
				TargetAddr: "api.example.com:443",
				Service:    "hello.HelloService",
				Method:     "SayHello",
				Messages:   msgs,
			},
			wantScheme:    "https",
			wantAuthority: "api.example.com:443",
			wantUseTLS:    true,
		},
		{
			name: "uppercase_http_is_normalised_and_still_h2c",
			input: &resendGRPCInput{
				TargetAddr: "127.0.0.1:50051",
				Scheme:     "HTTP",
				Service:    "hello.HelloService",
				Method:     "SayHello",
				Messages:   msgs,
			},
			wantScheme:    "http",
			wantAuthority: "127.0.0.1:50051",
			wantUseTLS:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &Server{}
			plan, err := s.buildResendGRPCPlan(context.Background(), tc.input)
			if err != nil {
				t.Fatalf("buildResendGRPCPlan: %v", err)
			}
			if plan.scheme != tc.wantScheme {
				t.Errorf("plan.scheme = %q, want %q", plan.scheme, tc.wantScheme)
			}
			if plan.authority != tc.wantAuthority {
				t.Errorf("plan.authority = %q, want %q", plan.authority, tc.wantAuthority)
			}
			if plan.useTLS != tc.wantUseTLS {
				t.Errorf("plan.useTLS = %v, want %v", plan.useTLS, tc.wantUseTLS)
			}

			// End-to-end through the envelope builder: the resolved values
			// must land on the GRPCStartMessage, which is the only source
			// the gRPC Layer reads for :authority / :scheme.
			env := buildResendGRPCStartEnvelope(plan)
			msg, ok := env.Message.(*envelope.GRPCStartMessage)
			if !ok {
				t.Fatalf("env.Message type = %T, want *envelope.GRPCStartMessage", env.Message)
			}
			if msg.Scheme != tc.wantScheme {
				t.Errorf("GRPCStartMessage.Scheme = %q, want %q", msg.Scheme, tc.wantScheme)
			}
			if msg.Authority != tc.wantAuthority {
				t.Errorf("GRPCStartMessage.Authority = %q, want %q", msg.Authority, tc.wantAuthority)
			}
		})
	}
}

// TestValidateResendGRPCInput_SchemeAllowlist pins USK-1051 review S-1:
// the http/https allowlist must apply on the flow_id path too, not only
// on the from-scratch path.
//
// Before the fix the allowlist lived in validateResendGRPCFromScratch,
// which validateResendGRPCInput calls only when FlowID is empty. Since
// this PR the resolved scheme reaches the wire as the :scheme
// pseudo-header, so an arbitrary value on the flow_id path would be
// forwarded verbatim while fuzz_grpc's scope/safety canonicalURL
// re-derived a different scheme from plan.useTLS.
func TestValidateResendGRPCInput_SchemeAllowlist(t *testing.T) {
	t.Parallel()

	msgs := []resendGRPCData{{Payload: "hello"}}

	cases := []struct {
		name    string
		input   *resendGRPCInput
		wantErr bool
	}{
		{
			name:    "flow_id_path_rejects_file_scheme",
			input:   &resendGRPCInput{FlowID: "stream-1", Scheme: "file", Messages: msgs},
			wantErr: true,
		},
		{
			name:    "flow_id_path_rejects_gopher_scheme",
			input:   &resendGRPCInput{FlowID: "stream-1", Scheme: "gopher", Messages: msgs},
			wantErr: true,
		},
		{
			name:    "flow_id_path_accepts_http",
			input:   &resendGRPCInput{FlowID: "stream-1", Scheme: "http", Messages: msgs},
			wantErr: false,
		},
		{
			name:    "flow_id_path_accepts_https",
			input:   &resendGRPCInput{FlowID: "stream-1", Scheme: "https", Messages: msgs},
			wantErr: false,
		},
		{
			name:    "flow_id_path_accepts_uppercase_https",
			input:   &resendGRPCInput{FlowID: "stream-1", Scheme: "HTTPS", Messages: msgs},
			wantErr: false,
		},
		{
			name:    "flow_id_path_accepts_empty_scheme",
			input:   &resendGRPCInput{FlowID: "stream-1", Messages: msgs},
			wantErr: false,
		},
		{
			// Regression guard for the path that already worked, so a
			// future refactor cannot drop the check from both sides.
			name: "from_scratch_path_still_rejects_file_scheme",
			input: &resendGRPCInput{
				TargetAddr: "127.0.0.1:50051",
				Scheme:     "file",
				Service:    "hello.HelloService",
				Method:     "SayHello",
				Messages:   msgs,
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateResendGRPCInput(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("validateResendGRPCInput() = nil, want an unsupported-scheme error")
				}
				if !strings.Contains(err.Error(), "unsupported scheme") {
					t.Errorf("error = %q, want it to mention \"unsupported scheme\"", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("validateResendGRPCInput() = %v, want nil", err)
			}
		})
	}
}

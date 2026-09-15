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
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

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

// ---------------------------------------------------------------------------
// USK-1056: the dial must not be decided by client-declared data alone.
// ---------------------------------------------------------------------------

// saveUSK1056GRPCFlow persists a minimal recorded gRPC stream — one Stream
// row (optionally carrying an observed upstream TLS version) plus one
// send-direction GRPCStart Flow whose URL is the client-declared
// :scheme / :authority / :path projection — and returns the stream id.
//
// It deliberately goes through the real SQLite store rather than a mock.
// Flow.URL is persisted as f.URL.String() and read back through
// url.Parse, and net/url lowercases the scheme on that read. A mock store
// would hand back whatever *url.URL the test built and would therefore
// assert behaviour production never exhibits (USK-1056 design review,
// constraint A).
func saveUSK1056GRPCFlow(t *testing.T, store flow.Store, declaredURL *url.URL, observedTLSVersion string) string {
	t.Helper()
	ctx := context.Background()

	streamID := uuid.NewString()
	st := &flow.Stream{
		ID:        streamID,
		ConnID:    uuid.NewString(),
		Protocol:  "grpc",
		State:     "complete",
		Timestamp: time.Now(),
	}
	// createStream projects Stream.Scheme from the same client-declared
	// GRPCStartMessage.Scheme, so mirror that here: it is not a second,
	// independent source.
	if declaredURL != nil {
		st.Scheme = declaredURL.Scheme
	}
	if observedTLSVersion != "" {
		// RecordStep.updateStreamTLS writes these from the upstream leg's
		// TLS snapshot on Receive envelopes.
		st.ConnInfo = &flow.ConnectionInfo{
			TLSVersion: observedTLSVersion,
			TLSCipher:  "TLS_AES_128_GCM_SHA256",
			TLSALPN:    "h2",
		}
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	sendFlow := &flow.Flow{
		ID:        uuid.NewString(),
		StreamID:  streamID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now(),
		URL:       declaredURL,
		Headers: map[string][]string{
			"authorization": {"Bearer recorded-secret"},
		},
		Metadata: map[string]string{"grpc_event": "start"},
	}
	if err := store.SaveFlow(ctx, sendFlow); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return streamID
}

// TestBuildResendGRPCPlan_DialTLSFromObservedTransport pins USK-1056.
//
// Flow.URL on a gRPC stream is projected from GRPCStartMessage.Authority /
// .Scheme, which the HTTP/2 assembler copies verbatim out of the client's
// HEADERS block — so the recovered scheme is client-declared. Deciding the
// socket from it alone lets a recorded TLS session replay in cleartext on
// port 80 together with its recorded `authorization` metadata.
//
// The fix reconciles it against Stream.ConnInfo.TLSVersion, an
// independently observed L4 fact, as a strictly one-sided oracle. Two
// assertions are load-bearing in every upgrade case:
//
//  1. plan.useTLS flips to true (the socket is protected), AND
//  2. plan.scheme and plan.canonicalURL.Scheme stay "http" (the wire and
//     the recorded flow are NOT distorted — reversing that would undo
//     USK-1051 and violate MITM Principle 1).
func TestBuildResendGRPCPlan_DialTLSFromObservedTransport(t *testing.T) {
	t.Parallel()

	msgs := []resendGRPCData{{Payload: "hello"}}

	cases := []struct {
		name string
		// declaredURL is what the client put on the wire, as projected
		// into Flow.URL by record_step.go projectGRPCStart.
		declaredURL *url.URL
		// observedTLSVersion is Stream.ConnInfo.TLSVersion; "" means the
		// whole ConnInfo is absent after the store round-trip.
		observedTLSVersion string
		// inputScheme is the caller's explicit scheme override.
		inputScheme string
		inputTarget string

		wantScheme   string
		wantUseTLS   bool
		wantDialAddr string
		wantWarning  string
	}{
		{
			// (a) The attack shape: correct authority, spoofed :scheme.
			// No :authority spoofing is needed — a hostname-only
			// TargetScope rule passes this unchanged.
			name:               "declared_http_but_upstream_was_tls_upgrades_dial_only",
			declaredURL:        &url.URL{Scheme: "http", Host: "api.example.com", Path: "/hello.HelloService/SayHello"},
			observedTLSVersion: "TLS 1.3",
			wantScheme:         "http",
			wantUseTLS:         true,
			wantDialAddr:       "api.example.com:443",
			wantWarning:        `observed "TLS 1.3" on the upstream leg`,
		},
		{
			// (b) One-sided: absence of an observation is not evidence.
			// ConnInfo is nil for every h2c stream and for any stream
			// that never saw a Receive envelope.
			name:         "declared_http_with_no_conninfo_stays_cleartext",
			declaredURL:  &url.URL{Scheme: "http", Host: "127.0.0.1:50051", Path: "/hello.HelloService/SayHello"},
			wantScheme:   "http",
			wantUseTLS:   false,
			wantDialAddr: "127.0.0.1:50051",
		},
		{
			// (c) An explicit scheme is the caller's own decision and is
			// the documented way to force a cleartext replay.
			name:               "explicit_http_override_is_never_upgraded",
			declaredURL:        &url.URL{Scheme: "https", Host: "api.example.com", Path: "/hello.HelloService/SayHello"},
			observedTLSVersion: "TLS 1.3",
			inputScheme:        "http",
			wantScheme:         "http",
			wantUseTLS:         false,
			wantDialAddr:       "api.example.com:80",
		},
		{
			// (d) Decision B regression guard: an absent recovered scheme
			// already fails safe via the https default, and must keep
			// doing so. "//host/path" is the string form that survives the
			// SQLite String()/url.Parse round-trip with an empty scheme.
			name:         "empty_recovered_scheme_still_defaults_to_https",
			declaredURL:  &url.URL{Host: "api.example.com", Path: "/hello.HelloService/SayHello"},
			wantScheme:   "https",
			wantUseTLS:   true,
			wantDialAddr: "api.example.com:443",
		},
		{
			// Never downgrade: a recovered https with no TLS observation
			// (e.g. the RPC never got a response) stays on TLS.
			name:         "declared_https_with_no_conninfo_stays_tls",
			declaredURL:  &url.URL{Scheme: "https", Host: "api.example.com", Path: "/hello.HelloService/SayHello"},
			wantScheme:   "https",
			wantUseTLS:   true,
			wantDialAddr: "api.example.com:443",
		},
		{
			// Constraint A, pinned rather than assumed: an uppercase
			// ":scheme: HTTPS" cannot survive the store, because Flow.URL
			// round-trips through net/url which lowercases it. This is why
			// the exact-match `scheme == "https"` in buildResendGRPCPlan is
			// not itself a live bypass.
			name:         "uppercase_declared_scheme_is_normalised_by_the_store",
			declaredURL:  &url.URL{Scheme: "HTTPS", Host: "api.example.com", Path: "/hello.HelloService/SayHello"},
			wantScheme:   "https",
			wantUseTLS:   true,
			wantDialAddr: "api.example.com:443",
		},
		{
			// target_addr pins the address but not the transport: the
			// scheme axis keeps its own override, so the upgrade still
			// applies and the redirected dial gets the TLS default port.
			name:               "target_addr_redirect_still_upgrades_transport",
			declaredURL:        &url.URL{Scheme: "http", Host: "api.example.com", Path: "/hello.HelloService/SayHello"},
			observedTLSVersion: "TLS 1.2",
			inputTarget:        "127.0.0.1",
			wantScheme:         "http",
			wantUseTLS:         true,
			wantDialAddr:       "127.0.0.1:443",
			wantWarning:        `observed "TLS 1.2" on the upstream leg`,
		},
	}

	// One store for the whole table: newTestStore runs the full schema
	// migration, which is the expensive part under -race, and every case
	// gets its own stream id anyway. The parent's t.Cleanup(Close) runs
	// only after all parallel subtests have finished.
	store := newTestStore(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flowID := saveUSK1056GRPCFlow(t, store, tc.declaredURL, tc.observedTLSVersion)

			s := &Server{flowStore: NewFlowStore(store, nil)}
			input := &resendGRPCInput{
				FlowID:     flowID,
				Scheme:     tc.inputScheme,
				TargetAddr: tc.inputTarget,
				Messages:   msgs,
			}
			plan, err := s.buildResendGRPCPlan(context.Background(), input)
			if err != nil {
				t.Fatalf("buildResendGRPCPlan: %v", err)
			}

			if plan.useTLS != tc.wantUseTLS {
				t.Errorf("plan.useTLS = %v, want %v", plan.useTLS, tc.wantUseTLS)
			}
			// Anti-distortion guard. plan.scheme is what reaches the
			// upstream HEADERS frame as :scheme via
			// buildResendGRPCStartEnvelope.
			if plan.scheme != tc.wantScheme {
				t.Errorf("plan.scheme = %q, want %q (the recorded :scheme must not be rewritten)", plan.scheme, tc.wantScheme)
			}
			if plan.canonicalURL == nil {
				t.Fatal("plan.canonicalURL = nil, want a URL")
			}
			if plan.canonicalURL.Scheme != tc.wantScheme {
				t.Errorf("plan.canonicalURL.Scheme = %q, want %q (scope/safety must check the wire scheme)", plan.canonicalURL.Scheme, tc.wantScheme)
			}
			if plan.dialAddr != tc.wantDialAddr {
				t.Errorf("plan.dialAddr = %q, want %q", plan.dialAddr, tc.wantDialAddr)
			}
			// The recorded credential must still be replayed verbatim —
			// this fix changes the socket, not the payload.
			if len(plan.metadata) == 0 {
				t.Error("plan.metadata is empty, want the recovered authorization header")
			}

			// End-to-end: the resolved scheme lands on the message the
			// gRPC Layer reads for :scheme.
			env := buildResendGRPCStartEnvelope(plan)
			msg, ok := env.Message.(*envelope.GRPCStartMessage)
			if !ok {
				t.Fatalf("env.Message type = %T, want *envelope.GRPCStartMessage", env.Message)
			}
			if msg.Scheme != tc.wantScheme {
				t.Errorf("GRPCStartMessage.Scheme = %q, want %q", msg.Scheme, tc.wantScheme)
			}

			// wantWarning is set exactly on the observed-transport upgrade
			// cases, so it doubles as the expectation for the flag the
			// failure path reads (wrapResendGRPCRunError).
			wantUpgraded := tc.wantWarning != ""
			if plan.tlsUpgradedFromObservation != wantUpgraded {
				t.Errorf("plan.tlsUpgradedFromObservation = %v, want %v", plan.tlsUpgradedFromObservation, wantUpgraded)
			}
			if tc.wantWarning != "" {
				if !containsWarning(plan.warnings, tc.wantWarning) {
					t.Errorf("plan.warnings = %q, want one containing %q", plan.warnings, tc.wantWarning)
				}
			} else if containsWarning(plan.warnings, "dialling with TLS") {
				t.Errorf("plan.warnings = %q, want no TLS-upgrade warning", plan.warnings)
			}
		})
	}
}

// TestBuildResendGRPCPlan_WarnsOnClientDeclaredDialTarget pins USK-1056
// decision U3: nothing in a persisted flow records the address the proxy
// originally connected to (createStream never fills ConnInfo.ServerAddr on
// the MITM path), so the host axis cannot be corrected — only reported.
// The warning is the caller's signal to pass target_addr.
func TestBuildResendGRPCPlan_WarnsOnClientDeclaredDialTarget(t *testing.T) {
	t.Parallel()

	const want = "client-declared :authority"
	msgs := []resendGRPCData{{Payload: "hello"}}
	declared := &url.URL{Scheme: "https", Host: "api.example.com", Path: "/hello.HelloService/SayHello"}

	cases := []struct {
		name        string
		targetAddr  string
		flowID      bool
		wantWarning bool
	}{
		{name: "flow_id_without_target_addr_warns", flowID: true, wantWarning: true},
		{name: "flow_id_with_target_addr_is_silent", flowID: true, targetAddr: "127.0.0.1:50051", wantWarning: false},
		{name: "from_scratch_is_silent", flowID: false, targetAddr: "127.0.0.1:50051", wantWarning: false},
	}

	store := newTestStore(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := &resendGRPCInput{TargetAddr: tc.targetAddr, Messages: msgs}
			if tc.flowID {
				input.FlowID = saveUSK1056GRPCFlow(t, store, declared, "")
			} else {
				input.Service = "hello.HelloService"
				input.Method = "SayHello"
			}

			s := &Server{flowStore: NewFlowStore(store, nil)}
			plan, err := s.buildResendGRPCPlan(context.Background(), input)
			if err != nil {
				t.Fatalf("buildResendGRPCPlan: %v", err)
			}
			if got := containsWarning(plan.warnings, want); got != tc.wantWarning {
				t.Errorf("warning containing %q present = %v, want %v (warnings=%q)", want, got, tc.wantWarning, plan.warnings)
			}
		})
	}
}

// TestRebuildFuzzGRPCCanonicalURL_FollowsPlanSchemeNotUseTLS is the
// USK-1056 WATCH item. cloneFuzzGRPCPlan nils canonicalURL and the
// per-variant rebuild recreates it; before this fix the rebuild derived
// the scheme from variantPlan.useTLS, which was equivalent only while
// useTLS and scheme could not diverge. Now that an observed-transport
// upgrade makes them diverge, a useTLS-derived rebuild would hand the
// safety / scope filters an "https://" URL for an RPC whose wire :scheme
// is "http" — the USK-1051 wire/checked-URL disagreement, reintroduced.
func TestRebuildFuzzGRPCCanonicalURL_FollowsPlanSchemeNotUseTLS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		scheme     string
		useTLS     bool
		wantScheme string
	}{
		{name: "upgraded_plan_keeps_http_in_the_checked_url", scheme: "http", useTLS: true, wantScheme: "http"},
		{name: "plain_h2c_plan", scheme: "http", useTLS: false, wantScheme: "http"},
		{name: "plain_tls_plan", scheme: "https", useTLS: true, wantScheme: "https"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			base := &resendGRPCPlan{
				streamID:  "base-stream",
				connID:    "base-conn",
				authority: "api.example.com",
				scheme:    tc.scheme,
				useTLS:    tc.useTLS,
				dialAddr:  "api.example.com:443",
				service:   "hello.HelloService",
				method:    "SayHello",
			}
			base.canonicalURL = resendGRPCCanonicalURL(base.scheme, base.authority, base.service, base.method)

			variant := cloneFuzzGRPCPlan(base)
			if variant.canonicalURL != nil {
				t.Fatalf("cloneFuzzGRPCPlan left canonicalURL = %v, want nil so the rebuild is mandatory", variant.canonicalURL)
			}
			if variant.scheme != tc.scheme {
				t.Errorf("cloned scheme = %q, want %q", variant.scheme, tc.scheme)
			}
			if variant.useTLS != tc.useTLS {
				t.Errorf("cloned useTLS = %v, want %v", variant.useTLS, tc.useTLS)
			}

			rebuildFuzzGRPCCanonicalURL(variant)
			if variant.canonicalURL.Scheme != tc.wantScheme {
				t.Errorf("variant canonicalURL.Scheme = %q, want %q", variant.canonicalURL.Scheme, tc.wantScheme)
			}
			if variant.canonicalURL.String() != base.canonicalURL.String() {
				t.Errorf("variant canonicalURL = %q, want it to agree with the base plan's %q",
					variant.canonicalURL.String(), base.canonicalURL.String())
			}
		})
	}
}

// TestWrapResendGRPCRunError_ExplainsObservedTransportUpgrade pins the
// USK-1056 failure-path advisory.
//
// plan.warnings is only ever attached to result.Warnings, which is built
// after runResendGRPC succeeds — so on the one topology this change
// knowingly breaks (a tcp_forwards plaintext client leg fronting an
// upstream_tls upstream, where the observed TLS belongs to a hop beyond the
// recorded :authority) the caller would see a bare handshake error with
// nothing naming the proxy's own transport choice, nor the documented way
// out of it.
//
// The non-upgraded wrap must stay byte-identical: existing assertions on
// "resend_grpc: ..." error text depend on it.
func TestWrapResendGRPCRunError_ExplainsObservedTransportUpgrade(t *testing.T) {
	t.Parallel()

	inner := errors.New("tls handshake 127.0.0.1:8443: EOF")
	unchanged := "resend_grpc: " + inner.Error()

	t.Run("no_upgrade_wrap_is_unchanged", func(t *testing.T) {
		t.Parallel()
		plan := &resendGRPCPlan{scheme: "https", useTLS: true}
		if got := wrapResendGRPCRunError(plan, inner).Error(); got != unchanged {
			t.Errorf("error = %q, want exactly %q", got, unchanged)
		}
	})

	t.Run("nil_plan_wrap_is_unchanged", func(t *testing.T) {
		t.Parallel()
		if got := wrapResendGRPCRunError(nil, inner).Error(); got != unchanged {
			t.Errorf("error = %q, want exactly %q", got, unchanged)
		}
	})

	t.Run("upgraded_dial_names_its_provenance_and_the_escape_hatch", func(t *testing.T) {
		t.Parallel()
		plan := &resendGRPCPlan{
			scheme:                     "http",
			useTLS:                     true,
			observedUpstreamTLSVersion: "TLS 1.3",
			tlsUpgradedFromObservation: true,
		}
		err := wrapResendGRPCRunError(plan, inner)
		if !errors.Is(err, inner) {
			t.Error("errors.Is(err, inner) = false, want true (the cause must stay unwrappable)")
		}
		got := err.Error()
		for _, want := range []string{
			inner.Error(),
			"upgraded to TLS",
			`observed "TLS 1.3"`,
			`:scheme was "http"`,
			`scheme="http"`,
		} {
			if !strings.Contains(got, want) {
				t.Errorf("error = %q, want it to contain %q", got, want)
			}
		}
	})
}

// TestCloneFuzzGRPCPlan_WarningsAreNotAliased pins the half of the
// fuzz_grpc warning wiring that the result shape cannot show: warnings is
// an append-target by construction, so sharing one backing array across N
// variant plans means the first per-variant append writes *into* the
// siblings' array instead of extending its own list.
//
// The base slice is given spare capacity deliberately — at len == cap a
// shared slice is indistinguishable from a copied one, because append
// reallocates and the aliasing bug hides.
func TestCloneFuzzGRPCPlan_WarningsAreNotAliased(t *testing.T) {
	t.Parallel()

	base := &resendGRPCPlan{
		authority: "api.example.com",
		scheme:    "http",
		service:   "hello.HelloService",
		method:    "SayHello",
		warnings:  append(make([]string, 0, 4), "base-0", "base-1"),
	}

	a := cloneFuzzGRPCPlan(base)
	b := cloneFuzzGRPCPlan(base)

	a.warnings = append(a.warnings, "variant-a")
	b.warnings = append(b.warnings, "variant-b")

	if got := a.warnings[len(a.warnings)-1]; got != "variant-a" {
		t.Errorf("variant A's own appended warning = %q, want %q (a sibling's append reached it through a shared array)", got, "variant-a")
	}
	if got := b.warnings[len(b.warnings)-1]; got != "variant-b" {
		t.Errorf("variant B's own appended warning = %q, want %q", got, "variant-b")
	}
	if len(base.warnings) != 2 {
		t.Errorf("base.warnings length = %d, want 2 (a variant append must not extend the base)", len(base.warnings))
	}
	if base.warnings[0] != "base-0" || base.warnings[1] != "base-1" {
		t.Errorf("base.warnings = %q, want the original entries untouched", base.warnings)
	}
}

// TestHandleFuzzGRPC_SurfacesBasePlanDialWarnings pins the fuzz_grpc half
// of the USK-1056 advisory wiring: plan.warnings is resolved once on the
// base plan, and fuzz_grpc must hand it to the agent the way resend_grpc
// does. Without it the only trace of an N-variant campaign aimed at a
// client-declared host is a server-side log the caller cannot see.
//
// The recorded authority is a closed loopback port, so every variant fails
// at the dial — which is deliberate: per-variant dial errors land in
// row.Error and the handler still returns a result, so the assertion is on
// the result wiring and needs no upstream.
func TestHandleFuzzGRPC_SurfacesBasePlanDialWarnings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newTestStore(t)
	declared := &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/hello.HelloService/SayHello"}
	flowID := saveUSK1056GRPCFlow(t, store, declared, "")

	s := newServer(ctx, nil, store, nil)
	timeout := 2000
	_, res, err := s.handleFuzzGRPC(ctx, nil, fuzzGRPCInput{
		FlowID:    flowID,
		Messages:  []resendGRPCData{{Payload: "hello"}},
		TimeoutMs: &timeout,
		Positions: []fuzzGRPCPosition{{
			Path:     "messages[0].payload",
			Payloads: []string{"a", "b"},
		}},
	})
	if err != nil {
		t.Fatalf("handleFuzzGRPC: %v", err)
	}
	if res == nil {
		t.Fatal("handleFuzzGRPC returned a nil result")
	}
	const want = "client-declared :authority"
	if !containsWarning(res.Warnings, want) {
		t.Errorf("result.Warnings = %q, want one containing %q", res.Warnings, want)
	}
}

// containsWarning reports whether any entry of warnings contains substr.
func containsWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

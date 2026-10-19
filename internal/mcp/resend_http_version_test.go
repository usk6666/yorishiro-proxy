package mcp

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-1198: resend_http / fuzz_http pick the upstream wire protocol from
// the explicit http_version parameter, else the recorded flow's
// http_version, else http/1.1. These unit tests pin the input validation
// and the resolution rule on the envelope the pipeline records.

// TestValidateResendHTTPInput_HTTPVersion pins the http_version allowlist
// and its scheme compatibility rule: h2 is HTTP/2 over TLS (ALPN), h2c is
// HTTP/2 over cleartext (prior knowledge), http/1.1 goes either way.
func TestValidateResendHTTPInput_HTTPVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		scheme  string
		wantErr string
	}{
		{name: "empty_https", version: "", scheme: "https"},
		{name: "http11_https", version: "http/1.1", scheme: "https"},
		{name: "http11_http", version: "http/1.1", scheme: "http"},
		{name: "h2_https", version: "h2", scheme: "https"},
		{name: "h2c_http", version: "h2c", scheme: "http"},
		{name: "h2_flow_scheme_unknown", version: "h2", scheme: ""},
		{name: "h2_on_http_rejected", version: "h2", scheme: "http", wantErr: "h2"},
		{name: "h2c_on_https_rejected", version: "h2c", scheme: "https", wantErr: "h2c"},
		{name: "unknown_rejected", version: "h3", scheme: "https", wantErr: "http_version"},
		{name: "http10_rejected", version: "http/1.0", scheme: "http", wantErr: "http_version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resend := resendHTTPInput{
				FlowID:      "some-flow",
				Scheme:      tc.scheme,
				HTTPVersion: tc.version,
			}
			fuzz := fuzzHTTPInput{
				FlowID:      "some-flow",
				Scheme:      tc.scheme,
				HTTPVersion: tc.version,
				Positions:   []fuzzHTTPPosition{{Path: "path", Payloads: []string{"/x"}}},
			}
			for _, got := range []struct {
				tool string
				err  error
			}{
				{"resend_http", validateResendHTTPInput(&resend)},
				{"fuzz_http", validateFuzzHTTPInput(&fuzz)},
			} {
				if tc.wantErr == "" {
					if got.err != nil {
						t.Errorf("%s: validate(http_version=%q, scheme=%q) = %v, want nil", got.tool, tc.version, tc.scheme, got.err)
					}
					continue
				}
				if got.err == nil {
					t.Errorf("%s: validate(http_version=%q, scheme=%q) = nil, want error containing %q", got.tool, tc.version, tc.scheme, tc.wantErr)
					continue
				}
				if !strings.Contains(got.err.Error(), tc.wantErr) {
					t.Errorf("%s: validate error = %q, want it to contain %q", got.tool, got.err, tc.wantErr)
				}
			}
		})
	}
}

// saveVersionedHTTPFlow stores a Stream + send Flow in the shape the live
// recorder produces: Stream.Protocol "http", the handshake transport in
// Stream.Scheme, and the producing Layer's wire version on the send Flow
// (internal/layer/httpaggregator stamps "h2"/"h2c", internal/layer/http1
// stamps "http/1.1"). HTTP/2 recordings carry lowercase header names and
// no host header — :authority lives in Flow.URL.
func saveVersionedHTTPFlow(t *testing.T, store flow.Store, rawURL, httpVersion string, headers map[string][]string) string {
	t.Helper()
	ctx := context.Background()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	id := "usk1198-" + uuid.NewString()
	st := &flow.Stream{ID: id, Protocol: "http", Scheme: u.Scheme, State: "complete", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	send := &flow.Flow{
		StreamID:    id,
		Sequence:    0,
		Direction:   "send",
		Timestamp:   time.Now().UTC(),
		Method:      "GET",
		URL:         u,
		Headers:     headers,
		HTTPVersion: httpVersion,
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return id
}

// TestBuildResendHTTPEnvelope_HTTPVersionResolution pins the resolution
// order (explicit http_version → recorded flow version → http/1.1) as it
// lands on the envelope RecordStep records, and that the synthetic Host
// header is injected only on the HTTP/1.1 path (HTTP/2 carries the target
// in :authority, RFC 9113 §8.3.1).
func TestBuildResendHTTPEnvelope_HTTPVersionResolution(t *testing.T) {
	h2Headers := map[string][]string{"user-agent": {"curl/8"}, "accept": {"*/*"}}
	cases := []struct {
		name        string
		flowURL     string // "" = from-scratch
		flowVersion string
		input       resendHTTPInput
		wantVersion string
		wantHost    bool
		wantErr     string
	}{
		{name: "h2_flow_defaults_to_h2", flowURL: "https://example.com/a", flowVersion: "h2", wantVersion: "h2"},
		{name: "h2c_flow_defaults_to_h2c", flowURL: "http://example.com/a", flowVersion: "h2c", wantVersion: "h2c"},
		{name: "h1_flow_stays_http11", flowURL: "https://example.com/a", flowVersion: "http/1.1", wantVersion: "http/1.1", wantHost: true},
		{name: "unversioned_flow_is_http11", flowURL: "https://example.com/a", flowVersion: "", wantVersion: "http/1.1", wantHost: true},
		{name: "h2_flow_explicit_http11", flowURL: "https://example.com/a", flowVersion: "h2", input: resendHTTPInput{HTTPVersion: "http/1.1"}, wantVersion: "http/1.1", wantHost: true},
		{name: "h2_flow_scheme_overridden_to_http_is_h2c", flowURL: "https://example.com/a", flowVersion: "h2", input: resendHTTPInput{Scheme: "http"}, wantVersion: "h2c"},
		{name: "h2c_flow_explicit_h2_rejected", flowURL: "http://example.com/a", flowVersion: "h2c", input: resendHTTPInput{HTTPVersion: "h2"}, wantErr: "h2"},
		{name: "from_scratch_defaults_to_http11", input: resendHTTPInput{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/"}, wantVersion: "http/1.1", wantHost: true},
		{name: "from_scratch_explicit_h2", input: resendHTTPInput{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/", HTTPVersion: "h2"}, wantVersion: "h2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			s := mkServerFromLegacyDeps(legacyDeps{store: store})
			input := tc.input
			if tc.flowURL != "" {
				hdrs := h2Headers
				if tc.wantHost {
					hdrs = map[string][]string{"User-Agent": {"curl/8"}}
				}
				input.FlowID = saveVersionedHTTPFlow(t, store, tc.flowURL, tc.flowVersion, hdrs)
			}
			env, err := s.buildResendHTTPEnvelope(context.Background(), &input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("buildResendHTTPEnvelope = nil error, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("buildResendHTTPEnvelope error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildResendHTTPEnvelope: %v", err)
			}
			msg := env.Message.(*envelope.HTTPMessage)
			if msg.HTTPVersion != tc.wantVersion {
				t.Errorf("msg.HTTPVersion = %q, want %q", msg.HTTPVersion, tc.wantVersion)
			}
			hasHost := false
			for _, kv := range msg.Headers {
				if strings.EqualFold(kv.Name, "host") {
					hasHost = true
				}
			}
			if hasHost != tc.wantHost {
				t.Errorf("host header present = %v, want %v (headers %v)", hasHost, tc.wantHost, msg.Headers)
			}
		})
	}
}

package connector

import (
	"context"
	"strings"
	"testing"
)

// helperResolver builds a RotationResolver with the supplied template
// + policy and returns it for direct testing.
func helperResolver(t *testing.T, template string, policy RotationPolicy) *RotationResolver {
	t.Helper()
	return NewRotationResolver(RotationConfig{
		Template:     template,
		Policy:       policy,
		ListenerName: "test",
	}, 0, 0)
}

// TestRotationResolver_PerRequest_FreshURLPerCall confirms the
// per_request policy mints a fresh URL on every Resolve invocation.
func TestRotationResolver_PerRequest_FreshURLPerCall(t *testing.T) {
	r := helperResolver(t, "http://user-§__nonce§:pass@proxy.example:8080", RotationPerRequest)

	uA, err := r.Resolve(context.Background(), "listener", "example.com:443")
	if err != nil {
		t.Fatalf("Resolve A: %v", err)
	}
	uB, err := r.Resolve(context.Background(), "listener", "example.com:443")
	if err != nil {
		t.Fatalf("Resolve B: %v", err)
	}
	if uA.User.Username() == uB.User.Username() {
		t.Errorf("per_request expected fresh nonce per call, got same %q", uA.User.Username())
	}
}

// TestRotationResolver_PerConnection_SameWithinConnID confirms that
// per_connection caches the URL by ConnID and mints fresh on a new
// ConnID.
func TestRotationResolver_PerConnection_SameWithinConnID(t *testing.T) {
	r := helperResolver(t, "http://user-§__nonce§:pass@proxy.example:8080", RotationPerConnection)

	ctxA := ContextWithConnID(context.Background(), "conn-A")
	ctxB := ContextWithConnID(context.Background(), "conn-B")

	u1, err := r.Resolve(ctxA, "listener", "example.com:443")
	if err != nil {
		t.Fatalf("Resolve A1: %v", err)
	}
	u2, err := r.Resolve(ctxA, "listener", "example.com:443")
	if err != nil {
		t.Fatalf("Resolve A2: %v", err)
	}
	if u1.User.Username() != u2.User.Username() {
		t.Errorf("per_connection expected same nonce within conn-A, got %q vs %q",
			u1.User.Username(), u2.User.Username())
	}
	u3, err := r.Resolve(ctxB, "listener", "example.com:443")
	if err != nil {
		t.Fatalf("Resolve B: %v", err)
	}
	if u3.User.Username() == u1.User.Username() {
		t.Errorf("per_connection expected fresh nonce on new conn-B, got same %q", u3.User.Username())
	}

	// ReleaseConnection drops the conn-A entry; a subsequent Resolve
	// on conn-A then mints fresh.
	r.ReleaseConnection("conn-A")
	u4, err := r.Resolve(ctxA, "listener", "example.com:443")
	if err != nil {
		t.Fatalf("Resolve A3 after release: %v", err)
	}
	if u4.User.Username() == u1.User.Username() {
		t.Errorf("per_connection expected fresh nonce after ReleaseConnection, got same %q", u4.User.Username())
	}
}

// TestRotationResolver_PerTargetHost_SamePerHost confirms that the
// per_target_host cache returns the same URL for a given host and a
// fresh URL for a different host.
func TestRotationResolver_PerTargetHost_SamePerHost(t *testing.T) {
	r := helperResolver(t, "http://user-§__nonce§:pass@proxy.example:8080", RotationPerTargetHost)

	uA1, err := r.Resolve(context.Background(), "listener", "alice.example.com:443")
	if err != nil {
		t.Fatalf("alice 1: %v", err)
	}
	uA2, err := r.Resolve(context.Background(), "listener", "alice.example.com:443")
	if err != nil {
		t.Fatalf("alice 2: %v", err)
	}
	if uA1.User.Username() != uA2.User.Username() {
		t.Errorf("per_target_host: expected same nonce for alice.example.com, got %q vs %q",
			uA1.User.Username(), uA2.User.Username())
	}
	uB, err := r.Resolve(context.Background(), "listener", "bob.example.com:443")
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	if uB.User.Username() == uA1.User.Username() {
		t.Errorf("per_target_host: expected fresh nonce for bob.example.com, got same %q", uB.User.Username())
	}
}

// TestRotationResolver_Sticky_FixedForListenerLifetime confirms that
// sticky mints once and returns the same URL for all subsequent calls.
func TestRotationResolver_Sticky_FixedForListenerLifetime(t *testing.T) {
	r := helperResolver(t, "http://user-§__nonce§:pass@proxy.example:8080", RotationSticky)

	u1, err := r.Resolve(context.Background(), "listener", "example.com:443")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	for i := 0; i < 5; i++ {
		u, err := r.Resolve(context.Background(), "listener", "other.example.com:443")
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if u.User.Username() != u1.User.Username() {
			t.Errorf("sticky: expected same nonce across calls, got %q vs %q",
				u.User.Username(), u1.User.Username())
		}
	}
	// Reset clears sticky; next call mints fresh.
	r.Reset()
	u2, err := r.Resolve(context.Background(), "listener", "example.com:443")
	if err != nil {
		t.Fatalf("post-reset: %v", err)
	}
	if u2.User.Username() == u1.User.Username() {
		t.Errorf("sticky: expected fresh nonce after Reset, got same %q", u2.User.Username())
	}
}

// TestRotationResolver_MalformedTemplate_SurfacesError confirms the
// resolver returns an error for templates that fail parse, scheme, or
// CRLF guards. Caller must fail-closed on this error.
func TestRotationResolver_MalformedTemplate_SurfacesError(t *testing.T) {
	cases := []struct {
		name     string
		template string
	}{
		{"bad-scheme", "ftp://proxy.example:8080"},
		{"missing-port", "http://proxy.example"},
		{"crlf-injection", "http://user\r\nInjected: yes@proxy.example:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := helperResolver(t, tc.template, RotationPerRequest)
			_, err := r.Resolve(context.Background(), "listener", "example.com:443")
			if err == nil {
				t.Fatalf("expected error for template %q", tc.template)
			}
			if !strings.Contains(err.Error(), "upstream_proxy.url_template") {
				t.Errorf("error missing user-facing prefix: %v", err)
			}
		})
	}
}

// TestRotationResolver_FastPathNoDelimiter confirms a template with no
// macro delimiter still parses (the engine treats unknown variables as
// literal). Acts as the "no §" fast-path test required by the
// implementation checklist.
func TestRotationResolver_FastPathNoDelimiter(t *testing.T) {
	r := helperResolver(t, "http://static-user:pass@proxy.example:8080", RotationPerRequest)
	u, err := r.Resolve(context.Background(), "listener", "example.com:443")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if u.User.Username() != "static-user" {
		t.Errorf("username = %q, want static-user", u.User.Username())
	}
}

// TestRedactProxyURL_OnTemplate verifies that RedactProxyURL operates
// on §-template strings verbatim — the user-facing redaction surface
// can call it on a template URL without parsing it (binding decision
// #13). The expected behaviour: a password-bearing template is
// redacted; the §__nonce§ macro is left untouched.
func TestRedactProxyURL_OnTemplate(t *testing.T) {
	in := "http://user-§__nonce§:secret-pass@proxy.example:8080"
	out := RedactProxyURL(in)
	if strings.Contains(out, "secret-pass") {
		t.Errorf("RedactProxyURL did not redact password: %q", out)
	}
	if !strings.Contains(out, "§__nonce§") {
		t.Errorf("RedactProxyURL altered macro: %q", out)
	}
	if !strings.Contains(out, "xxxxx") {
		t.Errorf("RedactProxyURL missing redaction marker: %q", out)
	}
}

// TestRedactProxyURL_NoPasswordMasksWholeUserinfo verifies that
// RedactProxyURL masks the entire userinfo region when no ":password"
// colon is present — a bare token in userinfo (e.g. session id, API
// key) is itself a credential and must not leak to status surfaces
// (CWE-200). Covers both the url.Parse path (plain URL) and the
// lexical fallback (§-template URL).
func TestRedactProxyURL_NoPasswordMasksWholeUserinfo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "url_parse_path_no_colon",
			in:   "http://session-token@proxy.example:8080",
			want: "http://xxxxx@proxy.example:8080",
		},
		{
			name: "lexical_fallback_no_colon",
			in:   "http://session-§__nonce§@proxy.example:8080",
			want: "http://xxxxx@proxy.example:8080",
		},
		{
			name: "lexical_fallback_with_colon_preserves_username",
			in:   "http://user-§__nonce§:secret@proxy.example:8080",
			want: "http://user-§__nonce§:xxxxx@proxy.example:8080",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactProxyURL(tc.in)
			if got != tc.want {
				t.Errorf("RedactProxyURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Contains(got, "session-token") || strings.Contains(got, "secret") {
				t.Errorf("RedactProxyURL leaked credential: %q", got)
			}
		})
	}
}

// TestRotationResolver_NilReturnsNil confirms the nil-receiver branch
// returns (nil, nil) so callers can safely Resolve on a missing
// resolver without nil panics.
func TestRotationResolver_NilReturnsNil(t *testing.T) {
	var r *RotationResolver
	u, err := r.Resolve(context.Background(), "listener", "example.com:443")
	if err != nil {
		t.Fatalf("nil resolver should not error: %v", err)
	}
	if u != nil {
		t.Errorf("nil resolver should return nil URL, got %v", u)
	}
}

// TestBuildConfigEffectiveUpstreamProxyForCtxErr_ResolverWins verifies
// the per-listener RotationResolver takes precedence over the
// per-listener static URL slot in EffectiveUpstreamProxyForCtxErr.
func TestBuildConfigEffectiveUpstreamProxyForCtxErr_ResolverWins(t *testing.T) {
	cfg := &BuildConfig{}
	staticURL, _ := ParseUpstreamProxy("http://static.example:9999")
	cfg.SetUpstreamProxyForListener("L1", staticURL)
	cfg.SetRotationForListener("L1", helperResolver(t,
		"http://session-§__nonce§:pass@rotating.example:8080", RotationPerRequest))

	ctx := ContextWithListenerName(context.Background(), "L1")
	u, err := cfg.EffectiveUpstreamProxyForCtxErr(ctx)
	if err != nil {
		t.Fatalf("EffectiveUpstreamProxyForCtxErr: %v", err)
	}
	if u == nil {
		t.Fatalf("expected resolved URL, got nil")
	}
	if u.Host != "rotating.example:8080" {
		t.Errorf("resolver did not win: host=%q want rotating.example:8080", u.Host)
	}
}

// TestBuildConfigEffectiveUpstreamProxyForCtxErr_CtxOverrideWins
// verifies ctx-attached overrides still beat per-listener resolvers
// (resolver should not run when a ctx override is present).
func TestBuildConfigEffectiveUpstreamProxyForCtxErr_CtxOverrideWins(t *testing.T) {
	cfg := &BuildConfig{}
	cfg.SetRotationForListener("L1", helperResolver(t,
		"http://session-§__nonce§:pass@rotating.example:8080", RotationPerRequest))

	override, _ := ParseUpstreamProxy("http://override.example:7777")
	ctx := ContextWithListenerName(context.Background(), "L1")
	ctx = ContextWithUpstreamProxyOverride(ctx, override)

	u, err := cfg.EffectiveUpstreamProxyForCtxErr(ctx)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if u == nil || u.Host != "override.example:7777" {
		t.Errorf("ctx override did not win: got %v", u)
	}
}

// TestRotationH2PoolKeyInvalidation_PerRequestProducesDistinctKeys
// verifies poolKeyForH2 hashes the resolved upstream-proxy URL so
// per_request rotation forces a fresh pool key per dial (USK-959
// implementation checklist item: H2 pool already correct via URL
// hash; no explicit eviction). Pool keys are stable functions of the
// EffectiveUpstreamProxyForCtx output, so the keyspace fragments
// automatically when the resolver mints fresh URLs.
func TestRotationH2PoolKeyInvalidation_PerRequestProducesDistinctKeys(t *testing.T) {
	cfg := &BuildConfig{}
	cfg.SetRotationForListener("L1", helperResolver(t,
		"http://session-§__nonce§:pass@proxy.example:8080", RotationPerRequest))

	ctx := ContextWithListenerName(context.Background(), "L1")
	hostTLS := &resolvedTLS{}

	keyA := poolKeyForH2(ctx, "example.com:443", cfg, hostTLS)
	keyB := poolKeyForH2(ctx, "example.com:443", cfg, hostTLS)
	if keyA == keyB {
		t.Errorf("per_request rotation: expected distinct pool keys, got identical %v", keyA)
	}
}

// TestRotationH2PoolKeyInvalidation_StickyProducesStableKey verifies
// that sticky rotation produces the same pool key across dials (the
// resolver returns the same URL → same hash → pool reuse remains
// possible).
func TestRotationH2PoolKeyInvalidation_StickyProducesStableKey(t *testing.T) {
	cfg := &BuildConfig{}
	cfg.SetRotationForListener("L1", helperResolver(t,
		"http://session-§__nonce§:pass@proxy.example:8080", RotationSticky))

	ctx := ContextWithListenerName(context.Background(), "L1")
	hostTLS := &resolvedTLS{}

	keyA := poolKeyForH2(ctx, "example.com:443", cfg, hostTLS)
	keyB := poolKeyForH2(ctx, "example.com:443", cfg, hostTLS)
	if keyA != keyB {
		t.Errorf("sticky rotation: expected identical pool keys, got %v vs %v", keyA, keyB)
	}
}

// TestBuildConfigReleaseConnectionState_DropsPerConn confirms that
// BuildConfig.ReleaseConnectionState propagates to per-listener
// resolvers and drops the per_connection entry.
func TestBuildConfigReleaseConnectionState_DropsPerConn(t *testing.T) {
	cfg := &BuildConfig{}
	r := helperResolver(t, "http://session-§__nonce§:pass@proxy.example:8080", RotationPerConnection)
	cfg.SetRotationForListener("L1", r)

	ctx := ContextWithListenerName(context.Background(), "L1")
	ctx = ContextWithConnID(ctx, "conn-X")

	u1, err := cfg.EffectiveUpstreamProxyForCtxErr(ctx)
	if err != nil {
		t.Fatalf("resolve 1: %v", err)
	}
	cfg.ReleaseConnectionState("conn-X")
	u2, err := cfg.EffectiveUpstreamProxyForCtxErr(ctx)
	if err != nil {
		t.Fatalf("resolve 2: %v", err)
	}
	if u1.User.Username() == u2.User.Username() {
		t.Errorf("expected fresh nonce after ReleaseConnectionState, got same %q", u1.User.Username())
	}
}

package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-858: client-side TLS MITM handshake failures (browser→proxy cert
// rejection, e.g. Chromium pinning) must be classified as
// FailureReason="client_tls_error" rather than the existing
// "upstream_tls_error" so MCP query consumers can tell the two
// directions apart at a glance. The recorder branches on
// errors.Is(buildErr, connector.ErrClientTLSMITMHandshake).
//
// These tests are the symmetric mirror of
// upstream_tls_error_recorder_test.go — anything they exercise on the
// client-side path must remain congruent with that file's invariants
// for the upstream path so the two branches do not drift.

// wrapClientMITMHandshakeErr returns an error chain matching the
// production wrap at internal/connector/stack_builder.go (the version
// with `for <target>` plus the underlying tlslayer.Server error).
// Centralising the wrap in one helper keeps the tests asserting on the
// real error shape rather than a hand-constructed approximation.
func wrapClientMITMHandshakeErr(target string, inner error) error {
	return fmt.Errorf("%w for %s: %w", connector.ErrClientTLSMITMHandshake, target, inner)
}

// TestBuildTLSStackBuildErrorRecorder_ClientSide_HappyPath verifies the
// recorder writes a state="error" Stream with
// FailureReason="client_tls_error" when the build error is wrapped with
// connector.ErrClientTLSMITMHandshake. All other fields mirror the
// USK-784 upstream-side contract (Protocol, Scheme, ConnInfo, Tags).
func TestBuildTLSStackBuildErrorRecorder_ClientSide_HappyPath(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildTLSStackBuildErrorRecorder(store, nil, "live", silentLogger())
	if rec == nil {
		t.Fatal("expected non-nil recorder")
	}

	ctx := connector.ContextWithConnID(context.Background(), "conn-858")
	ctx = connector.ContextWithClientAddr(ctx, "127.0.0.1:54321")

	target := "pinned.example.test:443"
	inner := errors.New("tlslayer: server handshake: remote error: tls: unknown certificate")
	buildErr := wrapClientMITMHandshakeErr(target, inner)

	rec(ctx, target, buildErr)

	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1", got)
	}
	st := store.saved[0]

	if st.State != "error" {
		t.Errorf("Stream.State = %q, want %q", st.State, "error")
	}
	if st.Protocol != string(envelope.ProtocolHTTP) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, envelope.ProtocolHTTP)
	}
	if st.Scheme != "https" {
		t.Errorf("Stream.Scheme = %q, want %q", st.Scheme, "https")
	}
	if st.FailureReason != "client_tls_error" {
		t.Errorf("Stream.FailureReason = %q, want %q",
			st.FailureReason, "client_tls_error")
	}
	if st.ConnID != "conn-858" {
		t.Errorf("Stream.ConnID = %q, want %q", st.ConnID, "conn-858")
	}
	if st.ConnInfo == nil {
		t.Fatal("Stream.ConnInfo is nil; want non-nil with target / client addr")
	}
	if st.ConnInfo.ServerAddr != target {
		t.Errorf("Stream.ConnInfo.ServerAddr = %q, want %q",
			st.ConnInfo.ServerAddr, target)
	}
	if st.ConnInfo.ClientAddr != "127.0.0.1:54321" {
		t.Errorf("Stream.ConnInfo.ClientAddr = %q, want %q",
			st.ConnInfo.ClientAddr, "127.0.0.1:54321")
	}
	if st.Tags == nil {
		t.Fatal("Stream.Tags is nil; want non-nil with target + error")
	}
	if st.Tags["target"] != target {
		t.Errorf("Stream.Tags[target] = %q, want %q",
			st.Tags["target"], target)
	}
	// Tags["error"] must surface the full wrapped string so MCP users
	// can grep for "unknown certificate" / pinning / unknown_ca etc.
	// without parsing FailureReason.
	if st.Tags["error"] == "" {
		t.Errorf("Stream.Tags[error] is empty; want underlying error message")
	}
	if !errors.Is(buildErr, connector.ErrClientTLSMITMHandshake) {
		t.Errorf("sanity: errors.Is(buildErr, ErrClientTLSMITMHandshake) = false; want true")
	}
}

// TestBuildTLSStackBuildErrorRecorder_ClientSideWithoutTarget_HappyPath
// covers the second wrap site in stack_builder.go (the form without `for
// <target>` — used inside performClientMITM at :1181). Both wrap shapes
// must classify as client_tls_error.
func TestBuildTLSStackBuildErrorRecorder_ClientSideWithoutTarget_HappyPath(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildTLSStackBuildErrorRecorder(store, nil, "live", silentLogger())

	target := "pinned.example.test:443"
	inner := errors.New("remote error: tls: unknown certificate")
	// Mirrors the :1181 wrap shape: %w: %w (no target embedded).
	buildErr := fmt.Errorf("%w: %w", connector.ErrClientTLSMITMHandshake, inner)

	rec(context.Background(), target, buildErr)

	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1", got)
	}
	if got := store.saved[0].FailureReason; got != "client_tls_error" {
		t.Errorf("FailureReason = %q, want %q", got, "client_tls_error")
	}
	if !errors.Is(buildErr, connector.ErrClientTLSMITMHandshake) {
		t.Errorf("errors.Is sentinel match failed for the :1181 wrap shape")
	}
}

// TestBuildTLSStackBuildErrorRecorder_UpstreamSide_Preserved is the
// regression guard: an error NOT wrapped with ErrClientTLSMITMHandshake
// (the upstream TLS handshake failure case) must still classify as
// "upstream_tls_error". The branching introduced for USK-858 must not
// disturb the existing USK-784 contract.
func TestBuildTLSStackBuildErrorRecorder_UpstreamSide_Preserved(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildTLSStackBuildErrorRecorder(store, nil, "live", silentLogger())

	target := "expired.example.test:443"
	// Production wrap site for upstream dial — see
	// internal/connector/stack_builder.go dialUpstreamWithALPN. No
	// ErrClientTLSMITMHandshake in this chain.
	buildErr := fmt.Errorf("connector: upstream dial for %s: %w", target,
		errors.New("tls: failed to verify certificate: x509: certificate has expired or is not yet valid"))

	rec(context.Background(), target, buildErr)

	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1", got)
	}
	if got := store.saved[0].FailureReason; got != "upstream_tls_error" {
		t.Errorf("FailureReason = %q, want %q (upstream path must not regress)",
			got, "upstream_tls_error")
	}
	if errors.Is(buildErr, connector.ErrClientTLSMITMHandshake) {
		t.Errorf("sanity: upstream-side error must NOT match ErrClientTLSMITMHandshake")
	}
}

// TestBuildTLSStackBuildErrorRecorder_ClientSide_AuthorityVerbatim asserts
// the CONNECT authority is preserved exactly as observed when the
// client-side branch fires (CLAUDE.md MITM Principle #1). Mirrors the
// upstream-side TestBuildUpstreamTLSErrorRecorder_AuthorityVerbatim.
func TestBuildTLSStackBuildErrorRecorder_ClientSide_AuthorityVerbatim(t *testing.T) {
	cases := []string{
		"Example.COM:443",
		"127.0.0.1:8443",
		"[::1]:443",
		"www-host.tld:65535",
		"trailing.example.com:80",
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			store := &recordingFlowStore{}
			rec := buildTLSStackBuildErrorRecorder(store, nil, "live", silentLogger())
			buildErr := wrapClientMITMHandshakeErr(target, errors.New("err"))
			rec(context.Background(), target, buildErr)
			if got := len(store.saved); got != 1 {
				t.Fatalf("SaveStream count = %d, want 1", got)
			}
			st := store.saved[0]
			if st.Tags["target"] != target {
				t.Errorf("Tags[target] = %q, want %q (verbatim)", st.Tags["target"], target)
			}
			if st.ConnInfo.ServerAddr != target {
				t.Errorf("ConnInfo.ServerAddr = %q, want %q (verbatim)",
					st.ConnInfo.ServerAddr, target)
			}
			if st.FailureReason != "client_tls_error" {
				t.Errorf("FailureReason = %q, want %q",
					st.FailureReason, "client_tls_error")
			}
		})
	}
}

// TestBuildTLSStackBuildErrorRecorder_ClientSide_OutOfScope_NotRecorded
// mirrors the USK-791 scope semantics for the client-side path: an
// out-of-scope host's client-rejection failure is dropped at slog.Debug.
// Hostname matchers operate on the synthetic envelope's TargetHost just
// like the upstream-side branch.
func TestBuildTLSStackBuildErrorRecorder_ClientSide_OutOfScope_NotRecorded(t *testing.T) {
	store := &recordingFlowStore{}
	scope := flow.NewRecordScope()
	scope.SetRules([]flow.ScopeRule{{Hostname: "httpbin.org"}}, nil)

	rec := buildTLSStackBuildErrorRecorder(store, scope, "live", silentLogger())
	if rec == nil {
		t.Fatal("expected non-nil recorder")
	}

	buildErr := wrapClientMITMHandshakeErr("accounts.google.com:443",
		errors.New("remote error: tls: unknown certificate"))

	rec(context.Background(), "accounts.google.com:443", buildErr)

	if got := len(store.saved); got != 0 {
		t.Fatalf("SaveStream count = %d, want 0 (out-of-scope client_tls_error must not record); saved=%+v",
			got, store.saved)
	}
}

// TestBuildTLSStackBuildErrorRecorder_ClientSide_InScope_Recorded asserts
// the converse: an in-scope host's client-rejection failure is recorded
// with FailureReason="client_tls_error" — the USK-858 acceptance
// criterion under USK-791-style capture_scope filtering.
func TestBuildTLSStackBuildErrorRecorder_ClientSide_InScope_Recorded(t *testing.T) {
	store := &recordingFlowStore{}
	scope := flow.NewRecordScope()
	scope.SetRules([]flow.ScopeRule{{Hostname: "httpbin.org"}}, nil)

	rec := buildTLSStackBuildErrorRecorder(store, scope, "live", silentLogger())

	buildErr := wrapClientMITMHandshakeErr("httpbin.org:443",
		errors.New("remote error: tls: unknown certificate"))

	rec(context.Background(), "httpbin.org:443", buildErr)

	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1 (in-scope host must record)", got)
	}
	st := store.saved[0]
	if st.FailureReason != "client_tls_error" {
		t.Errorf("FailureReason = %q, want %q", st.FailureReason, "client_tls_error")
	}
	if st.Tags == nil || st.Tags["target"] != "httpbin.org:443" {
		t.Errorf("Tags[target] = %q, want %q", st.Tags["target"], "httpbin.org:443")
	}
}

// TestBuildTLSStackBuildErrorRecorder_ClientSide_NoConnID_GeneratesFallback
// verifies the same ConnID-fallback semantics apply to the client-side
// path: an empty ConnIDFromContext yields a freshly-generated UUID so
// the audit row is never written with an empty ConnID.
func TestBuildTLSStackBuildErrorRecorder_ClientSide_NoConnID_GeneratesFallback(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildTLSStackBuildErrorRecorder(store, nil, "live", silentLogger())

	buildErr := wrapClientMITMHandshakeErr("example.com:443", errors.New("err"))
	rec(context.Background(), "example.com:443", buildErr)

	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1", got)
	}
	if store.saved[0].ConnID == "" {
		t.Error("Stream.ConnID is empty; want fallback UUID")
	}
}

package proxybuild

import (
	"context"
	"errors"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestBuildUpstreamTLSErrorRecorder_NilStore verifies the recorder returns
// nil when no flow.Writer is configured, preserving the silent-drop
// fallback path consistent with buildProtocolRejectedRecorder /
// buildPipelineDropRecorder.
func TestBuildUpstreamTLSErrorRecorder_NilStore(t *testing.T) {
	rec := buildUpstreamTLSErrorRecorder(nil, "test", silentLogger())
	if rec != nil {
		t.Fatal("expected nil callback when store is nil")
	}
}

// TestBuildUpstreamTLSErrorRecorder_HappyPath verifies the recorder writes
// a state="error" Stream with the CONNECT authority preserved in
// Tags["target"], the underlying error in Tags["error"], the canonical
// HTTPS surface (Protocol="http", Scheme="https"), and FailureReason set
// to the new "upstream_tls_error" classification.
func TestBuildUpstreamTLSErrorRecorder_HappyPath(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildUpstreamTLSErrorRecorder(store, "live", silentLogger())
	if rec == nil {
		t.Fatal("expected non-nil recorder")
	}

	ctx := connector.ContextWithConnID(context.Background(), "conn-784")
	ctx = connector.ContextWithClientAddr(ctx, "127.0.0.1:54321")

	target := "expired.example.test:443"
	upstreamErr := errors.New("connector: upstream dial for " + target +
		": tls: failed to verify certificate: x509: certificate has expired or is not yet valid")

	rec(ctx, target, upstreamErr)

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
	if st.FailureReason != "upstream_tls_error" {
		t.Errorf("Stream.FailureReason = %q, want %q",
			st.FailureReason, "upstream_tls_error")
	}
	if st.ConnID != "conn-784" {
		t.Errorf("Stream.ConnID = %q, want %q", st.ConnID, "conn-784")
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
	if st.Tags["error"] == "" {
		t.Errorf("Stream.Tags[error] is empty; want underlying error message")
	}
	if st.ID == "" {
		t.Error("Stream.ID is empty; want generated UUID")
	}
}

// TestBuildUpstreamTLSErrorRecorder_NilError_NoOp verifies the recorder
// silently ignores a callback fired with a nil error. There is no
// production caller that does this, but the guard is cheap insurance
// against future refactors.
func TestBuildUpstreamTLSErrorRecorder_NilError_NoOp(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildUpstreamTLSErrorRecorder(store, "live", silentLogger())
	rec(context.Background(), "example.com:443", nil)
	if got := len(store.saved); got != 0 {
		t.Errorf("SaveStream count = %d, want 0 (nil error ignored)", got)
	}
}

// TestBuildUpstreamTLSErrorRecorder_NoConnID_GeneratesFallback verifies
// that when the context does not carry a ConnID (test or non-listener
// path), the recorder falls back to a freshly-generated UUID rather than
// writing an empty ConnID. Mirrors the same defence in
// buildProtocolRejectedRecorder.
func TestBuildUpstreamTLSErrorRecorder_NoConnID_GeneratesFallback(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildUpstreamTLSErrorRecorder(store, "live", silentLogger())
	rec(context.Background(), "example.com:443", errors.New("test error"))
	if got := len(store.saved); got != 1 {
		t.Fatalf("SaveStream count = %d, want 1", got)
	}
	if store.saved[0].ConnID == "" {
		t.Error("Stream.ConnID is empty; want fallback UUID")
	}
}

// TestBuildUpstreamTLSErrorRecorder_AuthorityVerbatim asserts the CONNECT
// authority is preserved exactly as observed — no normalization,
// lowercasing, or port stripping (CLAUDE.md MITM Principle #1).
func TestBuildUpstreamTLSErrorRecorder_AuthorityVerbatim(t *testing.T) {
	cases := []string{
		"Example.COM:443",         // mixed case host
		"127.0.0.1:8443",          // ipv4
		"[::1]:443",               // ipv6 bracketed
		"www-host.tld:65535",      // hostname + max port
		"trailing.example.com:80", // non-default port
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			store := &recordingFlowStore{}
			rec := buildUpstreamTLSErrorRecorder(store, "live", silentLogger())
			rec(context.Background(), target, errors.New("err"))
			if got := len(store.saved); got != 1 {
				t.Fatalf("SaveStream count = %d, want 1", got)
			}
			if got := store.saved[0].Tags["target"]; got != target {
				t.Errorf("Tags[target] = %q, want %q (verbatim)", got, target)
			}
			if got := store.saved[0].ConnInfo.ServerAddr; got != target {
				t.Errorf("ConnInfo.ServerAddr = %q, want %q (verbatim)",
					got, target)
			}
		})
	}
}

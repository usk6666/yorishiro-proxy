package connector

import (
	"context"
	"strings"
	"testing"
)

// These guards lock RedialUpstreamH1's defensive preconditions so callers
// surface a structured error instead of silently nil-dereferencing.

// TestRedialUpstreamH1_NilCfg locks the defensive guard so callers never
// silently dial with a half-built BuildConfig.
func TestRedialUpstreamH1_NilCfg(t *testing.T) {
	_, err := RedialUpstreamH1(context.Background(), "example.com:443", nil, nil, 1)
	if err == nil {
		t.Fatal("RedialUpstreamH1(nil cfg, nil stale): got nil err, want guard message")
	}
	// nil stale check would also fire before reaching the dial — accept
	// either guard message as long as the helper bailed out cleanly.
	if !strings.Contains(err.Error(), "RedialUpstreamH1") {
		t.Errorf("RedialUpstreamH1: error %q should mention RedialUpstreamH1 helper name", err.Error())
	}
}

// TestRedialUpstreamH1_NilStale locks the second defensive guard. The
// stale Layer is the source of the EnvelopeContext template, so a nil
// stale would otherwise nil-dereference inside the helper.
func TestRedialUpstreamH1_NilStale(t *testing.T) {
	cfg := &BuildConfig{}
	_, err := RedialUpstreamH1(context.Background(), "example.com:443", nil, cfg, 1)
	if err == nil {
		t.Fatal("RedialUpstreamH1(non-nil cfg, nil stale): got nil err, want guard message")
	}
	if !strings.Contains(err.Error(), "stale is nil") {
		t.Errorf("RedialUpstreamH1: error %q should mention 'stale is nil'", err.Error())
	}
}

// TestExtractHost_EmptyReturnsEmpty locks the upstream contract that
// RedialUpstreamH1 relies on: an empty target string yields an empty
// host, which RedialUpstreamH1 then surfaces as a structured
// `invalid target %q` error rather than reaching the dial. Reaching
// RedialUpstreamH1's target-check branch directly requires a non-nil
// stale Layer (constructed over a live conn), which is exercised by the
// e2e integration test; this unit guard checks the helper boundary only.
func TestExtractHost_EmptyReturnsEmpty(t *testing.T) {
	if got := extractHost(""); got != "" {
		t.Errorf("extractHost(\"\") = %q, want empty (so RedialUpstreamH1 surfaces invalid target)", got)
	}
}

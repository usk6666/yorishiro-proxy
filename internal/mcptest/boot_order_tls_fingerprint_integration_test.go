//go:build e2e

// Package mcptest_test holds USK-727's regression for the USK-719
// boot-order class: -tls-fingerprint=chrome (and proxy.json's
// tls_fingerprint) must be honored at server startup so that resend_*
// tools picked up by the WebUI / AI agent before any proxy_start call
// dial uTLS — not the standard Go crypto/tls client.
//
// History: PR #712 fixed an inconsistency where proxyCfg.TLSFingerprint
// was only copied into the runtime via resetSettingsToDefaults, which
// itself only ran inside proxy_start. Calling resend_http directly
// without first calling proxy_start would therefore use the standard
// transport — silently defeating the operator's chosen profile. The
// fix landed without a regression test; this file is that regression
// test.
//
// What this test asserts:
//
//   - The proxy server boots with -tls-fingerprint=chrome.
//   - resend_http is invoked DIRECTLY, with no proxy_start call (and
//     PreStartTools left empty so the harness does not auto-fire one).
//   - The upstream test server, observing the ClientHello via
//     GetConfigForClient, reports a uTLS-flavored ClientHello (presence
//     of GREASE values per RFC 8701 — Go's crypto/tls does not emit
//     these).
//
// Reverting PR #712 locally must make this test FAIL — that is the
// gating verification for "this catches the regression class".
package mcptest_test

import (
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_BootOrder_ResendBeforeProxyStart_AppliesTLSFingerprint is the
// USK-719 regression: starting the server with -tls-fingerprint=chrome
// must honor the profile when resend_http is invoked before proxy_start.
//
// The test deliberately does not invoke proxy_start (no direct call,
// empty PreStartTools) so the resetSettingsToDefaults short-circuit
// that the original bug relied on never runs. If TLSFingerprint had to
// transit through proxy_start to take effect, the upstream would
// observe a vanilla Go ClientHello (no GREASE) and the assertion would
// fail.
func TestE2E_BootOrder_ResendBeforeProxyStart_AppliesTLSFingerprint(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		TLSFingerprint: "chrome",
		UpstreamProto:  "http/1.1",
		// PreStartTools intentionally empty — the regression hinges on
		// the server NOT having gone through proxy_start before resend
		// runs. Adding any tool here would mask the bug class.
	})

	if h.UpstreamFingerprint == nil {
		t.Fatal("UpstreamFingerprint observer is nil; harness wiring regressed")
	}

	// Sanity: the upstream is HTTPS via httptest.NewUnstartedServer +
	// StartTLS, so the URL is https://host:port. Trim the scheme so the
	// authority lands in resend_http's authority field.
	upstreamURL := h.UpstreamTLS.URL
	authority := strings.TrimPrefix(upstreamURL, "https://")
	if authority == upstreamURL {
		t.Fatalf("upstream URL = %q, expected https:// scheme", upstreamURL)
	}

	// Drive resend_http with no flow_id (from-scratch path). The
	// harness boots with -insecure so the upstream's self-signed leaf
	// cert is accepted; the assertion below pins the proof to the
	// ClientHello itself, not certificate validation.
	res := h.MustOK(t, "resend_http", map[string]any{
		"method":    "GET",
		"scheme":    "https",
		"authority": authority,
		"path":      "/",
	})
	if res.IsError {
		t.Fatalf("resend_http returned IsError=true: %s", res.Text)
	}

	// The load-bearing assertion: GREASE values in the ClientHello
	// cipher_suites prove a uTLS-style client made the handshake. If
	// USK-719 regresses, this returns "standard" instead.
	got := h.UpstreamFingerprint.LastObservedFingerprint()
	if got != "utls" {
		t.Fatalf("UpstreamFingerprint.LastObservedFingerprint() = %q, want %q "+
			"(USK-719 regression: -tls-fingerprint=chrome did not apply at startup, "+
			"so resend_http dialed without uTLS even though the operator configured it)",
			got, "utls")
	}
}

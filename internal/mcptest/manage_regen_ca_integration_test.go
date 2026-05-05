//go:build e2e

package mcptest_test

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_Manage_RegenerateCACert_RotatesPEM exercises scenario #18
// (latter half): query the bootstrap CA cert, regenerate it via the
// manage tool, and assert a fresh PEM is observed afterwards. The
// previous PEM must NOT match the post-regenerate PEM (regenerate is
// not idempotent on key material).
//
// We also assert that the new certificate's NotBefore is at or after
// the original's so future trust-store install hints reference fresh
// validity windows.
//
// What this test catches:
//   - A no-op regenerate that returns the cached cert.
//   - PEM corruption or empty cert in the regenerate response.
//   - Persistence-mode confusion (the harness uses ephemeral CA, so the
//     regenerate must succeed without complaining about explicit-CA mode).
func TestE2E_Manage_RegenerateCACert_RotatesPEM(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	// --- (1) Capture initial CA cert ---
	beforeRes := h.MustOK(t, "query", map[string]any{"resource": "ca_cert"})
	beforePEM, _ := beforeRes.Decoded["pem"].(string)
	beforeFP, _ := beforeRes.Decoded["fingerprint"].(string)
	if beforePEM == "" {
		t.Fatalf("query ca_cert: empty PEM in response: %+v", beforeRes.Decoded)
	}
	if beforeFP == "" {
		t.Fatalf("query ca_cert: empty fingerprint in response: %+v", beforeRes.Decoded)
	}
	beforeCert := mustParseCertPEM(t, beforePEM)

	// --- (2) Regenerate via manage tool ---
	regenRes := h.MustOK(t, "manage", map[string]any{
		"action": "regenerate_ca_cert",
		"params": map[string]any{},
	})
	regenFP, _ := regenRes.Decoded["fingerprint"].(string)
	if regenFP == "" {
		t.Fatalf("manage regenerate_ca_cert: missing fingerprint: %+v", regenRes.Decoded)
	}
	if regenFP == beforeFP {
		t.Errorf("manage regenerate_ca_cert: fingerprint did not change (%q); regenerate must produce fresh key material", regenFP)
	}
	// Persisted is false in ephemeral mode (the harness uses
	// -ca-ephemeral). Validate the response shape says so.
	if persisted, _ := regenRes.Decoded["persisted"].(bool); persisted {
		t.Errorf("manage regenerate_ca_cert: persisted = true, want false (harness is ephemeral)")
	}
	if hint, _ := regenRes.Decoded["install_hint"].(string); !strings.Contains(strings.ToLower(hint), "memory") {
		t.Errorf("manage regenerate_ca_cert: install_hint = %q, want a memory-mode reference", hint)
	}

	// --- (3) Re-query CA cert; PEM must differ from before ---
	afterRes := h.MustOK(t, "query", map[string]any{"resource": "ca_cert"})
	afterPEM, _ := afterRes.Decoded["pem"].(string)
	afterFP, _ := afterRes.Decoded["fingerprint"].(string)
	if afterPEM == "" {
		t.Fatalf("query ca_cert (after): empty PEM")
	}
	if afterPEM == beforePEM {
		t.Errorf("CA PEM did not rotate: before == after\nbefore=%q\nafter=%q", beforePEM, afterPEM)
	}
	if afterFP == beforeFP {
		t.Errorf("CA fingerprint did not rotate: before=%q after=%q", beforeFP, afterFP)
	}
	if afterFP != regenFP {
		t.Errorf("query/manage fingerprint mismatch: query=%q manage=%q", afterFP, regenFP)
	}

	afterCert := mustParseCertPEM(t, afterPEM)

	// NotBefore on the regenerated cert must be at or after the
	// original. This catches a pure-stub implementation that returns
	// the same in-memory CA on every call.
	if afterCert.NotBefore.Before(beforeCert.NotBefore) {
		t.Errorf("regenerated cert NotBefore (%s) is BEFORE original (%s)",
			afterCert.NotBefore, beforeCert.NotBefore)
	}

	// Subject is a distinguished name; for ephemeral CAs the project
	// emits a subject containing "yorishiro" — assert it appears so a
	// regression that swaps to an empty subject is caught.
	if !strings.Contains(strings.ToLower(afterCert.Subject.String()), "yorishiro") {
		t.Errorf("regenerated cert subject = %q, want to contain 'yorishiro'", afterCert.Subject.String())
	}

	// --- (4) New connections after regenerate use the new cert ---
	// We do not try to validate that a previously-established TLS
	// session somehow upgrades — that is a product question outside
	// this Issue's scope. We just confirm the proxy is still
	// queryable, which means the regenerate did not panic the server.
	statusRes := h.MustOK(t, "query", map[string]any{"resource": "status"})
	if statusRes.Decoded == nil {
		t.Errorf("query status returned empty decoded map after regenerate")
	}
}

// mustParseCertPEM decodes a PEM block and parses the contained x509
// certificate. Fatals on any error.
func mustParseCertPEM(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatalf("PEM decode failed for %q", pemStr)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

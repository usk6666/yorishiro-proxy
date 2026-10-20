package mcp

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// TestRedactMatchedFragment verifies that the safety-filter matched fragment is
// never emitted in clear text (CWE-312 / go/clear-text-logging) while remaining
// stable enough for cross-log correlation.
func TestRedactMatchedFragment(t *testing.T) {
	t.Run("empty stays empty", func(t *testing.T) {
		if got := redactMatchedFragment(""); got != "" {
			t.Errorf("redactMatchedFragment(\"\") = %q, want \"\"", got)
		}
	})

	t.Run("sensitive fragment is not echoed verbatim", func(t *testing.T) {
		secret := "Bearer sk-live-supersecrettoken"
		got := redactMatchedFragment(secret)
		if strings.Contains(got, secret) {
			t.Fatalf("redacted output %q leaks the raw fragment", got)
		}
		if !strings.HasPrefix(got, "hmac:") {
			t.Errorf("redacted output %q does not start with hmac:", got)
		}
		if !strings.Contains(got, fmt.Sprintf("len=%d", len(secret))) {
			t.Errorf("redacted output %q missing byte length", got)
		}
	})

	// USK-1109 review S-2: the digest is keyed per process (HMAC-SHA256),
	// so it is stable within the process but must NOT equal the unkeyed
	// SHA-256 prefix an attacker could brute-force offline.
	t.Run("digest is deterministic and keyed", func(t *testing.T) {
		frag := "DROP TABLE users"
		got := redactMatchedFragment(frag)
		if again := redactMatchedFragment(frag); again != got {
			t.Errorf("redactMatchedFragment(%q) not stable: %q vs %q", frag, got, again)
		}
		sum := sha256.Sum256([]byte(frag))
		if unkeyed := fmt.Sprintf("%x", sum[:8]); strings.Contains(got, unkeyed) {
			t.Errorf("redactMatchedFragment(%q) = %q exposes the unkeyed SHA-256 prefix %s", frag, got, unkeyed)
		}
		if !strings.HasSuffix(got, fmt.Sprintf(" len=%d", len(frag))) {
			t.Errorf("redactMatchedFragment(%q) = %q, want len=%d suffix", frag, got, len(frag))
		}
	})

	t.Run("distinct fragments produce distinct digests", func(t *testing.T) {
		if redactMatchedFragment("a") == redactMatchedFragment("b") {
			t.Error("distinct fragments produced identical digests")
		}
	})
}

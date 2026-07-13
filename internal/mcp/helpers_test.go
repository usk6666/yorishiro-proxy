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
		if !strings.HasPrefix(got, "sha256:") {
			t.Errorf("redacted output %q does not start with sha256:", got)
		}
		if !strings.Contains(got, fmt.Sprintf("len=%d", len(secret))) {
			t.Errorf("redacted output %q missing byte length", got)
		}
	})

	t.Run("digest is deterministic and matches SHA-256 prefix", func(t *testing.T) {
		frag := "DROP TABLE users"
		sum := sha256.Sum256([]byte(frag))
		want := fmt.Sprintf("sha256:%x len=%d", sum[:8], len(frag))
		if got := redactMatchedFragment(frag); got != want {
			t.Errorf("redactMatchedFragment(%q) = %q, want %q", frag, got, want)
		}
	})

	t.Run("distinct fragments produce distinct digests", func(t *testing.T) {
		if redactMatchedFragment("a") == redactMatchedFragment("b") {
			t.Error("distinct fragments produced identical digests")
		}
	})
}

package safety

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// USK-1109 review S-2 (CWE-759 / CWE-532): the log digest must be keyed,
// so a low-entropy match (card number, phone number, My Number) cannot be
// recovered offline by hashing candidates. Same fragment, same process →
// same digest (correlation keeps working).
func TestRedactFragment_KeyedDigest(t *testing.T) {
	const frag = "4111-1111-1111-1111"

	got := RedactFragment(frag)
	sum := sha256.Sum256([]byte(frag))
	unsalted := fmt.Sprintf("%x", sum[:8])
	if strings.Contains(got, unsalted) {
		t.Errorf("RedactFragment(%q) = %q contains the unkeyed SHA-256 prefix %s (offline brute-force possible)", frag, got, unsalted)
	}
	if !strings.HasPrefix(got, "hmac:") {
		t.Errorf("RedactFragment(%q) = %q, want an hmac: prefix", frag, got)
	}
	if !strings.HasSuffix(got, fmt.Sprintf(" len=%d", len(frag))) {
		t.Errorf("RedactFragment(%q) = %q, want a len=%d suffix", frag, got, len(frag))
	}
	if strings.Contains(got, frag) {
		t.Errorf("RedactFragment leaks the raw fragment: %q", got)
	}
	if again := RedactFragment(frag); again != got {
		t.Errorf("RedactFragment not stable within a process: %q vs %q", got, again)
	}
	if RedactFragment("a") == RedactFragment("b") {
		t.Error("distinct fragments produced identical digests")
	}
	if RedactFragment("") != "" {
		t.Error(`RedactFragment("") must stay empty`)
	}
}

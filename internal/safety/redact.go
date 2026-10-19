package safety

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
)

// LogOnlyMessage is the slog message emitted when an Input rule in log_only
// mode matches and the request is let through (USK-1109). The live-wire
// pipeline.SafetyStep and the MCP-plane Engine.CheckInput both use it so an
// operator can grep one string for every observe-only match.
const LogOnlyMessage = "safety: match observed (log_only, not blocked)"

var (
	redactKeyOnce sync.Once
	redactKey     []byte
)

// fragmentKey returns the per-process HMAC key, generated once from
// crypto/rand. It never leaves the process and is not persisted.
func fragmentKey() []byte {
	redactKeyOnce.Do(func() {
		k := make([]byte, 32)
		// crypto/rand.Read never returns an error on supported platforms
		// (Go 1.24+ crashes the program irrecoverably instead).
		_, _ = rand.Read(k)
		redactKey = k
	})
	return redactKey
}

// RedactFragment obfuscates a safety-filter matched fragment for logging.
// The raw fragment is a slice of the request that triggered the match (e.g.
// an Authorization/Cookie header value or a request-body span), so it must
// never be logged in clear text (CWE-312).
//
// The digest is HMAC-SHA256 under a random per-process key, truncated to
// 64 bits, plus the byte length: "hmac:<16 hex> len=N". Keying matters
// because many matches are low-entropy (card numbers, phone numbers, My
// Number); an unkeyed hash could be brute-forced offline from the log
// (CWE-759 / CWE-532). The same fragment yields the same digest for the
// lifetime of the process, so cross-log correlation and repeat detection
// still work; digests are not comparable across restarts.
//
// Shared by the MCP-plane Input Filter (internal/mcp) and the live-wire
// pipeline.SafetyStep so both halves log matches identically.
func RedactFragment(fragment string) string {
	if fragment == "" {
		return ""
	}
	mac := hmac.New(sha256.New, fragmentKey())
	mac.Write([]byte(fragment))
	sum := mac.Sum(nil)
	return fmt.Sprintf("hmac:%x len=%d", sum[:8], len(fragment))
}

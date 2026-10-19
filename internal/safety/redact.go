package safety

import (
	"crypto/sha256"
	"fmt"
)

// LogOnlyMessage is the slog message emitted when an Input rule in log_only
// mode matches and the request is let through (USK-1109). The live-wire
// pipeline.SafetyStep and the MCP-plane Engine.CheckInput both use it so an
// operator can grep one string for every observe-only match.
const LogOnlyMessage = "safety: match observed (log_only, not blocked)"

// RedactFragment obfuscates a safety-filter matched fragment for logging.
// The raw fragment is a slice of the request that triggered the match (e.g.
// an Authorization/Cookie header value or a request-body span), so it must
// never be logged in clear text (CWE-312). A truncated SHA-256 digest plus
// the byte length preserves cross-log correlation and lets an operator
// confirm a repeated match without exposing the underlying bytes.
//
// Shared by the MCP-plane Input Filter (internal/mcp) and the live-wire
// pipeline.SafetyStep so both halves log matches identically.
func RedactFragment(fragment string) string {
	if fragment == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fragment))
	return fmt.Sprintf("sha256:%x len=%d", sum[:8], len(fragment))
}

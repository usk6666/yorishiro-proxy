package connector

import (
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/hostcanon"
)

// PassthroughList manages a set of domain patterns that should bypass TLS
// interception (MITM). When a CONNECT request matches a pattern in this list,
// the proxy relays encrypted bytes directly instead of performing a TLS
// handshake and decrypting traffic.
//
// Supported pattern formats:
//   - Exact match: "example.com" matches only "example.com"
//   - Wildcard: "*.example.com" matches any subdomain of example.com
//     (e.g. "foo.example.com", "bar.baz.example.com") but not "example.com" itself
//
// Matching compares the pattern (for a wildcard, the part after "*.") and
// the hostname in hostcanon.FoldDialEquivalent form, so spellings that dial the
// same host match the same pattern ("example.com." / "example.com",
// "::ffff:127.0.0.1" / "127.0.0.1", "[::1]" / "0:0::1"). Legacy IPv4
// spellings are compared as written (USK-1263). Patterns are stored, listed
// and removed as added (lowercased and trimmed); the fold is comparison-only.
type PassthroughList struct {
	mu sync.RWMutex
	// patterns maps each stored pattern to its precomputed match form
	// (passthroughMatchPattern), so Contains does not re-fold per call.
	patterns map[string]string
}

// NewPassthroughList creates an empty PassthroughList.
func NewPassthroughList() *PassthroughList {
	return &PassthroughList{
		patterns: make(map[string]string),
	}
}

// Add adds a domain pattern to the passthrough list.
// The pattern is normalized to lowercase. Duplicate patterns are ignored.
// Returns false if the pattern is empty or invalid.
func (pl *PassthroughList) Add(pattern string) bool {
	pattern = normalizePattern(pattern)
	if pattern == "" {
		return false
	}

	pl.mu.Lock()
	defer pl.mu.Unlock()
	pl.patterns[pattern] = passthroughMatchPattern(pattern)
	return true
}

// Remove removes a domain pattern from the passthrough list.
// Returns true if the pattern was found and removed, false otherwise.
func (pl *PassthroughList) Remove(pattern string) bool {
	pattern = normalizePattern(pattern)
	if pattern == "" {
		return false
	}

	pl.mu.Lock()
	defer pl.mu.Unlock()

	if _, ok := pl.patterns[pattern]; !ok {
		return false
	}
	delete(pl.patterns, pattern)
	return true
}

// Contains checks whether the given hostname matches any pattern in the list.
// The hostname and the patterns are compared in hostcanon.FoldDialEquivalent form.
func (pl *PassthroughList) Contains(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return false
	}
	host := hostcanon.FoldDialEquivalent(hostname)

	pl.mu.RLock()
	defer pl.mu.RUnlock()

	for _, m := range pl.patterns {
		// Exact match, or *.example.com matching any subdomain.
		if m == host || matchWildcardPattern(m, host) {
			return true
		}
	}
	return false
}

// List returns all patterns in the passthrough list.
func (pl *PassthroughList) List() []string {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	result := make([]string, 0, len(pl.patterns))
	for p := range pl.patterns {
		result = append(result, p)
	}
	return result
}

// Clear removes all patterns from the passthrough list.
func (pl *PassthroughList) Clear() {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	pl.patterns = make(map[string]string)
}

// Len returns the number of patterns in the passthrough list.
func (pl *PassthroughList) Len() int {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	return len(pl.patterns)
}

// normalizePattern lowercases and trims the pattern.
// Returns empty string for invalid patterns.
func normalizePattern(pattern string) string {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return ""
	}
	return pattern
}

// passthroughMatchPattern returns the match form of a normalized pattern:
// hostcanon.FoldDialEquivalent of the pattern, or of the part after "*."
// for a wildcard. Passthrough is allow-like (a match means less
// inspection), so it uses the dial-equivalent fold that leaves legacy IPv4
// spellings verbatim (USK-1263).
func passthroughMatchPattern(pattern string) string {
	if strings.HasPrefix(pattern, "*.") {
		return "*." + hostcanon.FoldDialEquivalent(pattern[2:])
	}
	return hostcanon.FoldDialEquivalent(pattern)
}

// matchWildcardPattern checks if a wildcard pattern matches the hostname.
// Only patterns starting with "*." are treated as wildcards.
// "*.example.com" matches "foo.example.com" and "bar.baz.example.com"
// but not "example.com".
func matchWildcardPattern(pattern, hostname string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	// Extract the suffix: "*.example.com" -> ".example.com"
	suffix := pattern[1:] // ".example.com"
	return strings.HasSuffix(hostname, suffix)
}

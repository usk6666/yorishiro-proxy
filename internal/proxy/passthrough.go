package proxy

import (
	"strings"
	"sync"
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
type PassthroughList struct {
	mu       sync.RWMutex
	patterns map[string]struct{}
}

// NewPassthroughList creates an empty PassthroughList.
func NewPassthroughList() *PassthroughList {
	return &PassthroughList{
		patterns: make(map[string]struct{}),
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
	pl.patterns[pattern] = struct{}{}
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
// The hostname is normalized to lowercase before matching.
func (pl *PassthroughList) Contains(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" {
		return false
	}

	pl.mu.RLock()
	defer pl.mu.RUnlock()

	// Check exact match first.
	if _, ok := pl.patterns[hostname]; ok {
		return true
	}

	// Check wildcard patterns: *.example.com matches any subdomain.
	for pattern := range pl.patterns {
		if matchWildcard(pattern, hostname) {
			return true
		}
	}

	return false
}

// List returns all patterns in the passthrough list, sorted alphabetically.
func (pl *PassthroughList) List() []string {
	pl.mu.RLock()
	defer pl.mu.RUnlock()

	result := make([]string, 0, len(pl.patterns))
	for p := range pl.patterns {
		result = append(result, p)
	}
	return result
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

// matchWildcard checks if a wildcard pattern matches the hostname.
// Only patterns starting with "*." are treated as wildcards.
// "*.example.com" matches "foo.example.com" and "bar.baz.example.com"
// but not "example.com".
func matchWildcard(pattern, hostname string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	// Extract the suffix: "*.example.com" -> ".example.com"
	suffix := pattern[1:] // ".example.com"
	return strings.HasSuffix(hostname, suffix)
}

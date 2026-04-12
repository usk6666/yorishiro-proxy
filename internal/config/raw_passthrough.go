package config

import "strings"

// IsRawPassthrough reports whether the given host:port target is configured
// for raw passthrough mode (no L7 parsing). Matching is case-insensitive
// exact match on "host:port". Wildcard patterns are deferred to N4.
func (c *ProxyConfig) IsRawPassthrough(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	for _, h := range c.RawPassthroughHosts {
		if strings.ToLower(strings.TrimSpace(h)) == target {
			return true
		}
	}
	return false
}

// RawPassthroughSet builds a pre-normalized set for O(1) lookups.
// Use this when IsRawPassthrough will be called frequently (per-connection).
type RawPassthroughSet struct {
	hosts map[string]struct{}
}

// NewRawPassthroughSet creates a set from a ProxyConfig's RawPassthroughHosts.
func NewRawPassthroughSet(cfg *ProxyConfig) *RawPassthroughSet {
	s := &RawPassthroughSet{
		hosts: make(map[string]struct{}, len(cfg.RawPassthroughHosts)),
	}
	for _, h := range cfg.RawPassthroughHosts {
		normalized := strings.ToLower(strings.TrimSpace(h))
		if normalized != "" {
			s.hosts[normalized] = struct{}{}
		}
	}
	return s
}

// Contains reports whether the target is in the raw passthrough set.
func (s *RawPassthroughSet) Contains(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	_, ok := s.hosts[target]
	return ok
}

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

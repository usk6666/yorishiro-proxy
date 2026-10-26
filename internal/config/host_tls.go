package config

import (
	"fmt"
	"sort"

	"github.com/usk6666/yorishiro-proxy/internal/hostcanon"
)

// validateHostTLSKeys rejects host_tls maps with two keys that name the
// same host in the dial-equivalent form (hostcanon.DialEquivalentPatternKey,
// USK-1384) — "localhost" and "localhost.", or "A.x" and "a.x". Both seams
// that consume host_tls look entries up by that form, so such a pair would
// give one destination two TLS settings with the winner decided by map
// iteration order. Exact keys and "*." wildcard keys never collide with
// each other. The keys are visited in sorted order so the error names the
// same pair on every run.
func validateHostTLSKeys(hostTLS map[string]*HostTLSEntry) error {
	if len(hostTLS) < 2 {
		return nil
	}
	keys := make([]string, 0, len(hostTLS))
	for k := range hostTLS {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := make(map[string]string, len(keys))
	for _, k := range keys {
		folded := hostcanon.DialEquivalentPatternKey(k)
		if prev, ok := seen[folded]; ok {
			return fmt.Errorf("host_tls: keys %q and %q name the same host (%q); keep one of them", prev, k, folded)
		}
		seen[folded] = k
	}
	return nil
}

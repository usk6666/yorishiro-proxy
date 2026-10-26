package config

import (
	"fmt"
	"sort"

	"github.com/usk6666/yorishiro-proxy/internal/hostcanon"
)

// validateHostTLS checks the host_tls map. The keys are visited in sorted
// order so every error names the same entry on every run.
//
// An entry whose value is JSON null (USK-1389) is rejected first: it decodes
// to a nil *HostTLSEntry, which the host_tls consumers dereference. An empty
// object ({}) is the way to write an entry that inherits the global settings.
//
// Then it rejects two keys that name the same host in the dial-equivalent
// form (hostcanon.DialEquivalentPatternKey, USK-1384) — "localhost" and
// "localhost.", or "A.x" and "a.x". Both seams that consume host_tls look
// entries up by that form, so such a pair would give one destination two
// TLS settings with the winner decided by map iteration order. Exact keys
// and "*." wildcard keys never collide with each other.
func validateHostTLS(hostTLS map[string]*HostTLSEntry) error {
	keys := make([]string, 0, len(hostTLS))
	for k := range hostTLS {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if hostTLS[k] == nil {
			return fmt.Errorf("host_tls[%q]: entry is null; set it to an object (for example {}) or remove the key", k)
		}
	}
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

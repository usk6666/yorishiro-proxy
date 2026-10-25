package connector

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Name binding for transparent mode (USK-1316, owner amendment to U3).
//
// On a transparent listener the client chose the IP it dialed and also
// writes the names (TLS SNI, HTTP Host / absolute-form authority) the
// TargetScope name legs see. A name allow rule may admit a connection
// whose original destination IP is not itself allow-listed only when the
// original destination is one of the addresses the observed name resolves
// to: otherwise a Worker could write an allowed SNI / Host and reach an
// arbitrary IP. NameBindingCache answers that question with a per-listener
// cache in front of a NameResolver.

// NameResolver resolves a host name to its addresses. *net.Resolver
// satisfies it; tests inject a fake.
type NameResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Name-binding failure reasons, recorded as the audit Stream's
// FailureReason of a refused transparent connection.
const (
	// ReasonNameNotBound: the name resolved, but not to the original
	// destination.
	ReasonNameNotBound = "name_not_bound_to_original_dst"
	// ReasonNameResolutionFailed: the lookup failed, timed out or
	// returned no address.
	ReasonNameResolutionFailed = "name_resolution_failed"
)

// Name-binding cache defaults.
const (
	defaultNameBindingPositiveTTL = 30 * time.Second
	defaultNameBindingNegativeTTL = 5 * time.Second
	defaultNameBindingTimeout     = 5 * time.Second
	defaultNameBindingMaxEntries  = 4096
)

// NameBindingConfig configures a NameBindingCache. Zero fields take the
// defaults (30s positive TTL, 5s negative TTL, 5s lookup timeout, 4096
// entries).
type NameBindingConfig struct {
	PositiveTTL time.Duration
	NegativeTTL time.Duration
	Timeout     time.Duration
	MaxEntries  int
}

// NameBindingCache decides whether a name is bound to an address by DNS.
// Safe for concurrent use. Construct with NewNameBindingCache.
//
// Positive answers are cached for PositiveTTL, failures (error, timeout,
// empty answer) for NegativeTTL; concurrent lookups of one name collapse
// into one (singleflight). The cache holds at most MaxEntries names, so
// attacker-chosen names cannot grow it: when full, expired entries are
// purged and, if none expired, an arbitrary entry is evicted.
type NameBindingCache struct {
	resolver NameResolver
	cfg      NameBindingConfig
	// now is the clock (overridable in tests).
	now func() time.Time

	group   singleflight.Group
	mu      sync.Mutex
	entries map[string]nameBindingEntry
}

type nameBindingEntry struct {
	addrs   []netip.Addr // unmapped; nil = lookup failed
	expires time.Time
}

// NewNameBindingCache returns a cache over r (nil = net.DefaultResolver).
func NewNameBindingCache(r NameResolver, cfg NameBindingConfig) *NameBindingCache {
	if r == nil {
		r = net.DefaultResolver
	}
	if cfg.PositiveTTL <= 0 {
		cfg.PositiveTTL = defaultNameBindingPositiveTTL
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = defaultNameBindingNegativeTTL
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultNameBindingTimeout
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = defaultNameBindingMaxEntries
	}
	return &NameBindingCache{resolver: r, cfg: cfg, now: time.Now, entries: make(map[string]nameBindingEntry)}
}

// Bound reports whether name resolves to addr (compared unmapped, zone
// ignored). A name that is an IP literal (bracketed or not) is bound iff
// it equals addr; no lookup happens. Any other name is looked up only
// when it is a syntactically valid DNS host name (lookupHostName); one
// that is not — a Host value with trailing data, say — is not bound and
// never reaches the resolver. A failed, timed-out or empty lookup is not
// bound (fail closed). reason is ReasonNameResolutionFailed or
// ReasonNameNotBound when not bound, empty when bound. This only decides
// the binding; the name on the wire is never touched.
func (c *NameBindingCache) Bound(ctx context.Context, name string, addr netip.Addr) (bool, string) {
	want := addr.Unmap().WithZone("")
	host := strings.TrimSuffix(strings.TrimPrefix(name, "["), "]")
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Unmap().WithZone("") == want {
			return true, ""
		}
		return false, ReasonNameNotBound
	}
	if !lookupHostName(host) {
		return false, ReasonNameResolutionFailed
	}
	key := strings.ToLower(host)
	addrs := c.lookup(ctx, key)
	if len(addrs) == 0 {
		return false, ReasonNameResolutionFailed
	}
	for _, a := range addrs {
		if a == want {
			return true, ""
		}
	}
	return false, ReasonNameNotBound
}

// lookupHostName reports whether s is a DNS host name the binding may
// resolve: dot-separated labels of 1-63 letters, digits, '-' (not at
// either end of a label) or '_' (which the Go resolver's isDomainName
// also accepts), at most 253 bytes, with an optional trailing dot.
// Anything else — spaces, control bytes, '/', empty labels — fails
// closed before it reaches a resolver that might read past it.
func lookupHostName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// lookup returns the cached or freshly resolved addresses of key (nil on
// failure).
func (c *NameBindingCache) lookup(ctx context.Context, key string) []netip.Addr {
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.addrs
	}
	c.mu.Unlock()

	v, _, _ := c.group.Do(key, func() (any, error) {
		// The lookup outlives one caller's cancellation (others may wait
		// on it) but is bounded by the timeout.
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.cfg.Timeout)
		defer cancel()
		res, err := c.resolver.LookupNetIP(lctx, "ip", key)
		var addrs []netip.Addr
		if err == nil {
			for _, a := range res {
				addrs = append(addrs, a.Unmap().WithZone(""))
			}
		}
		ttl := c.cfg.PositiveTTL
		if len(addrs) == 0 {
			addrs, ttl = nil, c.cfg.NegativeTTL
		}
		c.store(key, nameBindingEntry{addrs: addrs, expires: c.now().Add(ttl)})
		return addrs, nil
	})
	addrs, _ := v.([]netip.Addr)
	return addrs
}

// store inserts e, keeping the cache within MaxEntries.
func (c *NameBindingCache) store(key string, e nameBindingEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.cfg.MaxEntries {
		now := c.now()
		for k, old := range c.entries {
			if !now.Before(old.expires) {
				delete(c.entries, k)
			}
		}
		for k := range c.entries {
			if len(c.entries) < c.cfg.MaxEntries {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[key] = e
}

// Len returns the number of cached entries.
func (c *NameBindingCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

package connector

import (
	"context"
	"net"
	"net/netip"
	"time"
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
type NameBindingCache struct {
	resolver NameResolver
	cfg      NameBindingConfig
	// now is the clock (overridable in tests).
	now func() time.Time
}

// NewNameBindingCache returns a cache over r (nil = net.DefaultResolver).
func NewNameBindingCache(r NameResolver, cfg NameBindingConfig) *NameBindingCache {
	if r == nil {
		r = net.DefaultResolver
	}
	return &NameBindingCache{resolver: r, cfg: cfg, now: time.Now}
}

// Bound reports whether name resolves to addr (compared unmapped). A
// name that is an IP literal is bound iff it equals addr. A failed,
// timed-out or empty lookup is not bound (fail closed); reason is
// ReasonNameResolutionFailed or ReasonNameNotBound when not bound.
func (c *NameBindingCache) Bound(ctx context.Context, name string, addr netip.Addr) (bool, string) {
	_ = ctx
	_ = name
	_ = addr
	return false, ReasonNameResolutionFailed
}

// Len returns the number of cached entries.
func (c *NameBindingCache) Len() int { return 0 }


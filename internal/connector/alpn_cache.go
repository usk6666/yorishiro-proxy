// alpn_cache.go implements a small LRU + TTL cache that remembers which ALPN
// protocol an upstream host negotiates. TunnelHandler consults the cache on
// every tunnel so that a cache hit can offer the right ALPN to the client
// without having to dial upstream first just to learn it.
//
// The cache key is a triple (host:port, uTLS fingerprint, mTLS cert hash)
// because real-world anti-bot deployments change their ALPN response based on
// the client fingerprint. Two connections to the same host with different
// client profiles are therefore stored independently.
//
// Eviction is LRU on size and lazy on TTL: a stale entry is removed the next
// time Get observes it. That means a slow-moving cache can still hold
// long-expired entries, but those entries cost nothing until accessed.
package connector

import (
	"container/list"
	"sync"
	"time"
)

// DefaultALPNCacheSize is the default maximum number of cache entries.
const DefaultALPNCacheSize = 1024

// DefaultALPNCacheTTL is the default per-entry TTL.
const DefaultALPNCacheTTL = time.Hour

// ALPNCacheKey identifies a cache entry. The zero value is a valid key
// (all three fields empty), representing the standard TLS profile with no
// client certificate.
type ALPNCacheKey struct {
	// HostPort is the "host:port" string that was dialled.
	HostPort string

	// Fingerprint is the uTLS profile name. Empty string means the standard
	// crypto/tls library was used.
	Fingerprint string

	// ClientCertHash is a hash of the mTLS client certificate. Empty string
	// means no mTLS certificate.
	ClientCertHash string
}

// ALPNCacheEntry holds the cached ALPN result and its expiry time.
type ALPNCacheEntry struct {
	// Protocol is the negotiated ALPN protocol (e.g. "h2", "http/1.1").
	// An empty string is a valid cached value and means "no ALPN was
	// negotiated" — usually because the server did not send the extension.
	Protocol string

	// Expiry is the absolute time after which the entry is considered stale.
	Expiry time.Time
}

// alpnCacheNode wraps a cache entry for storage in the LRU list.
type alpnCacheNode struct {
	key   ALPNCacheKey
	entry ALPNCacheEntry
}

// ALPNCache is a thread-safe LRU cache with per-entry TTL.
// The zero value is not usable; construct with NewALPNCache.
type ALPNCache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	ll    *list.List
	index map[ALPNCacheKey]*list.Element
	nowFn func() time.Time // overridable for tests
}

// NewALPNCache creates an ALPNCache with the given capacity and TTL.
// Non-positive values fall back to the package defaults.
func NewALPNCache(maxEntries int, ttl time.Duration) *ALPNCache {
	if maxEntries <= 0 {
		maxEntries = DefaultALPNCacheSize
	}
	if ttl <= 0 {
		ttl = DefaultALPNCacheTTL
	}
	return &ALPNCache{
		max:   maxEntries,
		ttl:   ttl,
		ll:    list.New(),
		index: make(map[ALPNCacheKey]*list.Element),
		nowFn: time.Now,
	}
}

// Get returns the cached entry for key if it exists and has not expired.
// Expired entries are removed as a side effect so that repeated lookups stay
// cheap. A successful lookup moves the entry to the front of the LRU list.
func (c *ALPNCache) Get(key ALPNCacheKey) (ALPNCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.index[key]
	if !ok {
		return ALPNCacheEntry{}, false
	}
	node := el.Value.(*alpnCacheNode)
	if c.nowFn().After(node.entry.Expiry) {
		c.ll.Remove(el)
		delete(c.index, key)
		return ALPNCacheEntry{}, false
	}
	c.ll.MoveToFront(el)
	return node.entry, true
}

// Set stores protocol under key with a fresh expiry. An existing entry for
// the same key is overwritten. When the cache exceeds its capacity the least
// recently used entry is evicted.
func (c *ALPNCache) Set(key ALPNCacheKey, protocol string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiry := c.nowFn().Add(c.ttl)

	if el, ok := c.index[key]; ok {
		node := el.Value.(*alpnCacheNode)
		node.entry.Protocol = protocol
		node.entry.Expiry = expiry
		c.ll.MoveToFront(el)
		return
	}

	node := &alpnCacheNode{
		key:   key,
		entry: ALPNCacheEntry{Protocol: protocol, Expiry: expiry},
	}
	el := c.ll.PushFront(node)
	c.index[key] = el

	for c.ll.Len() > c.max {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.ll.Remove(back)
		delete(c.index, back.Value.(*alpnCacheNode).key)
	}
}

// Delete removes the entry for key if it exists. This is called by
// TunnelHandler when a cache-hit path observes an ALPN mismatch so the next
// connection can re-learn.
func (c *ALPNCache) Delete(key ALPNCacheKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.index[key]; ok {
		c.ll.Remove(el)
		delete(c.index, key)
	}
}

// Len returns the current number of entries. Expired entries that have not
// been probed via Get still count.
func (c *ALPNCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

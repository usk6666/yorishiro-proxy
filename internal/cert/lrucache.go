package cert

import (
	"container/list"
	"crypto/tls"
	"sync"
	"time"
)

// defaultMaxCacheSize is the default maximum number of entries in the certificate LRU cache.
const defaultMaxCacheSize = 1024

// lruCache is a thread-safe LRU cache with expiration support for TLS certificates.
// When the cache reaches its maximum size, the least recently used entry is evicted.
// Expired entries are lazily removed on access and proactively removed during eviction.
type lruCache struct {
	mu       sync.Mutex
	maxSize  int
	items    map[string]*list.Element
	eviction *list.List // front = most recently used, back = least recently used
	nowFunc  func() time.Time
}

// lruEntry is a single entry in the LRU cache.
type lruEntry struct {
	key   string
	value *cachedCert
}

// newLRUCache creates a new LRU cache with the given maximum size.
// If maxSize is <= 0, defaultMaxCacheSize is used.
func newLRUCache(maxSize int) *lruCache {
	if maxSize <= 0 {
		maxSize = defaultMaxCacheSize
	}
	return &lruCache{
		maxSize:  maxSize,
		items:    make(map[string]*list.Element),
		eviction: list.New(),
		nowFunc:  time.Now,
	}
}

// Get retrieves a cached certificate by hostname.
// Returns the certificate and true if found and not expired, or nil and false otherwise.
// A successful Get promotes the entry to the front of the LRU list.
func (c *lruCache) Get(key string) (*cachedCert, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		return nil, false
	}

	entry := elem.Value.(*lruEntry)

	// Check expiration: entry is valid only when now is strictly before expiresAt.
	if !c.nowFunc().Before(entry.value.expiresAt) {
		c.removeLocked(elem)
		return nil, false
	}

	// Move to front (most recently used).
	c.eviction.MoveToFront(elem)
	return entry.value, true
}

// Put adds or updates a certificate in the cache.
// If the cache is at capacity, the least recently used entry is evicted first.
func (c *lruCache) Put(key string, value *cachedCert) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update existing entry.
	if elem, ok := c.items[key]; ok {
		entry := elem.Value.(*lruEntry)
		entry.value = value
		c.eviction.MoveToFront(elem)
		return
	}

	// Evict if at capacity.
	for c.eviction.Len() >= c.maxSize {
		c.evictOldestLocked()
	}

	// Add new entry at front.
	entry := &lruEntry{key: key, value: value}
	elem := c.eviction.PushFront(entry)
	c.items[key] = elem
}

// Delete removes a specific entry from the cache.
func (c *lruCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeLocked(elem)
	}
}

// Len returns the number of entries currently in the cache.
func (c *lruCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.eviction.Len()
}

// Clear removes all entries from the cache.
func (c *lruCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.eviction.Init()
}

// removeLocked removes an element from both the list and the map.
// Caller must hold c.mu.
func (c *lruCache) removeLocked(elem *list.Element) {
	entry := c.eviction.Remove(elem).(*lruEntry)
	delete(c.items, entry.key)
}

// evictOldestLocked removes the least recently used entry from the cache.
// Caller must hold c.mu.
func (c *lruCache) evictOldestLocked() {
	oldest := c.eviction.Back()
	if oldest == nil {
		return
	}
	c.removeLocked(oldest)
}

// configLRUCache is a thread-safe LRU cache for *tls.Config values keyed by
// (hostname, alpnOffer). It mirrors lruCache but specialises the value type
// because *tls.Config has no expiration concept — entries live until evicted
// by capacity or by Clear (called from Issuer.ClearCache after a CA regen,
// which makes any session-ticket-encryption keys held inside the cached
// Config stale).
type configLRUCache struct {
	mu       sync.Mutex
	maxSize  int
	items    map[serverCfgKey]*list.Element
	eviction *list.List // front = MRU, back = LRU
}

// configLRUEntry is a single entry in the *tls.Config LRU cache.
type configLRUEntry struct {
	key   serverCfgKey
	value *tls.Config
}

// newConfigLRUCache constructs a *tls.Config LRU cache.
// If maxSize is <= 0, defaultMaxCacheSize is used.
func newConfigLRUCache(maxSize int) *configLRUCache {
	if maxSize <= 0 {
		maxSize = defaultMaxCacheSize
	}
	return &configLRUCache{
		maxSize:  maxSize,
		items:    make(map[serverCfgKey]*list.Element),
		eviction: list.New(),
	}
}

// LoadOrStore returns the existing *tls.Config for key, or stores and returns
// cfg if no entry exists. The boolean reports whether an existing entry was
// found. A successful load promotes the entry to MRU; a successful store
// inserts at MRU and evicts the LRU entry if the cache is at capacity.
func (c *configLRUCache) LoadOrStore(key serverCfgKey, cfg *tls.Config) (*tls.Config, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.eviction.MoveToFront(elem)
		return elem.Value.(*configLRUEntry).value, true
	}

	for c.eviction.Len() >= c.maxSize {
		c.evictOldestLocked()
	}

	entry := &configLRUEntry{key: key, value: cfg}
	elem := c.eviction.PushFront(entry)
	c.items[key] = elem
	return cfg, false
}

// Len returns the number of entries currently in the cache.
func (c *configLRUCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.eviction.Len()
}

// Clear removes all entries from the cache.
func (c *configLRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[serverCfgKey]*list.Element)
	c.eviction.Init()
}

// evictOldestLocked removes the least recently used entry. Caller must hold c.mu.
func (c *configLRUCache) evictOldestLocked() {
	oldest := c.eviction.Back()
	if oldest == nil {
		return
	}
	entry := c.eviction.Remove(oldest).(*configLRUEntry)
	delete(c.items, entry.key)
}

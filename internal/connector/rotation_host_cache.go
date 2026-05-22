package connector

import (
	"container/list"
	"net/url"
	"sync"
	"time"
)

// rotationHostCache is a bounded LRU + TTL cache for the
// RotationPerTargetHost policy. Mirrors the ALPNCache shape so the
// eviction behaviour is familiar: capacity-driven LRU, lazy TTL
// expiry on Get.
type rotationHostCache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	ll    *list.List
	index map[string]*list.Element
	nowFn func() time.Time
}

// rotationHostNode bundles a hostKey with its cached URL + expiry for
// storage in the LRU list.
type rotationHostNode struct {
	host   string
	url    *url.URL
	expiry time.Time
}

// newRotationHostCache constructs a cache with the given capacity and
// TTL. Non-positive values fall back to the package defaults.
func newRotationHostCache(maxEntries int, ttl time.Duration) *rotationHostCache {
	if maxEntries <= 0 {
		maxEntries = DefaultRotationPerHostCacheSize
	}
	if ttl <= 0 {
		ttl = DefaultRotationPerHostCacheTTL
	}
	return &rotationHostCache{
		max:   maxEntries,
		ttl:   ttl,
		ll:    list.New(),
		index: make(map[string]*list.Element),
		nowFn: time.Now,
	}
}

// get returns the cached URL for host if present and unexpired. Expired
// entries are removed lazily so repeated lookups stay cheap.
func (c *rotationHostCache) get(host string) (*url.URL, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.index[host]
	if !ok {
		return nil, false
	}
	node := el.Value.(*rotationHostNode)
	if c.nowFn().After(node.expiry) {
		c.ll.Remove(el)
		delete(c.index, host)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return node.url, true
}

// set stores u under host with a fresh expiry. Capacity overflow
// evicts the least recently used entry.
func (c *rotationHostCache) set(host string, u *url.URL) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	expiry := c.nowFn().Add(c.ttl)
	if el, ok := c.index[host]; ok {
		node := el.Value.(*rotationHostNode)
		node.url = u
		node.expiry = expiry
		c.ll.MoveToFront(el)
		return
	}
	node := &rotationHostNode{host: host, url: u, expiry: expiry}
	el := c.ll.PushFront(node)
	c.index[host] = el
	for c.ll.Len() > c.max {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.ll.Remove(back)
		delete(c.index, back.Value.(*rotationHostNode).host)
	}
}

// clear removes every entry. Called from RotationResolver.Reset when
// configure_tool reloads the rotation configuration.
func (c *rotationHostCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll = list.New()
	c.index = make(map[string]*list.Element)
}

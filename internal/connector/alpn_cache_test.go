package connector

import (
	"sync"
	"testing"
	"time"
)

func TestALPNCache_SetGet(t *testing.T) {
	c := NewALPNCache(4, time.Minute)
	key := ALPNCacheKey{HostPort: "example.com:443"}

	if _, ok := c.Get(key); ok {
		t.Fatal("expected miss on empty cache")
	}

	c.Set(key, "h2")
	entry, ok := c.Get(key)
	if !ok {
		t.Fatal("expected hit after Set")
	}
	if entry.Protocol != "h2" {
		t.Errorf("Protocol = %q, want %q", entry.Protocol, "h2")
	}
}

func TestALPNCache_KeySensitivity(t *testing.T) {
	c := NewALPNCache(4, time.Minute)
	k1 := ALPNCacheKey{HostPort: "example.com:443", Fingerprint: ""}
	k2 := ALPNCacheKey{HostPort: "example.com:443", Fingerprint: "chrome"}
	k3 := ALPNCacheKey{HostPort: "example.com:443", Fingerprint: "chrome", ClientCertHash: "abc"}

	c.Set(k1, "http/1.1")
	c.Set(k2, "h2")
	c.Set(k3, "http/1.1")

	if e, _ := c.Get(k1); e.Protocol != "http/1.1" {
		t.Errorf("k1: got %q", e.Protocol)
	}
	if e, _ := c.Get(k2); e.Protocol != "h2" {
		t.Errorf("k2: got %q", e.Protocol)
	}
	if e, _ := c.Get(k3); e.Protocol != "http/1.1" {
		t.Errorf("k3: got %q", e.Protocol)
	}
}

func TestALPNCache_Overwrite(t *testing.T) {
	c := NewALPNCache(4, time.Minute)
	key := ALPNCacheKey{HostPort: "example.com:443"}

	c.Set(key, "http/1.1")
	c.Set(key, "h2")

	entry, ok := c.Get(key)
	if !ok {
		t.Fatal("expected hit")
	}
	if entry.Protocol != "h2" {
		t.Errorf("Protocol = %q, want h2", entry.Protocol)
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

func TestALPNCache_LRUEviction(t *testing.T) {
	c := NewALPNCache(3, time.Minute)

	keys := []ALPNCacheKey{
		{HostPort: "a:443"},
		{HostPort: "b:443"},
		{HostPort: "c:443"},
	}
	for _, k := range keys {
		c.Set(k, "h2")
	}
	if c.Len() != 3 {
		t.Fatalf("Len = %d, want 3", c.Len())
	}

	// Touch "a" so it becomes most recently used.
	if _, ok := c.Get(keys[0]); !ok {
		t.Fatal("expected a:443 hit")
	}

	// Add a 4th entry — this should evict "b" (least recently used).
	c.Set(ALPNCacheKey{HostPort: "d:443"}, "h2")

	if c.Len() != 3 {
		t.Fatalf("Len = %d after overflow, want 3", c.Len())
	}
	if _, ok := c.Get(keys[1]); ok {
		t.Error("b:443 should have been evicted")
	}
	if _, ok := c.Get(keys[0]); !ok {
		t.Error("a:443 should still be present")
	}
}

func TestALPNCache_TTLExpiry(t *testing.T) {
	c := NewALPNCache(4, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	c.nowFn = func() time.Time { return now }

	key := ALPNCacheKey{HostPort: "example.com:443"}
	c.Set(key, "h2")

	if _, ok := c.Get(key); !ok {
		t.Fatal("expected hit before expiry")
	}

	// Advance past TTL.
	now = now.Add(2 * time.Minute)
	if _, ok := c.Get(key); ok {
		t.Error("expected miss after TTL expiry")
	}
	// Expired entry should have been removed as a side effect.
	if c.Len() != 0 {
		t.Errorf("Len = %d after expiry GC, want 0", c.Len())
	}
}

func TestALPNCache_Delete(t *testing.T) {
	c := NewALPNCache(4, time.Minute)
	key := ALPNCacheKey{HostPort: "example.com:443"}

	c.Set(key, "h2")
	c.Delete(key)
	if _, ok := c.Get(key); ok {
		t.Error("expected miss after Delete")
	}
	// Delete on missing key is a no-op.
	c.Delete(ALPNCacheKey{HostPort: "other:443"})
}

func TestALPNCache_Defaults(t *testing.T) {
	c := NewALPNCache(0, 0)
	if c.max != DefaultALPNCacheSize {
		t.Errorf("max = %d, want %d", c.max, DefaultALPNCacheSize)
	}
	if c.ttl != DefaultALPNCacheTTL {
		t.Errorf("ttl = %v, want %v", c.ttl, DefaultALPNCacheTTL)
	}
}

func TestALPNCache_StaleDeleteAllowsRelearn(t *testing.T) {
	// Simulates the lazy-dial staleness path: the cache says "h2" but
	// upstream now negotiates "http/1.1". The handler deletes the stale
	// entry; a subsequent Set must install the new value.
	c := NewALPNCache(4, time.Minute)
	key := ALPNCacheKey{HostPort: "shifty.example:443"}

	c.Set(key, "h2")
	if got, _ := c.Get(key); got.Protocol != "h2" {
		t.Fatalf("initial protocol = %q", got.Protocol)
	}

	c.Delete(key)
	if _, ok := c.Get(key); ok {
		t.Fatal("Delete did not remove stale entry")
	}

	c.Set(key, "http/1.1")
	if got, _ := c.Get(key); got.Protocol != "http/1.1" {
		t.Errorf("relearned protocol = %q, want http/1.1", got.Protocol)
	}
}

func TestALPNCache_Concurrent(t *testing.T) {
	c := NewALPNCache(32, time.Minute)

	const goroutines = 16
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		gid := g
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				k := ALPNCacheKey{HostPort: "host:443", Fingerprint: string(rune('a' + (gid+i)%8))}
				c.Set(k, "h2")
				c.Get(k)
				if i%5 == 0 {
					c.Delete(k)
				}
			}
		}()
	}
	wg.Wait()
}

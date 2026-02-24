package cert

import (
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
	"time"
)

// makeCachedCert creates a cachedCert for testing with the given expiry time.
func makeCachedCert(t *testing.T, expiresAt time.Time) *cachedCert {
	t.Helper()
	return &cachedCert{
		cert:      &tls.Certificate{},
		expiresAt: expiresAt,
	}
}

func TestLRUCache_GetPut_BasicOperation(t *testing.T) {
	c := newLRUCache(10)
	now := time.Now()
	cc := makeCachedCert(t, now.Add(time.Hour))

	// Get on empty cache returns false.
	if _, ok := c.Get("example.com"); ok {
		t.Error("Get on empty cache returned ok=true")
	}

	// Put and Get.
	c.Put("example.com", cc)
	got, ok := c.Get("example.com")
	if !ok {
		t.Fatal("Get returned ok=false after Put")
	}
	if got != cc {
		t.Error("Get returned different cachedCert than what was Put")
	}
}

func TestLRUCache_Get_ExpiredEntry(t *testing.T) {
	c := newLRUCache(10)
	past := time.Now().Add(-time.Hour)
	cc := makeCachedCert(t, past)

	c.Put("expired.com", cc)

	// Get should return false for expired entry.
	if _, ok := c.Get("expired.com"); ok {
		t.Error("Get returned ok=true for expired entry")
	}

	// Entry should be removed.
	if c.Len() != 0 {
		t.Errorf("Len = %d after getting expired entry, want 0", c.Len())
	}
}

func TestLRUCache_Get_ExpirationWithCustomNowFunc(t *testing.T) {
	c := newLRUCache(10)
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c.nowFunc = func() time.Time { return baseTime }

	cc := makeCachedCert(t, baseTime.Add(time.Hour))
	c.Put("test.com", cc)

	// Still valid at base time.
	if _, ok := c.Get("test.com"); !ok {
		t.Error("Get returned ok=false for valid entry")
	}

	// Advance time past expiration.
	c.nowFunc = func() time.Time { return baseTime.Add(2 * time.Hour) }
	if _, ok := c.Get("test.com"); ok {
		t.Error("Get returned ok=true for entry that should be expired")
	}
}

func TestLRUCache_Put_UpdateExisting(t *testing.T) {
	c := newLRUCache(10)
	now := time.Now()

	cc1 := makeCachedCert(t, now.Add(time.Hour))
	cc2 := makeCachedCert(t, now.Add(2*time.Hour))

	c.Put("example.com", cc1)
	c.Put("example.com", cc2)

	// Should return the updated value.
	got, ok := c.Get("example.com")
	if !ok {
		t.Fatal("Get returned ok=false after update")
	}
	if got != cc2 {
		t.Error("Get returned old cachedCert after update")
	}

	// Length should still be 1.
	if c.Len() != 1 {
		t.Errorf("Len = %d after Put with same key, want 1", c.Len())
	}
}

func TestLRUCache_EvictionOrder(t *testing.T) {
	c := newLRUCache(3)
	now := time.Now()
	future := now.Add(time.Hour)

	// Fill cache to capacity.
	c.Put("a", makeCachedCert(t, future))
	c.Put("b", makeCachedCert(t, future))
	c.Put("c", makeCachedCert(t, future))

	// Adding a 4th entry should evict "a" (least recently used).
	c.Put("d", makeCachedCert(t, future))

	if _, ok := c.Get("a"); ok {
		t.Error("entry 'a' should have been evicted")
	}

	// b, c, d should still be present.
	for _, key := range []string{"b", "c", "d"} {
		if _, ok := c.Get(key); !ok {
			t.Errorf("entry %q should still be in cache", key)
		}
	}

	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
}

func TestLRUCache_GetPromotesEntry(t *testing.T) {
	c := newLRUCache(3)
	now := time.Now()
	future := now.Add(time.Hour)

	c.Put("a", makeCachedCert(t, future))
	c.Put("b", makeCachedCert(t, future))
	c.Put("c", makeCachedCert(t, future))

	// Access "a" to promote it to most recently used.
	c.Get("a")

	// Adding a 4th entry should evict "b" (now the least recently used).
	c.Put("d", makeCachedCert(t, future))

	if _, ok := c.Get("b"); ok {
		t.Error("entry 'b' should have been evicted (was LRU after 'a' was accessed)")
	}
	if _, ok := c.Get("a"); !ok {
		t.Error("entry 'a' should still be in cache (was promoted by Get)")
	}
}

func TestLRUCache_PutPromotesExisting(t *testing.T) {
	c := newLRUCache(3)
	now := time.Now()
	future := now.Add(time.Hour)

	c.Put("a", makeCachedCert(t, future))
	c.Put("b", makeCachedCert(t, future))
	c.Put("c", makeCachedCert(t, future))

	// Update "a" to promote it.
	c.Put("a", makeCachedCert(t, future))

	// Adding "d" should evict "b" (now LRU), not "a".
	c.Put("d", makeCachedCert(t, future))

	if _, ok := c.Get("b"); ok {
		t.Error("entry 'b' should have been evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Error("entry 'a' should still be in cache after update")
	}
}

func TestLRUCache_Delete(t *testing.T) {
	c := newLRUCache(10)
	now := time.Now()
	future := now.Add(time.Hour)

	c.Put("example.com", makeCachedCert(t, future))
	c.Delete("example.com")

	if _, ok := c.Get("example.com"); ok {
		t.Error("Get returned ok=true after Delete")
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d after Delete, want 0", c.Len())
	}
}

func TestLRUCache_Delete_NonExistent(t *testing.T) {
	c := newLRUCache(10)

	// Should not panic.
	c.Delete("nonexistent.com")

	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0", c.Len())
	}
}

func TestLRUCache_Len(t *testing.T) {
	c := newLRUCache(10)
	now := time.Now()
	future := now.Add(time.Hour)

	if c.Len() != 0 {
		t.Errorf("empty cache Len = %d, want 0", c.Len())
	}

	c.Put("a", makeCachedCert(t, future))
	if c.Len() != 1 {
		t.Errorf("Len = %d after 1 Put, want 1", c.Len())
	}

	c.Put("b", makeCachedCert(t, future))
	if c.Len() != 2 {
		t.Errorf("Len = %d after 2 Puts, want 2", c.Len())
	}

	c.Delete("a")
	if c.Len() != 1 {
		t.Errorf("Len = %d after Delete, want 1", c.Len())
	}
}

func TestLRUCache_MaxSize_One(t *testing.T) {
	c := newLRUCache(1)
	now := time.Now()
	future := now.Add(time.Hour)

	c.Put("a", makeCachedCert(t, future))
	c.Put("b", makeCachedCert(t, future))

	// "a" should be evicted.
	if _, ok := c.Get("a"); ok {
		t.Error("entry 'a' should have been evicted in size-1 cache")
	}
	if _, ok := c.Get("b"); !ok {
		t.Error("entry 'b' should be in cache")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

func TestNewLRUCache_DefaultSize(t *testing.T) {
	tests := []struct {
		name     string
		maxSize  int
		wantSize int
	}{
		{name: "zero uses default", maxSize: 0, wantSize: defaultMaxCacheSize},
		{name: "negative uses default", maxSize: -1, wantSize: defaultMaxCacheSize},
		{name: "positive is respected", maxSize: 100, wantSize: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newLRUCache(tt.maxSize)
			if c.maxSize != tt.wantSize {
				t.Errorf("maxSize = %d, want %d", c.maxSize, tt.wantSize)
			}
		})
	}
}

func TestLRUCache_ConcurrentAccess(t *testing.T) {
	c := newLRUCache(100)
	now := time.Now()
	future := now.Add(time.Hour)

	const goroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				key := fmt.Sprintf("host-%d-%d.example.com", id, j%10)
				cc := makeCachedCert(t, future)
				c.Put(key, cc)
				c.Get(key)
				if j%5 == 0 {
					c.Delete(key)
				}
				c.Len()
			}
		}(i)
	}

	wg.Wait()

	// Verify cache is in a consistent state.
	if c.Len() < 0 {
		t.Errorf("Len = %d, should be non-negative", c.Len())
	}
	if c.Len() > 100 {
		t.Errorf("Len = %d, should not exceed maxSize 100", c.Len())
	}
}

func TestLRUCache_ConcurrentPutSameKey(t *testing.T) {
	c := newLRUCache(10)
	now := time.Now()
	future := now.Add(time.Hour)

	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			c.Put("shared-key", makeCachedCert(t, future))
		}()
	}

	wg.Wait()

	// Should have exactly one entry.
	if c.Len() != 1 {
		t.Errorf("Len = %d after concurrent Puts with same key, want 1", c.Len())
	}

	if _, ok := c.Get("shared-key"); !ok {
		t.Error("Get returned ok=false for concurrently Put key")
	}
}

func TestLRUCache_EvictionDoesNotExceedMaxSize(t *testing.T) {
	maxSize := 5
	c := newLRUCache(maxSize)
	now := time.Now()
	future := now.Add(time.Hour)

	// Insert many more entries than maxSize.
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("host-%d.example.com", i)
		c.Put(key, makeCachedCert(t, future))

		if c.Len() > maxSize {
			t.Fatalf("Len = %d after inserting entry %d, exceeds maxSize %d", c.Len(), i, maxSize)
		}
	}

	if c.Len() != maxSize {
		t.Errorf("final Len = %d, want %d", c.Len(), maxSize)
	}

	// Only the last 5 entries should be present.
	for i := 95; i < 100; i++ {
		key := fmt.Sprintf("host-%d.example.com", i)
		if _, ok := c.Get(key); !ok {
			t.Errorf("entry %q should be in cache", key)
		}
	}
}

func TestLRUCache_ExpiredEntryEvictedOnGet(t *testing.T) {
	c := newLRUCache(10)
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	c.nowFunc = func() time.Time { return baseTime }

	cc := makeCachedCert(t, baseTime.Add(time.Minute))
	c.Put("short-lived.com", cc)

	// Verify it's there.
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}

	// Advance time past expiration.
	c.nowFunc = func() time.Time { return baseTime.Add(2 * time.Minute) }

	// Get should remove the expired entry.
	if _, ok := c.Get("short-lived.com"); ok {
		t.Error("Get returned ok=true for expired entry")
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d after expired Get, want 0", c.Len())
	}
}

func TestLRUCache_ExpirationBoundary(t *testing.T) {
	c := newLRUCache(10)
	exactTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	cc := makeCachedCert(t, exactTime)

	c.Put("boundary.com", cc)

	// Exactly at expiration time: now.After(expiresAt) is false when now == expiresAt,
	// so the entry is NOT considered expired (boundary is inclusive).
	c.nowFunc = func() time.Time { return exactTime }
	if _, ok := c.Get("boundary.com"); ok {
		t.Error("entry should not be valid when now == expiresAt")
	}

	// One nanosecond before expiration: should be valid.
	c.Put("boundary2.com", cc)
	c.nowFunc = func() time.Time { return exactTime.Add(-time.Nanosecond) }
	if _, ok := c.Get("boundary2.com"); !ok {
		t.Error("entry should be valid one nanosecond before expiration")
	}

	// One nanosecond after expiration: should be expired.
	c.Put("boundary3.com", cc)
	c.nowFunc = func() time.Time { return exactTime.Add(time.Nanosecond) }
	if _, ok := c.Get("boundary3.com"); ok {
		t.Error("entry should be expired one nanosecond after expiresAt")
	}
}

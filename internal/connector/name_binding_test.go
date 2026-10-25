package connector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeNameResolver answers from a table and counts lookups.
type fakeNameResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	errs    map[string]error
	calls   atomic.Int32
	block   chan struct{} // when non-nil, lookups wait on it
}

func (f *fakeNameResolver) LookupNetIP(ctx context.Context, _, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errs[host]; err != nil {
		return nil, err
	}
	return f.answers[host], nil
}

func TestNameBindingCache_Bound(t *testing.T) {
	dst := netip.MustParseAddr("192.0.2.10")
	r := &fakeNameResolver{
		answers: map[string][]netip.Addr{
			"bound.example":     {netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("::ffff:192.0.2.10")},
			"elsewhere.example": {netip.MustParseAddr("198.51.100.1")},
			"empty.example":     nil,
		},
		errs: map[string]error{"fail.example": errors.New("SERVFAIL")},
	}
	c := NewNameBindingCache(r, NameBindingConfig{})
	tests := []struct {
		name       string
		host       string
		wantOK     bool
		wantReason string
	}{
		{name: "resolves to dst (mapped answer)", host: "bound.example", wantOK: true},
		{name: "resolves elsewhere", host: "elsewhere.example", wantReason: ReasonNameNotBound},
		{name: "empty answer", host: "empty.example", wantReason: ReasonNameResolutionFailed},
		{name: "lookup error", host: "fail.example", wantReason: ReasonNameResolutionFailed},
		{name: "IP literal equal", host: "192.0.2.10", wantOK: true},
		{name: "IP literal different", host: "192.0.2.11", wantReason: ReasonNameNotBound},
		{name: "bracketed IPv6 literal different", host: "[2001:db8::1]", wantReason: ReasonNameNotBound},
		{name: "empty name", host: "", wantReason: ReasonNameResolutionFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := c.Bound(context.Background(), tc.host, dst)
			if ok != tc.wantOK || (!ok && reason != tc.wantReason) {
				t.Fatalf("Bound(%q) = %v, %q; want %v, %q", tc.host, ok, reason, tc.wantOK, tc.wantReason)
			}
		})
	}
	before := r.calls.Load()
	if ok, _ := c.Bound(context.Background(), "192.0.2.10", dst); !ok || r.calls.Load() != before {
		t.Errorf("IP literal looked up via the resolver (calls %d → %d)", before, r.calls.Load())
	}
}

func TestNameBindingCache_CachesPositiveAndNegative(t *testing.T) {
	dst := netip.MustParseAddr("192.0.2.10")
	r := &fakeNameResolver{
		answers: map[string][]netip.Addr{"bound.example": {dst}},
		errs:    map[string]error{"fail.example": errors.New("timeout")},
	}
	now := time.Unix(1000, 0)
	c := NewNameBindingCache(r, NameBindingConfig{})
	c.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := c.Bound(context.Background(), "Bound.Example", dst); !ok {
			t.Fatal("bound.example not bound")
		}
		_, _ = c.Bound(context.Background(), "fail.example", dst)
	}
	if n := r.calls.Load(); n != 2 {
		t.Fatalf("lookups = %d, want 2 (one per name, cached)", n)
	}
	now = now.Add(6 * time.Second) // past the negative TTL only
	_, _ = c.Bound(context.Background(), "fail.example", dst)
	_, _ = c.Bound(context.Background(), "bound.example", dst)
	if n := r.calls.Load(); n != 3 {
		t.Fatalf("lookups = %d, want 3 (negative entry expired, positive still cached)", n)
	}
	now = now.Add(31 * time.Second)
	_, _ = c.Bound(context.Background(), "bound.example", dst)
	if n := r.calls.Load(); n != 4 {
		t.Fatalf("lookups = %d, want 4 (positive entry expired)", n)
	}
}

func TestNameBindingCache_CollapsesConcurrentLookups(t *testing.T) {
	dst := netip.MustParseAddr("192.0.2.10")
	r := &fakeNameResolver{answers: map[string][]netip.Addr{"bound.example": {dst}}, block: make(chan struct{})}
	c := NewNameBindingCache(r, NameBindingConfig{})
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _ := c.Bound(context.Background(), "bound.example", dst)
			results <- ok
		}()
	}
	// Let the goroutines pile up on the in-flight lookup.
	deadline := time.Now().Add(2 * time.Second)
	for r.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(r.block)
	wg.Wait()
	close(results)
	for ok := range results {
		if !ok {
			t.Fatal("a concurrent caller saw not-bound")
		}
	}
	if n := r.calls.Load(); n != 1 {
		t.Fatalf("lookups = %d, want 1 (singleflight)", n)
	}
}

func TestNameBindingCache_LookupTimeoutDenies(t *testing.T) {
	r := &fakeNameResolver{block: make(chan struct{})}
	defer close(r.block)
	c := NewNameBindingCache(r, NameBindingConfig{Timeout: 50 * time.Millisecond})
	start := time.Now()
	ok, reason := c.Bound(context.Background(), "slow.example", netip.MustParseAddr("192.0.2.1"))
	if ok || reason != ReasonNameResolutionFailed {
		t.Fatalf("Bound = %v, %q; want not bound, %q", ok, reason, ReasonNameResolutionFailed)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("lookup took %v, want it bounded by the 50ms timeout", d)
	}
}

func TestNameBindingCache_EntryCap(t *testing.T) {
	r := &fakeNameResolver{answers: map[string][]netip.Addr{}}
	for i := 0; i < 100; i++ {
		r.answers[fmt.Sprintf("h%d.example", i)] = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	}
	c := NewNameBindingCache(r, NameBindingConfig{MaxEntries: 10})
	for i := 0; i < 100; i++ {
		_, _ = c.Bound(context.Background(), fmt.Sprintf("h%d.example", i), netip.MustParseAddr("192.0.2.1"))
		if n := c.Len(); n > 10 {
			t.Fatalf("cache holds %d entries after %d names, cap 10", n, i+1)
		}
	}
	if c.Len() == 0 {
		t.Fatal("cache holds no entries")
	}
}

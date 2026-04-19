package pool

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// fakeLayer: a poolLayer test-double driven by atomic counters. Used for the
// vast majority of tests to keep runtime low.
// -----------------------------------------------------------------------------

type fakeLayer struct {
	id                string
	active            atomic.Int32
	peerMax           atomic.Uint32
	lastErrMu         sync.Mutex
	lastErr           error
	closeBlockCh      chan struct{} // when non-nil, Close blocks on it
	closed            atomic.Bool
	closeCount        atomic.Int32
	closeInstrumented func()
}

func newFakeLayer(id string) *fakeLayer { return &fakeLayer{id: id} }

func (f *fakeLayer) ActiveStreamCount() int           { return int(f.active.Load()) }
func (f *fakeLayer) PeerMaxConcurrentStreams() uint32 { return f.peerMax.Load() }

func (f *fakeLayer) LastReaderError() error {
	f.lastErrMu.Lock()
	defer f.lastErrMu.Unlock()
	return f.lastErr
}

func (f *fakeLayer) setReaderErr(err error) {
	f.lastErrMu.Lock()
	f.lastErr = err
	f.lastErrMu.Unlock()
}

func (f *fakeLayer) Close() error {
	f.closeCount.Add(1)
	if ch := f.closeBlockCh; ch != nil {
		<-ch
	}
	f.closed.Store(true)
	if f.closeInstrumented != nil {
		f.closeInstrumented()
	}
	return nil
}

// -----------------------------------------------------------------------------
// Helpers that drive the Pool through its fakeLayer-aware internal API.
// Production code uses Get/Put with *http2.Layer; tests want to use fakes too.
// We piggyback on getAny / putLayer / evictLayer which accept poolLayer.
// -----------------------------------------------------------------------------

func putFake(t *testing.T, p *Pool, key PoolKey, l *fakeLayer) {
	t.Helper()
	p.putLayer(key, l)
}

func getFake(t *testing.T, p *Pool, key PoolKey) (*fakeLayer, error) {
	t.Helper()
	l, err := p.getAny(key)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, nil
	}
	f, ok := l.(*fakeLayer)
	if !ok {
		t.Fatalf("getAny returned %T, want *fakeLayer", l)
	}
	return f, nil
}

// -----------------------------------------------------------------------------
// Fixed-time clocks for deterministic TTL tests.
// -----------------------------------------------------------------------------

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestGet_Miss(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	l, err := p.Get(key)
	if err != nil {
		t.Fatalf("Get miss err: %v", err)
	}
	if l != nil {
		t.Fatalf("Get miss returned non-nil Layer")
	}
}

func TestPutGet_Same(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")
	putFake(t, p, key, fake)
	got, err := getFake(t, p, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != fake {
		t.Fatalf("Get returned different fake: got %p want %p", got, fake)
	}
}

// TestPublicGet_FakeMaskedAsMiss confirms the public Get API's type assertion
// path: a fake stored via putLayer is not leaked through the public *http2.Layer
// return — Get instead reports a miss. Production callers never put fakes, so
// this is defensive but documents the boundary.
func TestPublicGet_FakeMaskedAsMiss(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")
	putFake(t, p, key, fake)

	l, err := p.Get(key)
	if err != nil {
		t.Fatalf("public Get: %v", err)
	}
	if l != nil {
		t.Fatalf("public Get returned non-*http2.Layer entry: %v", l)
	}
}

func TestPutTwice_TwoEntries(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	f1 := newFakeLayer("a")
	f2 := newFakeLayer("b")
	putFake(t, p, key, f1)
	putFake(t, p, key, f2)

	// Both hold one slot. Get once → one of them; Get again → the other
	// (because inUseCount makes the first one still eligible if it's under
	// cap, so we can't rely on uniqueness unless we fill the cap).
	g1, err := getFake(t, p, key)
	if err != nil || g1 == nil {
		t.Fatalf("first Get: %v %v", g1, err)
	}
	g2, err := getFake(t, p, key)
	if err != nil || g2 == nil {
		t.Fatalf("second Get: %v %v", g2, err)
	}
	// Both slots are held. Ensure the pool still knows about both entries.
	p.mu.Lock()
	n := len(p.entries[key])
	p.mu.Unlock()
	if n != 2 {
		t.Fatalf("want 2 entries, got %d", n)
	}
}

func TestMaxStreamsPerConn_Cap(t *testing.T) {
	p := New(PoolOptions{MaxStreamsPerConn: 2})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")
	putFake(t, p, key, fake)

	// 1st and 2nd Get succeed; 3rd must miss.
	if g, err := getFake(t, p, key); g == nil || err != nil {
		t.Fatalf("1st get: %v %v", g, err)
	}
	if g, err := getFake(t, p, key); g == nil || err != nil {
		t.Fatalf("2nd get: %v %v", g, err)
	}
	if g, err := getFake(t, p, key); g != nil || err != nil {
		t.Fatalf("3rd get: want nil,nil got %v %v", g, err)
	}
}

func TestPeerMaxConcurrentStreams_Cap(t *testing.T) {
	p := New(PoolOptions{MaxStreamsPerConn: 100})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")
	fake.peerMax.Store(1)
	putFake(t, p, key, fake)

	if g, err := getFake(t, p, key); g == nil || err != nil {
		t.Fatalf("1st get: %v %v", g, err)
	}
	// Peer only allows 1 concurrent stream → 2nd Get must miss.
	if g, err := getFake(t, p, key); g != nil || err != nil {
		t.Fatalf("2nd get: want nil,nil got %v %v", g, err)
	}

	// Now test ActiveStreamCount cross-check: different layer, peer=0
	// (unbounded), but active count already high.
	key2 := PoolKey{HostPort: "example2:443", TLSConfigHash: "abc"}
	f2 := newFakeLayer("b")
	f2.active.Store(100)
	putFake(t, p, key2, f2)
	if g, err := getFake(t, p, key2); g != nil || err != nil {
		t.Fatalf("active-count cap: want nil,nil got %v %v", g, err)
	}
}

func TestIdleTimeout_Eviction(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	p := New(PoolOptions{IdleTimeout: 60 * time.Second, NowFn: clk.Now})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")
	putFake(t, p, key, fake)

	clk.Advance(61 * time.Second)
	got, err := getFake(t, p, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("Get should miss after idle timeout, got %v", got)
	}
	// fake should have been closed.
	waitUntil(t, func() bool { return fake.closeCount.Load() > 0 })
}

func TestLRU_EvictOnOverflow(t *testing.T) {
	p := New(PoolOptions{MaxIdleConns: 2})
	defer p.Close()
	k1 := PoolKey{HostPort: "h1:443", TLSConfigHash: "x"}
	k2 := PoolKey{HostPort: "h2:443", TLSConfigHash: "x"}
	k3 := PoolKey{HostPort: "h3:443", TLSConfigHash: "x"}
	f1 := newFakeLayer("1")
	f2 := newFakeLayer("2")
	f3 := newFakeLayer("3")
	putFake(t, p, k1, f1)
	putFake(t, p, k2, f2)
	putFake(t, p, k3, f3)

	// f1 (oldest) should be gone.
	waitUntil(t, func() bool { return f1.closeCount.Load() > 0 })
	g, err := getFake(t, p, k1)
	if err != nil || g != nil {
		t.Fatalf("k1 should have been evicted; got %v %v", g, err)
	}
}

// getOrDialFake is the fake-flavored analogue of GetOrDial. It goes through
// the same internal engine (getOrDialAny) that GetOrDial uses, so coverage
// of singleflight / capacity / error paths transfers 1:1 to the public API.
func getOrDialFake(t *testing.T, p *Pool, key PoolKey, dial func() (*fakeLayer, error)) (*fakeLayer, error) {
	t.Helper()
	adapt := func() (poolLayer, error) {
		l, err := dial()
		if err != nil {
			return nil, err
		}
		if l == nil {
			return nil, errors.New("dial returned nil fake")
		}
		return l, nil
	}
	l, err := p.getOrDialAny(context.Background(), key, adapt)
	if err != nil {
		return nil, err
	}
	f, ok := l.(*fakeLayer)
	if !ok {
		t.Fatalf("getOrDialAny returned %T, want *fakeLayer", l)
	}
	return f, nil
}

func TestGetOrDial_DialsOnMiss(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")

	var calls atomic.Int32
	got, err := getOrDialFake(t, p, key, func() (*fakeLayer, error) {
		calls.Add(1)
		return fake, nil
	})
	if err != nil {
		t.Fatalf("getOrDial: %v", err)
	}
	if got != fake {
		t.Fatalf("unexpected layer: got %p want %p", got, fake)
	}
	if calls.Load() != 1 {
		t.Fatalf("dial called %d times, want 1", calls.Load())
	}
	p.putLayer(key, got)
}

func TestGetOrDial_Singleflight(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")

	var dialCount atomic.Int32
	release := make(chan struct{})
	dial := func() (*fakeLayer, error) {
		dialCount.Add(1)
		<-release
		return fake, nil
	}

	const N = 10
	var wg sync.WaitGroup
	results := make([]*fakeLayer, N)
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l, err := getOrDialFake(t, p, key, dial)
			results[i] = l
			errs[i] = err
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := dialCount.Load(); got != 1 {
		t.Fatalf("dialFn called %d times, want 1", got)
	}
	for i, l := range results {
		if errs[i] != nil {
			t.Fatalf("caller %d error: %v", i, errs[i])
		}
		if l != fake {
			t.Fatalf("caller %d layer mismatch", i)
		}
	}

	// Each caller owes a Put. Return all slots.
	for _, l := range results {
		if l != nil {
			p.putLayer(key, l)
		}
	}
	// inUseCount should drop back to 0.
	p.mu.Lock()
	for _, e := range p.entries[key] {
		if e.inUseCount != 0 {
			t.Fatalf("after Put-all, inUseCount = %d, want 0", e.inUseCount)
		}
	}
	p.mu.Unlock()
}

func TestGetOrDial_UsesExistingPoolEntry(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")
	// Pre-populate.
	p.putLayer(key, fake)

	var dialCount atomic.Int32
	got, err := getOrDialFake(t, p, key, func() (*fakeLayer, error) {
		dialCount.Add(1)
		t.Fatalf("dialFn should not be called")
		return nil, errors.New("unreachable")
	})
	if err != nil {
		t.Fatalf("getOrDial: %v", err)
	}
	if got != fake {
		t.Fatalf("unexpected layer")
	}
	if dialCount.Load() != 0 {
		t.Fatalf("dialFn called %d times, want 0", dialCount.Load())
	}
	p.putLayer(key, got)
}

func TestGetOrDial_DialError(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	dialErr := errors.New("dial failure")
	_, err := getOrDialFake(t, p, key, func() (*fakeLayer, error) {
		return nil, dialErr
	})
	if !errors.Is(err, dialErr) {
		t.Fatalf("getOrDial err = %v, want %v", err, dialErr)
	}
	// Pool should not contain an entry for the failed dial.
	p.mu.Lock()
	n := len(p.entries[key])
	p.mu.Unlock()
	if n != 0 {
		t.Fatalf("failed dial leaked entry: %d", n)
	}
}

func TestEvict_RemovesFromPool(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("a")
	putFake(t, p, key, fake)
	p.evictLayer(key, fake)
	g, err := getFake(t, p, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g != nil {
		t.Fatalf("evicted entry still present: %v", g)
	}
	waitUntil(t, func() bool { return fake.closeCount.Load() > 0 })
}

func TestEvict_UnknownLayer_NoOp(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "example:443", TLSConfigHash: "abc"}
	fake := newFakeLayer("orphan")
	// Not inserted. Evict should just close it.
	p.evictLayer(key, fake)
	if fake.closeCount.Load() != 1 {
		t.Fatalf("orphan evict should close fake once, got %d", fake.closeCount.Load())
	}
}

func TestClose_ClosesPooledLayers(t *testing.T) {
	p := New(PoolOptions{})
	k1 := PoolKey{HostPort: "h1:443", TLSConfigHash: "x"}
	k2 := PoolKey{HostPort: "h2:443", TLSConfigHash: "x"}
	f1 := newFakeLayer("1")
	f2 := newFakeLayer("2")
	putFake(t, p, k1, f1)
	putFake(t, p, k2, f2)

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if f1.closeCount.Load() != 1 {
		t.Fatalf("f1 not closed")
	}
	if f2.closeCount.Load() != 1 {
		t.Fatalf("f2 not closed")
	}
	// Rejects further ops.
	if _, err := p.Get(k1); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get after Close: want ErrClosed, got %v", err)
	}
}

func TestClose_Parallel_Bounded(t *testing.T) {
	p := New(PoolOptions{})
	key := PoolKey{HostPort: "h:443", TLSConfigHash: "x"}
	// Layers that block forever in Close → Close should return timeout.
	block := make(chan struct{})
	// Leave channel open so Close blocks.
	_ = block
	f1 := newFakeLayer("1")
	f1.closeBlockCh = block
	f2 := newFakeLayer("2")
	f2.closeBlockCh = block
	putFake(t, p, key, f1)
	putFake(t, p, key, f2)

	start := time.Now()
	err := p.Close()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Close should have reported timeout")
	}
	// Parallel: total time ~= 1s outer bound, not 2s.
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("Close took %v, expected ~1s outer bound", elapsed)
	}
	close(block) // let goroutines drain so we don't leak them past test end
}

func TestClose_Idempotent(t *testing.T) {
	p := New(PoolOptions{})
	if err := p.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestClosedPool_RejectsOps(t *testing.T) {
	p := New(PoolOptions{})
	_ = p.Close()
	key := PoolKey{HostPort: "h:443", TLSConfigHash: "x"}
	if _, err := p.Get(key); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get: want ErrClosed, got %v", err)
	}
	// Put on a closed pool: should close the fake.
	f := newFakeLayer("x")
	p.putLayer(key, f)
	if f.closeCount.Load() != 1 {
		t.Fatalf("Put on closed pool should close layer, got %d", f.closeCount.Load())
	}
	// GetOrDial: closed pool → ErrClosed, no dial.
	var dialed atomic.Int32
	_, err := getOrDialFake(t, p, key, func() (*fakeLayer, error) {
		dialed.Add(1)
		return nil, errors.New("should not reach")
	})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("GetOrDial on closed pool: want ErrClosed, got %v", err)
	}
	if dialed.Load() != 0 {
		t.Fatalf("dialFn called on closed pool")
	}
}

func TestLivenessProbe_DeadReader(t *testing.T) {
	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "h:443", TLSConfigHash: "x"}
	fake := newFakeLayer("dead")
	fake.setReaderErr(errors.New("broken pipe"))
	putFake(t, p, key, fake)

	g, err := getFake(t, p, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g != nil {
		t.Fatalf("dead layer should not be returned")
	}
	waitUntil(t, func() bool { return fake.closeCount.Load() > 0 })
}

func TestConcurrent_GetPutEvict_NoRace(t *testing.T) {
	p := New(PoolOptions{MaxIdleConns: 8, MaxStreamsPerConn: 16})
	defer p.Close()
	keys := []PoolKey{
		{HostPort: "h1:443", TLSConfigHash: "x"},
		{HostPort: "h2:443", TLSConfigHash: "x"},
		{HostPort: "h3:443", TLSConfigHash: "x"},
	}
	const numGoroutines = 16
	duration := 300 * time.Millisecond

	fakes := make([]*fakeLayer, 32)
	for i := range fakes {
		fakes[i] = newFakeLayer("f")
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for {
				select {
				case <-stop:
					return
				default:
				}
				k := keys[r.Intn(len(keys))]
				switch r.Intn(4) {
				case 0:
					_, _ = getFake(t, p, k)
				case 1:
					p.putLayer(k, fakes[r.Intn(len(fakes))])
				case 2:
					p.evictLayer(k, fakes[r.Intn(len(fakes))])
				case 3:
					_, _ = p.Get(k) // returns nil because layer is fake, but exercises locks
				}
			}
		}(int64(i))
	}
	time.Sleep(duration)
	close(stop)
	wg.Wait()
}

func TestHashTLSConfig_Deterministic(t *testing.T) {
	a := HashTLSConfig([]byte("serverName=example.com;alpn=h2"))
	b := HashTLSConfig([]byte("serverName=example.com;alpn=h2"))
	c := HashTLSConfig([]byte("serverName=other.com;alpn=h2"))
	if a != b {
		t.Fatalf("same input produced different hashes: %s vs %s", a, b)
	}
	if a == c {
		t.Fatalf("different input produced same hash")
	}
	if len(a) != 16 {
		t.Fatalf("hash length = %d, want 16", len(a))
	}
}

func TestPoolKey_String(t *testing.T) {
	k := PoolKey{HostPort: "example:443", TLSConfigHash: "abcd"}
	if got := k.String(); got != "example:443|abcd" {
		t.Fatalf("String = %q", got)
	}
}

// waitUntil polls cond() at 10ms intervals up to 500ms. Useful when a pool
// operation triggers an async Close goroutine.
func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waitUntil: condition not satisfied")
}

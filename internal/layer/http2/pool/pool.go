package pool

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	http2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// Defaults used when PoolOptions leaves a field at its zero value.
const (
	defaultMaxIdleConns      = 100
	defaultIdleTimeout       = 90 * time.Second
	defaultMaxStreamsPerConn = 100
	closeAllTimeout          = 1 * time.Second
)

// ErrClosed is returned by Get / Put / GetOrDial once the pool has been closed.
var ErrClosed = errors.New("http2/pool: pool closed")

// PoolKey identifies a pooled upstream connection.
type PoolKey struct {
	HostPort      string
	TLSConfigHash string
}

// String returns a stable identifier suitable as a singleflight key.
func (k PoolKey) String() string { return k.HostPort + "|" + k.TLSConfigHash }

// PoolOptions configures a Pool.
type PoolOptions struct {
	MaxIdleConns      int
	IdleTimeout       time.Duration
	MaxStreamsPerConn int
	NowFn             func() time.Time
}

func (o *PoolOptions) withDefaults() {
	if o.MaxIdleConns <= 0 {
		o.MaxIdleConns = defaultMaxIdleConns
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = defaultIdleTimeout
	}
	if o.MaxStreamsPerConn <= 0 {
		o.MaxStreamsPerConn = defaultMaxStreamsPerConn
	}
	if o.NowFn == nil {
		o.NowFn = time.Now
	}
}

// poolLayer is the subset of *http2.Layer behavior the Pool relies on.
// Kept unexported so tests can substitute a fake without widening the
// package's public surface.
type poolLayer interface {
	ActiveStreamCount() int
	PeerMaxConcurrentStreams() uint32
	LastReaderError() error
	Close() error
}

// entry holds one pooled Layer and the bookkeeping needed for LRU / timeout
// decisions.
type entry struct {
	key        PoolKey
	layer      poolLayer
	lastUsed   time.Time
	inUseCount int
	elem       *list.Element // pointer into Pool.lru (nil if removed)
}

// Pool is a per-target cache of upstream *http2.Layer instances.
type Pool struct {
	mu      sync.Mutex
	entries map[PoolKey][]*entry
	lru     *list.List // values are *entry, front = MRU
	sfGroup singleflight.Group
	opts    PoolOptions
	closed  bool
}

// New constructs a Pool. Zero-valued PoolOptions fields pick sensible defaults.
func New(opts PoolOptions) *Pool {
	opts.withDefaults()
	return &Pool{
		entries: make(map[PoolKey][]*entry),
		lru:     list.New(),
		opts:    opts,
	}
}

// Get returns a usable Layer for key if one is present. Callers MUST pair
// each non-nil return with Put. Returns (nil, nil) on a pool miss, and
// (nil, ErrClosed) if the pool has been closed.
func (p *Pool) Get(key PoolKey) (*http2.Layer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	e := p.selectLocked(key)
	if e == nil {
		slog.Debug("h2pool miss", "key", key.String())
		return nil, nil
	}
	// Type-assert back to *http2.Layer at the boundary. Internal entries may
	// hold a test fake, so we only return the real type when the caller is
	// allowed to see one.
	l, ok := e.layer.(*http2.Layer)
	if !ok {
		// Fake-only entry — shouldn't be reachable via the public API but
		// degrade gracefully by treating it as a miss.
		return nil, nil
	}
	slog.Debug("h2pool hit", "key", key.String(), "in_use", e.inUseCount)
	return l, nil
}

// getAny is the internal variant used by tests — it returns the stored
// poolLayer (which may be a fake). Not exposed publicly.
func (p *Pool) getAny(key PoolKey) (poolLayer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	e := p.selectLocked(key)
	if e == nil {
		return nil, nil
	}
	return e.layer, nil
}

// selectLocked picks the first usable entry for key. Caller must hold p.mu.
// Performs idle-timeout pruning and liveness checks while scanning. Returns
// the chosen entry (with inUseCount already incremented) or nil.
func (p *Pool) selectLocked(key PoolKey) *entry {
	now := p.opts.NowFn()
	bucket := p.entries[key]
	// Phase 1: decide which entries survive the scan. Drop decisions are
	// staged into a dead list and applied after we've finished reading the
	// original bucket slice to avoid mutating the backing array in place.
	kept := make([]*entry, 0, len(bucket))
	var dead []*entry
	var pick *entry
	for _, e := range bucket {
		if e.inUseCount == 0 && now.Sub(e.lastUsed) > p.opts.IdleTimeout {
			dead = append(dead, e)
			slog.Debug("h2pool idle-timeout evict", "key", key.String())
			continue
		}
		if e.layer.LastReaderError() != nil {
			dead = append(dead, e)
			slog.Debug("h2pool dead-reader evict", "key", key.String())
			continue
		}
		kept = append(kept, e)
		if pick == nil && p.hasCapacityLocked(e) {
			pick = e
		}
	}
	if len(kept) == 0 {
		delete(p.entries, key)
	} else {
		p.entries[key] = kept
	}
	for _, e := range dead {
		p.removeFromLRULocked(e)
		go func(l poolLayer) { _ = l.Close() }(e.layer)
	}
	if pick != nil {
		pick.inUseCount++
	}
	return pick
}

// removeFromLRULocked unlinks e from the LRU list. Caller holds p.mu.
func (p *Pool) removeFromLRULocked(e *entry) {
	if e.elem != nil {
		p.lru.Remove(e.elem)
		e.elem = nil
	}
}

// hasCapacityLocked reports whether the Layer backing e can accept another
// stream without exceeding local or peer concurrency caps.
func (p *Pool) hasCapacityLocked(e *entry) bool {
	limit := uint32(p.opts.MaxStreamsPerConn)
	peer := e.layer.PeerMaxConcurrentStreams()
	if peer > 0 && peer < limit {
		limit = peer
	}
	if uint32(e.inUseCount) >= limit {
		return false
	}
	// Cross-check against the Layer's own view of active streams; covers
	// callers who forgot to Put.
	if uint32(e.layer.ActiveStreamCount()) >= limit {
		return false
	}
	return true
}

// Put returns a borrowed Layer to the pool (or registers a freshly-dialed
// one). It updates lastUsed, decrements inUseCount, and applies
// LRU / idle-timeout bookkeeping.
func (p *Pool) Put(key PoolKey, l *http2.Layer) {
	if l == nil {
		return
	}
	p.putLayer(key, l)
}

// putLayer is the poolLayer-typed variant used by GetOrDial and tests.
func (p *Pool) putLayer(key PoolKey, l poolLayer) {
	if l == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = l.Close()
		return
	}
	now := p.opts.NowFn()
	var found *entry
	for _, e := range p.entries[key] {
		if e.layer == l {
			found = e
			break
		}
	}
	if found != nil {
		found.lastUsed = now
		if found.inUseCount > 0 {
			found.inUseCount--
		}
		if found.elem != nil {
			p.lru.MoveToFront(found.elem)
		}
	} else {
		found = &entry{
			key:      key,
			layer:    l,
			lastUsed: now,
		}
		found.elem = p.lru.PushFront(found)
		p.entries[key] = append(p.entries[key], found)
		slog.Debug("h2pool insert", "key", key.String())
	}
	p.pruneIdleLocked()
	p.enforceMaxIdleLocked()
	p.mu.Unlock()
}

// pruneIdleLocked drops entries that have been idle past IdleTimeout.
// Caller holds p.mu.
func (p *Pool) pruneIdleLocked() {
	now := p.opts.NowFn()
	var dead []*entry
	for key, bucket := range p.entries {
		kept := make([]*entry, 0, len(bucket))
		for _, e := range bucket {
			if e.inUseCount == 0 && now.Sub(e.lastUsed) > p.opts.IdleTimeout {
				dead = append(dead, e)
				continue
			}
			kept = append(kept, e)
		}
		if len(kept) == 0 {
			delete(p.entries, key)
		} else {
			p.entries[key] = kept
		}
	}
	for _, e := range dead {
		p.removeFromLRULocked(e)
		go func(l poolLayer) { _ = l.Close() }(e.layer)
	}
}

// enforceMaxIdleLocked evicts least-recently-used idle entries until the
// total idle-capable entry count is within MaxIdleConns. Caller holds p.mu.
func (p *Pool) enforceMaxIdleLocked() {
	idle := 0
	for _, bucket := range p.entries {
		for _, e := range bucket {
			if e.inUseCount == 0 {
				idle++
			}
		}
	}
	for idle > p.opts.MaxIdleConns {
		// Walk LRU back-to-front finding the oldest idle entry.
		var victim *entry
		for el := p.lru.Back(); el != nil; el = el.Prev() {
			e := el.Value.(*entry)
			if e.inUseCount == 0 {
				victim = e
				break
			}
		}
		if victim == nil {
			return
		}
		p.dropEntryLocked(victim)
		slog.Debug("h2pool lru evict", "key", victim.key.String())
		idle--
	}
}

// dropEntryLocked removes e from the pool's tracking structures and closes
// the underlying Layer. Caller holds p.mu.
func (p *Pool) dropEntryLocked(e *entry) {
	bucket := p.entries[e.key]
	kept := bucket[:0]
	for _, x := range bucket {
		if x != e {
			kept = append(kept, x)
		}
	}
	if len(kept) == 0 {
		delete(p.entries, e.key)
	} else {
		p.entries[e.key] = kept
	}
	if e.elem != nil {
		p.lru.Remove(e.elem)
		e.elem = nil
	}
	go func(l poolLayer) { _ = l.Close() }(e.layer)
}

// GetOrDial returns a usable Layer for key, dialing through dialFn if no
// pooled Layer is available. Concurrent calls for the same key coalesce via
// singleflight. Callers MUST call Put when they are done with the returned
// Layer.
func (p *Pool) GetOrDial(ctx context.Context, key PoolKey, dialFn func() (*http2.Layer, error)) (*http2.Layer, error) {
	if dialFn == nil {
		return nil, errors.New("http2/pool: dialFn is nil")
	}
	adapt := func() (poolLayer, error) {
		l, err := dialFn()
		if err != nil {
			return nil, err
		}
		if l == nil {
			return nil, errors.New("http2/pool: dialFn returned nil Layer")
		}
		return l, nil
	}
	l, err := p.getOrDialAny(ctx, key, adapt)
	if err != nil {
		return nil, err
	}
	layer, ok := l.(*http2.Layer)
	if !ok {
		return nil, errors.New("http2/pool: pooled layer is not *http2.Layer")
	}
	return layer, nil
}

// getOrDialAny is the poolLayer-typed engine behind GetOrDial. Exposed to the
// test package via an internal helper in pool_test.go.
func (p *Pool) getOrDialAny(ctx context.Context, key PoolKey, dialFn func() (poolLayer, error)) (poolLayer, error) {
	// Fast path: pool hit.
	if l, err := p.getAny(key); err != nil {
		return nil, err
	} else if l != nil {
		return l, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, err, _ := p.sfGroup.Do(key.String(), func() (any, error) {
		// Another goroutine may have populated the pool while we waited.
		if l, err := p.getAny(key); err != nil {
			return nil, err
		} else if l != nil {
			// getAny already bumped inUseCount. Release it here so the
			// per-caller increment below reads as the single owner.
			p.releaseSlot(key, l)
			return l, nil
		}
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return nil, ErrClosed
		}
		slog.Debug("h2pool dial", "key", key.String())
		l, derr := dialFn()
		if derr != nil {
			return nil, derr
		}
		// Insert fresh — inUseCount starts at 0. Per-caller increment
		// happens below (outside the singleflight closure) so shared
		// callers each get a slot.
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			_ = l.Close()
			return nil, ErrClosed
		}
		now := p.opts.NowFn()
		e := &entry{
			key:      key,
			layer:    l,
			lastUsed: now,
		}
		e.elem = p.lru.PushFront(e)
		p.entries[key] = append(p.entries[key], e)
		p.enforceMaxIdleLocked()
		p.mu.Unlock()
		return l, nil
	})
	if err != nil {
		return nil, err
	}
	layer := v.(poolLayer)
	// Every caller (dialer or shared waiter) owes a Put. Increment the
	// entry's inUseCount on their behalf now.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	for _, e := range p.entries[key] {
		if e.layer == layer {
			e.inUseCount++
			break
		}
	}
	p.mu.Unlock()
	return layer, nil
}

// releaseSlot decrements inUseCount for the entry holding l under key. Used
// to undo a getAny increment when the caller decides not to take ownership.
func (p *Pool) releaseSlot(key PoolKey, l poolLayer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries[key] {
		if e.layer == l {
			if e.inUseCount > 0 {
				e.inUseCount--
			}
			e.lastUsed = p.opts.NowFn()
			if e.elem != nil {
				p.lru.MoveToFront(e.elem)
			}
			return
		}
	}
}

// Evict removes a known-dead Layer from the pool and closes it. Safe to call
// with a Layer that has already been removed.
func (p *Pool) Evict(key PoolKey, l *http2.Layer) {
	if l == nil {
		return
	}
	p.evictLayer(key, l)
}

func (p *Pool) evictLayer(key PoolKey, l poolLayer) {
	p.mu.Lock()
	var target *entry
	for _, e := range p.entries[key] {
		if e.layer == l {
			target = e
			break
		}
	}
	if target != nil {
		// dropEntryLocked closes the layer in a goroutine, which is fine for
		// the pool's invariants but means callers can't observe Close errors.
		p.dropEntryLocked(target)
		p.mu.Unlock()
		slog.Debug("h2pool evict", "key", key.String())
		return
	}
	p.mu.Unlock()
	// Not in pool; close defensively so the caller's "dead layer" is actually
	// torn down.
	_ = l.Close()
	slog.Debug("h2pool evict-orphan", "key", key.String())
}

// Close closes every pooled Layer in parallel, bounded at closeAllTimeout.
// Further Get / Put / GetOrDial calls return ErrClosed.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	layers := make([]poolLayer, 0)
	for _, bucket := range p.entries {
		for _, e := range bucket {
			if e.elem != nil {
				p.lru.Remove(e.elem)
				e.elem = nil
			}
			layers = append(layers, e.layer)
		}
	}
	p.entries = make(map[PoolKey][]*entry)
	p.mu.Unlock()

	if len(layers) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(layers))
	for _, l := range layers {
		wg.Add(1)
		go func(l poolLayer) {
			defer wg.Done()
			if err := l.Close(); err != nil {
				errCh <- err
			}
		}(l)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(closeAllTimeout):
		return errors.New("http2/pool: Close timed out")
	}
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// HashTLSConfig returns a short deterministic hex digest of the canonical
// bytes describing a TLS config. Callers are responsible for choosing a
// canonical byte form covering the TLS knobs that affect identity
// (ServerName, NextProtos, InsecureSkipVerify, Certificates, RootCAs, etc).
func HashTLSConfig(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:8])
}

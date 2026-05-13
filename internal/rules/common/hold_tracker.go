package common

import (
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// HoldTracker records whether a (StreamID, Direction) tuple has an in-flight
// hold inside the intercept HoldQueue. The session relay goroutines query
// the tracker on each WS hold-window keepalive tick: a hit means "keep
// injecting Pings", a miss means "the hold cleared, stop the keepalive
// goroutine". USK-854 is the first consumer.
//
// Lifecycle. One instance is constructed at MCP server startup and shared
// with the live data path via session.SessionOptions and the InterceptStep.
// InterceptStep stamps MarkHold before HoldQueue.Hold blocks and ForgetHold
// after Hold returns, regardless of the resolved HoldAction.
//
// The tracker mirrors the shape of ReleaseTracker (USK-851): a single
// sync.Mutex-guarded map, nil-receiver no-ops, lazy retention pruning, and
// no goroutines of its own. This is the second tracker in the package; the
// two encode orthogonal states (hold in flight vs. recently released) and
// are independent.
//
// Concurrency. All exported methods are safe for concurrent use. The
// internal map is guarded by a single sync.Mutex — contention is bounded
// by the number of intercept holds + tick reads per second, which is
// operator-driven (manual review pace) and therefore very low.
//
// MITM principle 6 (pre-implementation reality check): the tracker only
// records timestamps. A tracker outage degrades to "no keepalive injection"
// — the upstream connection may still half-close on idle, but no wire
// behaviour worsens vs. the USK-851 baseline.
type HoldTracker struct {
	mu        sync.Mutex
	entries   map[holdKey]time.Time
	retention time.Duration
}

// holdKey is the composite map key. envelope.Direction is small enough to
// use directly; the StreamID carries the canonical per-Stream identity.
type holdKey struct {
	streamID  string
	direction envelope.Direction
}

// defaultHoldRetention is the soft TTL after which a hold entry is
// considered stale and pruned on next access. The session-side keepalive
// goroutine ticks at ~5s; a 1-hour retention is generous and accommodates
// long human-review holds without unbounded growth. A leaked entry (an
// InterceptStep code path that called MarkHold but forgot ForgetHold)
// times out instead of pinning memory for the proxy's lifetime.
const defaultHoldRetention = 1 * time.Hour

// NewHoldTracker constructs a HoldTracker with the default retention.
// A nil HoldTracker is a valid no-op recipient.
func NewHoldTracker() *HoldTracker {
	return &HoldTracker{
		entries:   make(map[holdKey]time.Time),
		retention: defaultHoldRetention,
	}
}

// MarkHold records that the supplied (streamID, direction) tuple is
// currently held in the intercept queue. InterceptStep calls MarkHold
// before HoldQueue.Hold blocks. Empty streamID is a no-op so the caller
// can forward the held envelope's StreamID unconditionally.
//
// A nil receiver is a no-op.
func (t *HoldTracker) MarkHold(streamID string, direction envelope.Direction, ts time.Time) {
	if t == nil || streamID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[holdKey{streamID: streamID, direction: direction}] = ts
	t.pruneLocked(ts)
}

// ForgetHold removes the entry for (streamID, direction). Called by
// InterceptStep after HoldQueue.Hold returns (regardless of the resolved
// HoldAction) so the keepalive goroutine observes the hold cleared.
//
// A nil receiver and empty streamID are both no-ops.
func (t *HoldTracker) ForgetHold(streamID string, direction envelope.Direction) {
	if t == nil || streamID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, holdKey{streamID: streamID, direction: direction})
}

// IsHeld reports whether a hold is currently recorded for the supplied
// (streamID, direction) tuple. The session keepalive goroutine polls this
// on each tick: true → inject a Ping and tick again; false → terminate
// the goroutine cleanly.
//
// A nil receiver returns false so the caller can poll unconditionally.
func (t *HoldTracker) IsHeld(streamID string, direction envelope.Direction) bool {
	if t == nil || streamID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.entries[holdKey{streamID: streamID, direction: direction}]
	return ok
}

// ForgetStream removes all hold entries recorded for the supplied
// streamID across both directions. Called at Stream teardown so the map
// does not grow unbounded for long-running proxies that see many Streams
// with intercepts. Mirrors ReleaseTracker.ForgetStream so the production
// teardown wiring can call both unconditionally.
//
// A nil receiver and empty streamID are both no-ops.
func (t *HoldTracker) ForgetStream(streamID string) {
	if t == nil || streamID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, holdKey{streamID: streamID, direction: envelope.Send})
	delete(t.entries, holdKey{streamID: streamID, direction: envelope.Receive})
}

// Len returns the number of entries currently tracked. Test-only accessor.
func (t *HoldTracker) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// pruneLocked drops entries older than the retention window. Mirrors
// ReleaseTracker.pruneLocked — piggy-backing on each MarkHold access
// avoids a dedicated pruning goroutine. IsHeld and ForgetHold do not
// prune; they are hot-path reads driven by the keepalive tick and should
// stay branch-free of timestamp comparisons.
func (t *HoldTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-t.retention)
	for k, ts := range t.entries {
		if ts.Before(cutoff) {
			delete(t.entries, k)
		}
	}
}

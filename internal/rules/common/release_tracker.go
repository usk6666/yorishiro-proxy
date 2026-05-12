package common

import (
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// ReleaseTracker records the most recent intercept-release timestamp per
// (StreamID, Direction) tuple. The session relay goroutines query the
// tracker on EOF to detect the "long intercept hold caused upstream
// half-close" condition surfaced by USK-851.
//
// Lifecycle. One instance is constructed at MCP server startup and shared
// with the live data path via session.SessionOptions and the MCP intercept
// tool. Entries are pruned lazily on every MarkRelease, LookupOppositeRelease,
// and LookupAndForgetOpposite call when they observe entries older than
// retention.
//
// Concurrency. All exported methods are safe for concurrent use. The
// internal map is guarded by a single sync.Mutex — contention is bounded
// by the number of in-flight releases per second, which is operator-driven
// (manual review pace) and therefore very low.
//
// MITM principle 6 (pre-implementation reality check): the tracker only
// records timestamps. It does not mutate wire data, does not block, and
// does not introduce new failure modes — a tracker outage degrades to
// "no operator-facing tag" without affecting the wire path.
type ReleaseTracker struct {
	mu        sync.Mutex
	entries   map[releaseKey]time.Time
	retention time.Duration
}

// releaseKey is the composite map key for ReleaseTracker. envelope.Direction
// is small enough to use directly; the StreamID carries the canonical
// per-Stream identity already unified by upstreamToClient.
type releaseKey struct {
	streamID  string
	direction envelope.Direction
}

// defaultReleaseRetention is the soft TTL after which a release timestamp is
// considered stale and pruned on next access. The session-side detection
// window is much shorter (2s), so a 10s retention leaves headroom for
// pumps that run on slightly delayed scheduling. The constant intentionally
// is NOT exposed as configuration — see USK-851 design review decision U4.
const defaultReleaseRetention = 10 * time.Second

// NewReleaseTracker constructs a ReleaseTracker with the default retention.
// A nil ReleaseTracker is a valid no-op recipient; callers that did not
// wire the tracker (e.g. tests with no MCP server) can pass nil to the
// data-path functions that accept *ReleaseTracker without nil checks at
// each call site.
func NewReleaseTracker() *ReleaseTracker {
	return &ReleaseTracker{
		entries:   make(map[releaseKey]time.Time),
		retention: defaultReleaseRetention,
	}
}

// MarkRelease records the supplied release timestamp for the
// (streamID, direction) tuple. The MCP intercept tool calls MarkRelease
// after HoldQueue.Release succeeds. Empty streamID is a no-op so the
// caller can forward the held envelope's StreamID unconditionally.
//
// A nil receiver is a no-op so the MCP tool path can avoid a nil check
// when the live data path did not install a tracker.
func (t *ReleaseTracker) MarkRelease(streamID string, direction envelope.Direction, ts time.Time) {
	if t == nil || streamID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[releaseKey{streamID: streamID, direction: direction}] = ts
	t.pruneLocked(ts)
}

// LookupOppositeRelease returns the most recent release timestamp recorded
// for the OPPOSITE of the supplied direction on the same stream, provided
// it falls within window of now. The "opposite" semantics encode the
// USK-851 detection rule: an EOF observed on the Receive side of a Stream
// is correlated with a recent Send-side release (and vice versa) — the
// released frame goes upstream on one direction, the EOF returns on the
// other.
//
// A nil receiver returns (zero, false) so the data path can call
// LookupOppositeRelease unconditionally without first nil-checking.
func (t *ReleaseTracker) LookupOppositeRelease(streamID string, direction envelope.Direction, now time.Time, window time.Duration) (time.Time, bool) {
	if t == nil || streamID == "" {
		return time.Time{}, false
	}
	opposite := oppositeDirection(direction)
	t.mu.Lock()
	defer t.mu.Unlock()
	// Prune expired entries here too so lookup-heavy workloads with rare
	// MarkRelease calls do not leave stale entries sitting indefinitely.
	t.pruneLocked(now)
	ts, ok := t.entries[releaseKey{streamID: streamID, direction: opposite}]
	if !ok {
		return time.Time{}, false
	}
	if window <= 0 || now.Sub(ts) > window {
		return time.Time{}, false
	}
	return ts, true
}

// LookupAndForgetOpposite returns the timestamp of the most recent release
// on the OPPOSITE direction of the supplied (streamID, currentDirection) if
// it occurred within window of now, and atomically clears the matching
// entry so the same release cannot be observed by a second caller. Returns
// (zero, false) if no matching entry exists or the entry has aged past
// window.
//
// This is preferred over LookupOppositeRelease + ForgetStream for the EOF
// detection callback path, where exactly-once semantics on a given Stream
// are required: concurrent EOF on both relay directions could otherwise
// each observe the opposite-direction release and fire the callback twice.
//
// A nil receiver returns (zero, false).
func (t *ReleaseTracker) LookupAndForgetOpposite(streamID string, currentDirection envelope.Direction, now time.Time, window time.Duration) (time.Time, bool) {
	if t == nil || streamID == "" {
		return time.Time{}, false
	}
	opposite := oppositeDirection(currentDirection)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	key := releaseKey{streamID: streamID, direction: opposite}
	ts, ok := t.entries[key]
	if !ok {
		return time.Time{}, false
	}
	if window <= 0 || now.Sub(ts) > window {
		return time.Time{}, false
	}
	// Atomically clear both directions for this stream so a subsequent
	// EOF on either relay goroutine cannot re-observe the same release.
	delete(t.entries, releaseKey{streamID: streamID, direction: envelope.Send})
	delete(t.entries, releaseKey{streamID: streamID, direction: envelope.Receive})
	return ts, true
}

// ForgetStream removes all release timestamps recorded for the supplied
// streamID across both directions. Called at Stream teardown so the map
// does not grow unbounded for long-running proxies that see many Streams
// with intercepts.
//
// A nil receiver and an empty streamID are both no-ops.
func (t *ReleaseTracker) ForgetStream(streamID string) {
	if t == nil || streamID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, releaseKey{streamID: streamID, direction: envelope.Send})
	delete(t.entries, releaseKey{streamID: streamID, direction: envelope.Receive})
}

// Len returns the number of entries currently tracked. Test-only accessor.
func (t *ReleaseTracker) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// pruneLocked drops entries older than the retention window. Called from
// MarkRelease, LookupOppositeRelease, and LookupAndForgetOpposite under the
// lock — piggy-backing on each access avoids a dedicated pruning goroutine
// (which would itself need a termination contract) and prevents stale
// entries from sitting indefinitely on lookup-heavy workloads with rare
// MarkRelease calls.
func (t *ReleaseTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-t.retention)
	for k, ts := range t.entries {
		if ts.Before(cutoff) {
			delete(t.entries, k)
		}
	}
}

// oppositeDirection returns Send for Receive, Receive for Send. Any other
// value (defensive — Direction is an enum with only the two values today)
// returns the same direction so the lookup acts as a no-op rather than
// fabricating a correlation.
func oppositeDirection(d envelope.Direction) envelope.Direction {
	switch d {
	case envelope.Send:
		return envelope.Receive
	case envelope.Receive:
		return envelope.Send
	default:
		return d
	}
}

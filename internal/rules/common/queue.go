package common

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// DefaultHoldTimeout is the default timeout for held envelopes.
const DefaultHoldTimeout = 5 * time.Minute

// DefaultMaxQueueItems is the maximum number of items the queue can hold.
// When exceeded, new items are auto-released to prevent memory exhaustion.
const DefaultMaxQueueItems = 100

// HeldEntry represents an envelope held in the queue awaiting action.
type HeldEntry struct {
	ID           string
	Envelope     *envelope.Envelope
	MatchedRules []string
	HeldAt       time.Time

	actionCh chan HoldAction // buffered(1) to prevent goroutine leaks
}

// HoldQueue manages held envelopes awaiting external action (from MCP
// tools or AI agents). Thread-safe.
type HoldQueue struct {
	mu       sync.Mutex
	items    map[string]*HeldEntry
	timeout  time.Duration
	behavior TimeoutBehavior
	maxItems int
}

// NewHoldQueue creates a new HoldQueue with default settings.
func NewHoldQueue() *HoldQueue {
	return &HoldQueue{
		items:    make(map[string]*HeldEntry),
		timeout:  DefaultHoldTimeout,
		behavior: TimeoutAutoRelease,
		maxItems: DefaultMaxQueueItems,
	}
}

// SetTimeout sets the timeout duration for held envelopes.
func (q *HoldQueue) SetTimeout(d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.timeout = d
}

// SetTimeoutBehavior sets what happens when held envelopes time out.
func (q *HoldQueue) SetTimeoutBehavior(b TimeoutBehavior) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.behavior = b
}

// SetMaxItems sets the maximum number of items the queue can hold.
// 0 or negative means unlimited.
func (q *HoldQueue) SetMaxItems(n int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.maxItems = n
}

// Timeout returns the current timeout duration applied to held entries.
func (q *HoldQueue) Timeout() time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.timeout
}

// TimeoutBehavior returns the current timeout-expiry behavior.
func (q *HoldQueue) TimeoutBehavior() TimeoutBehavior {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.behavior
}

// Hold enqueues an envelope and blocks until an action is received,
// the context is cancelled, or the timeout expires.
func (q *HoldQueue) Hold(ctx context.Context, env *envelope.Envelope, matchedRules []string) (*HoldAction, error) {
	id := uuid.New().String()
	actionCh := make(chan HoldAction, 1)

	entry := &HeldEntry{
		ID:           id,
		Envelope:     env.Clone(),
		MatchedRules: cloneStrings(matchedRules),
		HeldAt:       time.Now(),
		actionCh:     actionCh,
	}

	q.mu.Lock()
	// Check capacity.
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.mu.Unlock()
		return &HoldAction{Type: ActionRelease}, nil
	}
	q.items[id] = entry
	timeout := q.timeout
	behavior := q.behavior
	q.mu.Unlock()

	// Wait for action, context cancellation, or timeout.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case action := <-actionCh:
		return &action, nil
	case <-ctx.Done():
		q.remove(id)
		return nil, ctx.Err()
	case <-timer.C:
		q.remove(id)
		switch behavior {
		case TimeoutAutoDrop:
			return &HoldAction{Type: ActionDrop}, nil
		default:
			return &HoldAction{Type: ActionRelease}, nil
		}
	}
}

// Release provides an action for a held entry, unblocking the Hold() caller.
func (q *HoldQueue) Release(id string, action *HoldAction) error {
	q.mu.Lock()
	entry, ok := q.items[id]
	if !ok {
		q.mu.Unlock()
		return fmt.Errorf("held entry %q not found", id)
	}
	delete(q.items, id)
	q.mu.Unlock()

	entry.actionCh <- *action
	return nil
}

// List returns all currently held entries. Returns cloned envelopes.
func (q *HoldQueue) List() []*HeldEntry {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil
	}

	result := make([]*HeldEntry, 0, len(q.items))
	for _, entry := range q.items {
		result = append(result, &HeldEntry{
			ID:           entry.ID,
			Envelope:     entry.Envelope.Clone(),
			MatchedRules: cloneStrings(entry.MatchedRules),
			HeldAt:       entry.HeldAt,
		})
	}
	return result
}

// Get returns a specific held entry by ID.
func (q *HoldQueue) Get(id string) (*HeldEntry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	entry, ok := q.items[id]
	if !ok {
		return nil, fmt.Errorf("held entry %q not found", id)
	}
	return &HeldEntry{
		ID:           entry.ID,
		Envelope:     entry.Envelope.Clone(),
		MatchedRules: cloneStrings(entry.MatchedRules),
		HeldAt:       entry.HeldAt,
	}, nil
}

// Len returns the number of items in the queue.
func (q *HoldQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Clear removes all entries from the queue and signals any goroutines
// currently blocked in Hold() with a default action derived from the
// configured TimeoutBehavior (Release for TimeoutAutoRelease, Drop for
// TimeoutAutoDrop). Without this signal, blocked goroutines would stay
// parked until their per-call timeout fires (default 5min). The
// per-entry actionCh is buffered(1), so the send is non-blocking under
// the lock — at most one observer per entry.
func (q *HoldQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	defaultAction := HoldAction{Type: ActionRelease}
	if q.behavior == TimeoutAutoDrop {
		defaultAction = HoldAction{Type: ActionDrop}
	}
	for _, entry := range q.items {
		// Non-blocking send: actionCh is buffered(1) and Hold() drains
		// at most once. A second sender (e.g. a concurrent Release that
		// already delivered) would be a programmer error elsewhere; the
		// default case prevents Clear() from blocking under the lock in
		// that case.
		select {
		case entry.actionCh <- defaultAction:
		default:
		}
	}
	q.items = make(map[string]*HeldEntry)
}

func (q *HoldQueue) remove(id string) {
	q.mu.Lock()
	delete(q.items, id)
	q.mu.Unlock()
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	c := make([]string, len(s))
	copy(c, s)
	return c
}

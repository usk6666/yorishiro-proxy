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

// DefaultHoldTimeoutWS is the default per-protocol hold-timeout for the
// WebSocket Protocol. Chosen below the commonly-observed ~10s upstream
// edge-idle threshold (e.g. Fly.io edge) so a held WS frame is auto-
// released before the upstream half-closes the conversation. See USK-855
// (USK-851 follow-up B).
const DefaultHoldTimeoutWS = 8 * time.Second

// DefaultHoldTimeoutSSE is the default per-protocol hold-timeout for the
// SSE Protocol. Mirrors DefaultHoldTimeoutWS for the same edge-idle
// rationale. Note: SSE currently passes through InterceptStep unchanged
// (no per-protocol intercept engine yet — see internal/pipeline/
// intercept_step.go's SSE arm), so this default is forward-compat. It
// activates only when an SSE intercept engine starts enqueuing frames.
const DefaultHoldTimeoutSSE = 8 * time.Second

// DefaultHoldTimeoutGRPC is the default per-protocol hold-timeout for the
// gRPC Protocol. 60s leaves room for human review of held RPCs while
// staying well below typical upstream stall thresholds.
const DefaultHoldTimeoutGRPC = 60 * time.Second

// HeldEntry represents an envelope held in the queue awaiting action.
type HeldEntry struct {
	ID           string
	Envelope     *envelope.Envelope
	MatchedRules []string
	HeldAt       time.Time

	actionCh chan HoldAction // buffered(1) to prevent goroutine leaks
}

// protocolTimeoutSetting holds the per-protocol overrides for hold
// timeout and timeout-expiry behavior. Both fields are pointer-optional
// so partial overrides inherit the global per-field: a protocol entry
// that sets only Timeout inherits global Behavior, and vice versa.
type protocolTimeoutSetting struct {
	Timeout  *time.Duration
	Behavior *TimeoutBehavior
}

// HoldQueue manages held envelopes awaiting external action (from MCP
// tools or AI agents). Thread-safe.
type HoldQueue struct {
	mu               sync.Mutex
	items            map[string]*HeldEntry
	timeout          time.Duration
	behavior         TimeoutBehavior
	maxItems         int
	protocolTimeouts map[envelope.Protocol]protocolTimeoutSetting
}

// NewHoldQueue creates a new HoldQueue with default settings. The queue
// is seeded with per-protocol hold-timeout defaults for WS, SSE, and
// gRPC (see DefaultHoldTimeoutWS / DefaultHoldTimeoutSSE /
// DefaultHoldTimeoutGRPC). Behavior pointers are left nil so the global
// auto_release default applies unless an operator overrides it.
func NewHoldQueue() *HoldQueue {
	wsTimeout := DefaultHoldTimeoutWS
	sseTimeout := DefaultHoldTimeoutSSE
	grpcTimeout := DefaultHoldTimeoutGRPC
	return &HoldQueue{
		items:    make(map[string]*HeldEntry),
		timeout:  DefaultHoldTimeout,
		behavior: TimeoutAutoRelease,
		maxItems: DefaultMaxQueueItems,
		protocolTimeouts: map[envelope.Protocol]protocolTimeoutSetting{
			envelope.ProtocolWebSocket: {Timeout: &wsTimeout},
			envelope.ProtocolSSE:       {Timeout: &sseTimeout},
			envelope.ProtocolGRPC:      {Timeout: &grpcTimeout},
		},
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

// SetProtocolTimeout overrides the hold timeout for the given Protocol.
// The override takes effect on subsequent Hold calls; in-flight holds
// already snapshotted the previous timeout and continue with the old
// value (matches the existing SetTimeout semantics).
func (q *HoldQueue) SetProtocolTimeout(proto envelope.Protocol, d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.protocolTimeouts == nil {
		q.protocolTimeouts = make(map[envelope.Protocol]protocolTimeoutSetting)
	}
	entry := q.protocolTimeouts[proto]
	entry.Timeout = &d
	q.protocolTimeouts[proto] = entry
}

// SetProtocolBehavior overrides the timeout-expiry behavior for the
// given Protocol. The override takes effect on subsequent Hold calls.
func (q *HoldQueue) SetProtocolBehavior(proto envelope.Protocol, b TimeoutBehavior) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.protocolTimeouts == nil {
		q.protocolTimeouts = make(map[envelope.Protocol]protocolTimeoutSetting)
	}
	entry := q.protocolTimeouts[proto]
	entry.Behavior = &b
	q.protocolTimeouts[proto] = entry
}

// ClearProtocolOverride removes any per-protocol override for the given
// Protocol. Subsequent Hold calls fall back to the global timeout /
// behavior. This is the inverse of Set{ProtocolTimeout,ProtocolBehavior}.
func (q *HoldQueue) ClearProtocolOverride(proto envelope.Protocol) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.protocolTimeouts, proto)
}

// ProtocolOverrides returns a shallow clone of the per-protocol override
// map suitable for read-only inspection. Modifications to the returned
// map do not affect the queue.
func (q *HoldQueue) ProtocolOverrides() map[envelope.Protocol]protocolTimeoutSetting {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.protocolTimeouts) == 0 {
		return nil
	}
	out := make(map[envelope.Protocol]protocolTimeoutSetting, len(q.protocolTimeouts))
	for k, v := range q.protocolTimeouts {
		// Deep-copy the pointer fields so caller mutations cannot mutate the
		// queue's internal state.
		var copyEntry protocolTimeoutSetting
		if v.Timeout != nil {
			t := *v.Timeout
			copyEntry.Timeout = &t
		}
		if v.Behavior != nil {
			b := *v.Behavior
			copyEntry.Behavior = &b
		}
		out[k] = copyEntry
	}
	return out
}

// ProtocolOverrideResolved reports the effective (timeout, behavior) for
// the given Protocol, applying global fallbacks per field. Returns the
// resolved values regardless of whether an explicit override is set.
// Used by the MCP configure tool's effective-state response so callers
// can confirm what the wire will actually observe.
func (q *HoldQueue) ProtocolOverrideResolved(proto envelope.Protocol) (time.Duration, TimeoutBehavior) {
	q.mu.Lock()
	defer q.mu.Unlock()
	timeout := q.timeout
	behavior := q.behavior
	if entry, ok := q.protocolTimeouts[proto]; ok {
		if entry.Timeout != nil {
			timeout = *entry.Timeout
		}
		if entry.Behavior != nil {
			behavior = *entry.Behavior
		}
	}
	return timeout, behavior
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
	// Per-protocol override resolution (USK-855). Honour the Envelope's
	// Provenance.Protocol; fall back per-field to the global value. The
	// snapshot is taken under the existing mutex so concurrent
	// SetProtocolTimeout / SetProtocolBehavior cannot retroactively change
	// in-flight holds.
	if entry := q.protocolTimeouts[env.Protocol]; entry.Timeout != nil || entry.Behavior != nil {
		if entry.Timeout != nil {
			timeout = *entry.Timeout
		}
		if entry.Behavior != nil {
			behavior = *entry.Behavior
		}
	}
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

//go:build e2e

package flow_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newTestStore creates a temporary SQLiteStore for testing.
func newTestStore(t *testing.T) *flow.SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// insertTestFlow saves a flow with the given timestamp and returns its ID.
func insertTestFlow(t *testing.T, ctx context.Context, store flow.Store, ts time.Time, protocol string) string {
	t.Helper()
	fl := &flow.Flow{
		ConnID:    "conn-test",
		Protocol:  protocol,
		FlowType:  "unary",
		State:     "complete",
		Timestamp: ts,
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return fl.ID
}

func TestCleaner_MaxFlows(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Insert 10 flows with staggered timestamps.
	now := time.Now().UTC()
	ids := make([]string, 10)
	for i := 0; i < 10; i++ {
		ts := now.Add(time.Duration(i) * time.Second)
		ids[i] = insertTestFlow(t, ctx, store, ts, "HTTP/1.x")
	}

	// Configure cleaner to keep only 5 flows.
	cfg := flow.CleanerConfig{
		MaxFlows: 5,
		Interval: 0, // no periodic cleanup; we test RunOnce
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)

	deleted, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if deleted != 5 {
		t.Errorf("expected 5 deleted, got %d", deleted)
	}

	// Verify only the 5 newest flows remain.
	remaining, err := store.ListFlows(ctx, flow.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 5 {
		t.Fatalf("expected 5 remaining flows, got %d", len(remaining))
	}

	// The oldest 5 should be deleted (ids[0]..ids[4]).
	remainingIDs := make(map[string]bool)
	for _, f := range remaining {
		remainingIDs[f.ID] = true
	}
	for i := 0; i < 5; i++ {
		if remainingIDs[ids[i]] {
			t.Errorf("expected flow %s (index %d) to be deleted, but it still exists", ids[i], i)
		}
	}
	for i := 5; i < 10; i++ {
		if !remainingIDs[ids[i]] {
			t.Errorf("expected flow %s (index %d) to remain, but it was deleted", ids[i], i)
		}
	}
}

func TestCleaner_MaxAge(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	// Insert 3 old flows (2 hours ago) and 3 recent flows.
	for i := 0; i < 3; i++ {
		insertTestFlow(t, ctx, store, now.Add(-2*time.Hour+time.Duration(i)*time.Second), "HTTP/1.x")
	}
	recentIDs := make([]string, 3)
	for i := 0; i < 3; i++ {
		recentIDs[i] = insertTestFlow(t, ctx, store, now.Add(-time.Duration(i)*time.Second), "HTTP/1.x")
	}

	cfg := flow.CleanerConfig{
		MaxAge:   1 * time.Hour,
		Interval: 0,
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)

	deleted, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if deleted != 3 {
		t.Errorf("expected 3 deleted, got %d", deleted)
	}

	remaining, err := store.ListFlows(ctx, flow.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 3 {
		t.Fatalf("expected 3 remaining flows, got %d", len(remaining))
	}
}

func TestCleaner_MaxFlowsAndMaxAge_Combined(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	// 3 old flows (2h old) + 7 recent flows = 10 total
	for i := 0; i < 3; i++ {
		insertTestFlow(t, ctx, store, now.Add(-2*time.Hour+time.Duration(i)*time.Second), "HTTP/1.x")
	}
	for i := 0; i < 7; i++ {
		insertTestFlow(t, ctx, store, now.Add(-time.Duration(i)*time.Second), "HTTP/1.x")
	}

	// MaxAge=1h deletes 3 old flows, then MaxFlows=5 deletes 2 more (7-5=2).
	cfg := flow.CleanerConfig{
		MaxAge:   1 * time.Hour,
		MaxFlows: 5,
		Interval: 0,
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)

	deleted, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if deleted != 5 {
		t.Errorf("expected 5 deleted (3 by age + 2 by count), got %d", deleted)
	}

	remaining, err := store.ListFlows(ctx, flow.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 5 {
		t.Fatalf("expected 5 remaining flows, got %d", len(remaining))
	}
}

func TestCleaner_NoPolicyDeletesNothing(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		insertTestFlow(t, ctx, store, now.Add(time.Duration(i)*time.Second), "HTTP/1.x")
	}

	cfg := flow.CleanerConfig{
		// No MaxFlows, no MaxAge — nothing should be deleted.
		Interval: 0,
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)

	deleted, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}

	remaining, err := store.ListFlows(ctx, flow.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 5 {
		t.Fatalf("expected 5 remaining flows, got %d", len(remaining))
	}
}

func TestCleaner_StartStop_Lifecycle(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		insertTestFlow(t, ctx, store, now.Add(time.Duration(i)*time.Second), "HTTP/1.x")
	}

	cfg := flow.CleanerConfig{
		MaxFlows: 5,
		Interval: 50 * time.Millisecond, // fast interval for testing
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)

	// Start runs an immediate cleanup.
	cleaner.Start(ctx)

	// Wait for the initial cleanup to take effect.
	var remaining []*flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(50 * time.Millisecond)
		var err error
		remaining, err = store.ListFlows(ctx, flow.ListOptions{Limit: 100})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(remaining) <= 5 {
			break
		}
	}
	if len(remaining) > 5 {
		t.Fatalf("expected <= 5 flows after cleaner start, got %d", len(remaining))
	}

	// Stop must return (no goroutine leak).
	done := make(chan struct{})
	go func() {
		cleaner.Stop()
		close(done)
	}()
	select {
	case <-done:
		// OK — Stop returned promptly.
	case <-time.After(5 * time.Second):
		t.Fatal("Cleaner.Stop() did not return within 5 seconds — possible goroutine leak")
	}
}

func TestCleaner_StartStop_ContextCancellation(t *testing.T) {
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())

	cfg := flow.CleanerConfig{
		MaxFlows: 100,
		Interval: 50 * time.Millisecond,
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)

	cleaner.Start(ctx)

	// Cancel context — goroutine should exit.
	cancel()

	done := make(chan struct{})
	go func() {
		cleaner.Stop()
		close(done)
	}()
	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("Cleaner.Stop() did not return after context cancellation")
	}
}

func TestCleaner_PeriodicCleanup(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	cfg := flow.CleanerConfig{
		MaxFlows: 3,
		Interval: 100 * time.Millisecond,
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)
	cleaner.Start(ctx)
	defer cleaner.Stop()

	// Insert flows after cleaner has started.
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		insertTestFlow(t, ctx, store, now.Add(time.Duration(i)*time.Second), "HTTP/1.x")
	}

	// Wait for periodic cleanup to reduce to MaxFlows.
	var remaining []*flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		var err error
		remaining, err = store.ListFlows(ctx, flow.ListOptions{Limit: 100})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(remaining) <= 3 {
			break
		}
	}
	if len(remaining) > 3 {
		t.Fatalf("expected <= 3 flows after periodic cleanup, got %d", len(remaining))
	}
}

func TestCleaner_ConcurrentRecordingAndCleanup(t *testing.T) {
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := flow.CleanerConfig{
		MaxFlows: 10,
		Interval: 50 * time.Millisecond,
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)
	cleaner.Start(ctx)
	defer cleaner.Stop()

	// Concurrently insert flows while cleaner is running.
	var wg sync.WaitGroup
	errCh := make(chan error, 30)

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ts := time.Now().UTC().Add(time.Duration(idx) * time.Millisecond)
			fl := &flow.Flow{
				ConnID:    fmt.Sprintf("conn-%d", idx),
				Protocol:  "HTTP/1.x",
				FlowType:  "unary",
				State:     "active",
				Timestamp: ts,
				Duration:  50 * time.Millisecond,
			}
			if err := store.SaveFlow(ctx, fl); err != nil {
				errCh <- fmt.Errorf("SaveFlow %d: %w", idx, err)
				return
			}
			// Simulate completing the flow after a short delay.
			time.Sleep(20 * time.Millisecond)
			if err := store.UpdateFlow(ctx, fl.ID, flow.FlowUpdate{State: "complete"}); err != nil {
				errCh <- fmt.Errorf("UpdateFlow %d: %w", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent operation error: %v", err)
	}

	// After all insertions, wait for cleanup to stabilize.
	time.Sleep(300 * time.Millisecond)

	remaining, err := store.ListFlows(ctx, flow.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) > 10 {
		t.Errorf("expected <= 10 flows after concurrent cleanup, got %d", len(remaining))
	}
}

func TestCleaner_Enabled(t *testing.T) {
	tests := []struct {
		name    string
		config  flow.CleanerConfig
		enabled bool
	}{
		{"no policy", flow.CleanerConfig{}, false},
		{"max_flows only", flow.CleanerConfig{MaxFlows: 10}, true},
		{"max_age only", flow.CleanerConfig{MaxAge: time.Hour}, true},
		{"both policies", flow.CleanerConfig{MaxFlows: 10, MaxAge: time.Hour}, true},
		{"interval only", flow.CleanerConfig{Interval: time.Minute}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.Enabled(); got != tt.enabled {
				t.Errorf("Enabled() = %v, want %v", got, tt.enabled)
			}
		})
	}
}

func TestCleaner_StartWithZeroInterval(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 8; i++ {
		insertTestFlow(t, ctx, store, now.Add(time.Duration(i)*time.Second), "HTTP/1.x")
	}

	// Interval=0 means only the initial cleanup runs, no periodic ticker.
	cfg := flow.CleanerConfig{
		MaxFlows: 5,
		Interval: 0,
	}
	logger := testutil.DiscardLogger()
	cleaner := flow.NewCleaner(store, cfg, logger)
	cleaner.Start(ctx)

	// The goroutine should complete quickly since Interval=0.
	done := make(chan struct{})
	go func() {
		cleaner.Stop()
		close(done)
	}()
	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("Cleaner.Stop() timed out with zero interval")
	}

	// Initial cleanup should have run.
	remaining, err := store.ListFlows(ctx, flow.ListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 5 {
		t.Errorf("expected 5 remaining flows after initial cleanup, got %d", len(remaining))
	}
}

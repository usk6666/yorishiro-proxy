package flow

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func newTestCleaner(t *testing.T, cfg CleanerConfig) (*Cleaner, *SQLiteStore) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "cleaner.db")
	logger := testutil.DiscardLogger()
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cleaner := NewCleaner(store, cfg, logger)
	return cleaner, store
}

// saveCleanerSession is a helper that saves a minimal flow for cleaner tests.
func saveCleanerSession(t *testing.T, store *SQLiteStore, ts time.Time, reqURL string) {
	t.Helper()
	ctx := context.Background()

	fl := &Flow{
		Protocol:  "HTTP/1.x",
		Timestamp: ts,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	msg := &Message{
		FlowID: fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    "GET",
		URL:       mustParseURL(reqURL),
	}
	if err := store.AppendMessage(ctx, msg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
}

func TestCleaner_RunOnce_MaxAge(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{
		MaxAge: 12 * time.Hour,
	})
	ctx := context.Background()

	now := time.Now().UTC()
	saveCleanerSession(t, store, now.Add(-24*time.Hour), "http://example.com/old")
	saveCleanerSession(t, store, now.Add(-1*time.Hour), "http://example.com/new")

	n, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Errorf("RunOnce deleted %d, want 1", n)
	}

	remaining, err := store.ListFlows(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining flow, got %d", len(remaining))
	}
}

func TestCleaner_RunOnce_MaxSessions(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{
		MaxFlows: 2,
	})
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		saveCleanerSession(t, store, now.Add(time.Duration(i)*time.Second), "http://example.com/entry")
	}

	n, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 3 {
		t.Errorf("RunOnce deleted %d, want 3", n)
	}

	remaining, err := store.ListFlows(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 2 {
		t.Errorf("expected 2 remaining sessions, got %d", len(remaining))
	}
}

func TestCleaner_RunOnce_Disabled(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{})
	ctx := context.Background()

	saveCleanerSession(t, store, time.Now().UTC(), "http://example.com/keep")

	n, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Errorf("RunOnce deleted %d, want 0", n)
	}
}

func TestCleaner_Start_RunsAtStartup(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{
		MaxFlows: 1,
		Interval:    time.Hour,
	})
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		saveCleanerSession(t, store, now.Add(time.Duration(i)*time.Second), "http://example.com/startup")
	}

	cleaner.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	cleaner.Stop()

	remaining, err := store.ListFlows(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining session after startup cleanup, got %d", len(remaining))
	}
}

func TestCleaner_Start_Periodic(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{
		MaxAge:   50 * time.Millisecond,
		Interval: 100 * time.Millisecond,
	})
	ctx := context.Background()

	saveCleanerSession(t, store, time.Now().UTC(), "http://example.com/periodic")

	cleaner.Start(ctx)
	time.Sleep(300 * time.Millisecond)
	cleaner.Stop()

	remaining, err := store.ListFlows(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining sessions after periodic cleanup, got %d", len(remaining))
	}
}

func TestCleanerConfig_Enabled(t *testing.T) {
	tests := []struct {
		name   string
		config CleanerConfig
		want   bool
	}{
		{"both zero", CleanerConfig{}, false},
		{"max sessions only", CleanerConfig{MaxFlows: 100}, true},
		{"max age only", CleanerConfig{MaxAge: time.Hour}, true},
		{"both set", CleanerConfig{MaxFlows: 100, MaxAge: time.Hour}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.Enabled()
			if got != tt.want {
				t.Errorf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

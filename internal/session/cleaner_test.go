package session

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func newTestCleaner(t *testing.T, cfg CleanerConfig) (*Cleaner, *SQLiteStore) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "cleaner.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	cleaner := NewCleaner(store, cfg, logger)
	return cleaner, store
}

func TestCleaner_RunOnce_MaxAge(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{
		MaxAge: 12 * time.Hour,
	})
	ctx := context.Background()

	now := time.Now().UTC()
	entries := []*Entry{
		{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-24 * time.Hour),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/old")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-1 * time.Hour),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/new")},
			Response:  RecordedResponse{StatusCode: 200},
		},
	}
	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	n, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 1 {
		t.Errorf("RunOnce deleted %d, want 1", n)
	}

	remaining, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", len(remaining))
	}
}

func TestCleaner_RunOnce_MaxSessions(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{
		MaxSessions: 2,
	})
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		entry := &Entry{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/entry")},
			Response:  RecordedResponse{StatusCode: 200},
		}
		if err := store.Save(ctx, entry); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	n, err := cleaner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 3 {
		t.Errorf("RunOnce deleted %d, want 3", n)
	}

	remaining, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining) != 2 {
		t.Errorf("expected 2 remaining entries, got %d", len(remaining))
	}
}

func TestCleaner_RunOnce_Disabled(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{})
	ctx := context.Background()

	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/keep")},
		Response:  RecordedResponse{StatusCode: 200},
	}
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

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
		MaxSessions: 1,
		Interval:    time.Hour, // long interval — only startup run matters
	})
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		entry := &Entry{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/startup")},
			Response:  RecordedResponse{StatusCode: 200},
		}
		if err := store.Save(ctx, entry); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	cleaner.Start(ctx)
	// Give the goroutine time to run the initial cleanup.
	time.Sleep(200 * time.Millisecond)
	cleaner.Stop()

	remaining, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining entry after startup cleanup, got %d", len(remaining))
	}
}

func TestCleaner_Start_Periodic(t *testing.T) {
	cleaner, store := newTestCleaner(t, CleanerConfig{
		MaxAge:   50 * time.Millisecond,
		Interval: 100 * time.Millisecond,
	})
	ctx := context.Background()

	// Insert an entry that will expire after 50ms.
	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/periodic")},
		Response:  RecordedResponse{StatusCode: 200},
	}
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cleaner.Start(ctx)
	// Wait for at least one periodic run after the entry expires.
	time.Sleep(300 * time.Millisecond)
	cleaner.Stop()

	remaining, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining entries after periodic cleanup, got %d", len(remaining))
	}
}

func TestCleanerConfig_Enabled(t *testing.T) {
	tests := []struct {
		name   string
		config CleanerConfig
		want   bool
	}{
		{"both zero", CleanerConfig{}, false},
		{"max sessions only", CleanerConfig{MaxSessions: 100}, true},
		{"max age only", CleanerConfig{MaxAge: time.Hour}, true},
		{"both set", CleanerConfig{MaxSessions: 100, MaxAge: time.Hour}, true},
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

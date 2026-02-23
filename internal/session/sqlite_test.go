package session

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestSQLiteStore_SaveAndGet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	u, _ := url.Parse("http://example.com/path")
	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Duration:  150 * time.Millisecond,
		Request: RecordedRequest{
			Method:  "GET",
			URL:     u,
			Headers: map[string][]string{"Host": {"example.com"}},
			Body:    nil,
		},
		Response: RecordedResponse{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/html"}},
			Body:       []byte("<html>ok</html>"),
		},
	}

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if entry.ID == "" {
		t.Fatal("Save did not assign ID")
	}

	got, err := store.Get(ctx, entry.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Request.Method != "GET" {
		t.Errorf("Method = %q, want %q", got.Request.Method, "GET")
	}
	if got.Request.URL.String() != "http://example.com/path" {
		t.Errorf("URL = %q, want %q", got.Request.URL.String(), "http://example.com/path")
	}
	if got.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want %d", got.Response.StatusCode, 200)
	}
	if string(got.Response.Body) != "<html>ok</html>" {
		t.Errorf("Body = %q, want %q", got.Response.Body, "<html>ok</html>")
	}
	if got.Request.Headers["Host"][0] != "example.com" {
		t.Errorf("Host header = %q, want %q", got.Request.Headers["Host"][0], "example.com")
	}
}

func TestSQLiteStore_List_Filters(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entries := []*Entry{
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/a")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "POST", URL: mustParseURL("http://example.com/b")},
			Response:  RecordedResponse{StatusCode: 201},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://other.com/c")},
			Response:  RecordedResponse{StatusCode: 404},
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	tests := []struct {
		name    string
		opts    ListOptions
		wantLen int
	}{
		{"all", ListOptions{}, 3},
		{"method GET", ListOptions{Method: "GET"}, 2},
		{"method POST", ListOptions{Method: "POST"}, 1},
		{"URL pattern example", ListOptions{URLPattern: "example.com"}, 2},
		{"status 404", ListOptions{StatusCode: 404}, 1},
		{"limit 1", ListOptions{Limit: 1}, 1},
		{"combined", ListOptions{Method: "GET", StatusCode: 200}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.List(ctx, tt.opts)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("got %d entries, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestSQLiteStore_Delete(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/del")},
		Response:  RecordedResponse{StatusCode: 200},
	}
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.Delete(ctx, entry.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.Get(ctx, entry.ID)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}

func TestSQLiteStore_DeleteAll(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Insert multiple entries.
	entries := []*Entry{
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/a")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "POST", URL: mustParseURL("http://example.com/b")},
			Response:  RecordedResponse{StatusCode: 201},
		},
		{
			Protocol:  "HTTPS",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("https://example.com/c")},
			Response:  RecordedResponse{StatusCode: 200},
		},
	}
	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	// Verify entries exist.
	all, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries before DeleteAll, got %d", len(all))
	}

	// Delete all.
	n, err := store.DeleteAll(ctx)
	if err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	if n != 3 {
		t.Errorf("DeleteAll returned %d, want 3", n)
	}

	// Verify all deleted.
	all, err = store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List after DeleteAll: %v", err)
	}
	if len(all) != 0 {
		t.Errorf("expected 0 entries after DeleteAll, got %d", len(all))
	}
}

func TestSQLiteStore_DeleteAll_Empty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Delete all on empty store should return 0.
	n, err := store.DeleteAll(ctx)
	if err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	if n != 0 {
		t.Errorf("DeleteAll on empty store returned %d, want 0", n)
	}
}

func TestMigrate_FreshDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var version int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}

	_, err = db.ExecContext(ctx,
		`INSERT INTO sessions (id, protocol, method, url, request_headers, request_body, response_status, response_headers, response_body, timestamp, duration_ms)
		 VALUES ('test-id', 'HTTP/1.x', 'GET', 'http://example.com', '{}', NULL, 200, '{}', NULL, '2025-01-01T00:00:00Z', 100)`)
	if err != nil {
		t.Fatalf("insert into sessions: %v", err)
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "idempotent.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := migrate(ctx, db); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := migrate(ctx, db); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	var version int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}
}

func TestMigrate_FutureVersionError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "future.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if _, err := db.ExecContext(ctx, bootstrapSQL); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (999)"); err != nil {
		t.Fatalf("insert version: %v", err)
	}

	err = migrate(ctx, db)
	if err == nil {
		t.Fatal("expected error for future version, got nil")
	}
	if !strings.Contains(err.Error(), "newer than latest") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetCurrentVersion_EmptyTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "empty-version.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if _, err := db.ExecContext(ctx, bootstrapSQL); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	version, err := getCurrentVersion(ctx, db)
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if version != 0 {
		t.Errorf("version = %d, want 0", version)
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func TestSQLiteStore_Save_CancelledContext(t *testing.T) {
	store := newTestStore(t)

	// Cancel the context before calling Save.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/cancelled")},
		Response:  RecordedResponse{StatusCode: 200},
	}

	err := store.Save(ctx, entry)
	if err == nil {
		t.Fatal("expected error from Save with cancelled context, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestSQLiteStore_Close_CompletesWithPendingWrites(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// Write some entries before closing.
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		entry := &Entry{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/close-test")},
			Response:  RecordedResponse{StatusCode: 200},
		}
		if err := store.Save(ctx, entry); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	// Close should complete within a bounded time.
	done := make(chan error, 1)
	go func() {
		done <- store.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not complete within 10 seconds")
	}
}

func TestSQLiteStore_Save_ContextPropagation(t *testing.T) {
	store := newTestStore(t)

	// Use a context with a short timeout to verify it propagates through writeOp.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "POST", URL: mustParseURL("http://example.com/ctx-prop")},
		Response:  RecordedResponse{StatusCode: 201},
	}

	// Save should succeed with a valid context.
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save with valid context: %v", err)
	}

	// Verify the entry was actually written.
	got, err := store.Get(ctx, entry.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Request.Method != "POST" {
		t.Errorf("Method = %q, want %q", got.Request.Method, "POST")
	}
}

func TestSQLiteStore_List_LIKEWildcardEscape(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Insert entries with special LIKE characters in URLs.
	entries := []*Entry{
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/100%25off")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/user_name")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/username")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/normal")},
			Response:  RecordedResponse{StatusCode: 200},
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	tests := []struct {
		name       string
		urlPattern string
		wantLen    int
	}{
		{
			name:       "literal percent sign matches only URLs containing %25",
			urlPattern: "%25",
			wantLen:    1,
		},
		{
			name:       "literal underscore matches only URLs containing _",
			urlPattern: "user_name",
			wantLen:    1,
		},
		{
			name:       "plain substring still works",
			urlPattern: "example.com",
			wantLen:    4,
		},
		{
			name:       "no match",
			urlPattern: "nonexistent",
			wantLen:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.List(ctx, ListOptions{URLPattern: tt.urlPattern})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("got %d entries, want %d", len(got), tt.wantLen)
			}
		})
	}
}

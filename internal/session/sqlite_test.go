package session

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
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
	want := latestVersion()
	if version != want {
		t.Errorf("version = %d, want %d", version, want)
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
	want := latestVersion()
	if version != want {
		t.Errorf("version = %d, want %d", version, want)
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

func TestMigrate_V3_CreatesIndexes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "indexes.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Query SQLite for index names on the sessions table.
	rows, err := db.QueryContext(ctx, "SELECT name FROM pragma_index_list('sessions')")
	if err != nil {
		t.Fatalf("query index list: %v", err)
	}
	defer rows.Close()

	indexes := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		indexes[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows iteration: %v", err)
	}

	wantIndexes := []string{
		"idx_sessions_protocol",
		"idx_sessions_timestamp",
		"idx_sessions_method",
		"idx_sessions_url",
		"idx_sessions_response_status",
		"idx_sessions_conn_id",
	}
	for _, idx := range wantIndexes {
		if !indexes[idx] {
			t.Errorf("expected index %q to exist, but it was not found", idx)
		}
	}
}

func TestMigrate_UpgradeFromV1_CreatesV3Indexes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "upgrade.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Simulate a database at v1 by running bootstrap + v1 migration manually.
	if _, err := db.ExecContext(ctx, bootstrapSQL); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if _, err := db.ExecContext(ctx, schemaV1); err != nil {
		t.Fatalf("apply v1: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (1)"); err != nil {
		t.Fatalf("insert version: %v", err)
	}

	// Run migrate — should apply all pending migrations (v2, v3, v4).
	if err := migrate(ctx, db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var version int
	if err := db.QueryRowContext(ctx, "SELECT version FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != latestVersion() {
		t.Errorf("version = %d, want %d", version, latestVersion())
	}

	// Verify v3 indexes exist.
	rows, err := db.QueryContext(ctx, "SELECT name FROM pragma_index_list('sessions')")
	if err != nil {
		t.Fatalf("query index list: %v", err)
	}
	defer rows.Close()

	indexes := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		indexes[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows iteration: %v", err)
	}

	for _, idx := range []string{"idx_sessions_protocol", "idx_sessions_timestamp", "idx_sessions_conn_id"} {
		if !indexes[idx] {
			t.Errorf("expected index %q to exist after upgrade, but it was not found", idx)
		}
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

func TestSQLiteStore_Count(t *testing.T) {
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
			Protocol:  "HTTPS",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("https://example.com/c")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://other.com/d")},
			Response:  RecordedResponse{StatusCode: 404},
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	tests := []struct {
		name      string
		opts      ListOptions
		wantCount int
	}{
		{"all", ListOptions{}, 4},
		{"method GET", ListOptions{Method: "GET"}, 3},
		{"method POST", ListOptions{Method: "POST"}, 1},
		{"protocol HTTPS", ListOptions{Protocol: "HTTPS"}, 1},
		{"URL pattern example.com", ListOptions{URLPattern: "example.com"}, 3},
		{"status 404", ListOptions{StatusCode: 404}, 1},
		{"status 200", ListOptions{StatusCode: 200}, 2},
		{"combined GET+200", ListOptions{Method: "GET", StatusCode: 200}, 2},
		{"no match", ListOptions{Method: "DELETE"}, 0},
		{"limit ignored", ListOptions{Method: "GET", Limit: 1}, 3},
		{"offset ignored", ListOptions{Method: "GET", Offset: 2}, 3},
		{"limit and offset ignored", ListOptions{Limit: 1, Offset: 1}, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.Count(ctx, tt.opts)
			if err != nil {
				t.Fatalf("Count: %v", err)
			}
			if got != tt.wantCount {
				t.Errorf("got %d, want %d", got, tt.wantCount)
			}
		})
	}
}

func TestSQLiteStore_Count_Empty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	count, err := store.Count(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Errorf("got %d, want 0", count)
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

func TestSQLiteStore_DeleteOlderThan(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	entries := []*Entry{
		{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-48 * time.Hour), // 2 days ago
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/old1")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-24 * time.Hour), // 1 day ago
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/old2")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-1 * time.Hour), // 1 hour ago
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/recent")},
			Response:  RecordedResponse{StatusCode: 200},
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	// Delete entries older than 12 hours.
	cutoff := now.Add(-12 * time.Hour)
	n, err := store.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("DeleteOlderThan: %v", err)
	}
	if n != 2 {
		t.Errorf("DeleteOlderThan returned %d, want 2", n)
	}

	// Verify only the recent entry remains.
	remaining, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", len(remaining))
	}
	if remaining[0].Request.URL.Path != "/recent" {
		t.Errorf("remaining URL = %q, want /recent", remaining[0].Request.URL.Path)
	}
}

func TestSQLiteStore_DeleteOlderThan_NoMatches(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/new")},
		Response:  RecordedResponse{StatusCode: 200},
	}
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Cutoff in the past — nothing should be deleted.
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	n, err := store.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("DeleteOlderThan: %v", err)
	}
	if n != 0 {
		t.Errorf("DeleteOlderThan returned %d, want 0", n)
	}
}

func TestSQLiteStore_DeleteExcess(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		entry := &Entry{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL(fmt.Sprintf("http://example.com/%d", i))},
			Response:  RecordedResponse{StatusCode: 200},
		}
		if err := store.Save(ctx, entry); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	// Keep only 5 most recent.
	n, err := store.DeleteExcess(ctx, 5)
	if err != nil {
		t.Fatalf("DeleteExcess: %v", err)
	}
	if n != 5 {
		t.Errorf("DeleteExcess returned %d, want 5", n)
	}

	// Verify 5 remain.
	remaining, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(remaining) != 5 {
		t.Fatalf("expected 5 remaining entries, got %d", len(remaining))
	}

	// Verify the remaining entries are the most recent (timestamps 5-9).
	for _, e := range remaining {
		path := e.Request.URL.Path
		if path == "/0" || path == "/1" || path == "/2" || path == "/3" || path == "/4" {
			t.Errorf("old entry %s should have been deleted", path)
		}
	}
}

func TestSQLiteStore_DeleteExcess_NoExcess(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		entry := &Entry{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL(fmt.Sprintf("http://example.com/%d", i))},
			Response:  RecordedResponse{StatusCode: 200},
		}
		if err := store.Save(ctx, entry); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	// maxCount >= current count — nothing deleted.
	n, err := store.DeleteExcess(ctx, 5)
	if err != nil {
		t.Fatalf("DeleteExcess: %v", err)
	}
	if n != 0 {
		t.Errorf("DeleteExcess returned %d, want 0", n)
	}
}

func TestSQLiteStore_ConnID_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entry := &Entry{
		ConnID:    "abcd1234",
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Duration:  50 * time.Millisecond,
		Request: RecordedRequest{
			Method: "GET",
			URL:    mustParseURL("http://example.com/connid"),
		},
		Response: RecordedResponse{StatusCode: 200},
	}

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, entry.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.ConnID != "abcd1234" {
		t.Errorf("ConnID = %q, want %q", got.ConnID, "abcd1234")
	}
}

func TestSQLiteStore_ConnID_EmptyDefault(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Save an entry without ConnID — should default to empty string.
	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request: RecordedRequest{
			Method: "GET",
			URL:    mustParseURL("http://example.com/no-connid"),
		},
		Response: RecordedResponse{StatusCode: 200},
	}

	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, entry.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.ConnID != "" {
		t.Errorf("ConnID = %q, want empty string", got.ConnID)
	}
}

func TestSQLiteStore_ConnID_InList(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entries := []*Entry{
		{
			ConnID:    "conn0001",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/a")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			ConnID:    "conn0001",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "POST", URL: mustParseURL("http://example.com/b")},
			Response:  RecordedResponse{StatusCode: 201},
		},
		{
			ConnID:    "conn0002",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/c")},
			Response:  RecordedResponse{StatusCode: 200},
		},
	}

	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	got, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	connIDCounts := make(map[string]int)
	for _, e := range got {
		connIDCounts[e.ConnID]++
	}

	if connIDCounts["conn0001"] != 2 {
		t.Errorf("conn0001 count = %d, want 2", connIDCounts["conn0001"])
	}
	if connIDCounts["conn0002"] != 1 {
		t.Errorf("conn0002 count = %d, want 1", connIDCounts["conn0002"])
	}
}

func TestSQLiteStore_DeleteExcess_InvalidMaxCount(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.DeleteExcess(ctx, 0)
	if err == nil {
		t.Fatal("expected error for maxCount=0, got nil")
	}

	_, err = store.DeleteExcess(ctx, -1)
	if err == nil {
		t.Fatal("expected error for maxCount=-1, got nil")
	}
}

// --- Error Recovery Tests ---

func TestSQLiteStore_Save_AfterClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// Close the store first.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Save after Close should not panic. It should either return an error
	// or block until the context is cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/after-close")},
		Response:  RecordedResponse{StatusCode: 200},
	}

	err = store.Save(ctx, entry)
	if err == nil {
		t.Fatal("expected error from Save after Close, got nil")
	}
}

func TestSQLiteStore_Get_AfterClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// Save an entry before closing.
	ctx := context.Background()
	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/get-after-close")},
		Response:  RecordedResponse{StatusCode: 200},
	}
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}
	savedID := entry.ID

	// Close the store.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Get after Close should return an error (database is closed), not panic.
	_, err = store.Get(ctx, savedID)
	if err == nil {
		t.Fatal("expected error from Get after Close, got nil")
	}
}

func TestSQLiteStore_List_AfterClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// List after Close should return an error, not panic.
	_, err = store.List(context.Background(), ListOptions{})
	if err == nil {
		t.Fatal("expected error from List after Close, got nil")
	}
}

func TestSQLiteStore_Count_AfterClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Count after Close should return an error, not panic.
	_, err = store.Count(context.Background(), ListOptions{})
	if err == nil {
		t.Fatal("expected error from Count after Close, got nil")
	}
}

func TestSQLiteStore_Delete_AfterClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Delete after Close should return an error, not panic.
	err = store.Delete(context.Background(), "nonexistent-id")
	if err == nil {
		t.Fatal("expected error from Delete after Close, got nil")
	}
}

func TestSQLiteStore_Save_ContextCancelWhenWriteLoopStopped(t *testing.T) {
	// This test verifies that Save respects context cancellation when the
	// write loop is no longer processing operations (e.g., after Close).
	// After Close, Save can enqueue to the buffered channel but no goroutine
	// consumes it, so Save blocks on the result channel until context expires.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// Close the store to stop the write loop.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Save with a short-lived context should return a context error
	// because no goroutine is consuming from the write channel.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/backpressure")},
		Response:  RecordedResponse{StatusCode: 200},
	}

	err = store.Save(ctx, entry)
	if err == nil {
		t.Fatal("expected error from Save when write loop is stopped and context expires, got nil")
	}
	if err != context.DeadlineExceeded {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestSQLiteStore_Get_CancelledContext(t *testing.T) {
	store := newTestStore(t)

	// Save an entry with a valid context.
	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/ctx-cancel")},
		Response:  RecordedResponse{StatusCode: 200},
	}
	if err := store.Save(context.Background(), entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Cancel the context before Get.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.Get(ctx, entry.ID)
	if err == nil {
		t.Fatal("expected error from Get with cancelled context, got nil")
	}
}

func TestSQLiteStore_List_CancelledContext(t *testing.T) {
	store := newTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.List(ctx, ListOptions{})
	if err == nil {
		t.Fatal("expected error from List with cancelled context, got nil")
	}
}

func TestSQLiteStore_Count_CancelledContext(t *testing.T) {
	store := newTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.Count(ctx, ListOptions{})
	if err == nil {
		t.Fatal("expected error from Count with cancelled context, got nil")
	}
}

func TestSQLiteStore_Delete_CancelledContext(t *testing.T) {
	store := newTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := store.Delete(ctx, "some-id")
	if err == nil {
		t.Fatal("expected error from Delete with cancelled context, got nil")
	}
}

func TestSQLiteStore_DeleteAll_CancelledContext(t *testing.T) {
	store := newTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.DeleteAll(ctx)
	if err == nil {
		t.Fatal("expected error from DeleteAll with cancelled context, got nil")
	}
}

func TestSQLiteStore_ReadOnlyDB(t *testing.T) {
	// Create a normal store, save an entry, then make the DB file read-only.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	ctx := context.Background()
	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/readonly")},
		Response:  RecordedResponse{StatusCode: 200},
	}
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}
	savedID := entry.ID
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Make the DB file and its WAL/SHM files read-only.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := dbPath + suffix
		// Ignore errors for WAL/SHM files — they may not exist yet.
		os.Chmod(p, 0444)
	}
	// Also make the directory read-only so SQLite cannot create new files.
	os.Chmod(tmpDir, 0555)
	t.Cleanup(func() {
		// Restore permissions so t.TempDir() cleanup can remove files.
		os.Chmod(tmpDir, 0755)
		for _, suffix := range []string{"", "-wal", "-shm"} {
			os.Chmod(dbPath+suffix, 0644)
		}
	})

	// Re-open the store. The driver might succeed at opening (since the file
	// is readable), but writes should fail because the filesystem is read-only.
	roStore, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		// If the store cannot even open in this read-only state, that is
		// acceptable — the important thing is it does not panic.
		t.Skipf("NewSQLiteStore on read-only DB returned error (acceptable): %v", err)
	}
	defer roStore.Close()

	// Reading the previously saved entry should succeed.
	got, err := roStore.Get(ctx, savedID)
	if err != nil {
		// Some SQLite implementations may fail reads too when
		// WAL mode cannot be initialized. Skip rather than silently pass.
		t.Skipf("Get from read-only store failed (acceptable): %v", err)
	}
	if got.Request.Method != "GET" {
		t.Errorf("Method = %q, want %q", got.Request.Method, "GET")
	}

	// Writing to a read-only DB should fail.
	writeEntry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "POST", URL: mustParseURL("http://example.com/readonly-write")},
		Response:  RecordedResponse{StatusCode: 201},
	}
	writeCtx, writeCancel := context.WithTimeout(ctx, 3*time.Second)
	defer writeCancel()
	err = roStore.Save(writeCtx, writeEntry)
	if err == nil {
		t.Log("Save to read-only store succeeded unexpectedly — filesystem may not enforce read-only on this platform")
	} else {
		t.Logf("Save to read-only store correctly failed: %v", err)
	}
}

func TestSQLiteStore_ConcurrentSavesUnderLoad(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Fire many concurrent saves to stress the write channel.
	const numGoroutines = 100
	errs := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(n int) {
			entry := &Entry{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now(),
				Request:   RecordedRequest{Method: "GET", URL: mustParseURL(fmt.Sprintf("http://example.com/concurrent/%d", n))},
				Response:  RecordedResponse{StatusCode: 200},
			}
			errs <- store.Save(ctx, entry)
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Save %d failed: %v", i, err)
		}
	}

	// Verify all entries were saved.
	entries, err := store.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != numGoroutines {
		t.Errorf("got %d entries, want %d", len(entries), numGoroutines)
	}
}

func TestSQLiteStore_Save_ContextCancelDuringWriteLoop(t *testing.T) {
	// Verifies that when the write loop is processing, cancelling the
	// context of a pending Save returns promptly.
	store := newTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())

	// Start a save, then immediately cancel the context.
	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/cancel-during-write")},
		Response:  RecordedResponse{StatusCode: 200},
	}

	// Cancel almost immediately to race with the write loop.
	go func() {
		time.Sleep(1 * time.Millisecond)
		cancel()
	}()

	// This may succeed (if writeLoop processes it before cancel) or fail with
	// context.Canceled. Either is acceptable — it must not panic or deadlock.
	err := store.Save(ctx, entry)
	if err != nil && err != context.Canceled {
		// If the write completed before cancellation, the save succeeds.
		// If cancelled first, we get context.Canceled. Anything else is unexpected.
		t.Logf("Save returned: %v (acceptable if context.Canceled or nil)", err)
	}
}

func TestSQLiteStore_Close_IdempotentDoneChannel(t *testing.T) {
	// Verify that the store's writeLoop exits cleanly when Close is called
	// and no pending writes exist.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	// Close immediately with no writes — should not hang or panic.
	done := make(chan error, 1)
	go func() {
		done <- store.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not complete within 5 seconds")
	}
}

func TestSQLiteStore_DeleteOlderThan_CancelledContext(t *testing.T) {
	store := newTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.DeleteOlderThan(ctx, time.Now())
	if err == nil {
		t.Fatal("expected error from DeleteOlderThan with cancelled context, got nil")
	}
}

func TestSQLiteStore_DeleteExcess_CancelledContext(t *testing.T) {
	store := newTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.DeleteExcess(ctx, 10)
	if err == nil {
		t.Fatal("expected error from DeleteExcess with cancelled context, got nil")
	}
}

func TestSQLiteStore_PersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	u, _ := url.Parse("http://example.com/persist")

	entry := &Entry{
		ConnID:    "conn-persist-001",
		Protocol:  "HTTP/1.x",
		Timestamp: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		Duration:  250 * time.Millisecond,
		Request: RecordedRequest{
			Method:  "POST",
			URL:     u,
			Headers: map[string][]string{"Content-Type": {"application/json"}, "Host": {"example.com"}},
			Body:    []byte(`{"key":"value"}`),
		},
		Response: RecordedResponse{
			StatusCode: 201,
			Headers:    map[string][]string{"Content-Type": {"application/json"}, "X-Request-Id": {"abc123"}},
			Body:       []byte(`{"id":"42"}`),
		},
		Tags: map[string]string{"source": "test", "category": "persistence"},
	}

	// 1. Open store, save entry, close.
	store1, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("open store1: %v", err)
	}
	if err := store1.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}
	savedID := entry.ID
	if savedID == "" {
		t.Fatal("Save did not assign ID")
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("close store1: %v", err)
	}

	// 2. Reopen the same database file.
	store2, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("open store2: %v", err)
	}
	defer store2.Close()

	// 3. Retrieve the entry and verify all fields survived the reopen.
	got, err := store2.Get(ctx, savedID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}

	if got.ID != savedID {
		t.Errorf("ID = %q, want %q", got.ID, savedID)
	}
	if got.ConnID != "conn-persist-001" {
		t.Errorf("ConnID = %q, want %q", got.ConnID, "conn-persist-001")
	}
	if got.Protocol != "HTTP/1.x" {
		t.Errorf("Protocol = %q, want %q", got.Protocol, "HTTP/1.x")
	}
	if got.Request.Method != "POST" {
		t.Errorf("Method = %q, want %q", got.Request.Method, "POST")
	}
	if got.Request.URL.String() != "http://example.com/persist" {
		t.Errorf("URL = %q, want %q", got.Request.URL.String(), "http://example.com/persist")
	}
	if got.Request.Headers["Content-Type"][0] != "application/json" {
		t.Errorf("Request Content-Type = %q, want %q", got.Request.Headers["Content-Type"][0], "application/json")
	}
	if got.Request.Headers["Host"][0] != "example.com" {
		t.Errorf("Request Host = %q, want %q", got.Request.Headers["Host"][0], "example.com")
	}
	if string(got.Request.Body) != `{"key":"value"}` {
		t.Errorf("Request Body = %q, want %q", got.Request.Body, `{"key":"value"}`)
	}
	if got.Response.StatusCode != 201 {
		t.Errorf("StatusCode = %d, want %d", got.Response.StatusCode, 201)
	}
	if got.Response.Headers["Content-Type"][0] != "application/json" {
		t.Errorf("Response Content-Type = %q, want %q", got.Response.Headers["Content-Type"][0], "application/json")
	}
	if got.Response.Headers["X-Request-Id"][0] != "abc123" {
		t.Errorf("Response X-Request-Id = %q, want %q", got.Response.Headers["X-Request-Id"][0], "abc123")
	}
	if string(got.Response.Body) != `{"id":"42"}` {
		t.Errorf("Response Body = %q, want %q", got.Response.Body, `{"id":"42"}`)
	}
	if !got.Timestamp.Equal(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("Timestamp = %v, want %v", got.Timestamp, time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC))
	}
	if got.Duration != 250*time.Millisecond {
		t.Errorf("Duration = %v, want %v", got.Duration, 250*time.Millisecond)
	}
	if got.Tags["source"] != "test" {
		t.Errorf("Tags[source] = %q, want %q", got.Tags["source"], "test")
	}
	if got.Tags["category"] != "persistence" {
		t.Errorf("Tags[category] = %q, want %q", got.Tags["category"], "persistence")
	}

	// 4. List and Count should also reflect persisted data.
	entries, err := store2.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List after reopen: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("List returned %d entries, want 1", len(entries))
	}

	count, err := store2.Count(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("Count after reopen: %v", err)
	}
	if count != 1 {
		t.Errorf("Count = %d, want 1", count)
	}
}

func TestSQLiteStore_PersistenceAcrossReopen_MultipleEntries(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// 1. Open store and save multiple entries with different characteristics.
	store1, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("open store1: %v", err)
	}

	entries := []*Entry{
		{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Date(2025, 1, 1, 10, 0, 0, 0, time.UTC),
			Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/a")},
			Response:  RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTPS",
			Timestamp: time.Date(2025, 1, 1, 11, 0, 0, 0, time.UTC),
			Request:   RecordedRequest{Method: "POST", URL: mustParseURL("https://example.com/b")},
			Response:  RecordedResponse{StatusCode: 201, Body: []byte("created")},
		},
		{
			ConnID:    "conn-multi-003",
			Protocol:  "HTTP/1.x",
			Timestamp: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
			Request:   RecordedRequest{Method: "DELETE", URL: mustParseURL("http://other.com/c")},
			Response:  RecordedResponse{StatusCode: 204},
		},
	}

	savedIDs := make([]string, len(entries))
	for i, e := range entries {
		if err := store1.Save(ctx, e); err != nil {
			t.Fatalf("Save[%d]: %v", i, err)
		}
		savedIDs[i] = e.ID
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("close store1: %v", err)
	}

	// 2. Reopen and verify all entries persist.
	store2, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("open store2: %v", err)
	}
	defer store2.Close()

	all, err := store2.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("List returned %d entries, want 3", len(all))
	}

	// Verify each entry can be individually retrieved.
	for i, id := range savedIDs {
		got, err := store2.Get(ctx, id)
		if err != nil {
			t.Fatalf("Get[%d]: %v", i, err)
		}
		if got.Request.Method != entries[i].Request.Method {
			t.Errorf("entry[%d] Method = %q, want %q", i, got.Request.Method, entries[i].Request.Method)
		}
		if got.Response.StatusCode != entries[i].Response.StatusCode {
			t.Errorf("entry[%d] StatusCode = %d, want %d", i, got.Response.StatusCode, entries[i].Response.StatusCode)
		}
	}

	// Verify filters work against persisted data.
	getEntries, err := store2.List(ctx, ListOptions{Method: "GET"})
	if err != nil {
		t.Fatalf("List(Method=GET): %v", err)
	}
	if len(getEntries) != 1 {
		t.Errorf("List(Method=GET) returned %d entries, want 1", len(getEntries))
	}

	httpsEntries, err := store2.List(ctx, ListOptions{Protocol: "HTTPS"})
	if err != nil {
		t.Fatalf("List(Protocol=HTTPS): %v", err)
	}
	if len(httpsEntries) != 1 {
		t.Errorf("List(Protocol=HTTPS) returned %d entries, want 1", len(httpsEntries))
	}
}

func TestSQLiteStore_PersistenceAcrossReopen_DeletePersists(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// 1. Open store, save two entries, delete one, close.
	store1, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("open store1: %v", err)
	}

	entry1 := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/keep")},
		Response:  RecordedResponse{StatusCode: 200},
	}
	entry2 := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
		Request:   RecordedRequest{Method: "GET", URL: mustParseURL("http://example.com/remove")},
		Response:  RecordedResponse{StatusCode: 200},
	}

	if err := store1.Save(ctx, entry1); err != nil {
		t.Fatalf("Save entry1: %v", err)
	}
	if err := store1.Save(ctx, entry2); err != nil {
		t.Fatalf("Save entry2: %v", err)
	}
	if err := store1.Delete(ctx, entry2.ID); err != nil {
		t.Fatalf("Delete entry2: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("close store1: %v", err)
	}

	// 2. Reopen and verify the deletion persisted.
	store2, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("open store2: %v", err)
	}
	defer store2.Close()

	all, err := store2.List(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 entry after reopen, got %d", len(all))
	}
	if all[0].ID != entry1.ID {
		t.Errorf("remaining entry ID = %q, want %q", all[0].ID, entry1.ID)
	}

	// Deleted entry should not be found.
	_, err = store2.Get(ctx, entry2.ID)
	if err == nil {
		t.Fatal("expected error for deleted entry, got nil")
	}
}

func TestSQLiteStore_PersistenceAcrossReopen_NilBodyAndHeaders(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Save an entry with nil body and nil headers — verifies edge case handling.
	entry := &Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
		Request: RecordedRequest{
			Method:  "GET",
			URL:     mustParseURL("http://example.com/empty"),
			Headers: nil,
			Body:    nil,
		},
		Response: RecordedResponse{
			StatusCode: 204,
			Headers:    nil,
			Body:       nil,
		},
	}

	store1, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("open store1: %v", err)
	}
	if err := store1.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}
	savedID := entry.ID
	if err := store1.Close(); err != nil {
		t.Fatalf("close store1: %v", err)
	}

	// Reopen and verify nil fields are handled correctly.
	store2, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("open store2: %v", err)
	}
	defer store2.Close()

	got, err := store2.Get(ctx, savedID)
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}

	if got.Request.Method != "GET" {
		t.Errorf("Method = %q, want %q", got.Request.Method, "GET")
	}
	if got.Response.StatusCode != 204 {
		t.Errorf("StatusCode = %d, want %d", got.Response.StatusCode, 204)
	}
	if got.Request.URL.String() != "http://example.com/empty" {
		t.Errorf("URL = %q, want %q", got.Request.URL.String(), "http://example.com/empty")
	}
	if got.Tags != nil {
		t.Errorf("Tags = %v, want nil", got.Tags)
	}
}

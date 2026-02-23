package session

import (
	"context"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"testing"
	"time"
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

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

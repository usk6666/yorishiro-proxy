package session

import (
	"context"
	"database/sql"
	"errors"
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

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// saveTestSession saves a session with one send and one receive message.
func saveTestSession(t *testing.T, store *SQLiteStore, protocol string, ts time.Time, method string, reqURL string, statusCode int, reqBody, respBody []byte) *Session {
	t.Helper()
	ctx := context.Background()

	sess := &Session{
		Protocol:    protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   ts,
		Duration:    100 * time.Millisecond,
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	sendMsg := &Message{
		SessionID: sess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    method,
		URL:       mustParseURL(reqURL),
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      reqBody,
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	recvMsg := &Message{
		SessionID:  sess.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  ts.Add(100 * time.Millisecond),
		StatusCode: statusCode,
		Headers:    map[string][]string{"Content-Type": {"text/html"}},
		Body:       respBody,
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(receive): %v", err)
	}

	return sess
}

func TestSQLiteStore_SaveAndGetSession(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{
		Protocol:    "HTTP/1.x",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now().UTC(),
		Duration:    150 * time.Millisecond,
	}

	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("SaveSession did not assign ID")
	}

	got, err := store.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}

	if got.Protocol != "HTTP/1.x" {
		t.Errorf("Protocol = %q, want %q", got.Protocol, "HTTP/1.x")
	}
	if got.SessionType != "unary" {
		t.Errorf("SessionType = %q, want %q", got.SessionType, "unary")
	}
	if got.State != "complete" {
		t.Errorf("State = %q, want %q", got.State, "complete")
	}
	if got.Duration != 150*time.Millisecond {
		t.Errorf("Duration = %v, want %v", got.Duration, 150*time.Millisecond)
	}
}

func TestSQLiteStore_ConnInfo(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{
		Protocol:  "HTTPS",
		Timestamp: time.Now().UTC(),
		ConnInfo: &ConnectionInfo{
			ClientAddr:           "192.168.1.100:54321",
			ServerAddr:           "93.184.216.34:443",
			TLSVersion:           "TLS 1.3",
			TLSCipher:            "TLS_AES_128_GCM_SHA256",
			TLSALPN:              "h2",
			TLSServerCertSubject: "CN=example.com",
		},
	}

	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	got, err := store.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}

	if got.ConnInfo == nil {
		t.Fatal("ConnInfo is nil")
	}
	if got.ConnInfo.ClientAddr != "192.168.1.100:54321" {
		t.Errorf("ClientAddr = %q, want %q", got.ConnInfo.ClientAddr, "192.168.1.100:54321")
	}
	if got.ConnInfo.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want %q", got.ConnInfo.TLSVersion, "TLS 1.3")
	}
}

func TestSQLiteStore_AppendAndGetMessages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	sendMsg := &Message{
		SessionID: sess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       mustParseURL("http://example.com/api"),
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(`{"key":"value"}`),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}
	if sendMsg.ID == "" {
		t.Fatal("AppendMessage did not assign ID")
	}

	recvMsg := &Message{
		SessionID:  sess.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 201,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"id":"123"}`),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(receive): %v", err)
	}

	msgs, err := store.GetMessages(ctx, sess.ID, MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].Direction != "send" {
		t.Errorf("first message direction = %q, want %q", msgs[0].Direction, "send")
	}
	if msgs[0].Method != "POST" {
		t.Errorf("send method = %q, want %q", msgs[0].Method, "POST")
	}
	if msgs[1].StatusCode != 201 {
		t.Errorf("receive status = %d, want %d", msgs[1].StatusCode, 201)
	}
}

func TestSQLiteStore_FilterByDirection(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveSession(ctx, sess)

	store.AppendMessage(ctx, &Message{SessionID: sess.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET"})
	store.AppendMessage(ctx, &Message{SessionID: sess.ID, Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 200})

	sendMsgs, _ := store.GetMessages(ctx, sess.ID, MessageListOptions{Direction: "send"})
	if len(sendMsgs) != 1 {
		t.Errorf("expected 1 send message, got %d", len(sendMsgs))
	}

	recvMsgs, _ := store.GetMessages(ctx, sess.ID, MessageListOptions{Direction: "receive"})
	if len(recvMsgs) != 1 {
		t.Errorf("expected 1 receive message, got %d", len(recvMsgs))
	}
}

func TestSQLiteStore_CountMessages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveSession(ctx, sess)
	store.AppendMessage(ctx, &Message{SessionID: sess.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})
	store.AppendMessage(ctx, &Message{SessionID: sess.ID, Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC()})

	count, err := store.CountMessages(ctx, sess.ID)
	if err != nil {
		t.Fatalf("CountMessages: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestSQLiteStore_UpdateSession(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{Protocol: "HTTP/1.x", State: "active", Timestamp: time.Now().UTC()}
	store.SaveSession(ctx, sess)

	err := store.UpdateSession(ctx, sess.ID, SessionUpdate{
		State:    "complete",
		Duration: 500 * time.Millisecond,
		Tags:     map[string]string{"smuggling": "cl_te"},
	})
	if err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}

	got, _ := store.GetSession(ctx, sess.ID)
	if got.State != "complete" {
		t.Errorf("State = %q, want %q", got.State, "complete")
	}
	if got.Duration != 500*time.Millisecond {
		t.Errorf("Duration = %v, want %v", got.Duration, 500*time.Millisecond)
	}
	if got.Tags["smuggling"] != "cl_te" {
		t.Errorf("Tags[smuggling] = %q, want %q", got.Tags["smuggling"], "cl_te")
	}
}

func TestSQLiteStore_ListSessions_Filters(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/page", 200, nil, []byte("ok"))
	saveTestSession(t, store, "HTTPS", now, "POST", "https://api.example.com/data", 201, []byte("body"), []byte("created"))
	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://other.com/test", 404, nil, []byte("not found"))

	tests := []struct {
		name string
		opts ListOptions
		want int
	}{
		{"no filter", ListOptions{}, 3},
		{"by protocol HTTP", ListOptions{Protocol: "HTTP/1.x"}, 2},
		{"by protocol HTTPS", ListOptions{Protocol: "HTTPS"}, 1},
		{"by method GET", ListOptions{Method: "GET"}, 2},
		{"by method POST", ListOptions{Method: "POST"}, 1},
		{"by URL pattern", ListOptions{URLPattern: "api.example"}, 1},
		{"by status 404", ListOptions{StatusCode: 404}, 1},
		{"by status 200", ListOptions{StatusCode: 200}, 1},
		{"limit", ListOptions{Limit: 1}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := store.ListSessions(ctx, tt.opts)
			if err != nil {
				t.Fatalf("ListSessions: %v", err)
			}
			if len(sessions) != tt.want {
				t.Errorf("got %d sessions, want %d", len(sessions), tt.want)
			}
		})
	}
}

func TestSQLiteStore_CountSessions(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/a", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "POST", "http://example.com/b", 201, nil, nil)

	count, err := store.CountSessions(ctx, ListOptions{Method: "GET"})
	if err != nil {
		t.Fatalf("CountSessions: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	total, err := store.CountSessions(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("CountSessions: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

func TestSQLiteStore_DeleteSession_CascadeMessages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := saveTestSession(t, store, "HTTP/1.x", time.Now().UTC(), "GET", "http://example.com/del", 200, nil, nil)

	// Verify messages exist.
	count, _ := store.CountMessages(ctx, sess.ID)
	if count != 2 {
		t.Fatalf("expected 2 messages before delete, got %d", count)
	}

	if err := store.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	// Session should be gone.
	_, err := store.GetSession(ctx, sess.ID)
	if err == nil {
		t.Fatal("expected error for deleted session, got nil")
	}

	// Messages should be cascade-deleted.
	count, _ = store.CountMessages(ctx, sess.ID)
	if count != 0 {
		t.Errorf("expected 0 messages after cascade delete, got %d", count)
	}
}

func TestSQLiteStore_DeleteAllSessions(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/1", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/2", 200, nil, nil)

	n, err := store.DeleteAllSessions(ctx)
	if err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2", n)
	}

	remaining, _ := store.ListSessions(ctx, ListOptions{})
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_DeleteSessionsOlderThan(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now.Add(-48*time.Hour), "GET", "http://a.com/old", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/new", 200, nil, nil)

	n, err := store.DeleteSessionsOlderThan(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("DeleteSessionsOlderThan: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}

	remaining, _ := store.ListSessions(ctx, ListOptions{})
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_DeleteExcessSessions(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		saveTestSession(t, store, "HTTP/1.x", now.Add(time.Duration(i)*time.Second), "GET", fmt.Sprintf("http://a.com/%d", i), 200, nil, nil)
	}

	n, err := store.DeleteExcessSessions(ctx, 2)
	if err != nil {
		t.Fatalf("DeleteExcessSessions: %v", err)
	}
	if n != 3 {
		t.Errorf("deleted %d, want 3", n)
	}

	remaining, _ := store.ListSessions(ctx, ListOptions{})
	if len(remaining) != 2 {
		t.Errorf("expected 2 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_RawBytes(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveSession(ctx, sess)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	store.AppendMessage(ctx, &Message{
		SessionID: sess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		RawBytes:  rawReq,
	})

	msgs, _ := store.GetMessages(ctx, sess.ID, MessageListOptions{Direction: "send"})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 send message, got %d", len(msgs))
	}
	if string(msgs[0].RawBytes) != string(rawReq) {
		t.Errorf("RawBytes mismatch")
	}
}

func TestSQLiteStore_SequenceUniqueness(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveSession(ctx, sess)

	store.AppendMessage(ctx, &Message{SessionID: sess.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})

	// Duplicate sequence should fail.
	err := store.AppendMessage(ctx, &Message{SessionID: sess.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})
	if err == nil {
		t.Fatal("expected error for duplicate sequence, got nil")
	}
}

func TestSQLiteStore_CancelledContext(t *testing.T) {
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sess := &Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	err := store.SaveSession(ctx, sess)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestSQLiteStore_ConcurrentSaves(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	const n = 50
	errCh := make(chan error, n)

	for i := 0; i < n; i++ {
		go func(i int) {
			sess := &Session{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now().UTC(),
			}
			errCh <- store.SaveSession(ctx, sess)
		}(i)
	}

	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent SaveSession: %v", err)
		}
	}

	sessions, _ := store.ListSessions(ctx, ListOptions{})
	if len(sessions) != n {
		t.Errorf("expected %d sessions, got %d", n, len(sessions))
	}
}

func TestSQLiteStore_LIKEWildcardEscape(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/100%25_done", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/normal", 200, nil, nil)

	sessions, err := store.ListSessions(ctx, ListOptions{URLPattern: "100%25_done"})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 match for LIKE wildcard escape, got %d", len(sessions))
	}
}

func TestSQLiteStore_PersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// Create store and save a session.
	store1, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore(1): %v", err)
	}
	sess := &Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store1.SaveSession(ctx, sess)
	store1.AppendMessage(ctx, &Message{SessionID: sess.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET", URL: mustParseURL("http://example.com/persist")})
	store1.Close()

	// Reopen and verify.
	store2, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore(2): %v", err)
	}
	defer store2.Close()

	sessions, _ := store2.ListSessions(ctx, ListOptions{})
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after reopen, got %d", len(sessions))
	}
	msgs, _ := store2.GetMessages(ctx, sessions[0].ID, MessageListOptions{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message after reopen, got %d", len(msgs))
	}
}

func TestSQLiteStore_Migration(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "migrate.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	store, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Verify schema version.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != latestVersion() {
		t.Errorf("version = %d, want %d", version, latestVersion())
	}
}

func TestSQLiteStore_FutureSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "future.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	// Create a database with a future schema version.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.ExecContext(ctx, bootstrapSQL)
	db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (?)", latestVersion()+1)
	db.Close()

	_, err = NewSQLiteStore(ctx, dbPath, logger)
	if err == nil {
		t.Fatal("expected error for future schema version, got nil")
	}
	if !strings.Contains(err.Error(), "newer than latest") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSQLiteStore_GetNotFound(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GetSession(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session, got nil")
	}
}

func TestSQLiteStore_InvalidDBPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := NewSQLiteStore(context.Background(), "/nonexistent/path/to/db", logger)
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
}

func TestSQLiteStore_Tags(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
		Tags:      map[string]string{"key1": "val1", "key2": "val2"},
	}
	store.SaveSession(ctx, sess)

	got, _ := store.GetSession(ctx, sess.ID)
	if got.Tags["key1"] != "val1" {
		t.Errorf("Tags[key1] = %q, want %q", got.Tags["key1"], "val1")
	}
	if got.Tags["key2"] != "val2" {
		t.Errorf("Tags[key2] = %q, want %q", got.Tags["key2"], "val2")
	}
}

func TestSQLiteStore_BodyTruncated(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	sess := &Session{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveSession(ctx, sess)

	store.AppendMessage(ctx, &Message{
		SessionID:     sess.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     time.Now().UTC(),
		Body:          []byte("partial"),
		BodyTruncated: true,
	})

	msgs, _ := store.GetMessages(ctx, sess.ID, MessageListOptions{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !msgs[0].BodyTruncated {
		t.Error("BodyTruncated = false, want true")
	}
}

func TestSQLiteStore_DBFileCreated(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "created.db")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		t.Errorf("database file was not created at %s", dbPath)
	}
}

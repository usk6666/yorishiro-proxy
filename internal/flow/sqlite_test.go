package flow

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
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

// saveTestSession saves a flow with one send and one receive message.
func saveTestSession(t *testing.T, store *SQLiteStore, protocol string, ts time.Time, method string, reqURL string, statusCode int, reqBody, respBody []byte) *Stream {
	t.Helper()
	ctx := context.Background()

	fl := &Stream{
		Protocol:  protocol,
		State:     "complete",
		Timestamp: ts,
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: ts,
		Method:    method,
		URL:       mustParseURL(reqURL),
		Headers:   map[string][]string{"Host": {"example.com"}},
		Body:      reqBody,
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	recvMsg := &Flow{
		StreamID:   fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  ts.Add(100 * time.Millisecond),
		StatusCode: statusCode,
		Headers:    map[string][]string{"Content-Type": {"text/html"}},
		Body:       respBody,
	}
	if err := store.SaveFlow(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(receive): %v", err)
	}

	return fl
}

func TestNewSQLiteStore_BusyTimeout(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "busy_timeout_test.db")
	logger := testutil.DiscardLogger()
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	var timeout int
	err = store.db.QueryRow("PRAGMA busy_timeout").Scan(&timeout)
	if err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if timeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", timeout)
	}
}

func TestSQLiteStore_SaveAndGetSession(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  150 * time.Millisecond,
	}

	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if fl.ID == "" {
		t.Fatal("SaveFlow did not assign ID")
	}

	got, err := store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	if got.Protocol != "HTTP/1.x" {
		t.Errorf("Protocol = %q, want %q", got.Protocol, "HTTP/1.x")
	}
	if got.State != "complete" {
		t.Errorf("State = %q, want %q", got.State, "complete")
	}
	if got.Duration != 150*time.Millisecond {
		t.Errorf("Duration = %v, want %v", got.Duration, 150*time.Millisecond)
	}
}

func TestSQLiteStore_ConnInfo(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{
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

	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	got, err := store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
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
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       mustParseURL("http://example.com/api"),
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(`{"key":"value"}`),
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}
	if sendMsg.ID == "" {
		t.Fatal("AppendMessage did not assign ID")
	}

	recvMsg := &Flow{
		StreamID:   fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 201,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"id":"123"}`),
	}
	if err := store.SaveFlow(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(receive): %v", err)
	}

	msgs, err := store.GetFlows(ctx, fl.ID, FlowListOptions{})
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
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveStream(ctx, fl)

	store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET"})
	store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 200})

	sendMsgs, _ := store.GetFlows(ctx, fl.ID, FlowListOptions{Direction: "send"})
	if len(sendMsgs) != 1 {
		t.Errorf("expected 1 send message, got %d", len(sendMsgs))
	}

	recvMsgs, _ := store.GetFlows(ctx, fl.ID, FlowListOptions{Direction: "receive"})
	if len(recvMsgs) != 1 {
		t.Errorf("expected 1 receive message, got %d", len(recvMsgs))
	}
}

func TestSQLiteStore_CountMessages(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveStream(ctx, fl)
	store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})
	store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC()})

	count, err := store.CountFlows(ctx, fl.ID)
	if err != nil {
		t.Fatalf("CountMessages: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestSQLiteStore_UpdateSession(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", State: "active", Timestamp: time.Now().UTC()}
	store.SaveStream(ctx, fl)

	err := store.UpdateStream(ctx, fl.ID, StreamUpdate{
		State:    "complete",
		Duration: 500 * time.Millisecond,
		Tags:     map[string]string{"smuggling": "cl_te"},
	})
	if err != nil {
		t.Fatalf("UpdateFlow: %v", err)
	}

	got, _ := store.GetStream(ctx, fl.ID)
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
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/page", 200, nil, []byte("ok"))
	saveTestSession(t, store, "HTTPS", now, "POST", "https://api.example.com/data", 201, []byte("body"), []byte("created"))
	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://other.com/test", 404, nil, []byte("not found"))

	tests := []struct {
		name string
		opts StreamListOptions
		want int
	}{
		{"no filter", StreamListOptions{}, 3},
		{"by protocol HTTP", StreamListOptions{Protocol: "HTTP/1.x"}, 2},
		{"by protocol HTTPS", StreamListOptions{Protocol: "HTTPS"}, 1},
		{"by method GET", StreamListOptions{Method: "GET"}, 2},
		{"by method POST", StreamListOptions{Method: "POST"}, 1},
		{"by URL pattern", StreamListOptions{URLPattern: "api.example"}, 1},
		{"by status 404", StreamListOptions{StatusCode: 404}, 1},
		{"by status 200", StreamListOptions{StatusCode: 200}, 1},
		{"by state complete", StreamListOptions{State: "complete"}, 3},
		{"by state error", StreamListOptions{State: "error"}, 0},
		{"limit", StreamListOptions{Limit: 1}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := store.ListStreams(ctx, tt.opts)
			if err != nil {
				t.Fatalf("ListFlows: %v", err)
			}
			if len(sessions) != tt.want {
				t.Errorf("got %d sessions, want %d", len(sessions), tt.want)
			}
		})
	}
}

func TestSQLiteStore_ListSessions_StateFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create sessions with different states.
	activeSession := &Stream{
		Protocol:  "HTTPS",
		State:     "active",
		Timestamp: now,
	}
	if err := store.SaveStream(ctx, activeSession); err != nil {
		t.Fatalf("SaveSession(active): %v", err)
	}

	completeSession := &Stream{
		Protocol:  "HTTPS",
		State:     "complete",
		Timestamp: now,
	}
	if err := store.SaveStream(ctx, completeSession); err != nil {
		t.Fatalf("SaveSession(complete): %v", err)
	}

	errorSession := &Stream{
		Protocol:  "HTTPS",
		State:     "error",
		Timestamp: now,
	}
	if err := store.SaveStream(ctx, errorSession); err != nil {
		t.Fatalf("SaveSession(error): %v", err)
	}

	tests := []struct {
		name  string
		state string
		want  int
	}{
		{"active sessions", "active", 1},
		{"complete sessions", "complete", 1},
		{"error sessions", "error", 1},
		{"all sessions", "", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := store.ListStreams(ctx, StreamListOptions{State: tt.state})
			if err != nil {
				t.Fatalf("ListSessions: %v", err)
			}
			if len(sessions) != tt.want {
				t.Errorf("got %d sessions, want %d", len(sessions), tt.want)
			}

			count, err := store.CountStreams(ctx, StreamListOptions{State: tt.state})
			if err != nil {
				t.Fatalf("CountSessions: %v", err)
			}
			if count != tt.want {
				t.Errorf("count = %d, want %d", count, tt.want)
			}
		})
	}
}

func TestSQLiteStore_CountSessions(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/a", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "POST", "http://example.com/b", 201, nil, nil)

	count, err := store.CountStreams(ctx, StreamListOptions{Method: "GET"})
	if err != nil {
		t.Fatalf("CountFlows: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	total, err := store.CountStreams(ctx, StreamListOptions{})
	if err != nil {
		t.Fatalf("CountFlows: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

func TestSQLiteStore_DeleteSession_CascadeMessages(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := saveTestSession(t, store, "HTTP/1.x", time.Now().UTC(), "GET", "http://example.com/del", 200, nil, nil)

	// Verify messages exist.
	count, _ := store.CountFlows(ctx, fl.ID)
	if count != 2 {
		t.Fatalf("expected 2 messages before delete, got %d", count)
	}

	if err := store.DeleteStream(ctx, fl.ID); err != nil {
		t.Fatalf("DeleteFlow: %v", err)
	}

	// Flow should be gone.
	_, err := store.GetStream(ctx, fl.ID)
	if err == nil {
		t.Fatal("expected error for deleted flow, got nil")
	}

	// Messages should be cascade-deleted.
	count, _ = store.CountFlows(ctx, fl.ID)
	if count != 0 {
		t.Errorf("expected 0 messages after cascade delete, got %d", count)
	}
}

func TestSQLiteStore_DeleteAllSessions(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	fl1 := saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/1", 200, nil, nil)
	fl2 := saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/2", 200, nil, nil)

	n, err := store.DeleteAllStreams(ctx)
	if err != nil {
		t.Fatalf("DeleteAllFlows: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 0 {
		t.Errorf("expected 0 remaining, got %d", len(remaining))
	}

	// Verify messages are cascade-deleted (regression test for BUG-001).
	for _, id := range []string{fl1.ID, fl2.ID} {
		count, _ := store.CountFlows(ctx, id)
		if count != 0 {
			t.Errorf("expected 0 messages for flow %s after cascade delete, got %d", id, count)
		}
	}
}

func TestSQLiteStore_DeleteSessionsOlderThan(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now.Add(-48*time.Hour), "GET", "http://a.com/old", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/new", 200, nil, nil)

	n, err := store.DeleteStreamsOlderThan(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("DeleteFlowsOlderThan: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_DeleteSessionsByProtocol(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/1", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "POST", "http://a.com/2", 201, nil, nil)
	saveTestSession(t, store, "HTTPS", now, "GET", "https://a.com/3", 200, nil, nil)
	saveTestSession(t, store, "TCP", now, "GET", "http://a.com/4", 200, nil, nil)

	tests := []struct {
		name          string
		protocol      string
		wantDeleted   int64
		wantRemaining int
	}{
		{
			name:          "delete TCP sessions",
			protocol:      "TCP",
			wantDeleted:   1,
			wantRemaining: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := store.DeleteStreamsByProtocol(ctx, tt.protocol)
			if err != nil {
				t.Fatalf("DeleteFlowsByProtocol: %v", err)
			}
			if n != tt.wantDeleted {
				t.Errorf("deleted %d, want %d", n, tt.wantDeleted)
			}
			remaining, _ := store.ListStreams(ctx, StreamListOptions{})
			if len(remaining) != tt.wantRemaining {
				t.Errorf("expected %d remaining, got %d", tt.wantRemaining, len(remaining))
			}
		})
	}
}

func TestSQLiteStore_DeleteSessionsByProtocol_NoMatches(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/1", 200, nil, nil)

	n, err := store.DeleteStreamsByProtocol(ctx, "WebSocket")
	if err != nil {
		t.Fatalf("DeleteFlowsByProtocol: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted %d, want 0", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_DeleteSessionsByProtocol_CascadeMessages(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	fl := saveTestSession(t, store, "TCP", now, "GET", "http://a.com/tcp", 200, nil, nil)

	// Verify messages exist before deletion.
	count, _ := store.CountFlows(ctx, fl.ID)
	if count != 2 {
		t.Fatalf("expected 2 messages before delete, got %d", count)
	}

	n, err := store.DeleteStreamsByProtocol(ctx, "TCP")
	if err != nil {
		t.Fatalf("DeleteFlowsByProtocol: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}

	// Messages should be cascade-deleted.
	count, _ = store.CountFlows(ctx, fl.ID)
	if count != 0 {
		t.Errorf("expected 0 messages after cascade delete, got %d", count)
	}
}

func TestSQLiteStore_DeleteExcessSessions(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		saveTestSession(t, store, "HTTP/1.x", now.Add(time.Duration(i)*time.Second), "GET", fmt.Sprintf("http://a.com/%d", i), 200, nil, nil)
	}

	n, err := store.DeleteExcessStreams(ctx, 2)
	if err != nil {
		t.Fatalf("DeleteExcessFlows: %v", err)
	}
	if n != 3 {
		t.Errorf("deleted %d, want 3", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 2 {
		t.Errorf("expected 2 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_RawBytes(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveStream(ctx, fl)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	store.SaveFlow(ctx, &Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		RawBytes:  rawReq,
	})

	msgs, _ := store.GetFlows(ctx, fl.ID, FlowListOptions{Direction: "send"})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 send message, got %d", len(msgs))
	}
	if string(msgs[0].RawBytes) != string(rawReq) {
		t.Errorf("RawBytes mismatch")
	}
}

func TestSQLiteStore_SequenceUniqueness(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveStream(ctx, fl)

	store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})

	// Duplicate sequence should fail.
	err := store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})
	if err == nil {
		t.Fatal("expected error for duplicate sequence, got nil")
	}
}

func TestSQLiteStore_CancelledContext(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	err := store.SaveStream(ctx, fl)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestSQLiteStore_ConcurrentSaves(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	const n = 50
	errCh := make(chan error, n)

	for i := 0; i < n; i++ {
		go func(i int) {
			fl := &Stream{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now().UTC(),
			}
			errCh <- store.SaveStream(ctx, fl)
		}(i)
	}

	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent SaveFlow: %v", err)
		}
	}

	sessions, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(sessions) != n {
		t.Errorf("expected %d sessions, got %d", n, len(sessions))
	}
}

func TestSQLiteStore_LIKEWildcardEscape(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/100%25_done", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/normal", 200, nil, nil)

	sessions, err := store.ListStreams(ctx, StreamListOptions{URLPattern: "100%25_done"})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 match for LIKE wildcard escape, got %d", len(sessions))
	}
}

func TestSQLiteStore_PersistenceAcrossReopen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist.db")
	logger := testutil.DiscardLogger()
	ctx := context.Background()

	// Create store and save a flow.
	store1, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore(1): %v", err)
	}
	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store1.SaveStream(ctx, fl)
	store1.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET", URL: mustParseURL("http://example.com/persist")})
	store1.Close()

	// Reopen and verify.
	store2, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore(2): %v", err)
	}
	defer store2.Close()

	sessions, _ := store2.ListStreams(ctx, StreamListOptions{})
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session after reopen, got %d", len(sessions))
	}
	msgs, _ := store2.GetFlows(ctx, sessions[0].ID, FlowListOptions{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message after reopen, got %d", len(msgs))
	}
}

func TestSQLiteStore_Migration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "migrate.db")
	logger := testutil.DiscardLogger()
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
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "future.db")
	logger := testutil.DiscardLogger()
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
	t.Parallel()
	store := newTestStore(t)
	_, err := store.GetStream(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent flow, got nil")
	}
}

func TestSQLiteStore_InvalidDBPath(t *testing.T) {
	t.Parallel()
	logger := testutil.DiscardLogger()
	_, err := NewSQLiteStore(context.Background(), "/nonexistent/path/to/db", logger)
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
}

func TestSQLiteStore_Tags(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
		Tags:      map[string]string{"key1": "val1", "key2": "val2"},
	}
	store.SaveStream(ctx, fl)

	got, _ := store.GetStream(ctx, fl.ID)
	if got.Tags["key1"] != "val1" {
		t.Errorf("Tags[key1] = %q, want %q", got.Tags["key1"], "val1")
	}
	if got.Tags["key2"] != "val2" {
		t.Errorf("Tags[key2] = %q, want %q", got.Tags["key2"], "val2")
	}
}

func TestSQLiteStore_BodyTruncated(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveStream(ctx, fl)

	store.SaveFlow(ctx, &Flow{
		StreamID:      fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     time.Now().UTC(),
		Body:          []byte("partial"),
		BodyTruncated: true,
	})

	msgs, _ := store.GetFlows(ctx, fl.ID, FlowListOptions{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !msgs[0].BodyTruncated {
		t.Error("BodyTruncated = false, want true")
	}
}

func TestSQLiteStore_DBFileCreated(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "created.db")
	logger := testutil.DiscardLogger()

	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		t.Errorf("database file was not created at %s", dbPath)
	}
}

func TestSQLiteStore_BlockedBy_SaveAndGet(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	tests := []struct {
		name      string
		blockedBy string
	}{
		{"not blocked", ""},
		{"blocked by target_scope", "target_scope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := &Stream{
				Protocol:  "HTTPS",
				Timestamp: time.Now().UTC(),
				BlockedBy: tt.blockedBy,
			}
			if err := store.SaveStream(ctx, fl); err != nil {
				t.Fatalf("SaveFlow: %v", err)
			}

			got, err := store.GetStream(ctx, fl.ID)
			if err != nil {
				t.Fatalf("GetFlow: %v", err)
			}

			if got.BlockedBy != tt.blockedBy {
				t.Errorf("BlockedBy = %q, want %q", got.BlockedBy, tt.blockedBy)
			}
		})
	}
}

func TestSQLiteStore_BlockedBy_ListFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Save a normal flow.
	normalSess := &Stream{
		Protocol:  "HTTPS",
		Timestamp: now,
	}
	if err := store.SaveStream(ctx, normalSess); err != nil {
		t.Fatalf("SaveFlow(normal): %v", err)
	}

	// Save a blocked flow.
	blockedSess := &Stream{
		Protocol:  "HTTPS",
		Timestamp: now,
		BlockedBy: "target_scope",
	}
	if err := store.SaveStream(ctx, blockedSess); err != nil {
		t.Fatalf("SaveFlow(blocked): %v", err)
	}

	tests := []struct {
		name string
		opts StreamListOptions
		want int
	}{
		{"no filter returns all", StreamListOptions{}, 2},
		{"filter by target_scope", StreamListOptions{BlockedBy: "target_scope"}, 1},
		{"filter by nonexistent blocker", StreamListOptions{BlockedBy: "nonexistent"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := store.ListStreams(ctx, tt.opts)
			if err != nil {
				t.Fatalf("ListFlows: %v", err)
			}
			if len(sessions) != tt.want {
				t.Errorf("got %d sessions, want %d", len(sessions), tt.want)
			}
		})
	}
}

func TestSQLiteStore_BlockedBy_CountFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Save two normal sessions and one blocked.
	for i := 0; i < 2; i++ {
		if err := store.SaveStream(ctx, &Stream{
			Protocol:  "HTTPS",
			Timestamp: now,
		}); err != nil {
			t.Fatalf("SaveFlow(normal %d): %v", i, err)
		}
	}
	if err := store.SaveStream(ctx, &Stream{
		Protocol:  "HTTPS",
		Timestamp: now,
		BlockedBy: "target_scope",
	}); err != nil {
		t.Fatalf("SaveFlow(blocked): %v", err)
	}

	count, err := store.CountStreams(ctx, StreamListOptions{BlockedBy: "target_scope"})
	if err != nil {
		t.Fatalf("CountFlows: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	total, err := store.CountStreams(ctx, StreamListOptions{})
	if err != nil {
		t.Fatalf("CountFlows: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
}

func TestSQLiteStore_BlockedBy_DefaultEmpty(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Save a flow without setting BlockedBy — it should default to "".
	fl := &Stream{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	got, err := store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if got.BlockedBy != "" {
		t.Errorf("BlockedBy = %q, want empty string", got.BlockedBy)
	}
}

func TestSQLiteStore_BlockedBy_WithMessages(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// A blocked session: has a send message (the request that was attempted)
	// but no receive message (because it was blocked).
	fl := &Stream{
		Protocol:  "HTTPS",
		State:     "complete",
		Timestamp: now,
		BlockedBy: "target_scope",
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: now,
		Method:    "GET",
		URL:       mustParseURL("https://evil.com/admin"),
		Headers:   map[string][]string{"Host": {"evil.com"}},
	}
	if err := store.SaveFlow(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	// Retrieve and verify.
	got, err := store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if got.BlockedBy != "target_scope" {
		t.Errorf("BlockedBy = %q, want %q", got.BlockedBy, "target_scope")
	}

	msgs, err := store.GetFlows(ctx, fl.ID, FlowListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 message (send only), got %d", len(msgs))
	}
	if msgs[0].Direction != "send" {
		t.Errorf("message direction = %q, want %q", msgs[0].Direction, "send")
	}
}

func TestSQLiteStore_BlockedBy_MigrationFromV2(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v2_migrate.db")
	logger := testutil.DiscardLogger()
	ctx := context.Background()

	// Create a V2 database manually (simulate a pre-existing database).
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := db.ExecContext(ctx, bootstrapSQL); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if _, err := db.ExecContext(ctx, schemaV1); err != nil {
		t.Fatalf("schema v1: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (1)"); err != nil {
		t.Fatalf("insert version 1: %v", err)
	}
	if _, err := db.ExecContext(ctx, schemaV2); err != nil {
		t.Fatalf("schema v2: %v", err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE schema_version SET version = 2"); err != nil {
		t.Fatalf("update version 2: %v", err)
	}

	// Insert a flow into the V2 schema (no blocked_by column yet).
	// Note: At V2, the table is still named "sessions" — it gets renamed to "flows" in V4.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sessions (id, conn_id, protocol, session_type, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"old-session-id", "conn-1", "HTTPS", "unary", "complete",
		time.Now().UTC().Format(time.RFC3339Nano), 100, "{}", "", "", "", "", "", "",
	); err != nil {
		t.Fatalf("insert V2 session: %v", err)
	}
	db.Close()

	// Open with migration — should add blocked_by column.
	store, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore (migration): %v", err)
	}
	defer store.Close()

	// Verify the old session has empty blocked_by.
	fl, err := store.GetStream(ctx, "old-session-id")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if fl.BlockedBy != "" {
		t.Errorf("old session BlockedBy = %q, want empty", fl.BlockedBy)
	}

	// Verify we can save a new flow with blocked_by.
	newSess := &Stream{
		Protocol:  "HTTPS",
		Timestamp: time.Now().UTC(),
		BlockedBy: "target_scope",
	}
	if err := store.SaveStream(ctx, newSess); err != nil {
		t.Fatalf("SaveFlow(new): %v", err)
	}

	got, err := store.GetStream(ctx, newSess.ID)
	if err != nil {
		t.Fatalf("GetFlow(new): %v", err)
	}
	if got.BlockedBy != "target_scope" {
		t.Errorf("new flow BlockedBy = %q, want %q", got.BlockedBy, "target_scope")
	}

	// Verify schema version is latest (V3 adds blocked_by, V4 renames sessions→flows,
	// V5 adds timing columns, V6 adds scheme, V7 renames flows→streams,
	// V8 adds direction to unique constraint).
	checkDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open check db: %v", err)
	}
	defer checkDB.Close()

	var version int
	if err := checkDB.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != latestVersion() {
		t.Errorf("schema version = %d, want %d", version, latestVersion())
	}
}

// TestSQLiteStore_V7Migration_TableRename verifies the V7 migration that renames
// flows→streams and messages→flows, drops the flow_type column, and updates
// foreign key references.
func TestSQLiteStore_V7Migration_TableRename(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v7_migrate.db")
	ctx := context.Background()
	logger := testutil.DiscardLogger()

	// Create a V6 database manually with old schema.
	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	// Apply V1-V6 migrations manually.
	for _, ddl := range []string{bootstrapSQL, schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatalf("apply schema: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (6)"); err != nil {
		t.Fatalf("insert version: %v", err)
	}

	// Insert test data in old schema (flows table = connection-level, messages table = per-message).
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO flows (id, conn_id, protocol, scheme, flow_type, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"stream-1", "conn-1", "HTTPS", "https", "unary", "complete", ts, 100, "{}", "", "93.184.216.34:443", "", "", "", "", "", nil, nil, nil,
	); err != nil {
		t.Fatalf("insert old flow: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO messages (id, flow_id, sequence, direction, timestamp, headers, body, method, url, status_code, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"flow-1", "stream-1", 0, "send", ts, "{}", []byte("hello"), "GET", "https://example.com/", 0, "{}",
	); err != nil {
		t.Fatalf("insert old message: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO messages (id, flow_id, sequence, direction, timestamp, headers, body, method, url, status_code, metadata)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"flow-2", "stream-1", 1, "receive", ts, "{}", []byte("world"), "", "", 200, "{}",
	); err != nil {
		t.Fatalf("insert old message: %v", err)
	}
	db.Close()

	// Open with migration — should apply V7 (table rename + flow_type removal).
	store, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore (V7 migration): %v", err)
	}
	defer store.Close()

	// Verify stream is readable via the new schema.
	st, err := store.GetStream(ctx, "stream-1")
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if st.Protocol != "HTTPS" {
		t.Errorf("stream protocol = %q, want %q", st.Protocol, "HTTPS")
	}
	if st.Scheme != "https" {
		t.Errorf("stream scheme = %q, want %q", st.Scheme, "https")
	}

	// Verify flows (formerly messages) are readable.
	flows, err := store.GetFlows(ctx, "stream-1", FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(flows) != 2 {
		t.Fatalf("got %d flows, want 2", len(flows))
	}
	if flows[0].StreamID != "stream-1" {
		t.Errorf("flow[0].StreamID = %q, want %q", flows[0].StreamID, "stream-1")
	}
	if flows[0].Direction != "send" {
		t.Errorf("flow[0].Direction = %q, want %q", flows[0].Direction, "send")
	}
	if flows[1].StatusCode != 200 {
		t.Errorf("flow[1].StatusCode = %d, want 200", flows[1].StatusCode)
	}

	// Verify flow_type column is removed (no longer in the schema).
	checkDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open check db: %v", err)
	}
	defer checkDB.Close()

	// flow_type column should not exist in the streams table.
	rows, err := checkDB.QueryContext(ctx, "PRAGMA table_info(streams)")
	if err != nil {
		t.Fatalf("pragma table_info: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		if name == "flow_type" {
			t.Error("flow_type column still exists in streams table — should have been removed")
		}
	}

	// Verify schema version is latest.
	var version int
	if err := checkDB.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != latestVersion() {
		t.Errorf("schema version = %d, want %d", version, latestVersion())
	}

	// Verify cascade delete still works.
	if err := store.DeleteStream(ctx, "stream-1"); err != nil {
		t.Fatalf("DeleteStream: %v", err)
	}
	flowsAfter, err := store.GetFlows(ctx, "stream-1", FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows after delete: %v", err)
	}
	if len(flowsAfter) != 0 {
		t.Errorf("got %d flows after cascade delete, want 0", len(flowsAfter))
	}
}

func TestGetFlow_PrefixMatch(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a flow with a known ID.
	fl := &Stream{
		ID:        "abcdef12-3456-7890-abcd-ef1234567890",
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	tests := []struct {
		name    string
		id      string
		wantID  string
		wantErr string
	}{
		{
			name:   "full UUID exact match",
			id:     "abcdef12-3456-7890-abcd-ef1234567890",
			wantID: "abcdef12-3456-7890-abcd-ef1234567890",
		},
		{
			name:   "8-char prefix match",
			id:     "abcdef12",
			wantID: "abcdef12-3456-7890-abcd-ef1234567890",
		},
		{
			name:    "8-char prefix no match",
			id:      "xxxxxxxx",
			wantErr: "stream not found",
		},
		{
			name:    "full UUID no match",
			id:      "00000000-0000-0000-0000-000000000000",
			wantErr: "stream not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.GetStream(ctx, tt.id)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("GetFlow() error = nil, wantErr %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("GetFlow() error = %q, want containing %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetFlow() unexpected error: %v", err)
			}
			if got.ID != tt.wantID {
				t.Errorf("GetFlow() ID = %q, want %q", got.ID, tt.wantID)
			}
		})
	}
}

func TestValidateFlowID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "full UUID (36 chars)", id: "abcdef12-3456-7890-abcd-ef1234567890", wantErr: false},
		{name: "8-char prefix", id: "abcdef12", wantErr: false},
		{name: "empty string", id: "", wantErr: true},
		{name: "1 char", id: "a", wantErr: true},
		{name: "7 chars", id: "abcdef1", wantErr: true},
		{name: "9 chars", id: "abcdef12-", wantErr: true},
		{name: "20 chars", id: "abcdef12-3456-7890-a", wantErr: true},
		{name: "35 chars", id: "abcdef12-3456-7890-abcd-ef123456789", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStreamID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStreamID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
			if tt.wantErr && err != nil {
				if !strings.Contains(err.Error(), "invalid stream ID") {
					t.Errorf("ValidateStreamID(%q) error = %q, want containing 'invalid stream ID'", tt.id, err.Error())
				}
			}
		})
	}
}

func TestGetFlow_PrefixMatch_Ambiguous(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create two flows that share the same 8-char prefix.
	fl1 := &Stream{
		ID:        "abcdef12-1111-1111-1111-111111111111",
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	fl2 := &Stream{
		ID:        "abcdef12-2222-2222-2222-222222222222",
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl1); err != nil {
		t.Fatalf("SaveFlow fl1: %v", err)
	}
	if err := store.SaveStream(ctx, fl2); err != nil {
		t.Fatalf("SaveFlow fl2: %v", err)
	}

	// 8-char prefix should be ambiguous.
	_, err := store.GetStream(ctx, "abcdef12")
	if err == nil {
		t.Fatal("GetFlow() expected ambiguous error, got nil")
	}
	if !strings.Contains(err.Error(), "ambiguous stream ID prefix") {
		t.Errorf("GetFlow() error = %q, want containing 'ambiguous stream ID prefix'", err.Error())
	}
	if !strings.Contains(err.Error(), "matched 2 streams") {
		t.Errorf("GetFlow() error = %q, want containing 'matched 2 streams'", err.Error())
	}

	// Full UUID should still work for each flow.
	got1, err := store.GetStream(ctx, fl1.ID)
	if err != nil {
		t.Fatalf("GetFlow(fl1 full ID): %v", err)
	}
	if got1.ID != fl1.ID {
		t.Errorf("GetFlow(fl1) ID = %q, want %q", got1.ID, fl1.ID)
	}

	got2, err := store.GetStream(ctx, fl2.ID)
	if err != nil {
		t.Fatalf("GetFlow(fl2 full ID): %v", err)
	}
	if got2.ID != fl2.ID {
		t.Errorf("GetFlow(fl2) ID = %q, want %q", got2.ID, fl2.ID)
	}
}

func TestGetFlow_PrefixMatch_UniqueAfterAmbiguity(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Two flows with different 8-char prefixes.
	fl1 := &Stream{
		ID:        "aaaaaaaa-1111-1111-1111-111111111111",
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	fl2 := &Stream{
		ID:        "bbbbbbbb-2222-2222-2222-222222222222",
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl1); err != nil {
		t.Fatalf("SaveFlow fl1: %v", err)
	}
	if err := store.SaveStream(ctx, fl2); err != nil {
		t.Fatalf("SaveFlow fl2: %v", err)
	}

	// Each 8-char prefix should uniquely resolve.
	got1, err := store.GetStream(ctx, "aaaaaaaa")
	if err != nil {
		t.Fatalf("GetFlow(aaaaaaaa): %v", err)
	}
	if got1.ID != fl1.ID {
		t.Errorf("GetFlow(aaaaaaaa) ID = %q, want %q", got1.ID, fl1.ID)
	}

	got2, err := store.GetStream(ctx, "bbbbbbbb")
	if err != nil {
		t.Fatalf("GetFlow(bbbbbbbb): %v", err)
	}
	if got2.ID != fl2.ID {
		t.Errorf("GetFlow(bbbbbbbb) ID = %q, want %q", got2.ID, fl2.ID)
	}
}

func TestSQLiteStore_HostFilter_BoundaryAnchoring(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Flow 1: URL with path — https://example.com/path
	saveTestSession(t, store, "HTTPS", now, "GET", "https://example.com/path", 200, nil, []byte("ok"))
	// Flow 2: URL with query string only — https://example.com?q=1
	saveTestSession(t, store, "HTTPS", now, "GET", "https://example.com?q=1", 200, nil, []byte("ok"))
	// Flow 3: URL with port — https://example.com:8443/path
	saveTestSession(t, store, "HTTPS", now, "GET", "https://example.com:8443/path", 200, nil, []byte("ok"))
	// Flow 4: bare host URL — https://example.com
	saveTestSession(t, store, "HTTPS", now, "GET", "https://example.com", 200, nil, []byte("ok"))
	// Flow 5: subdomain impostor — https://example.com.evil.com/path (should NOT match)
	saveTestSession(t, store, "HTTPS", now, "GET", "https://example.com.evil.com/path", 200, nil, []byte("ok"))
	// Flow 6: subdomain impostor bare — https://example.com.evil.com (should NOT match)
	saveTestSession(t, store, "HTTPS", now, "GET", "https://example.com.evil.com", 200, nil, []byte("ok"))

	tests := []struct {
		name string
		host string
		want int
	}{
		{"matches path URL", "example.com", 4},
		{"no subdomain false positive", "example.com", 4},
		{"evil domain matches itself", "example.com.evil.com", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows, err := store.ListStreams(ctx, StreamListOptions{Host: tt.host})
			if err != nil {
				t.Fatalf("ListFlows(Host=%q): %v", tt.host, err)
			}
			if len(flows) != tt.want {
				var urls []string
				for _, f := range flows {
					msgs, _ := store.GetFlows(ctx, f.ID, FlowListOptions{Direction: "send"})
					if len(msgs) > 0 && msgs[0].URL != nil {
						urls = append(urls, msgs[0].URL.String())
					}
				}
				t.Errorf("Host=%q: got %d flows %v, want %d", tt.host, len(flows), urls, tt.want)
			}
		})
	}
}

func TestSQLiteStore_FlowTiming_SaveAndGet(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	sendMs := int64(10)
	waitMs := int64(50)
	receiveMs := int64(30)

	fl := &Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  90 * time.Millisecond,
		SendMs:    &sendMs,
		WaitMs:    &waitMs,
		ReceiveMs: &receiveMs,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	got, err := store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	if got.SendMs == nil || *got.SendMs != 10 {
		t.Errorf("SendMs = %v, want 10", got.SendMs)
	}
	if got.WaitMs == nil || *got.WaitMs != 50 {
		t.Errorf("WaitMs = %v, want 50", got.WaitMs)
	}
	if got.ReceiveMs == nil || *got.ReceiveMs != 30 {
		t.Errorf("ReceiveMs = %v, want 30", got.ReceiveMs)
	}
}

func TestSQLiteStore_FlowTiming_NullByDefault(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Flow without timing (e.g., Raw TCP or legacy flow).
	fl := &Stream{
		Protocol:  "Raw TCP",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  200 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	got, err := store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	if got.SendMs != nil {
		t.Errorf("SendMs = %v, want nil", got.SendMs)
	}
	if got.WaitMs != nil {
		t.Errorf("WaitMs = %v, want nil", got.WaitMs)
	}
	if got.ReceiveMs != nil {
		t.Errorf("ReceiveMs = %v, want nil", got.ReceiveMs)
	}
}

func TestSQLiteStore_FlowTiming_UpdateFlow(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create flow without timing (progressive recording: send phase).
	fl := &Stream{
		Protocol:  "HTTPS",
		State:     "active",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Verify timing is null initially.
	got, err := store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow (before update): %v", err)
	}
	if got.SendMs != nil || got.WaitMs != nil || got.ReceiveMs != nil {
		t.Fatalf("timing should be nil before update")
	}

	// Update flow with timing (receive phase).
	sendMs := int64(5)
	waitMs := int64(120)
	receiveMs := int64(45)
	update := StreamUpdate{
		State:     "complete",
		Duration:  170 * time.Millisecond,
		SendMs:    &sendMs,
		WaitMs:    &waitMs,
		ReceiveMs: &receiveMs,
	}
	if err := store.UpdateStream(ctx, fl.ID, update); err != nil {
		t.Fatalf("UpdateFlow: %v", err)
	}

	got, err = store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow (after update): %v", err)
	}
	if got.State != "complete" {
		t.Errorf("State = %q, want %q", got.State, "complete")
	}
	if got.SendMs == nil || *got.SendMs != 5 {
		t.Errorf("SendMs = %v, want 5", got.SendMs)
	}
	if got.WaitMs == nil || *got.WaitMs != 120 {
		t.Errorf("WaitMs = %v, want 120", got.WaitMs)
	}
	if got.ReceiveMs == nil || *got.ReceiveMs != 45 {
		t.Errorf("ReceiveMs = %v, want 45", got.ReceiveMs)
	}
}

func TestSQLiteStore_FlowTiming_ErrorFlowNullTiming(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Simulate 502 error: flow created during send phase, then updated to error.
	fl := &Stream{
		Protocol:  "HTTP/1.x",
		State:     "active",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Update to error state without timing (upstream failed before response).
	update := StreamUpdate{
		State:    "error",
		Duration: 50 * time.Millisecond,
	}
	if err := store.UpdateStream(ctx, fl.ID, update); err != nil {
		t.Fatalf("UpdateFlow: %v", err)
	}

	got, err := store.GetStream(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if got.State != "error" {
		t.Errorf("State = %q, want %q", got.State, "error")
	}
	if got.SendMs != nil || got.WaitMs != nil || got.ReceiveMs != nil {
		t.Errorf("error flow should have nil timing, got send=%v wait=%v receive=%v",
			got.SendMs, got.WaitMs, got.ReceiveMs)
	}
}

func TestSQLiteStore_FlowTiming_ListFlows(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a flow with timing.
	sendMs := int64(8)
	waitMs := int64(100)
	receiveMs := int64(22)
	fl := &Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  130 * time.Millisecond,
		SendMs:    &sendMs,
		WaitMs:    &waitMs,
		ReceiveMs: &receiveMs,
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	flows, err := store.ListStreams(ctx, StreamListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows) != 1 {
		t.Fatalf("ListFlows: got %d flows, want 1", len(flows))
	}

	got := flows[0]
	if got.SendMs == nil || *got.SendMs != 8 {
		t.Errorf("SendMs = %v, want 8", got.SendMs)
	}
	if got.WaitMs == nil || *got.WaitMs != 100 {
		t.Errorf("WaitMs = %v, want 100", got.WaitMs)
	}
	if got.ReceiveMs == nil || *got.ReceiveMs != 22 {
		t.Errorf("ReceiveMs = %v, want 22", got.ReceiveMs)
	}
}

func Test_streamOrderClause(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		sortBy string
		want   string
	}{
		{name: "empty defaults to timestamp", sortBy: "", want: " ORDER BY s.timestamp DESC"},
		{name: "timestamp", sortBy: "timestamp", want: " ORDER BY s.timestamp DESC"},
		{name: "duration_ms", sortBy: "duration_ms", want: " ORDER BY s.duration_ms DESC"},
		{name: "invalid falls back to timestamp", sortBy: "invalid_field", want: " ORDER BY s.timestamp DESC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := streamOrderClause(tt.sortBy)
			if got != tt.want {
				t.Errorf("streamOrderClause(%q) = %q, want %q", tt.sortBy, got, tt.want)
			}
		})
	}
}

func Test_ListFlows_SortByDuration(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Create 3 flows with different durations: 300ms, 100ms, 200ms.
	durations := []time.Duration{300 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}
	for i, dur := range durations {
		fl := &Stream{
			Protocol:  "HTTP/1.x",
			State:     "complete",
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Duration:  dur,
		}
		if err := store.SaveStream(ctx, fl); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
	}

	// Default sort (timestamp DESC): order should be flow[2], flow[1], flow[0].
	defaultFlows, err := store.ListStreams(ctx, StreamListOptions{})
	if err != nil {
		t.Fatalf("ListFlows default: %v", err)
	}
	if len(defaultFlows) != 3 {
		t.Fatalf("expected 3 flows, got %d", len(defaultFlows))
	}
	// Most recent timestamp first.
	if defaultFlows[0].Duration != 200*time.Millisecond {
		t.Errorf("default sort: first flow duration = %v, want 200ms", defaultFlows[0].Duration)
	}

	// Sort by duration_ms DESC: order should be 300ms, 200ms, 100ms.
	sorted, err := store.ListStreams(ctx, StreamListOptions{SortBy: "duration_ms"})
	if err != nil {
		t.Fatalf("ListFlows sort by duration: %v", err)
	}
	if len(sorted) != 3 {
		t.Fatalf("expected 3 flows, got %d", len(sorted))
	}
	if sorted[0].Duration != 300*time.Millisecond {
		t.Errorf("duration sort: first = %v, want 300ms", sorted[0].Duration)
	}
	if sorted[1].Duration != 200*time.Millisecond {
		t.Errorf("duration sort: second = %v, want 200ms", sorted[1].Duration)
	}
	if sorted[2].Duration != 100*time.Millisecond {
		t.Errorf("duration sort: third = %v, want 100ms", sorted[2].Duration)
	}
}

func TestSQLiteStore_SchemeField(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Save flows with different schemes.
	flows := []*Stream{
		{Protocol: "HTTPS", Scheme: "https", Timestamp: time.Now()},
		{Protocol: "HTTP/2", Scheme: "https", Timestamp: time.Now()},
		{Protocol: "gRPC", Scheme: "https", Timestamp: time.Now()},
		{Protocol: "HTTP/1.x", Scheme: "http", Timestamp: time.Now()},
		{Protocol: "WebSocket", Scheme: "wss", Timestamp: time.Now()},
		{Protocol: "WebSocket", Scheme: "ws", Timestamp: time.Now()},
		{Protocol: "TCP", Scheme: "tcp", Timestamp: time.Now()},
	}
	for _, fl := range flows {
		if err := store.SaveStream(ctx, fl); err != nil {
			t.Fatalf("save flow: %v", err)
		}
	}

	// Test scheme filter: "https" should return 3 flows.
	httpsFlows, err := store.ListStreams(ctx, StreamListOptions{Scheme: "https", Limit: 100})
	if err != nil {
		t.Fatalf("list https flows: %v", err)
	}
	if len(httpsFlows) != 3 {
		t.Errorf("https filter: got %d flows, want 3", len(httpsFlows))
	}
	for _, fl := range httpsFlows {
		if fl.Scheme != "https" {
			t.Errorf("expected scheme=https, got %q", fl.Scheme)
		}
	}

	// Test scheme filter: "ws" should return 1 flow.
	wsFlows, err := store.ListStreams(ctx, StreamListOptions{Scheme: "ws", Limit: 100})
	if err != nil {
		t.Fatalf("list ws flows: %v", err)
	}
	if len(wsFlows) != 1 {
		t.Errorf("ws filter: got %d flows, want 1", len(wsFlows))
	}

	// Test combined protocol + scheme filter: protocol="HTTP/2" AND scheme="https".
	h2TlsFlows, err := store.ListStreams(ctx, StreamListOptions{Protocol: "HTTP/2", Scheme: "https", Limit: 100})
	if err != nil {
		t.Fatalf("list h2+https flows: %v", err)
	}
	if len(h2TlsFlows) != 1 {
		t.Errorf("h2+https filter: got %d flows, want 1", len(h2TlsFlows))
	}

	// Test count with scheme filter.
	count, err := store.CountStreams(ctx, StreamListOptions{Scheme: "https"})
	if err != nil {
		t.Fatalf("count https flows: %v", err)
	}
	if count != 3 {
		t.Errorf("count https: got %d, want 3", count)
	}

	// Verify scheme is persisted and retrieved via GetFlow.
	got, err := store.GetStream(ctx, flows[0].ID)
	if err != nil {
		t.Fatalf("get flow: %v", err)
	}
	if got.Scheme != "https" {
		t.Errorf("GetFlow scheme = %q, want %q", got.Scheme, "https")
	}
}

// TestSQLiteStore_StreamFailureReason_RoundTrip covers the USK-620 classification
// column: FailureReason persists through UpdateStream and is read back via
// GetStream/ListStreams.
func TestSQLiteStore_StreamFailureReason_RoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	st := &Stream{
		Protocol:  "HTTP/2",
		State:     "active",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	// Precondition: freshly saved stream has empty FailureReason.
	got, err := store.GetStream(ctx, st.ID)
	if err != nil {
		t.Fatalf("GetStream (pre-update): %v", err)
	}
	if got.FailureReason != "" {
		t.Errorf("FailureReason before update = %q, want empty", got.FailureReason)
	}

	// Apply error state + classification.
	if err := store.UpdateStream(ctx, st.ID, StreamUpdate{
		State:         "error",
		FailureReason: "refused",
	}); err != nil {
		t.Fatalf("UpdateStream: %v", err)
	}

	got, err = store.GetStream(ctx, st.ID)
	if err != nil {
		t.Fatalf("GetStream (post-update): %v", err)
	}
	if got.State != "error" {
		t.Errorf("State = %q, want %q", got.State, "error")
	}
	if got.FailureReason != "refused" {
		t.Errorf("FailureReason = %q, want %q", got.FailureReason, "refused")
	}

	// ListStreams must surface the same value.
	list, err := store.ListStreams(ctx, StreamListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	var found bool
	for _, s := range list {
		if s.ID == st.ID {
			found = true
			if s.FailureReason != "refused" {
				t.Errorf("ListStreams FailureReason = %q, want %q", s.FailureReason, "refused")
			}
		}
	}
	if !found {
		t.Fatalf("stream %s not present in ListStreams output", st.ID)
	}
}

// TestSQLiteStore_StreamFailureReason_EmptySkipsUpdate verifies the standard
// partial-update contract: empty FailureReason does not overwrite an existing
// value. This matters for sequences like "refused" then a follow-up
// UpdateStream that only changes Duration.
func TestSQLiteStore_StreamFailureReason_EmptySkipsUpdate(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	st := &Stream{
		Protocol:  "HTTP/2",
		State:     "active",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	if err := store.UpdateStream(ctx, st.ID, StreamUpdate{
		State:         "error",
		FailureReason: "canceled",
	}); err != nil {
		t.Fatalf("UpdateStream (initial): %v", err)
	}

	// Second update with no FailureReason — value must be preserved.
	if err := store.UpdateStream(ctx, st.ID, StreamUpdate{
		Duration: 200 * time.Millisecond,
	}); err != nil {
		t.Fatalf("UpdateStream (follow-up): %v", err)
	}

	got, err := store.GetStream(ctx, st.ID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.FailureReason != "canceled" {
		t.Errorf("FailureReason after follow-up update = %q, want %q",
			got.FailureReason, "canceled")
	}
}

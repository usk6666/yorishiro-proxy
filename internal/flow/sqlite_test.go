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
func saveTestSession(t *testing.T, store *SQLiteStore, protocol string, ts time.Time, method string, reqURL string, statusCode int, reqBody, respBody []byte) *Flow {
	t.Helper()
	ctx := context.Background()

	fl := &Flow{
		Protocol:  protocol,
		FlowType:  "unary",
		State:     "complete",
		Timestamp: ts,
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &Message{
		FlowID:    fl.ID,
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
		FlowID:     fl.ID,
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

	return fl
}

func TestNewSQLiteStore_BusyTimeout(t *testing.T) {
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
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Flow{
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  150 * time.Millisecond,
	}

	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if fl.ID == "" {
		t.Fatal("SaveFlow did not assign ID")
	}

	got, err := store.GetFlow(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	if got.Protocol != "HTTP/1.x" {
		t.Errorf("Protocol = %q, want %q", got.Protocol, "HTTP/1.x")
	}
	if got.FlowType != "unary" {
		t.Errorf("FlowType = %q, want %q", got.FlowType, "unary")
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

	fl := &Flow{
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

	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	got, err := store.GetFlow(ctx, fl.ID)
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
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &Message{
		FlowID:    fl.ID,
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
		FlowID:     fl.ID,
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

	msgs, err := store.GetMessages(ctx, fl.ID, MessageListOptions{})
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

	fl := &Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveFlow(ctx, fl)

	store.AppendMessage(ctx, &Message{FlowID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET"})
	store.AppendMessage(ctx, &Message{FlowID: fl.ID, Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC(), StatusCode: 200})

	sendMsgs, _ := store.GetMessages(ctx, fl.ID, MessageListOptions{Direction: "send"})
	if len(sendMsgs) != 1 {
		t.Errorf("expected 1 send message, got %d", len(sendMsgs))
	}

	recvMsgs, _ := store.GetMessages(ctx, fl.ID, MessageListOptions{Direction: "receive"})
	if len(recvMsgs) != 1 {
		t.Errorf("expected 1 receive message, got %d", len(recvMsgs))
	}
}

func TestSQLiteStore_CountMessages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveFlow(ctx, fl)
	store.AppendMessage(ctx, &Message{FlowID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})
	store.AppendMessage(ctx, &Message{FlowID: fl.ID, Sequence: 1, Direction: "receive", Timestamp: time.Now().UTC()})

	count, err := store.CountMessages(ctx, fl.ID)
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

	fl := &Flow{Protocol: "HTTP/1.x", State: "active", Timestamp: time.Now().UTC()}
	store.SaveFlow(ctx, fl)

	err := store.UpdateFlow(ctx, fl.ID, FlowUpdate{
		State:    "complete",
		Duration: 500 * time.Millisecond,
		Tags:     map[string]string{"smuggling": "cl_te"},
	})
	if err != nil {
		t.Fatalf("UpdateFlow: %v", err)
	}

	got, _ := store.GetFlow(ctx, fl.ID)
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
		{"by state complete", ListOptions{State: "complete"}, 3},
		{"by state error", ListOptions{State: "error"}, 0},
		{"limit", ListOptions{Limit: 1}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := store.ListFlows(ctx, tt.opts)
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
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Create sessions with different states.
	activeSession := &Flow{
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "active",
		Timestamp: now,
	}
	if err := store.SaveFlow(ctx, activeSession); err != nil {
		t.Fatalf("SaveSession(active): %v", err)
	}

	completeSession := &Flow{
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: now,
	}
	if err := store.SaveFlow(ctx, completeSession); err != nil {
		t.Fatalf("SaveSession(complete): %v", err)
	}

	errorSession := &Flow{
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "error",
		Timestamp: now,
	}
	if err := store.SaveFlow(ctx, errorSession); err != nil {
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
			sessions, err := store.ListFlows(ctx, ListOptions{State: tt.state})
			if err != nil {
				t.Fatalf("ListSessions: %v", err)
			}
			if len(sessions) != tt.want {
				t.Errorf("got %d sessions, want %d", len(sessions), tt.want)
			}

			count, err := store.CountFlows(ctx, ListOptions{State: tt.state})
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
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://example.com/a", 200, nil, nil)
	saveTestSession(t, store, "HTTP/1.x", now, "POST", "http://example.com/b", 201, nil, nil)

	count, err := store.CountFlows(ctx, ListOptions{Method: "GET"})
	if err != nil {
		t.Fatalf("CountFlows: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	total, err := store.CountFlows(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("CountFlows: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
}

func TestSQLiteStore_DeleteSession_CascadeMessages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := saveTestSession(t, store, "HTTP/1.x", time.Now().UTC(), "GET", "http://example.com/del", 200, nil, nil)

	// Verify messages exist.
	count, _ := store.CountMessages(ctx, fl.ID)
	if count != 2 {
		t.Fatalf("expected 2 messages before delete, got %d", count)
	}

	if err := store.DeleteFlow(ctx, fl.ID); err != nil {
		t.Fatalf("DeleteFlow: %v", err)
	}

	// Flow should be gone.
	_, err := store.GetFlow(ctx, fl.ID)
	if err == nil {
		t.Fatal("expected error for deleted flow, got nil")
	}

	// Messages should be cascade-deleted.
	count, _ = store.CountMessages(ctx, fl.ID)
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

	n, err := store.DeleteAllFlows(ctx)
	if err != nil {
		t.Fatalf("DeleteAllFlows: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2", n)
	}

	remaining, _ := store.ListFlows(ctx, ListOptions{})
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

	n, err := store.DeleteFlowsOlderThan(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("DeleteFlowsOlderThan: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}

	remaining, _ := store.ListFlows(ctx, ListOptions{})
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_DeleteSessionsByProtocol(t *testing.T) {
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
			n, err := store.DeleteFlowsByProtocol(ctx, tt.protocol)
			if err != nil {
				t.Fatalf("DeleteFlowsByProtocol: %v", err)
			}
			if n != tt.wantDeleted {
				t.Errorf("deleted %d, want %d", n, tt.wantDeleted)
			}
			remaining, _ := store.ListFlows(ctx, ListOptions{})
			if len(remaining) != tt.wantRemaining {
				t.Errorf("expected %d remaining, got %d", tt.wantRemaining, len(remaining))
			}
		})
	}
}

func TestSQLiteStore_DeleteSessionsByProtocol_NoMatches(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	saveTestSession(t, store, "HTTP/1.x", now, "GET", "http://a.com/1", 200, nil, nil)

	n, err := store.DeleteFlowsByProtocol(ctx, "WebSocket")
	if err != nil {
		t.Fatalf("DeleteFlowsByProtocol: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted %d, want 0", n)
	}

	remaining, _ := store.ListFlows(ctx, ListOptions{})
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_DeleteSessionsByProtocol_CascadeMessages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	fl := saveTestSession(t, store, "TCP", now, "GET", "http://a.com/tcp", 200, nil, nil)

	// Verify messages exist before deletion.
	count, _ := store.CountMessages(ctx, fl.ID)
	if count != 2 {
		t.Fatalf("expected 2 messages before delete, got %d", count)
	}

	n, err := store.DeleteFlowsByProtocol(ctx, "TCP")
	if err != nil {
		t.Fatalf("DeleteFlowsByProtocol: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}

	// Messages should be cascade-deleted.
	count, _ = store.CountMessages(ctx, fl.ID)
	if count != 0 {
		t.Errorf("expected 0 messages after cascade delete, got %d", count)
	}
}

func TestSQLiteStore_DeleteExcessSessions(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		saveTestSession(t, store, "HTTP/1.x", now.Add(time.Duration(i)*time.Second), "GET", fmt.Sprintf("http://a.com/%d", i), 200, nil, nil)
	}

	n, err := store.DeleteExcessFlows(ctx, 2)
	if err != nil {
		t.Fatalf("DeleteExcessFlows: %v", err)
	}
	if n != 3 {
		t.Errorf("deleted %d, want 3", n)
	}

	remaining, _ := store.ListFlows(ctx, ListOptions{})
	if len(remaining) != 2 {
		t.Errorf("expected 2 remaining, got %d", len(remaining))
	}
}

func TestSQLiteStore_RawBytes(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveFlow(ctx, fl)

	rawReq := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	store.AppendMessage(ctx, &Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		RawBytes:  rawReq,
	})

	msgs, _ := store.GetMessages(ctx, fl.ID, MessageListOptions{Direction: "send"})
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

	fl := &Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveFlow(ctx, fl)

	store.AppendMessage(ctx, &Message{FlowID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})

	// Duplicate sequence should fail.
	err := store.AppendMessage(ctx, &Message{FlowID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC()})
	if err == nil {
		t.Fatal("expected error for duplicate sequence, got nil")
	}
}

func TestSQLiteStore_CancelledContext(t *testing.T) {
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fl := &Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	err := store.SaveFlow(ctx, fl)
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
			fl := &Flow{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now().UTC(),
			}
			errCh <- store.SaveFlow(ctx, fl)
		}(i)
	}

	for i := 0; i < n; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent SaveFlow: %v", err)
		}
	}

	sessions, _ := store.ListFlows(ctx, ListOptions{})
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

	sessions, err := store.ListFlows(ctx, ListOptions{URLPattern: "100%25_done"})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 match for LIKE wildcard escape, got %d", len(sessions))
	}
}

func TestSQLiteStore_PersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist.db")
	logger := testutil.DiscardLogger()
	ctx := context.Background()

	// Create store and save a flow.
	store1, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore(1): %v", err)
	}
	fl := &Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store1.SaveFlow(ctx, fl)
	store1.AppendMessage(ctx, &Message{FlowID: fl.ID, Sequence: 0, Direction: "send", Timestamp: time.Now().UTC(), Method: "GET", URL: mustParseURL("http://example.com/persist")})
	store1.Close()

	// Reopen and verify.
	store2, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore(2): %v", err)
	}
	defer store2.Close()

	sessions, _ := store2.ListFlows(ctx, ListOptions{})
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
	store := newTestStore(t)
	_, err := store.GetFlow(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent flow, got nil")
	}
}

func TestSQLiteStore_InvalidDBPath(t *testing.T) {
	logger := testutil.DiscardLogger()
	_, err := NewSQLiteStore(context.Background(), "/nonexistent/path/to/db", logger)
	if err == nil {
		t.Fatal("expected error for invalid path, got nil")
	}
}

func TestSQLiteStore_Tags(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Flow{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
		Tags:      map[string]string{"key1": "val1", "key2": "val2"},
	}
	store.SaveFlow(ctx, fl)

	got, _ := store.GetFlow(ctx, fl.ID)
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

	fl := &Flow{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	store.SaveFlow(ctx, fl)

	store.AppendMessage(ctx, &Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     time.Now().UTC(),
		Body:          []byte("partial"),
		BodyTruncated: true,
	})

	msgs, _ := store.GetMessages(ctx, fl.ID, MessageListOptions{})
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
			fl := &Flow{
				Protocol:  "HTTPS",
				Timestamp: time.Now().UTC(),
				BlockedBy: tt.blockedBy,
			}
			if err := store.SaveFlow(ctx, fl); err != nil {
				t.Fatalf("SaveFlow: %v", err)
			}

			got, err := store.GetFlow(ctx, fl.ID)
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
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Save a normal flow.
	normalSess := &Flow{
		Protocol:  "HTTPS",
		Timestamp: now,
	}
	if err := store.SaveFlow(ctx, normalSess); err != nil {
		t.Fatalf("SaveFlow(normal): %v", err)
	}

	// Save a blocked flow.
	blockedSess := &Flow{
		Protocol:  "HTTPS",
		Timestamp: now,
		BlockedBy: "target_scope",
	}
	if err := store.SaveFlow(ctx, blockedSess); err != nil {
		t.Fatalf("SaveFlow(blocked): %v", err)
	}

	tests := []struct {
		name string
		opts ListOptions
		want int
	}{
		{"no filter returns all", ListOptions{}, 2},
		{"filter by target_scope", ListOptions{BlockedBy: "target_scope"}, 1},
		{"filter by nonexistent blocker", ListOptions{BlockedBy: "nonexistent"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions, err := store.ListFlows(ctx, tt.opts)
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
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Save two normal sessions and one blocked.
	for i := 0; i < 2; i++ {
		if err := store.SaveFlow(ctx, &Flow{
			Protocol:  "HTTPS",
			Timestamp: now,
		}); err != nil {
			t.Fatalf("SaveFlow(normal %d): %v", i, err)
		}
	}
	if err := store.SaveFlow(ctx, &Flow{
		Protocol:  "HTTPS",
		Timestamp: now,
		BlockedBy: "target_scope",
	}); err != nil {
		t.Fatalf("SaveFlow(blocked): %v", err)
	}

	count, err := store.CountFlows(ctx, ListOptions{BlockedBy: "target_scope"})
	if err != nil {
		t.Fatalf("CountFlows: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	total, err := store.CountFlows(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("CountFlows: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
}

func TestSQLiteStore_BlockedBy_DefaultEmpty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Save a flow without setting BlockedBy — it should default to "".
	fl := &Flow{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	got, err := store.GetFlow(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if got.BlockedBy != "" {
		t.Errorf("BlockedBy = %q, want empty string", got.BlockedBy)
	}
}

func TestSQLiteStore_BlockedBy_WithMessages(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// A blocked session: has a send message (the request that was attempted)
	// but no receive message (because it was blocked).
	fl := &Flow{
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: now,
		BlockedBy: "target_scope",
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	sendMsg := &Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: now,
		Method:    "GET",
		URL:       mustParseURL("https://evil.com/admin"),
		Headers:   map[string][]string{"Host": {"evil.com"}},
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	// Retrieve and verify.
	got, err := store.GetFlow(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if got.BlockedBy != "target_scope" {
		t.Errorf("BlockedBy = %q, want %q", got.BlockedBy, "target_scope")
	}

	msgs, err := store.GetMessages(ctx, fl.ID, MessageListOptions{})
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
	fl, err := store.GetFlow(ctx, "old-session-id")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if fl.BlockedBy != "" {
		t.Errorf("old session BlockedBy = %q, want empty", fl.BlockedBy)
	}

	// Verify we can save a new flow with blocked_by.
	newSess := &Flow{
		Protocol:  "HTTPS",
		Timestamp: time.Now().UTC(),
		BlockedBy: "target_scope",
	}
	if err := store.SaveFlow(ctx, newSess); err != nil {
		t.Fatalf("SaveFlow(new): %v", err)
	}

	got, err := store.GetFlow(ctx, newSess.ID)
	if err != nil {
		t.Fatalf("GetFlow(new): %v", err)
	}
	if got.BlockedBy != "target_scope" {
		t.Errorf("new flow BlockedBy = %q, want %q", got.BlockedBy, "target_scope")
	}

	// Verify schema version is now 4 (V3 adds blocked_by, V4 renames sessions→flows).
	checkDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open check db: %v", err)
	}
	defer checkDB.Close()

	var version int
	if err := checkDB.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != 4 {
		t.Errorf("schema version = %d, want 4", version)
	}
}

func TestGetFlow_PrefixMatch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Create a flow with a known ID.
	fl := &Flow{
		ID:        "abcdef12-3456-7890-abcd-ef1234567890",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
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
			wantErr: "flow not found",
		},
		{
			name:    "full UUID no match",
			id:      "00000000-0000-0000-0000-000000000000",
			wantErr: "flow not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.GetFlow(ctx, tt.id)
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
			err := ValidateFlowID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFlowID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
			if tt.wantErr && err != nil {
				if !strings.Contains(err.Error(), "invalid flow ID") {
					t.Errorf("ValidateFlowID(%q) error = %q, want containing 'invalid flow ID'", tt.id, err.Error())
				}
			}
		})
	}
}

func TestGetFlow_PrefixMatch_Ambiguous(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Create two flows that share the same 8-char prefix.
	fl1 := &Flow{
		ID:        "abcdef12-1111-1111-1111-111111111111",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	fl2 := &Flow{
		ID:        "abcdef12-2222-2222-2222-222222222222",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl1); err != nil {
		t.Fatalf("SaveFlow fl1: %v", err)
	}
	if err := store.SaveFlow(ctx, fl2); err != nil {
		t.Fatalf("SaveFlow fl2: %v", err)
	}

	// 8-char prefix should be ambiguous.
	_, err := store.GetFlow(ctx, "abcdef12")
	if err == nil {
		t.Fatal("GetFlow() expected ambiguous error, got nil")
	}
	if !strings.Contains(err.Error(), "ambiguous flow ID prefix") {
		t.Errorf("GetFlow() error = %q, want containing 'ambiguous flow ID prefix'", err.Error())
	}
	if !strings.Contains(err.Error(), "matched 2 flows") {
		t.Errorf("GetFlow() error = %q, want containing 'matched 2 flows'", err.Error())
	}

	// Full UUID should still work for each flow.
	got1, err := store.GetFlow(ctx, fl1.ID)
	if err != nil {
		t.Fatalf("GetFlow(fl1 full ID): %v", err)
	}
	if got1.ID != fl1.ID {
		t.Errorf("GetFlow(fl1) ID = %q, want %q", got1.ID, fl1.ID)
	}

	got2, err := store.GetFlow(ctx, fl2.ID)
	if err != nil {
		t.Fatalf("GetFlow(fl2 full ID): %v", err)
	}
	if got2.ID != fl2.ID {
		t.Errorf("GetFlow(fl2) ID = %q, want %q", got2.ID, fl2.ID)
	}
}

func TestGetFlow_PrefixMatch_UniqueAfterAmbiguity(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Two flows with different 8-char prefixes.
	fl1 := &Flow{
		ID:        "aaaaaaaa-1111-1111-1111-111111111111",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	fl2 := &Flow{
		ID:        "bbbbbbbb-2222-2222-2222-222222222222",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl1); err != nil {
		t.Fatalf("SaveFlow fl1: %v", err)
	}
	if err := store.SaveFlow(ctx, fl2); err != nil {
		t.Fatalf("SaveFlow fl2: %v", err)
	}

	// Each 8-char prefix should uniquely resolve.
	got1, err := store.GetFlow(ctx, "aaaaaaaa")
	if err != nil {
		t.Fatalf("GetFlow(aaaaaaaa): %v", err)
	}
	if got1.ID != fl1.ID {
		t.Errorf("GetFlow(aaaaaaaa) ID = %q, want %q", got1.ID, fl1.ID)
	}

	got2, err := store.GetFlow(ctx, "bbbbbbbb")
	if err != nil {
		t.Fatalf("GetFlow(bbbbbbbb): %v", err)
	}
	if got2.ID != fl2.ID {
		t.Errorf("GetFlow(bbbbbbbb) ID = %q, want %q", got2.ID, fl2.ID)
	}
}

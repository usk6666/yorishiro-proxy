package mcp

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

func TestClearSessions_Success(t *testing.T) {
	ca := newTestCA(t)
	store := newTestStore(t)
	cs := setupTestSession(t, ca, store)

	ctx := context.Background()
	now := time.Now().UTC()

	// Insert old and new sessions.
	saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-72 * time.Hour), // 3 days ago
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: now.Add(-72 * time.Hour),
			Method:    "GET",
			URL:       mustParseTestURL("http://example.com/old"),
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  now.Add(-72 * time.Hour),
			StatusCode: 200,
		},
	)
	saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-1 * time.Hour), // 1 hour ago
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: now.Add(-1 * time.Hour),
			Method:    "GET",
			URL:       mustParseTestURL("http://example.com/new"),
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  now.Add(-1 * time.Hour),
			StatusCode: 200,
		},
	)

	// Clear sessions older than 2 days.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "clear_sessions",
		Arguments: map[string]any{
			"older_than": 2,
			"confirm":    true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("clear_sessions returned error: %v", result.Content)
	}

	var res clearSessionsResult
	tc := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(tc.Text), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1", res.DeletedCount)
	}
	if res.CutoffTime == "" {
		t.Error("cutoff_time is empty")
	}

	// Verify only the new session remains.
	remaining, err := store.ListSessions(ctx, session.ListOptions{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining session, got %d", len(remaining))
	}
}

func TestClearSessions_ConfirmFalse(t *testing.T) {
	ca := newTestCA(t)
	store := newTestStore(t)
	cs := setupTestSession(t, ca, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "clear_sessions",
		Arguments: map[string]any{
			"older_than": 7,
			"confirm":    false,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for confirm=false, got success")
	}
}

func TestClearSessions_InvalidOlderThan(t *testing.T) {
	ca := newTestCA(t)
	store := newTestStore(t)
	cs := setupTestSession(t, ca, store)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "clear_sessions",
		Arguments: map[string]any{
			"older_than": 0,
			"confirm":    true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for older_than=0, got success")
	}
}

func TestClearSessions_NothingToDelete(t *testing.T) {
	ca := newTestCA(t)
	store := newTestStore(t)
	cs := setupTestSession(t, ca, store)

	ctx := context.Background()

	// Insert a recent session.
	saveTestEntry(t, store,
		&session.Session{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now().UTC(),
		},
		&session.Message{
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now().UTC(),
			Method:    "GET",
			URL:       mustParseTestURL("http://example.com/recent"),
		},
		&session.Message{
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now().UTC(),
			StatusCode: 200,
		},
	)

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "clear_sessions",
		Arguments: map[string]any{
			"older_than": 30,
			"confirm":    true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("clear_sessions returned error: %v", result.Content)
	}

	var res clearSessionsResult
	tc := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(tc.Text), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.DeletedCount != 0 {
		t.Errorf("deleted_count = %d, want 0", res.DeletedCount)
	}
}

func mustParseTestURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

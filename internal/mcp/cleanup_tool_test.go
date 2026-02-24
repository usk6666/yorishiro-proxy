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
	entries := []*session.Entry{
		{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-72 * time.Hour), // 3 days ago
			Request: session.RecordedRequest{
				Method: "GET",
				URL:    mustParseTestURL("http://example.com/old"),
			},
			Response: session.RecordedResponse{StatusCode: 200},
		},
		{
			Protocol:  "HTTP/1.x",
			Timestamp: now.Add(-1 * time.Hour), // 1 hour ago
			Request: session.RecordedRequest{
				Method: "GET",
				URL:    mustParseTestURL("http://example.com/new"),
			},
			Response: session.RecordedResponse{StatusCode: 200},
		},
	}
	for _, e := range entries {
		if err := store.Save(ctx, e); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

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
	remaining, err := store.List(ctx, session.ListOptions{})
	if err != nil {
		t.Fatalf("List: %v", err)
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
	entry := &session.Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now().UTC(),
		Request: session.RecordedRequest{
			Method: "GET",
			URL:    mustParseTestURL("http://example.com/recent"),
		},
		Response: session.RecordedResponse{StatusCode: 200},
	}
	if err := store.Save(ctx, entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

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

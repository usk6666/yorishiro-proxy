package mcp

import (
	"context"
	"fmt"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// clearSessionsInput is the typed input for the clear_sessions tool.
type clearSessionsInput struct {
	// OlderThan is the number of days. Sessions older than this will be deleted.
	OlderThan int `json:"older_than" jsonschema:"number of days; sessions older than this will be deleted (must be >= 1)"`
	// Confirm must be true to proceed with deletion (safety guard).
	Confirm bool `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

// clearSessionsResult is the structured output of the clear_sessions tool.
type clearSessionsResult struct {
	// DeletedCount is the number of sessions that were deleted.
	DeletedCount int64 `json:"deleted_count"`
	// CutoffTime is the cutoff timestamp in RFC 3339 format.
	CutoffTime string `json:"cutoff_time"`
}

// registerClearSessions registers the clear_sessions MCP tool.
func (s *Server) registerClearSessions() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "clear_sessions",
		Description: "Delete recorded proxy sessions older than a specified number of days. Requires explicit confirmation to prevent accidental data loss. Use this for manual cleanup of old session data.",
	}, s.handleClearSessions)
}

// handleClearSessions handles the clear_sessions tool invocation.
func (s *Server) handleClearSessions(ctx context.Context, _ *gomcp.CallToolRequest, input clearSessionsInput) (*gomcp.CallToolResult, *clearSessionsResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.OlderThan < 1 {
		return nil, nil, fmt.Errorf("older_than must be >= 1, got %d", input.OlderThan)
	}

	if !input.Confirm {
		return nil, nil, fmt.Errorf("confirm must be true to proceed with deletion")
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -input.OlderThan)
	n, err := s.store.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		return nil, nil, fmt.Errorf("delete old sessions: %w", err)
	}

	result := &clearSessionsResult{
		DeletedCount: n,
		CutoffTime:   cutoff.Format(time.RFC3339),
	}
	return nil, result, nil
}

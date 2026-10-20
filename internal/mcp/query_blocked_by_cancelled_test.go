package mcp

import (
	"slices"
	"strings"
	"testing"
)

// USK-1193: a hold whose ctx ended without an agent action is recorded as
// blocked_by=intercept_cancelled, and query must accept and filter on it.

func TestQuery_Flows_FilterByInterceptCancelled(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedSession(t, store, "normal", "HTTPS", "GET", "https://example.com/ok", 200)
	seedBlockedSession(t, store, "cancelled", "HTTPS", "GET", "https://example.com/held", "intercept_cancelled")
	seedBlockedSession(t, store, "dropped", "HTTPS", "GET", "https://example.com/drop", "intercept_drop")

	cs := setupQueryTestSession(t, store)
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{BlockedBy: "intercept_cancelled"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)
	if out.Count != 1 || len(out.Flows) != 1 {
		t.Fatalf("count = %d, want 1", out.Count)
	}
	if out.Flows[0].ID != "cancelled" {
		t.Errorf("id = %q, want cancelled", out.Flows[0].ID)
	}
	if out.Flows[0].BlockedBy != "intercept_cancelled" {
		t.Errorf("blocked_by = %q, want intercept_cancelled", out.Flows[0].BlockedBy)
	}
}

// The help text advertises the same blocked_by vocabulary the query tool
// validates against.
func TestQuery_BlockedByVocabulary_InSync(t *testing.T) {
	if !slices.Contains(validFilterBlockedBy, "intercept_cancelled") {
		t.Errorf("validFilterBlockedBy = %v, missing intercept_cancelled", validFilterBlockedBy)
	}

	help, err := resourcesFS.ReadFile("resources/help_query.md")
	if err != nil {
		t.Fatalf("read help_query.md: %v", err)
	}
	for _, v := range validFilterBlockedBy {
		if !strings.Contains(string(help), "`\""+v+"\"`") {
			t.Errorf("help_query.md does not list blocked_by value %q", v)
		}
	}
}

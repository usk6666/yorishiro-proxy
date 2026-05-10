package mcp

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// seedFilterStreamWithURL stores a stream with a single send flow
// that carries the supplied URL string. The USK-822 url_pattern
// filter targets flows.url, so the URL on the row is the
// load-bearing fixture for these tests.
func seedFilterStreamWithURL(t *testing.T, store flow.Store, id, rawURL string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "http",
		Scheme:    "https",
		State:     "complete",
		Timestamp: now,
		Duration:  10 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream(%s): %v", id, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	send := &flow.Flow{
		ID:          id + "-send",
		StreamID:    id,
		Sequence:    0,
		Direction:   "send",
		Timestamp:   now,
		Method:      "GET",
		URL:         parsed,
		HTTPVersion: "h2",
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(%s send): %v", id, err)
	}
}

// seedFilterStreamAt stores a stream stamped at the supplied wall
// clock so the USK-822 time-bound filters can be exercised against
// deterministic boundaries instead of time.Now().
func seedFilterStreamAt(t *testing.T, store flow.Store, id string, ts time.Time) {
	t.Helper()
	ctx := context.Background()

	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "http",
		Scheme:    "https",
		State:     "complete",
		Timestamp: ts,
		Duration:  10 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream(%s): %v", id, err)
	}
	parsed, _ := url.Parse("https://example.com/" + id)
	send := &flow.Flow{
		ID:          id + "-send",
		StreamID:    id,
		Sequence:    0,
		Direction:   "send",
		Timestamp:   ts,
		Method:      "GET",
		URL:         parsed,
		HTTPVersion: "h2",
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(%s send): %v", id, err)
	}
}

// TestManageDelete_FilterURLPattern_PartialDelete is the canonical
// USK-822 repro: 4 streams seeded, delete_flows with
// filter.url_pattern targeting two of them deletes only those two
// rather than silently falling through to DeleteAllStreams. Pre-fix
// this test was guaranteed to delete all 4 streams (the original bug
// report's "70 of 71 deleted" outcome).
func TestManageDelete_FilterURLPattern_PartialDelete(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStreamWithURL(t, store, "match-1", "https://httpbin.org/status/200")
	seedFilterStreamWithURL(t, store, "match-2", "https://httpbin.org/status/200/redirect")
	seedFilterStreamWithURL(t, store, "miss-1", "https://httpbin.org/status/404")
	seedFilterStreamWithURL(t, store, "miss-2", "https://example.com/health")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"url_pattern": "httpbin.org/status/200",
			},
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 2 {
		t.Errorf("deleted_count = %d, want 2 — pre-fix behavior would have wiped all 4", del.DeletedCount)
	}

	remaining := listStreamIDs(t, store)
	if !sameStringSetMCP(remaining, []string{"miss-1", "miss-2"}) {
		t.Errorf("remaining = %v, want [miss-1 miss-2]", remaining)
	}
}

// TestManageDelete_FilterURLPattern_NoMatch pins that a pattern that
// matches no stored flow returns deleted_count=0 and leaves every row
// in place — the silent-no-op outcome must not regress to a silent
// delete-all.
func TestManageDelete_FilterURLPattern_NoMatch(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStreamWithURL(t, store, "keep-1", "https://example.com/a")
	seedFilterStreamWithURL(t, store, "keep-2", "https://example.com/b")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"url_pattern": "no-such-host.invalid",
			},
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 0 {
		t.Errorf("deleted_count = %d, want 0", del.DeletedCount)
	}
	if got := listStreamIDs(t, store); len(got) != 2 {
		t.Errorf("remaining = %v, want all 2 rows preserved", got)
	}
}

// TestManageDelete_FilterURLPatternEscape pins that the SQL LIKE
// metacharacters '%' and '_' supplied via filter.url_pattern act as
// literals, not wildcards. This is the exact failure mode that
// turns "delete URLs containing a literal percent" into "delete
// every URL".
func TestManageDelete_FilterURLPatternEscape(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStreamWithURL(t, store, "literal-percent", "https://example.com/%20path")
	seedFilterStreamWithURL(t, store, "plain-1", "https://example.com/foo")
	seedFilterStreamWithURL(t, store, "plain-2", "https://example.com/bar")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"url_pattern": "%20",
			},
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 1 {
		t.Errorf("deleted_count = %d, want 1 (only the row containing literal '%%20')", del.DeletedCount)
	}
}

// TestManageDelete_FilterTimeRange pins that filter.time_after and
// filter.time_before form a closed window on streams.timestamp; only
// rows whose timestamps lie within the window are deleted.
func TestManageDelete_FilterTimeRange(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	base := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	seedFilterStreamAt(t, store, "before", base)
	seedFilterStreamAt(t, store, "in-1", base.Add(time.Hour))
	seedFilterStreamAt(t, store, "in-2", base.Add(2*time.Hour))
	seedFilterStreamAt(t, store, "after", base.Add(3*time.Hour))

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"time_after":  base.Add(time.Hour).Format(time.RFC3339),
				"time_before": base.Add(2 * time.Hour).Format(time.RFC3339),
			},
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 2 {
		t.Errorf("deleted_count = %d, want 2 (in-1 and in-2)", del.DeletedCount)
	}

	remaining := listStreamIDs(t, store)
	if !sameStringSetMCP(remaining, []string{"before", "after"}) {
		t.Errorf("remaining = %v, want [before after]", remaining)
	}
}

// TestManageDelete_FilterTimeAfterOnly pins that filter.time_after
// alone keeps everything chronologically before the bound and deletes
// the rest — a partial-window delete usually used with a
// retention-style "wipe everything since outage X" workflow.
func TestManageDelete_FilterTimeAfterOnly(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	base := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	seedFilterStreamAt(t, store, "old", base)
	seedFilterStreamAt(t, store, "edge", base.Add(time.Hour))
	seedFilterStreamAt(t, store, "new", base.Add(2*time.Hour))

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"time_after": base.Add(time.Hour).Format(time.RFC3339),
			},
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 2 {
		t.Errorf("deleted_count = %d, want 2", del.DeletedCount)
	}
	if got := listStreamIDs(t, store); !sameStringSetMCP(got, []string{"old"}) {
		t.Errorf("remaining = %v, want [old]", got)
	}
}

// TestManageDelete_FilterAndTopLevel_Rejected pins the unambiguous-
// semantics guard: passing params.filter alongside any top-level
// axis returns a validation error AND deletes nothing — the
// zero-rows assertion is the entire point of the USK-822 fix.
func TestManageDelete_FilterAndTopLevel_Rejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStreamWithURL(t, store, "k-1", "https://example.com/a")
	seedFilterStreamWithURL(t, store, "k-2", "https://example.com/b")
	seedFilterStreamWithURL(t, store, "k-3", "https://example.com/c")

	cases := []map[string]any{
		{
			"protocol": "http",
			"filter":   map[string]any{"url_pattern": "example"},
			"confirm":  true,
		},
		{
			"scheme":  "https",
			"filter":  map[string]any{"url_pattern": "example"},
			"confirm": true,
		},
		{
			"http_version": "h2",
			"filter":       map[string]any{"url_pattern": "example"},
			"confirm":      true,
		},
	}

	for i, params := range cases {
		result := manageCallTool(t, cs, map[string]any{
			"action": "delete_flows",
			"params": params,
		})
		if !result.IsError {
			t.Errorf("case %d: expected error mixing top-level + filter, got success", i)
		}
		// Critical: no rows deleted on rejection.
		if got := listStreamIDs(t, store); len(got) != 3 {
			t.Errorf("case %d: remaining = %v, want all 3 — rejection must not delete", i, got)
		}
	}
}

// TestManageDelete_FilterRequiresConfirm_USK822 pins that
// params.filter still demands confirm: true. Pre-fix, the silent-
// drop bug took confirm: true and routed through DeleteAllStreams;
// the symmetric guard here keeps the new filter path safe even on
// the confirm: false default.
func TestManageDelete_FilterRequiresConfirm_USK822(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStreamWithURL(t, store, "doomed", "https://example.com/foo")
	seedFilterStreamWithURL(t, store, "kept", "https://example.com/bar")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"url_pattern": "example.com/foo",
			},
			// confirm intentionally omitted
		},
	})
	if !result.IsError {
		t.Fatal("expected error when confirm is missing on filter delete")
	}
	if got := listStreamIDs(t, store); len(got) != 2 {
		t.Errorf("remaining = %v, want both rows preserved", got)
	}
}

// TestManageDelete_FilterRejectsInvalidEnums_USK822 pins that the
// export-style enum validation already wired into validateManage-
// ExportFilter is reused on the delete path: bad scheme /
// http_version values inside params.filter are rejected with the
// same shape the export and query tools emit.
func TestManageDelete_FilterRejectsInvalidEnums_USK822(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStreamWithURL(t, store, "keep", "https://example.com/foo")

	bad := []map[string]any{
		{"filter": map[string]any{"scheme": "gopher"}, "confirm": true},
		{"filter": map[string]any{"http_version": "http/3"}, "confirm": true},
	}
	for _, params := range bad {
		result := manageCallTool(t, cs, map[string]any{
			"action": "delete_flows",
			"params": params,
		})
		if !result.IsError {
			t.Errorf("expected error for params=%v", params)
		}
	}
	if got := listStreamIDs(t, store); len(got) != 1 {
		t.Errorf("remaining = %v, want [keep]", got)
	}
}

// TestManageDelete_FilterRejectsInvalidTime_USK822 pins that an
// unparseable time bound surfaces a validation error rather than
// silently dropping the predicate (which would route through to
// delete-all when confirm is true).
func TestManageDelete_FilterRejectsInvalidTime_USK822(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStreamWithURL(t, store, "keep", "https://example.com/foo")

	bad := []map[string]any{
		{"filter": map[string]any{"time_after": "yesterday"}, "confirm": true},
		{"filter": map[string]any{"time_before": "next-tuesday"}, "confirm": true},
	}
	for _, params := range bad {
		result := manageCallTool(t, cs, map[string]any{
			"action": "delete_flows",
			"params": params,
		})
		if !result.IsError {
			t.Errorf("expected error for params=%v", params)
		}
	}
	if got := listStreamIDs(t, store); len(got) != 1 {
		t.Errorf("remaining = %v, want [keep]", got)
	}
}

// TestManageDelete_FilterEmptyObject_FallsThroughToDeleteAll pins
// the deliberate symmetry with export_flows: an empty filter object
// is treated as "no filter" and routes through to DeleteAllStreams
// when confirm is true. The Info-level audit log at that branch
// closes the silent-mass-delete gap separately. This test guards
// against future strict-rejection drift that would surprise callers.
func TestManageDelete_FilterEmptyObject_FallsThroughToDeleteAll(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	seedFilterStreamWithURL(t, store, "a", "https://example.com/a")
	seedFilterStreamWithURL(t, store, "b", "https://example.com/b")

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"filter":  map[string]any{},
			"confirm": true,
		},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}

	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != 2 {
		t.Errorf("deleted_count = %d, want 2 (delete-all)", del.DeletedCount)
	}
}

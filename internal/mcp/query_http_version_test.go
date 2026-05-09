package mcp

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// seedFlowWithHTTPVersion stores a unary HTTP stream whose send and
// receive flows carry a specific HTTPVersion. Used by the projection
// tests below.
func seedFlowWithHTTPVersion(t *testing.T, store flow.Store, id, httpVersion string) {
	t.Helper()
	ctx := context.Background()

	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "HTTPS",
		Scheme:    "https",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse("https://example.com/api")

	send := &flow.Flow{
		ID:          id + "-send",
		StreamID:    id,
		Sequence:    0,
		Direction:   "send",
		Timestamp:   time.Now().UTC(),
		Method:      "GET",
		URL:         parsedURL,
		HTTPVersion: httpVersion,
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(send): %v", err)
	}

	recv := &flow.Flow{
		ID:          id + "-recv",
		StreamID:    id,
		Sequence:    1,
		Direction:   "receive",
		Timestamp:   time.Now().UTC(),
		StatusCode:  200,
		HTTPVersion: httpVersion,
	}
	if err := store.SaveFlow(ctx, recv); err != nil {
		t.Fatalf("SaveFlow(recv): %v", err)
	}
}

// TestQuery_Flow_HTTPVersion_Projection pins that the MCP query tool
// projects the recorded HTTPVersion on a flow detail response under the
// json key "http_version" (USK-788). Each canonical wire-version value
// is exercised end-to-end through the SQLite store + projection layer
// so a future schema or projection rename cannot silently drop the
// field for any one branch.
func TestQuery_Flow_HTTPVersion_Projection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version string
	}{
		{name: "http/1.0", version: "http/1.0"},
		{name: "http/1.1", version: "http/1.1"},
		{name: "h2", version: "h2"},
		{name: "h2c", version: "h2c"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			id := "flow-" + tc.name
			seedFlowWithHTTPVersion(t, store, id, tc.version)
			cs := setupQueryTestSession(t, store)

			result := callQuery(t, cs, queryInput{
				Resource: "flow",
				ID:       id,
			})
			if result.IsError {
				t.Fatalf("expected success, got error: %v", result.Content)
			}

			var out queryFlowResult
			unmarshalQueryResult(t, result, &out)

			if out.HTTPVersion != tc.version {
				t.Errorf("HTTPVersion = %q, want %q", out.HTTPVersion, tc.version)
			}
		})
	}
}

// TestQuery_Flow_HTTPVersion_EmptyOmitted pins that a flow recorded
// before USK-788 (no HTTPVersion) projects with an empty / omitted
// http_version field — the omitempty tag on the struct keeps the
// JSON output free of a noisy "" entry for legacy rows.
func TestQuery_Flow_HTTPVersion_EmptyOmitted(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedFlowWithHTTPVersion(t, store, "legacy", "")
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "legacy",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)
	if out.HTTPVersion != "" {
		t.Errorf("HTTPVersion = %q, want empty", out.HTTPVersion)
	}
}

// TestQuery_Flow_HTTPVersion_FallsBackToReceive pins the projection's
// fallback rule (USK-788): when the request flow is missing or carries
// no HTTPVersion, the response flow's value surfaces instead. This
// keeps observability accurate for partial captures where the request
// side never recorded.
func TestQuery_Flow_HTTPVersion_FallsBackToReceive(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	st := &flow.Stream{
		ID:        "no-send",
		ConnID:    "conn-no-send",
		Protocol:  "HTTPS",
		Scheme:    "https",
		State:     "complete",
		Timestamp: time.Now().UTC(),
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	// Send flow with empty HTTPVersion.
	parsedURL, _ := url.Parse("https://example.com/")
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID:        "no-send-send",
		StreamID:  "no-send",
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
	}); err != nil {
		t.Fatalf("SaveFlow(send): %v", err)
	}
	// Receive flow with HTTPVersion populated.
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID:          "no-send-recv",
		StreamID:    "no-send",
		Sequence:    1,
		Direction:   "receive",
		Timestamp:   time.Now().UTC(),
		StatusCode:  200,
		HTTPVersion: "h2",
	}); err != nil {
		t.Fatalf("SaveFlow(recv): %v", err)
	}

	cs := setupQueryTestSession(t, store)
	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "no-send",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)
	if out.HTTPVersion != "h2" {
		t.Errorf("HTTPVersion fallback = %q, want %q", out.HTTPVersion, "h2")
	}
}

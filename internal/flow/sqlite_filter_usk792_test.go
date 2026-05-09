package flow

import (
	"context"
	"testing"
	"time"
)

// saveTestStreamWithSchemeAndVersion saves a stream with the supplied
// protocol/scheme plus a single send flow whose http_version mirrors
// the stream-level version, exercising both the streams.scheme column
// and the flows.http_version column the USK-792 filter touches.
func saveTestStreamWithSchemeAndVersion(t *testing.T, store *SQLiteStore, id, protocol, scheme, httpVersion string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	st := &Stream{
		ID:        id,
		Protocol:  protocol,
		Scheme:    scheme,
		State:     "complete",
		Timestamp: now,
		Duration:  10 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream(%s): %v", id, err)
	}
	send := &Flow{
		ID:          id + "-send",
		StreamID:    id,
		Sequence:    0,
		Direction:   "send",
		Timestamp:   now,
		Method:      "GET",
		URL:         mustParseURL(scheme + "://example.com/" + id),
		HTTPVersion: httpVersion,
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(%s send): %v", id, err)
	}
}

// strPtr is a tiny helper because the filter takes *string and several
// table-driven subtests need different literal values inline.
func strPtr(s string) *string { return &s }

// TestSQLiteStore_ListStreams_FilterByHTTPVersion pins the EXISTS-on-
// flows.http_version subquery USK-792 added to buildStreamWhereClause:
// each canonical wire version selects only streams whose flows match,
// and the empty-string sentinel surfaces pre-USK-788 rows.
func TestSQLiteStore_ListStreams_FilterByHTTPVersion(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithSchemeAndVersion(t, store, "s-h11", "http", "http", "http/1.1")
	saveTestStreamWithSchemeAndVersion(t, store, "s-h2", "http", "https", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "s-h2c", "http", "http", "h2c")
	saveTestStreamWithSchemeAndVersion(t, store, "s-legacy", "http", "https", "")

	cases := []struct {
		name    string
		version string
		wantIDs []string
	}{
		{name: "http/1.1", version: "http/1.1", wantIDs: []string{"s-h11"}},
		{name: "h2", version: "h2", wantIDs: []string{"s-h2"}},
		{name: "h2c", version: "h2c", wantIDs: []string{"s-h2c"}},
		{name: "empty matches legacy", version: "", wantIDs: []string{"s-legacy"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := store.ListStreams(ctx, StreamListOptions{HTTPVersion: strPtr(tc.version)})
			if err != nil {
				t.Fatalf("ListStreams: %v", err)
			}
			gotIDs := make([]string, len(got))
			for i, s := range got {
				gotIDs[i] = s.ID
			}
			if !sameStringSet(gotIDs, tc.wantIDs) {
				t.Errorf("ids = %v, want %v", gotIDs, tc.wantIDs)
			}
		})
	}
}

// TestSQLiteStore_ListStreams_FilterByScheme pins that the existing
// scheme column filter still selects only the requested transport.
// Asserted alongside the new http_version filter so the two
// orthogonal axes can later be combined with confidence.
func TestSQLiteStore_ListStreams_FilterByScheme(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithSchemeAndVersion(t, store, "s-https-1", "http", "https", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "s-https-2", "http", "https", "http/1.1")
	saveTestStreamWithSchemeAndVersion(t, store, "s-http", "http", "http", "http/1.1")

	got, err := store.ListStreams(ctx, StreamListOptions{Scheme: "https"})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	for _, s := range got {
		if s.Scheme != "https" {
			t.Errorf("Scheme = %q, want https", s.Scheme)
		}
	}
}

// TestSQLiteStore_ListStreams_FilterCombinationANDs pins that
// protocol + scheme + http_version compose with AND so a USK-792
// caller can ask for "https streams of HTTP family on h2" and see
// only the row that satisfies all three.
func TestSQLiteStore_ListStreams_FilterCombinationANDs(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// (protocol, scheme, http_version) tuples
	saveTestStreamWithSchemeAndVersion(t, store, "match", "http", "https", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "wrong-scheme", "http", "http", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "wrong-version", "http", "https", "http/1.1")
	saveTestStreamWithSchemeAndVersion(t, store, "wrong-protocol", "ws", "https", "h2")

	got, err := store.ListStreams(ctx, StreamListOptions{
		Protocol:    "http",
		Scheme:      "https",
		HTTPVersion: strPtr("h2"),
	})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d, want 1 (id=match)", len(got))
	}
	if got[0].ID != "match" {
		t.Errorf("id = %q, want match", got[0].ID)
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_HTTPVersion pins that the
// new bulk-delete filter targets only matching streams, leaves
// everything else intact, and cascade-deletes the associated flow
// rows so the orphan check stays clean.
func TestSQLiteStore_DeleteStreamsByFilter_HTTPVersion(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithSchemeAndVersion(t, store, "k-h2-1", "http", "https", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "k-h2-2", "http", "http", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "k-h11", "http", "https", "http/1.1")

	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{HTTPVersion: strPtr("h2")})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 1 {
		t.Fatalf("remaining %d, want 1", len(remaining))
	}
	if remaining[0].ID != "k-h11" {
		t.Errorf("remaining id = %q, want k-h11", remaining[0].ID)
	}

	// Cascade: deleted streams' flows should be gone.
	for _, gone := range []string{"k-h2-1", "k-h2-2"} {
		c, _ := store.CountFlows(ctx, gone)
		if c != 0 {
			t.Errorf("flows for %s remaining = %d, want 0", gone, c)
		}
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_Scheme pins that scheme=https
// erases only the TLS streams while http (cleartext) survives —
// the central acceptance criterion in USK-792.
func TestSQLiteStore_DeleteStreamsByFilter_Scheme(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithSchemeAndVersion(t, store, "tls-1", "http", "https", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "tls-2", "ws", "wss", "")
	saveTestStreamWithSchemeAndVersion(t, store, "plain", "http", "http", "http/1.1")

	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{Scheme: "https"})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	gotIDs := make([]string, len(remaining))
	for i, s := range remaining {
		gotIDs[i] = s.ID
	}
	if !sameStringSet(gotIDs, []string{"tls-2", "plain"}) {
		t.Errorf("remaining = %v, want [tls-2 plain]", gotIDs)
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_Combination pins that
// protocol + scheme + http_version compose with AND on the delete
// path the same way they do on the list path.
func TestSQLiteStore_DeleteStreamsByFilter_Combination(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithSchemeAndVersion(t, store, "match", "http", "https", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "scheme-mismatch", "http", "http", "h2")
	saveTestStreamWithSchemeAndVersion(t, store, "version-mismatch", "http", "https", "http/1.1")

	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{
		Protocol:    "http",
		Scheme:      "https",
		HTTPVersion: strPtr("h2"),
	})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 2 {
		t.Errorf("remaining %d, want 2", len(remaining))
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_RejectsZero pins the safety
// guard against accidental DELETE FROM streams via an empty filter
// object — callers must use DeleteAllStreams when they really mean
// to wipe the table.
func TestSQLiteStore_DeleteStreamsByFilter_RejectsZero(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithSchemeAndVersion(t, store, "keep", "http", "https", "h2")

	if _, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{}); err == nil {
		t.Fatal("expected error for zero filter, got nil")
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 1 {
		t.Errorf("remaining %d, want 1 — safety guard must not delete", len(remaining))
	}
}

// TestSQLiteStore_DeleteStreamsByProtocol_Compatibility pins that the
// deprecated DeleteStreamsByProtocol shim continues to behave the
// same after USK-792 routed it through DeleteStreamsByFilter.
func TestSQLiteStore_DeleteStreamsByProtocol_Compatibility(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithSchemeAndVersion(t, store, "ws-1", "ws", "wss", "")
	saveTestStreamWithSchemeAndVersion(t, store, "http-1", "http", "https", "h2")

	n, err := store.DeleteStreamsByProtocol(ctx, "ws")
	if err != nil {
		t.Fatalf("DeleteStreamsByProtocol: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 1 || remaining[0].ID != "http-1" {
		t.Errorf("remaining ids = %v, want [http-1]", remaining)
	}
}

// sameStringSet reports whether got and want contain the same string
// values (set semantics — order ignored, duplicates not expected).
func sameStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	m := make(map[string]int, len(want))
	for _, w := range want {
		m[w]++
	}
	for _, g := range got {
		m[g]--
		if m[g] < 0 {
			return false
		}
	}
	return true
}

package flow

import (
	"context"
	"testing"
	"time"
)

// saveTestStreamWithSchemeAndVersionAt is the timestamped variant of
// the USK-792 helper. The USK-822 delete filter exposes streams.timestamp
// as a SQL bound, so several subtests need to control the wall-clock
// the saved row is stamped with rather than rely on time.Now().
func saveTestStreamWithSchemeAndVersionAt(t *testing.T, store *SQLiteStore, id, protocol, scheme, httpVersion string, ts time.Time) {
	t.Helper()
	ctx := context.Background()

	st := &Stream{
		ID:        id,
		Protocol:  protocol,
		Scheme:    scheme,
		State:     "complete",
		Timestamp: ts,
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
		Timestamp:   ts,
		Method:      "GET",
		URL:         mustParseURL(scheme + "://example.com/" + id),
		HTTPVersion: httpVersion,
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(%s send): %v", id, err)
	}
}

// saveTestStreamWithURL stores a stream with a single send flow whose
// URL matches the supplied raw string. The USK-822 filter's
// url_pattern axis runs an EXISTS-on-flows.url predicate, so the URL
// shape on the row is the load-bearing fixture.
func saveTestStreamWithURL(t *testing.T, store *SQLiteStore, id, rawURL string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	st := &Stream{
		ID:        id,
		Protocol:  "http",
		Scheme:    "https",
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
		URL:         mustParseURL(rawURL),
		HTTPVersion: "h2",
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(%s send): %v", id, err)
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_URLPattern pins the new
// USK-822 url_pattern predicate: the substring match selects only
// streams whose send-direction flow URL contains the pattern, and
// pre-existing streams that don't match survive untouched.
func TestSQLiteStore_DeleteStreamsByFilter_URLPattern(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithURL(t, store, "match-1", "https://httpbin.org/status/200")
	saveTestStreamWithURL(t, store, "match-2", "https://httpbin.org/status/200/redirect")
	saveTestStreamWithURL(t, store, "miss-1", "https://httpbin.org/status/404")
	saveTestStreamWithURL(t, store, "miss-2", "https://example.com/healthcheck")

	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{
		URLPattern: "httpbin.org/status/200",
	})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	gotIDs := make([]string, len(remaining))
	for i, s := range remaining {
		gotIDs[i] = s.ID
	}
	if !sameStringSet(gotIDs, []string{"miss-1", "miss-2"}) {
		t.Errorf("remaining = %v, want [miss-1 miss-2]", gotIDs)
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_URLPatternEscape pins that
// SQL LIKE wildcards (% / _) and the escape character (\) in the
// caller-supplied pattern are treated as literal characters. Without
// the ESCAPE clause, "%200" would match every URL containing "200"
// — exactly the kind of silent over-match USK-822 was filed about.
func TestSQLiteStore_DeleteStreamsByFilter_URLPatternEscape(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	saveTestStreamWithURL(t, store, "literal-percent", "https://example.com/%20path")
	saveTestStreamWithURL(t, store, "literal-underscore", "https://example.com/foo_bar")
	saveTestStreamWithURL(t, store, "plain", "https://example.com/normal")

	// "%20" must match the literal "%20" in literal-percent's URL only.
	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{URLPattern: "%20"})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1 — %% must not act as wildcard", n)
	}
	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 2 {
		t.Errorf("remaining %d, want 2", len(remaining))
	}

	// "_" must match the literal "_" in literal-underscore's URL only.
	n, err = store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{URLPattern: "foo_bar"})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1 — _ must not act as single-char wildcard", n)
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_TimeAfter pins the new
// USK-822 lower-bound predicate: streams.timestamp >= ? lex-compares
// the RFC3339Nano column with the bound's RFC3339Nano serialization,
// the same shape DeleteStreamsOlderThan already uses.
func TestSQLiteStore_DeleteStreamsByFilter_TimeAfter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	saveTestStreamWithSchemeAndVersionAt(t, store, "old", "http", "https", "h2", base)
	saveTestStreamWithSchemeAndVersionAt(t, store, "edge", "http", "https", "h2", base.Add(time.Hour))
	saveTestStreamWithSchemeAndVersionAt(t, store, "new", "http", "https", "h2", base.Add(2*time.Hour))

	// >= edge → edge and new survive deletion's complement (i.e. are
	// the ones deleted) but old stays.
	cutoff := base.Add(time.Hour)
	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{TimeAfter: &cutoff})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2 (edge and new at >= cutoff)", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 1 || remaining[0].ID != "old" {
		t.Errorf("remaining = %v, want [old]", remaining)
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_TimeBefore pins the new
// USK-822 upper-bound predicate (streams.timestamp <= ?). Combined
// with TimeAfter in a separate subtest the two yield a closed range.
func TestSQLiteStore_DeleteStreamsByFilter_TimeBefore(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	saveTestStreamWithSchemeAndVersionAt(t, store, "old", "http", "https", "h2", base)
	saveTestStreamWithSchemeAndVersionAt(t, store, "edge", "http", "https", "h2", base.Add(time.Hour))
	saveTestStreamWithSchemeAndVersionAt(t, store, "new", "http", "https", "h2", base.Add(2*time.Hour))

	cutoff := base.Add(time.Hour)
	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{TimeBefore: &cutoff})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2 (old and edge at <= cutoff)", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	if len(remaining) != 1 || remaining[0].ID != "new" {
		t.Errorf("remaining = %v, want [new]", remaining)
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_TimeRange pins that supplying
// both bounds yields a half-closed/closed window — only streams
// strictly inside [TimeAfter, TimeBefore] are deleted.
func TestSQLiteStore_DeleteStreamsByFilter_TimeRange(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	saveTestStreamWithSchemeAndVersionAt(t, store, "before", "http", "https", "h2", base)
	saveTestStreamWithSchemeAndVersionAt(t, store, "in-1", "http", "https", "h2", base.Add(time.Hour))
	saveTestStreamWithSchemeAndVersionAt(t, store, "in-2", "http", "https", "h2", base.Add(2*time.Hour))
	saveTestStreamWithSchemeAndVersionAt(t, store, "after", "http", "https", "h2", base.Add(3*time.Hour))

	lo := base.Add(time.Hour)
	hi := base.Add(2 * time.Hour)
	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{
		TimeAfter:  &lo,
		TimeBefore: &hi,
	})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d, want 2 (in-1 and in-2 between bounds)", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	gotIDs := make([]string, len(remaining))
	for i, s := range remaining {
		gotIDs[i] = s.ID
	}
	if !sameStringSet(gotIDs, []string{"before", "after"}) {
		t.Errorf("remaining = %v, want [before after]", gotIDs)
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_URLPlusTime pins that
// url_pattern AND-combines with the time bounds: only rows that
// satisfy every supplied predicate are deleted, matching the
// AND-everywhere convention buildStreamWhereClause established.
func TestSQLiteStore_DeleteStreamsByFilter_URLPlusTime(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)

	// Save four streams crossing the (URL × time) plane.
	saveStreamAt(t, store, "match", "https://api.example.com/foo", base.Add(time.Hour))
	saveStreamAt(t, store, "wrong-time", "https://api.example.com/foo", base) // before window
	saveStreamAt(t, store, "wrong-url", "https://other.example.com/bar", base.Add(time.Hour))
	saveStreamAt(t, store, "both-wrong", "https://other.example.com/bar", base)

	cutoff := base.Add(30 * time.Minute)
	n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{
		URLPattern: "api.example.com/foo",
		TimeAfter:  &cutoff,
	})
	if err != nil {
		t.Fatalf("DeleteStreamsByFilter: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want 1 (only the row matching both URL and time)", n)
	}

	remaining, _ := store.ListStreams(ctx, StreamListOptions{})
	gotIDs := make([]string, len(remaining))
	for i, s := range remaining {
		gotIDs[i] = s.ID
	}
	if !sameStringSet(gotIDs, []string{"wrong-time", "wrong-url", "both-wrong"}) {
		t.Errorf("remaining = %v", gotIDs)
	}
}

// saveStreamAt is a stamping variant of saveTestStreamWithURL used by
// the URL+time cross-product test above.
func saveStreamAt(t *testing.T, store *SQLiteStore, id, rawURL string, ts time.Time) {
	t.Helper()
	ctx := context.Background()

	st := &Stream{
		ID:        id,
		Protocol:  "http",
		Scheme:    "https",
		State:     "complete",
		Timestamp: ts,
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
		Timestamp:   ts,
		Method:      "GET",
		URL:         mustParseURL(rawURL),
		HTTPVersion: "h2",
	}
	if err := store.SaveFlow(ctx, send); err != nil {
		t.Fatalf("SaveFlow(%s send): %v", id, err)
	}
}

// TestStreamDeleteFilter_IsZero pins that the IsZero check covers the
// new USK-822 fields — without it a caller passing {URLPattern: "x"}
// could be misclassified as zero and route into DeleteAllStreams.
func TestStreamDeleteFilter_IsZero(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cases := []struct {
		name string
		f    StreamDeleteFilter
		want bool
	}{
		{"empty", StreamDeleteFilter{}, true},
		{"protocol", StreamDeleteFilter{Protocol: "http"}, false},
		{"scheme", StreamDeleteFilter{Scheme: "https"}, false},
		{"http_version", StreamDeleteFilter{HTTPVersion: strPtr("h2")}, false},
		{"url_pattern", StreamDeleteFilter{URLPattern: "x"}, false},
		{"time_after", StreamDeleteFilter{TimeAfter: &now}, false},
		{"time_before", StreamDeleteFilter{TimeBefore: &now}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.f.IsZero(); got != tc.want {
				t.Errorf("IsZero() = %v, want %v for %+v", got, tc.want, tc.f)
			}
		})
	}
}

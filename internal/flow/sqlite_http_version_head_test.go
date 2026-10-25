package flow

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"
)

// headVersionStream is one stream of the head-version corpus: its flows
// and the head HTTP version the MCP flows list displays for it
// (resolveHTTPVersion over resolveHeadPair in internal/mcp/query_tool.go).
type headVersionStream struct {
	id       string
	protocol string
	flows    []*Flow
	// head is the expected head version; "" means "no HTTP version".
	head string
}

// hf builds a flow row of the corpus. meta is merged over
// {"protocol": proto}.
func hf(seq int, dir, proto, version string, status int, wireLevel string, meta map[string]string) *Flow {
	m := map[string]string{"protocol": proto}
	for k, v := range meta {
		m[k] = v
	}
	return &Flow{
		Sequence: seq, Direction: dir, HTTPVersion: version, StatusCode: status,
		WireLevel: wireLevel, Metadata: m,
	}
}

// headVersionCorpus returns the stream shapes the filter must classify by
// head version. Row shapes follow RecordStep.envelopeToFlow: only
// HTTPMessage rows carry an http_version; WS / SSE / gRPC / raw rows and
// overlay (Message-nil) rows are written with an empty http_version.
func headVersionCorpus() []headVersionStream {
	variant := func(v string) map[string]string { return map[string]string{"variant": v} }
	return []headVersionStream{
		{id: "h11", protocol: "http", head: "http/1.1", flows: []*Flow{
			hf(0, "send", "http", "http/1.1", 0, "", nil),
			hf(1, "receive", "http", "http/1.1", 200, "", nil),
		}},
		{id: "ws", protocol: "ws", head: "http/1.1", flows: []*Flow{
			hf(0, "send", "http", "http/1.1", 0, "", nil),
			hf(1, "receive", "http", "http/1.1", 101, "", nil),
			hf(2, "send", "ws", "", 0, "", nil),
			hf(3, "receive", "ws", "", 0, "", nil),
		}},
		{id: "sse", protocol: "sse", head: "http/1.1", flows: []*Flow{
			hf(0, "send", "http", "http/1.1", 0, "", nil),
			hf(1, "receive", "http", "http/1.1", 200, "", nil),
			hf(2, "receive", "sse", "", 0, "", nil),
		}},
		// Plain h2 with h2-frame overlay rows at lower sequences: overlays
		// are never the head.
		{id: "h2-frames", protocol: "http", head: "h2", flows: []*Flow{
			hf(0, "send", "http", "", 0, WireLevelH2Frame, nil),
			hf(1, "send", "http", "h2", 0, "", nil),
			hf(2, "receive", "http", "", 0, WireLevelH2Frame, nil),
			hf(3, "receive", "http", "h2", 200, "", nil),
		}},
		{id: "h10-h11", protocol: "http", head: "http/1.0", flows: []*Flow{
			hf(0, "send", "http", "http/1.0", 0, "", nil),
			hf(1, "receive", "http", "http/1.1", 200, "", nil),
		}},
		{id: "grpc", protocol: "grpc", head: "", flows: []*Flow{
			hf(0, "send", "grpc", "", 0, "", nil),
			hf(1, "send", "grpc", "", 0, "", nil),
			hf(2, "receive", "grpc", "", 0, "", nil),
		}},
		{id: "legacy", protocol: "http", head: "", flows: []*Flow{
			hf(0, "send", "http", "", 0, "", nil),
			hf(1, "receive", "http", "", 200, "", nil),
		}},
		{id: "zero-flows", protocol: "http", head: ""},
		// Send head without a version (request-head recorder shape) falls
		// back to the receive head.
		{id: "send-empty", protocol: "http", head: "http/1.1", flows: []*Flow{
			hf(0, "send", "http", "", 0, "", nil),
			hf(1, "receive", "http", "http/1.1", 200, "", nil),
		}},
		{id: "1xx-skipped", protocol: "http", head: "h2", flows: []*Flow{
			hf(0, "send", "http", "", 0, "", nil),
			hf(1, "receive", "http", "http/1.0", 103, "", nil),
			hf(2, "receive", "http", "h2", 200, "", nil),
		}},
		{id: "101-not-skipped", protocol: "ws", head: "http/1.0", flows: []*Flow{
			hf(0, "send", "http", "", 0, "", nil),
			hf(1, "receive", "http", "http/1.0", 101, "", nil),
			hf(2, "receive", "http", "h2", 200, "", nil),
		}},
		{id: "all-1xx", protocol: "http", head: "h2c", flows: []*Flow{
			hf(0, "send", "http", "", 0, "", nil),
			hf(1, "receive", "http", "http/1.0", 100, "", nil),
			hf(2, "receive", "http", "h2c", 103, "", nil),
		}},
		{id: "non-http-1xx", protocol: "http", head: "http/1.0", flows: []*Flow{
			hf(0, "send", "http", "", 0, "", nil),
			hf(1, "receive", "raw", "http/1.0", 150, "", nil),
			hf(2, "receive", "http", "h2", 200, "", nil),
		}},
		{id: "send-variant", protocol: "http", head: "http/1.1", flows: []*Flow{
			hf(0, "send", "http", "http/1.0", 0, "", variant("original")),
			hf(0, "send", "http", "http/1.1", 0, "", variant("modified")),
			hf(1, "receive", "http", "http/1.0", 200, "", nil),
		}},
		{id: "recv-variant", protocol: "http", head: "h2", flows: []*Flow{
			hf(0, "send", "http", "", 0, "", nil),
			hf(1, "receive", "http", "http/1.1", 200, "", variant("original")),
			hf(1, "receive", "http", "h2", 200, "", variant("modified")),
		}},
		// A non-canonical version recorded verbatim is matched by neither
		// "" nor any enum value.
		{id: "non-canonical", protocol: "http", head: "HTTP/0.9", flows: []*Flow{
			hf(0, "send", "http", "HTTP/0.9", 0, "", nil),
		}},
	}
}

func seedHeadVersionCorpus(t *testing.T, store *SQLiteStore) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, s := range headVersionCorpus() {
		if err := store.SaveStream(ctx, &Stream{
			ID: s.id, Protocol: s.protocol, Scheme: "https", State: "complete", Timestamp: now,
		}); err != nil {
			t.Fatalf("SaveStream(%s): %v", s.id, err)
		}
		for i, f := range s.flows {
			f.ID = s.id + "-" + string(rune('a'+i))
			f.StreamID = s.id
			f.Timestamp = now.Add(time.Duration(i) * time.Millisecond)
			if err := store.SaveFlow(ctx, f); err != nil {
				t.Fatalf("SaveFlow(%s): %v", f.ID, err)
			}
		}
	}
}

// expectedHeadIDs returns the sorted corpus ids whose head is v.
func expectedHeadIDs(v string) []string {
	var ids []string
	for _, s := range headVersionCorpus() {
		if s.head == v {
			ids = append(ids, s.id)
		}
	}
	sort.Strings(ids)
	return ids
}

var headVersionFilterValues = []string{"", "http/1.0", "http/1.1", "h2", "h2c"}

// TestSQLiteStore_ListStreams_FilterByHTTPVersion_HeadVersion pins that
// ListStreams / CountStreams select a stream iff its head HTTP version
// equals the filter value.
func TestSQLiteStore_ListStreams_FilterByHTTPVersion_HeadVersion(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedHeadVersionCorpus(t, store)
	ctx := context.Background()

	for _, v := range headVersionFilterValues {
		opts := StreamListOptions{HTTPVersion: strPtr(v)}
		got, err := store.ListStreams(ctx, opts)
		if err != nil {
			t.Fatalf("ListStreams(%q): %v", v, err)
		}
		ids := make([]string, len(got))
		for i, s := range got {
			ids[i] = s.ID
		}
		sort.Strings(ids)
		want := expectedHeadIDs(v)
		if strings.Join(ids, ",") != strings.Join(want, ",") {
			t.Errorf("http_version=%q ids = %v, want %v", v, ids, want)
		}
		n, err := store.CountStreams(ctx, opts)
		if err != nil {
			t.Fatalf("CountStreams(%q): %v", v, err)
		}
		if n != len(want) {
			t.Errorf("http_version=%q count = %d, want %d", v, n, len(want))
		}
	}
}

// TestSQLiteStore_DeleteStreamsByFilter_HTTPVersionMatchesListStreams
// guards the two SQL sites against drift: for every value, the streams
// DeleteStreamsByFilter removes are exactly the ones ListStreams selects.
func TestSQLiteStore_DeleteStreamsByFilter_HTTPVersionMatchesListStreams(t *testing.T) {
	t.Parallel()
	for _, v := range headVersionFilterValues {
		v := v
		t.Run("v="+v, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			seedHeadVersionCorpus(t, store)
			ctx := context.Background()

			listed, err := store.ListStreams(ctx, StreamListOptions{HTTPVersion: strPtr(v)})
			if err != nil {
				t.Fatalf("ListStreams: %v", err)
			}
			selected := map[string]bool{}
			for _, s := range listed {
				selected[s.ID] = true
			}

			n, err := store.DeleteStreamsByFilter(ctx, StreamDeleteFilter{HTTPVersion: strPtr(v)})
			if err != nil {
				t.Fatalf("DeleteStreamsByFilter: %v", err)
			}
			want := expectedHeadIDs(v)
			if n != int64(len(want)) {
				t.Errorf("deleted = %d, want %d (%v)", n, len(want), want)
			}
			remaining, err := store.ListStreams(ctx, StreamListOptions{})
			if err != nil {
				t.Fatalf("ListStreams(all): %v", err)
			}
			if len(remaining)+int(n) != len(headVersionCorpus()) {
				t.Errorf("remaining %d + deleted %d != corpus %d", len(remaining), n, len(headVersionCorpus()))
			}
			for _, s := range remaining {
				if selected[s.ID] {
					t.Errorf("stream %s listed by http_version=%q but not deleted", s.ID, v)
				}
			}
			if len(selected) != int(n) {
				t.Errorf("listed %d streams, deleted %d", len(selected), n)
			}
		})
	}
}

package flow

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// flowWirePaths are request paths exactly as observed on the wire
// (USK-1139). Row 1 is the reported ad cookie-sync shape; the rest are
// pentest shapes (invented) that net/url cannot round-trip through
// String() → Parse() byte-exactly, including %zz which today makes the
// sqlite read silently drop Flow.URL and the JSONL import fail.
var flowWirePaths = []struct {
	name string
	wire string
}{
	{"reported cookie-sync", "/check_uuid/https%3A%2F%2Fsync.example%2Fsetuid%3Fa%3D1"},
	{"encoded question mark", "/a%3Fb"},
	{"encoded unreserved", "/%61dmin"},
	{"invalid escape", "/a%zz"},
	{"bare percent", "/a%"},
	{"template braces", "/{{7*7}}"},
	{"pipe", "/a|b"},
	{"raw utf-8", "/caf\xc3\xa9"},
	{"control byte", "/ctl\x01x"},
}

func saveWirePathFlow(t *testing.T, store *SQLiteStore, id, wire string) {
	t.Helper()
	ctx := context.Background()
	ts := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	if err := store.SaveStream(ctx, &Stream{
		ID: id, ConnID: "c-" + id, Protocol: "http", Scheme: "https",
		State: "complete", Timestamp: ts,
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, &Flow{
		ID: "f-" + id, StreamID: id, Sequence: 0, Direction: "send",
		Timestamp: ts, Method: "GET",
		URL:     envelope.URLFromWirePath("https", "example.com", wire, "q=x%3Ay"),
		Headers: map[string][]string{"Host": {"example.com"}},
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
}

// TestSQLiteStore_FlowURLKeepsWirePath covers save → GetFlows: the read-back
// URL is non-nil and its wire path is byte-identical to what was recorded.
func TestSQLiteStore_FlowURLKeepsWirePath(t *testing.T) {
	store := newTestStore(t)
	for i, p := range flowWirePaths {
		t.Run(p.name, func(t *testing.T) {
			id := "wp-" + string(rune('a'+i))
			saveWirePathFlow(t, store, id, p.wire)
			flows, err := store.GetFlows(context.Background(), id, FlowListOptions{})
			if err != nil || len(flows) != 1 {
				t.Fatalf("GetFlows = %d flows, err %v", len(flows), err)
			}
			u := flows[0].URL
			if u == nil {
				t.Fatalf("Flow.URL read back as nil")
			}
			if got := envelope.WirePath(u); got != p.wire {
				t.Errorf("WirePath = %q, want %q", got, p.wire)
			}
			want := "https://example.com" + p.wire + "?q=x%3Ay"
			if got := envelope.WireURLString(u); got != want {
				t.Errorf("WireURLString = %q, want %q", got, want)
			}
		})
	}
}

// TestExportImport_FlowURLKeepsWirePath covers JSONL export → import: the
// exported url field is the wire form and imports without error.
func TestExportImport_FlowURLKeepsWirePath(t *testing.T) {
	ctx := context.Background()
	for i, p := range flowWirePaths {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			src := newTestStore(t)
			id := "ex-" + string(rune('a'+i))
			saveWirePathFlow(t, src, id, p.wire)

			var buf bytes.Buffer
			if _, err := ExportStreams(ctx, src, &buf, ExportOptions{}); err != nil {
				t.Fatalf("ExportStreams: %v", err)
			}
			want := "https://example.com" + p.wire + "?q=x%3Ay"
			var rec ExportRecord
			sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
			for sc.Scan() {
				if err := json.Unmarshal(sc.Bytes(), &rec); err == nil && len(rec.Flows) > 0 {
					break
				}
			}
			if len(rec.Flows) == 0 {
				t.Fatalf("no exported flows in %q", buf.String())
			}
			if got := rec.Flows[0].URL; got != want {
				t.Errorf("exported url = %q, want %q", got, want)
			}

			dst := newTestStore(t)
			res, err := ImportStreams(ctx, dst, bytes.NewReader(buf.Bytes()), ImportOptions{OnConflict: ConflictSkip})
			if err != nil {
				t.Fatalf("ImportStreams: %v", err)
			}
			if res.Imported != 1 || res.Errors != 0 {
				t.Fatalf("import result = %+v, want 1 imported / 0 errors", res)
			}
			flows, err := dst.GetFlows(ctx, id, FlowListOptions{})
			if err != nil || len(flows) != 1 || flows[0].URL == nil {
				t.Fatalf("imported flows = %v, err %v", flows, err)
			}
			if got := envelope.WirePath(flows[0].URL); got != p.wire {
				t.Errorf("imported WirePath = %q, want %q", got, p.wire)
			}
		})
	}
}

// TestExportHAR_FlowURLKeepsWirePath pins that HAR request.url carries the
// wire path, not a re-escaped copy.
func TestExportHAR_FlowURLKeepsWirePath(t *testing.T) {
	for i, p := range flowWirePaths {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			saveWirePathFlow(t, store, "har-"+string(rune('a'+i)), p.wire)
			var buf bytes.Buffer
			if _, err := ExportHAR(context.Background(), store, &buf, ExportOptions{}, "test"); err != nil {
				t.Fatalf("ExportHAR: %v", err)
			}
			var har HAR
			if err := json.Unmarshal(buf.Bytes(), &har); err != nil {
				t.Fatalf("unmarshal HAR: %v", err)
			}
			if len(har.Log.Entries) != 1 {
				t.Fatalf("entries = %d, want 1", len(har.Log.Entries))
			}
			want := "https://example.com" + p.wire + "?q=x%3Ay"
			if got := har.Log.Entries[0].Request.URL; got != want {
				t.Errorf("HAR request.url = %q, want %q", got, want)
			}
		})
	}
}

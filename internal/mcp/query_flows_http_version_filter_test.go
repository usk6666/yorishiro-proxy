package mcp

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// The tests in this file pin that filter.http_version selects a stream by
// its head HTTP version — the value the flows list shows as
// flows[].http_version (resolveHTTPVersion over the head pair) — on every
// surface that shares the predicate: query resource=flows (list + total),
// manage export_flows (JSONL + HAR) and manage delete_flows. "" therefore
// selects streams with no HTTP version (non-HTTP protocols, rows recorded
// before the field existed, streams with no flows), never a WS / SSE /
// plain h2 stream whose head carries a version.

// httpVersionFilterValues is every value the differential tests sweep:
// the "no version" sentinel plus each canonical enum value.
var httpVersionFilterValues = []string{"", envelope.HTTPVersion10, envelope.HTTPVersion11, envelope.HTTPVersionH2, envelope.HTTPVersionH2C}

// noHTTPVersionStreamIDs is the stream set "" must select for the corpus
// recordAllProtocolStreams + seedFlowWithHTTPVersion("legacy", "") builds.
var noHTTPVersionStreamIDs = []string{"stream-grpc", "stream-grpc-web", "stream-raw", "stream-tls-handshake", "legacy"}

// recordH2PairWithFrameOverlays records a plain h2 (https) GET + 200 the
// way the live h2 path does when h2-frame recording is on (the default):
// each semantic HTTPMessage is preceded by a Message-nil h2-frame overlay
// envelope whose Raw is the frame payload. The overlay shape follows
// buildH2FrameWireEnvelope (internal/layer/httpaggregator/channel.go):
// Protocol http, Message nil, Context.WireLevel stamped h2-frame by the
// session helper. RecordStep persists overlay rows with an empty http_version.
// Sequences are assigned in order by r.run, so each overlay row sits at a
// lower sequence than the semantic row it precedes.
func recordH2PairWithFrameOverlays(t *testing.T, r *webUIFixtureRecorder, streamID string) {
	t.Helper()
	reqFrame := h2HeadersFrameOn(t, 1,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "h2frames.example.com"},
		hpack.HeaderField{Name: ":path", Value: "/frames"},
	)
	respFrame := h2HeadersFrameOn(t, 1, hpack.HeaderField{Name: ":status", Value: "200"})
	r.run(streamID,
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       reqFrame,
			Context: envelope.EnvelopeContext{
				WireLevel:        flow.WireLevelH2Frame,
				RequestMethod:    "GET",
				RequestPath:      "/frames",
				RequestAuthority: "h2frames.example.com",
			},
		},
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       reqFrame,
			Message: &envelope.HTTPMessage{
				Method: "GET", Scheme: "https", Authority: "h2frames.example.com", Path: "/frames",
				HTTPVersion: envelope.HTTPVersionH2,
			},
		},
		&envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       respFrame,
			Context:   envelope.EnvelopeContext{WireLevel: flow.WireLevelH2Frame},
		},
		&envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       respFrame,
			Message:   &envelope.HTTPMessage{Status: 200, HTTPVersion: envelope.HTTPVersionH2},
		},
	)
}

// recordH10RequestH11Response records an HTTP/1.0 request answered with an
// HTTP/1.1 response: the http1 Layer stamps each message's own wire
// version (request line / status line, internal/layer/http1/channel.go),
// so the two rows of the stream carry different versions. The head
// version is the request's.
func recordH10RequestH11Response(r *webUIFixtureRecorder, streamID string) {
	r.t.Helper()
	r.run(streamID,
		&envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("GET /old HTTP/1.0\r\nHost: h10.example.com\r\n\r\n"),
			Message: &envelope.HTTPMessage{
				Method: "GET", Scheme: "http", Authority: "h10.example.com", Path: "/old",
				HTTPVersion: envelope.HTTPVersion10,
				Headers:     []envelope.KeyValue{{Name: "Host", Value: "h10.example.com"}},
			},
		},
		&envelope.Envelope{
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
			Message: &envelope.HTTPMessage{
				Status: 200, StatusReason: "OK",
				HTTPVersion: envelope.HTTPVersion11,
				Headers:     []envelope.KeyValue{{Name: "Content-Length", Value: "0"}},
			},
		},
	)
}

// saveHeadEdgeFlows stores streamID (protocol http) with the given flows
// written straight to the store, for head shapes RecordStep does not
// produce from a single pipeline run (variant pairs, 1xx sequences,
// send rows without a version).
func saveHeadEdgeFlows(t *testing.T, store flow.Store, streamID string, flows ...*flow.Flow) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.SaveStream(ctx, &flow.Stream{
		ID: streamID, ConnID: "conn-" + streamID, Protocol: "http", Scheme: "https",
		State: "complete", Timestamp: now,
	}); err != nil {
		t.Fatalf("SaveStream(%s): %v", streamID, err)
	}
	for i, f := range flows {
		f.StreamID = streamID
		if f.ID == "" {
			f.ID = streamID + "-" + string(rune('a'+i))
		}
		f.Timestamp = now.Add(time.Duration(i) * time.Millisecond)
		if f.Metadata == nil {
			f.Metadata = map[string]string{}
		}
		if _, ok := f.Metadata["protocol"]; !ok {
			f.Metadata["protocol"] = "http"
		}
		if err := store.SaveFlow(ctx, f); err != nil {
			t.Fatalf("SaveFlow(%s/%s): %v", streamID, f.ID, err)
		}
	}
}

// seedHeadEdgeCases stores the head-resolution edge cases mirrored from
// TestResolveHeadPair and the request-head recorder (a send row with no
// HTTP version, internal/connector/request_head_recorder.go): send
// fallback to receive, 1xx skip, all-1xx, variant pairs at the head.
func seedHeadEdgeCases(t *testing.T, store flow.Store) {
	t.Helper()
	u, _ := url.Parse("https://edge.example.com/")
	saveHeadEdgeFlows(t, store, "edge-send-empty",
		&flow.Flow{Sequence: 0, Direction: "send", Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", StatusCode: 200, HTTPVersion: envelope.HTTPVersion11},
	)
	saveHeadEdgeFlows(t, store, "edge-1xx-skipped",
		&flow.Flow{Sequence: 0, Direction: "send", Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", StatusCode: 103, HTTPVersion: envelope.HTTPVersion10},
		&flow.Flow{Sequence: 2, Direction: "receive", StatusCode: 200, HTTPVersion: envelope.HTTPVersionH2},
	)
	saveHeadEdgeFlows(t, store, "edge-all-1xx",
		&flow.Flow{Sequence: 0, Direction: "send", Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", StatusCode: 100, HTTPVersion: envelope.HTTPVersion10},
		&flow.Flow{Sequence: 2, Direction: "receive", StatusCode: 103, HTTPVersion: envelope.HTTPVersionH2C},
	)
	saveHeadEdgeFlows(t, store, "edge-non-http-1xx",
		&flow.Flow{Sequence: 0, Direction: "send", Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", StatusCode: 150, HTTPVersion: envelope.HTTPVersion10,
			Metadata: map[string]string{"protocol": "raw"}},
		&flow.Flow{Sequence: 2, Direction: "receive", StatusCode: 200, HTTPVersion: envelope.HTTPVersionH2},
	)
	saveHeadEdgeFlows(t, store, "edge-send-variant",
		&flow.Flow{Sequence: 0, Direction: "send", Method: "GET", URL: u, HTTPVersion: envelope.HTTPVersion10,
			Metadata: map[string]string{"variant": "original"}},
		&flow.Flow{Sequence: 0, Direction: "send", Method: "GET", URL: u, HTTPVersion: envelope.HTTPVersion11,
			Metadata: map[string]string{"variant": "modified"}},
		&flow.Flow{Sequence: 1, Direction: "receive", StatusCode: 200, HTTPVersion: envelope.HTTPVersion10},
	)
	saveHeadEdgeFlows(t, store, "edge-recv-variant",
		&flow.Flow{Sequence: 0, Direction: "send", Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", StatusCode: 200, HTTPVersion: envelope.HTTPVersion11,
			Metadata: map[string]string{"variant": "original"}},
		&flow.Flow{Sequence: 1, Direction: "receive", StatusCode: 200, HTTPVersion: envelope.HTTPVersionH2,
			Metadata: map[string]string{"variant": "modified"}},
	)
}

// seedZeroFlowStream stores a stream with no flow rows (the shape of an
// error / capacity-rejected stream that never recorded a message).
func seedZeroFlowStream(t *testing.T, store flow.Store, id string) {
	t.Helper()
	if err := store.SaveStream(context.Background(), &flow.Stream{
		ID: id, ConnID: "conn-" + id, Protocol: "http", Scheme: "https",
		State: "error", Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveStream(%s): %v", id, err)
	}
}

// seedHTTPVersionFilterCorpus stores every head shape the differential
// tests sweep.
func seedHTTPVersionFilterCorpus(t *testing.T, store flow.Store) {
	t.Helper()
	r := newWebUIFixtureRecorder(t, store)
	recordAllProtocolStreams(t, r)
	recordH2PairWithFrameOverlays(t, r, "stream-h2-frames")
	recordH10RequestH11Response(r, "stream-h10-h11")
	seedFlowWithHTTPVersion(t, store, "legacy", "")
	seedHeadEdgeCases(t, store)
	seedZeroFlowStream(t, store, "zero-flows")
}

// listFlowsFiltered calls query resource=flows with filter.http_version=v
// and returns the sorted stream ids plus the reported total.
func listFlowsFiltered(t *testing.T, cs *gomcp.ClientSession, v string) ([]string, int) {
	t.Helper()
	out := queryJSON(t, cs, map[string]any{
		"resource": "flows",
		"limit":    100,
		"filter":   map[string]any{"http_version": v},
	})
	list, _ := out["flows"].([]any)
	ids := make([]string, 0, len(list))
	for _, e := range list {
		ids = append(ids, e.(map[string]any)["id"].(string))
	}
	sort.Strings(ids)
	total, _ := out["total"].(float64)
	return ids, int(total)
}

// displayedVersionPartition groups the unfiltered flows list by the
// http_version each entry displays (absent ⇒ "").
func displayedVersionPartition(t *testing.T, cs *gomcp.ClientSession) map[string][]string {
	t.Helper()
	byID := listFlowsByID(t, cs, nil)
	part := map[string][]string{}
	for id, e := range byID {
		v, _ := e["http_version"].(string)
		part[v] = append(part[v], id)
	}
	for v := range part {
		sort.Strings(part[v])
	}
	return part
}

func sortedCopy(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

// TestQueryFlows_FilterHTTPVersionEmpty_MatchesNoVersionStreams reproduces
// the report: filter.http_version="" returned WS and SSE entries whose
// flows[].http_version is http/1.1, because any frame / event row (all
// recorded with an empty http_version) matched.
func TestQueryFlows_FilterHTTPVersionEmpty_MatchesNoVersionStreams(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordAllProtocolStreams(t, r)
	seedFlowWithHTTPVersion(t, store, "legacy", "")
	cs := setupQueryTestSession(t, store)

	ids, total := listFlowsFiltered(t, cs, "")
	want := sortedCopy(noHTTPVersionStreamIDs)
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("http_version=\"\" ids = %v, want %v", ids, want)
	}
	if total != len(ids) {
		t.Errorf("total = %d, want %d (count of listed streams)", total, len(ids))
	}
}

// TestQueryFlows_FilterHTTPVersion_MatchesDisplayedVersion is the
// differential oracle: for every filter value v, the filtered id set (and
// total) equals the set of unfiltered entries whose displayed
// http_version is v.
func TestQueryFlows_FilterHTTPVersion_MatchesDisplayedVersion(t *testing.T) {
	store := newTestStore(t)
	seedHTTPVersionFilterCorpus(t, store)
	cs := setupQueryTestSession(t, store)

	part := displayedVersionPartition(t, cs)
	for _, v := range httpVersionFilterValues {
		ids, total := listFlowsFiltered(t, cs, v)
		want := part[v]
		if strings.Join(ids, ",") != strings.Join(want, ",") {
			t.Errorf("http_version=%q ids = %v, want displayed set %v", v, ids, want)
		}
		if total != len(want) {
			t.Errorf("http_version=%q total = %d, want %d", v, total, len(want))
		}
	}
}

// TestQueryFlows_FilterHTTPVersion_HeadSemantics pins the expected head
// version of each special shape, so the differential test above cannot
// pass vacuously if the projection itself drifted.
func TestQueryFlows_FilterHTTPVersion_HeadSemantics(t *testing.T) {
	store := newTestStore(t)
	seedHTTPVersionFilterCorpus(t, store)
	cs := setupQueryTestSession(t, store)

	matches := map[string]map[string]bool{}
	for _, v := range httpVersionFilterValues {
		ids, _ := listFlowsFiltered(t, cs, v)
		for _, id := range ids {
			if matches[id] == nil {
				matches[id] = map[string]bool{}
			}
			matches[id][v] = true
		}
	}
	for _, tc := range []struct{ id, want string }{
		{"stream-ws", envelope.HTTPVersion11},
		{"stream-sse", envelope.HTTPVersion11},
		{"stream-h2-frames", envelope.HTTPVersionH2},
		{"stream-h10-h11", envelope.HTTPVersion10},
		{"zero-flows", ""},
		{"edge-send-empty", envelope.HTTPVersion11},
		{"edge-1xx-skipped", envelope.HTTPVersionH2},
		{"edge-all-1xx", envelope.HTTPVersionH2C},
		{"edge-non-http-1xx", envelope.HTTPVersion10},
		{"edge-send-variant", envelope.HTTPVersion11},
		{"edge-recv-variant", envelope.HTTPVersionH2},
	} {
		got := matches[tc.id]
		if !got[tc.want] || len(got) != 1 {
			t.Errorf("%s matched by %v, want exactly {%q}", tc.id, got, tc.want)
		}
	}
}

// TestManageDelete_FilterHTTPVersionEmpty_DeletesNoVersionStreamsOnly pins
// that delete_flows http_version="" + confirm removes only streams with no
// HTTP version; HTTP / WS / SSE streams survive.
func TestManageDelete_FilterHTTPVersionEmpty_DeletesNoVersionStreamsOnly(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordAllProtocolStreams(t, r)
	seedFlowWithHTTPVersion(t, store, "legacy", "")
	cs := setupTestSession(t, newTestCA(t), store)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{"http_version": "", "confirm": true},
	})
	if result.IsError {
		t.Fatalf("delete error: %v", result.Content)
	}
	var del executeDeleteFlowsResult
	unmarshalManageResult(t, result, &del)
	if del.DeletedCount != int64(len(noHTTPVersionStreamIDs)) {
		t.Errorf("deleted_count = %d, want %d", del.DeletedCount, len(noHTTPVersionStreamIDs))
	}
	remaining := listStreamIDs(t, store)
	want := []string{"stream-http-h1", "stream-http-h2", "stream-http-h2c", "stream-ws", "stream-sse"}
	if !sameStringSetMCP(remaining, want) {
		t.Errorf("remaining = %v, want %v", remaining, want)
	}
}

// TestManageExport_FilterHTTPVersionEmpty_ExportsNoVersionStreamsOnly pins
// that export_flows filter.http_version="" exports only streams with no
// HTTP version, for both JSONL and HAR.
func TestManageExport_FilterHTTPVersionEmpty_ExportsNoVersionStreamsOnly(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordAllProtocolStreams(t, r)
	seedFlowWithHTTPVersion(t, store, "legacy", "")
	cs, dir := setupExportSession(t, newTestCA(t), store)

	t.Run("jsonl", func(t *testing.T) {
		out := filepath.Join(dir, "empty-version.jsonl")
		result := manageCallTool(t, cs, map[string]any{
			"action": "export_flows",
			"params": map[string]any{
				"output_path": out,
				"filter":      map[string]any{"http_version": ""},
			},
		})
		if result.IsError {
			t.Fatalf("export error: %v", result.Content)
		}
		ids := readExportedJSONL(t, out)
		if !sameStringSetMCP(ids, noHTTPVersionStreamIDs) {
			t.Errorf("exported = %v, want %v", ids, noHTTPVersionStreamIDs)
		}
	})

	t.Run("har", func(t *testing.T) {
		out := filepath.Join(dir, "empty-version.har")
		result := manageCallTool(t, cs, map[string]any{
			"action": "export_flows",
			"params": map[string]any{
				"format":      "har",
				"output_path": out,
				"filter":      map[string]any{"http_version": ""},
			},
		})
		if result.IsError {
			t.Fatalf("export error: %v", result.Content)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		var har struct {
			Log struct {
				Entries []struct {
					Request struct {
						URL string `json:"url"`
					} `json:"request"`
				} `json:"entries"`
			} `json:"log"`
		}
		if err := json.Unmarshal(data, &har); err != nil {
			t.Fatalf("Unmarshal HAR: %v", err)
		}
		sawLegacy := false
		for _, e := range har.Log.Entries {
			u := e.Request.URL
			for _, host := range []string{"ws.example.com", "sse.example.com", "h1.example.com", "h2.example.com"} {
				if strings.Contains(u, "://"+host) {
					t.Errorf("HAR entry %q exported, want only streams with no HTTP version", u)
				}
			}
			if u == "https://example.com/api" {
				sawLegacy = true
			}
		}
		if !sawLegacy {
			t.Errorf("HAR entries %v lack the legacy stream", har.Log.Entries)
		}
	})
}

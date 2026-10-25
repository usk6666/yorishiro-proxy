package mcp

import (
	"context"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// listFlowsByID calls query resource=flows with args (resource and limit
// are filled in) and returns each entry keyed by its id.
func listFlowsByID(t *testing.T, cs *gomcp.ClientSession, args map[string]any) map[string]map[string]any {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	args["resource"] = "flows"
	args["limit"] = 100
	out := queryJSON(t, cs, args)
	list, ok := out["flows"].([]any)
	if !ok {
		t.Fatalf("flows = %T, want array", out["flows"])
	}
	byID := make(map[string]map[string]any, len(list))
	for _, e := range list {
		m := e.(map[string]any)
		byID[m["id"].(string)] = m
	}
	return byID
}

// TestQueryFlows_HTTPVersion_MatchesDetail pins that every resource=flows
// entry carries the same http_version as resource=flow for the same
// stream: the wire version of the head message, verbatim (USK-1359). WS
// and SSE streams report the version of their HTTP head.
func TestQueryFlows_HTTPVersion_MatchesDetail(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordAllProtocolStreams(t, r)
	cs := setupQueryTestSession(t, store)

	byID := listFlowsByID(t, cs, nil)
	for _, tc := range []struct{ id, want string }{
		{"stream-http-h1", "http/1.1"},
		{"stream-http-h2", "h2"},
		{"stream-http-h2c", "h2c"},
		{"stream-ws", "http/1.1"},
		{"stream-sse", "http/1.1"},
	} {
		entry, ok := byID[tc.id]
		if !ok {
			t.Fatalf("stream %s missing from flows list", tc.id)
		}
		if got := entry["http_version"]; got != tc.want {
			t.Errorf("flows[%s].http_version = %v, want %q", tc.id, got, tc.want)
		}
		detail := queryJSON(t, cs, map[string]any{"resource": "flow", "id": tc.id})
		if entry["http_version"] != detail["http_version"] {
			t.Errorf("flows[%s].http_version = %v, flow.http_version = %v; want equal",
				tc.id, entry["http_version"], detail["http_version"])
		}
	}
}

// TestQueryFlows_HTTPVersion_OmittedWithoutVersion pins that streams whose
// head carries no HTTP version — non-HTTP protocols and pre-USK-788 HTTP
// rows — omit the key instead of reporting a synthesized value.
func TestQueryFlows_HTTPVersion_OmittedWithoutVersion(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordAllProtocolStreams(t, r)
	seedFlowWithHTTPVersion(t, store, "legacy", "")
	cs := setupQueryTestSession(t, store)

	byID := listFlowsByID(t, cs, nil)
	for _, id := range []string{"stream-grpc", "stream-grpc-web", "stream-raw", "stream-tls-handshake", "legacy"} {
		entry, ok := byID[id]
		if !ok {
			t.Fatalf("stream %s missing from flows list", id)
		}
		if v, present := entry["http_version"]; present {
			t.Errorf("flows[%s].http_version = %v, want key absent", id, v)
		}
	}
}

// TestQueryFlows_HTTPVersion_FallsBackToReceive pins that a list entry
// whose send side carries no HTTP version reports the receive side's.
func TestQueryFlows_HTTPVersion_FallsBackToReceive(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if err := store.SaveStream(ctx, &flow.Stream{
		ID: "no-send", ConnID: "conn-no-send", Protocol: "http", Scheme: "https",
		State: "complete", Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	u, _ := url.Parse("https://example.com/")
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID: "no-send-send", StreamID: "no-send", Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: u,
	}); err != nil {
		t.Fatalf("SaveFlow(send): %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		ID: "no-send-recv", StreamID: "no-send", Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200, HTTPVersion: "h2",
	}); err != nil {
		t.Fatalf("SaveFlow(recv): %v", err)
	}
	cs := setupQueryTestSession(t, store)

	byID := listFlowsByID(t, cs, nil)
	if got := byID["no-send"]["http_version"]; got != "h2" {
		t.Errorf("flows[no-send].http_version = %v, want %q", got, "h2")
	}
}

// TestQueryFlows_HTTPVersion_IndependentOfWireLevel pins that
// filter.wire_level, which governs only message_count / message_preview,
// does not change the head-derived http_version.
func TestQueryFlows_HTTPVersion_IndependentOfWireLevel(t *testing.T) {
	store := newTestStore(t)
	r := newWebUIFixtureRecorder(t, store)
	recordH2Pair(t, r, "stream-http-h2", "https")
	cs := setupQueryTestSession(t, store)

	for _, wl := range []string{"", flow.WireLevelSemantic, "all", "h2-frame", "h1-chunk"} {
		args := map[string]any{}
		if wl != "" {
			args["filter"] = map[string]any{"wire_level": wl}
		}
		byID := listFlowsByID(t, cs, args)
		if got := byID["stream-http-h2"]["http_version"]; got != "h2" {
			t.Errorf("wire_level=%q: flows[stream-http-h2].http_version = %v, want %q", wl, got, "h2")
		}
	}
}

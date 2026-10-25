package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestQueryOutput_InvalidUTF8WirePathEscaped pins USK-1139 review F-1 on the
// query tool: a recorded wire path holding bytes that are not valid UTF-8
// cannot travel in a JSON string (encoding/json would replace each with
// U+FFFD), so every query url field shows those bytes %XX-escaped while
// valid UTF-8 and existing escapes stay verbatim.
func TestQueryOutput_InvalidUTF8WirePathEscaped(t *testing.T) {
	const want = "https://example.com/a%80b/%FF%FE/café/%61?q=%ff"
	send := &flow.Flow{
		ID:        "f-send",
		Direction: "send",
		Method:    "GET",
		URL:       envelope.URLFromWirePath("https", "example.com", "/a\x80b/\xff\xfe/caf\xc3\xa9/%61", "q=%ff"),
	}

	assertJSONSafe := func(t *testing.T, field, got string) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %q, want %q", field, got, want)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back string
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if back != got {
			t.Errorf("%s does not survive a JSON round trip: %q -> %q", field, got, back)
		}
	}

	_, urlStr, _, _ := extractFlowSummary([]*flow.Flow{send})
	assertJSONSafe(t, "extractFlowSummary url", urlStr)

	s := newServer(context.Background(), nil, nil, nil)
	limit := bodyLimitOptions{includeBodies: true}
	if v := s.buildOriginalRequest(send, false, limit); v == nil {
		t.Fatal("buildOriginalRequest = nil")
	} else {
		assertJSONSafe(t, "buildOriginalRequest URL", v.URL)
	}
	assertJSONSafe(t, "projectFlowSide url", s.projectFlowSide(send, false, limit).url)
	entries := s.convertMessagesToEntries([]*flow.Flow{send}, false, limit)
	if len(entries) != 1 {
		t.Fatalf("convertMessagesToEntries = %d entries, want 1", len(entries))
	}
	assertJSONSafe(t, "convertMessagesToEntries URL", entries[0].URL)
}

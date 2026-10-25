package mcp

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/flow/flowtest"
)

// seedTaggedStream saves a stream with the given id, origin and tags.
func seedTaggedStream(t *testing.T, store flow.Store, id string, origin flow.Origin, tags map[string]string) {
	t.Helper()
	if err := store.SaveStream(context.Background(), &flow.Stream{
		ID: id, ConnID: "conn-" + id, Protocol: "http", Scheme: "http",
		State: "complete", Timestamp: time.Now().UTC(), Origin: origin, Tags: tags,
	}); err != nil {
		t.Fatalf("SaveStream(%s): %v", id, err)
	}
}

// queryFlowIDs runs query resource=flows with filter and returns the
// sorted stream ids plus the count / total fields.
func queryFlowIDs(t *testing.T, cs *gomcp.ClientSession, filter map[string]any, limit int) (ids []string, count, total int) {
	t.Helper()
	out := queryJSON(t, cs, map[string]any{"resource": "flows", "filter": filter, "limit": limit})
	list, ok := out["flows"].([]any)
	if !ok {
		t.Fatalf("flows = %T, want array", out["flows"])
	}
	for _, e := range list {
		ids = append(ids, e.(map[string]any)["id"].(string))
	}
	sort.Strings(ids)
	return ids, int(out["count"].(float64)), int(out["total"].(float64))
}

// TestQueryFlows_FilterTag_ExactMatch pins that filter.tag on
// resource=flows selects only the stream whose Stream.Tags["tag"] equals
// the value exactly, and that count / total agree.
func TestQueryFlows_FilterTag_ExactMatch(t *testing.T) {
	store := flowtest.NewStore(t)
	seedTaggedStream(t, store, "want", flow.OriginResend, map[string]string{"tag": "probe-1"})
	seedTaggedStream(t, store, "target-key", flow.OriginProxy, map[string]string{"target": "probe-1"})
	seedTaggedStream(t, store, "prefix", flow.OriginResend, map[string]string{"tag": "probe-10"})
	seedTaggedStream(t, store, "case", flow.OriginResend, map[string]string{"tag": "Probe-1"})
	seedTaggedStream(t, store, "untagged", flow.OriginProxy, nil)
	seedTaggedStream(t, store, "malformed", flow.OriginResend, nil)
	if _, err := store.DB().ExecContext(context.Background(),
		`UPDATE streams SET tags = ? WHERE id = ?`, `not json`, "malformed"); err != nil {
		t.Fatalf("seed malformed tags: %v", err)
	}
	cs := setupQueryTestSession(t, store)

	ids, count, total := queryFlowIDs(t, cs, map[string]any{"tag": "probe-1"}, 100)
	if strings.Join(ids, ",") != "want" {
		t.Errorf("flows(tag=probe-1) ids = %v, want [want]", ids)
	}
	if count != 1 || total != 1 {
		t.Errorf("flows(tag=probe-1) count=%d total=%d, want 1/1", count, total)
	}
}

// TestQueryFlows_FilterTag_CombinesWithOrigin pins that filter.tag is
// ANDed with the other flows filters.
func TestQueryFlows_FilterTag_CombinesWithOrigin(t *testing.T) {
	store := newTestStore(t)
	seedTaggedStream(t, store, "proxy-tagged", flow.OriginProxy, map[string]string{"tag": "probe-1"})
	seedTaggedStream(t, store, "resend-tagged", flow.OriginResend, map[string]string{"tag": "probe-1"})
	seedTaggedStream(t, store, "resend-other", flow.OriginResend, map[string]string{"tag": "other"})
	cs := setupQueryTestSession(t, store)

	ids, _, total := queryFlowIDs(t, cs, map[string]any{"tag": "probe-1", "origin": "resend"}, 100)
	if strings.Join(ids, ",") != "resend-tagged" {
		t.Errorf("flows(tag=probe-1, origin=resend) ids = %v, want [resend-tagged]", ids)
	}
	if total != 1 {
		t.Errorf("flows(tag=probe-1, origin=resend) total = %d, want 1", total)
	}
}

// TestQueryFlows_FilterTag_TotalUnderLimit pins that total counts every
// tag match, not every stream, when the page is smaller than the match set.
func TestQueryFlows_FilterTag_TotalUnderLimit(t *testing.T) {
	store := newTestStore(t)
	for _, id := range []string{"m1", "m2", "m3"} {
		seedTaggedStream(t, store, id, flow.OriginResend, map[string]string{"tag": "probe-1"})
	}
	for _, id := range []string{"o1", "o2"} {
		seedTaggedStream(t, store, id, flow.OriginResend, map[string]string{"tag": "other"})
	}
	cs := setupQueryTestSession(t, store)

	ids, count, total := queryFlowIDs(t, cs, map[string]any{"tag": "probe-1"}, 1)
	if count != 1 || len(ids) != 1 {
		t.Fatalf("flows(tag=probe-1, limit=1) count=%d ids=%v, want 1 entry", count, ids)
	}
	if !strings.HasPrefix(ids[0], "m") {
		t.Errorf("flows(tag=probe-1, limit=1) returned %s, want one of m1..m3", ids[0])
	}
	if total != 3 {
		t.Errorf("flows(tag=probe-1, limit=1) total = %d, want 3", total)
	}
}

// TestQueryFlows_RejectsFuzzOnlyFilters pins that filter fields which only
// apply to fuzz_results / fuzz_jobs are rejected on resource=flows instead
// of being silently ignored.
func TestQueryFlows_RejectsFuzzOnlyFilters(t *testing.T) {
	store := newTestStore(t)
	seedTaggedStream(t, store, "s1", flow.OriginProxy, nil)
	cs := setupQueryTestSession(t, store)

	for _, tc := range []struct {
		field string
		value any
		hint  string
	}{
		{"body_contains", "secret", "fuzz_results"},
		{"outliers_only", true, "fuzz_results"},
		{"status", "running", "fuzz_jobs"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			res := callQueryRaw(t, cs, map[string]any{
				"resource": "flows",
				"filter":   map[string]any{tc.field: tc.value},
			})
			if !res.IsError {
				t.Fatalf("query flows filter.%s succeeded, want error", tc.field)
			}
			msg := extractTextContent(res)
			if !strings.Contains(msg, tc.field) || !strings.Contains(msg, tc.hint) {
				t.Errorf("error = %q, want it to name %q and %q", msg, tc.field, tc.hint)
			}
		})
	}
}

// TestQueryToolSchema_TagDescribesFlows pins that the tools/list schema
// for filter.tag says it applies to flows, and that the fuzz-only fields
// name the resources they apply to.
func TestQueryToolSchema_TagDescribesFlows(t *testing.T) {
	cs := setupResourceTestSession(t)
	result, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var tool *gomcp.Tool
	for _, tl := range result.Tools {
		if tl.Name == "query" {
			tool = tl
			break
		}
	}
	if tool == nil || tool.InputSchema == nil {
		t.Fatal("query tool (with InputSchema) not found in tools/list")
	}
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("marshal InputSchema: %v", err)
	}
	var schema struct {
		Properties map[string]struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("unmarshal InputSchema: %v", err)
	}
	props := schema.Properties["filter"].Properties
	if _, ok := props["tag"]; !ok {
		t.Fatalf("query filter has no tag property: %s", raw)
	}
	for field, wants := range map[string][]string{
		"tag":           {"flows", "Stream.Tags", "fuzz_jobs", "exact"},
		"body_contains": {"fuzz_results only"},
		"outliers_only": {"fuzz_results only"},
		"status":        {"fuzz_jobs only"},
	} {
		desc := props[field].Description
		for _, w := range wants {
			if !strings.Contains(desc, w) {
				t.Errorf("filter.%s description = %q, want it to mention %q", field, desc, w)
			}
		}
	}
}

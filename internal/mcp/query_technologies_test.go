package mcp

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// seedFlowWithTechnologies creates a flow with technology detection tags.
func seedFlowWithTechnologies(t *testing.T, store flow.Store, id, protocol, method, urlStr string, statusCode int, techJSON string) {
	t.Helper()
	ctx := context.Background()

	tags := map[string]string{}
	if techJSON != "" {
		tags["technologies"] = techJSON
	}

	fl := &flow.Flow{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  protocol,
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  150 * time.Millisecond,
		Tags:      tags,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow(%s): %v", id, err)
	}

	parsedURL, _ := url.Parse(urlStr)

	sendMsg := &flow.Message{
		ID:        id + "-send",
		FlowID:    id,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    method,
		URL:       parsedURL,
		Headers:   map[string][]string{"Host": {parsedURL.Hostname()}},
		Body:      []byte("request body"),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}

	recvMsg := &flow.Message{
		ID:         id + "-recv",
		FlowID:     id,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: statusCode,
		Headers:    map[string][]string{"Content-Type": {"text/html"}},
		Body:       []byte("<html></html>"),
	}
	if err := store.AppendMessage(ctx, recvMsg); err != nil {
		t.Fatalf("AppendMessage(recv): %v", err)
	}
}

func TestQuery_Technologies_Empty(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "technologies"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryTechnologiesResult
	unmarshalQueryResult(t, result, &out)
	if out.Count != 0 {
		t.Errorf("Count = %d, want 0", out.Count)
	}
	if len(out.Hosts) != 0 {
		t.Errorf("len(Hosts) = %d, want 0", len(out.Hosts))
	}
}

func TestQuery_Technologies_SingleHost(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	techJSON := `[{"name":"nginx","version":"1.25","category":"web_server","confidence":"high"},{"name":"PHP","version":"8.2","category":"language","confidence":"medium"}]`
	seedFlowWithTechnologies(t, store, "flow-1", "HTTPS", "GET", "https://example.com/page", 200, techJSON)

	result := callQuery(t, cs, queryInput{Resource: "technologies"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryTechnologiesResult
	unmarshalQueryResult(t, result, &out)
	if out.Count != 1 {
		t.Fatalf("Count = %d, want 1", out.Count)
	}
	if out.Hosts[0].Host != "example.com" {
		t.Errorf("Host = %q, want %q", out.Hosts[0].Host, "example.com")
	}
	if len(out.Hosts[0].Technologies) != 2 {
		t.Fatalf("len(Technologies) = %d, want 2", len(out.Hosts[0].Technologies))
	}

	// Technologies should be sorted by category then name.
	// "language" < "web_server" alphabetically
	if out.Hosts[0].Technologies[0].Name != "PHP" {
		t.Errorf("Technologies[0].Name = %q, want %q", out.Hosts[0].Technologies[0].Name, "PHP")
	}
	if out.Hosts[0].Technologies[1].Name != "nginx" {
		t.Errorf("Technologies[1].Name = %q, want %q", out.Hosts[0].Technologies[1].Name, "nginx")
	}
}

func TestQuery_Technologies_MultipleHosts(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	techJSON1 := `[{"name":"nginx","version":"1.25","category":"web_server","confidence":"high"}]`
	techJSON2 := `[{"name":"Apache","version":"2.4","category":"web_server","confidence":"high"},{"name":"WordPress","version":"6.4","category":"cms","confidence":"high"}]`

	seedFlowWithTechnologies(t, store, "flow-1", "HTTPS", "GET", "https://alpha.com/", 200, techJSON1)
	seedFlowWithTechnologies(t, store, "flow-2", "HTTPS", "GET", "https://beta.com/wp-admin", 200, techJSON2)

	result := callQuery(t, cs, queryInput{Resource: "technologies"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryTechnologiesResult
	unmarshalQueryResult(t, result, &out)
	if out.Count != 2 {
		t.Fatalf("Count = %d, want 2", out.Count)
	}

	// Hosts should be sorted alphabetically.
	if out.Hosts[0].Host != "alpha.com" {
		t.Errorf("Hosts[0].Host = %q, want %q", out.Hosts[0].Host, "alpha.com")
	}
	if out.Hosts[1].Host != "beta.com" {
		t.Errorf("Hosts[1].Host = %q, want %q", out.Hosts[1].Host, "beta.com")
	}
	if len(out.Hosts[1].Technologies) != 2 {
		t.Errorf("len(Hosts[1].Technologies) = %d, want 2", len(out.Hosts[1].Technologies))
	}
}

func TestQuery_Technologies_Dedup(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	// Two flows to the same host with overlapping technologies.
	techJSON1 := `[{"name":"nginx","version":"","category":"web_server","confidence":"high"}]`
	techJSON2 := `[{"name":"nginx","version":"1.25","category":"web_server","confidence":"high"}]`

	seedFlowWithTechnologies(t, store, "flow-1", "HTTPS", "GET", "https://example.com/a", 200, techJSON1)
	seedFlowWithTechnologies(t, store, "flow-2", "HTTPS", "GET", "https://example.com/b", 200, techJSON2)

	result := callQuery(t, cs, queryInput{Resource: "technologies"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryTechnologiesResult
	unmarshalQueryResult(t, result, &out)
	if out.Count != 1 {
		t.Fatalf("Count = %d, want 1", out.Count)
	}
	if len(out.Hosts[0].Technologies) != 1 {
		t.Fatalf("len(Technologies) = %d, want 1 (dedup)", len(out.Hosts[0].Technologies))
	}
	// Should have version from the second flow (dedup prefers version).
	if out.Hosts[0].Technologies[0].Version != "1.25" {
		t.Errorf("Version = %q, want %q", out.Hosts[0].Technologies[0].Version, "1.25")
	}
}

func TestQuery_Flows_TechnologyFilter(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	techJSON := `[{"name":"nginx","version":"1.25","category":"web_server","confidence":"high"}]`
	seedFlowWithTechnologies(t, store, "flow-with-tech", "HTTPS", "GET", "https://example.com/", 200, techJSON)
	seedSession(t, store, "flow-no-tech", "HTTPS", "GET", "https://other.com/", 200)

	// Filter by technology.
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter: &queryFilter{
			Technology: "nginx",
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)
	if out.Count != 1 {
		t.Fatalf("Count = %d, want 1", out.Count)
	}
	if out.Flows[0].ID != "flow-with-tech" {
		t.Errorf("Flow ID = %q, want %q", out.Flows[0].ID, "flow-with-tech")
	}
}

func TestQuery_Flows_TechnologyFilter_CaseInsensitive(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	techJSON := `[{"name":"WordPress","version":"6.4","category":"cms","confidence":"high"}]`
	seedFlowWithTechnologies(t, store, "flow-wp", "HTTPS", "GET", "https://blog.example.com/", 200, techJSON)

	// Filter with different case.
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter: &queryFilter{
			Technology: "wordpress",
		},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)
	if out.Count != 1 {
		t.Fatalf("Count = %d, want 1", out.Count)
	}
}

func TestQuery_Flow_TagsIncludeTechnologies(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	techJSON := `[{"name":"nginx","version":"1.25","category":"web_server","confidence":"high"}]`
	seedFlowWithTechnologies(t, store, "flow-detail", "HTTPS", "GET", "https://example.com/", 200, techJSON)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       "flow-detail",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	techVal, ok := out.Tags["technologies"]
	if !ok {
		t.Fatal("expected 'technologies' key in tags")
	}

	var detections []json.RawMessage
	if err := json.Unmarshal([]byte(techVal), &detections); err != nil {
		t.Fatalf("parse technologies tag: %v", err)
	}
	if len(detections) != 1 {
		t.Errorf("len(detections) = %d, want 1", len(detections))
	}
}

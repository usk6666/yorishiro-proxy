package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// compareCallTool is a helper that calls the resend tool with compare action.
func compareCallTool(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// parseCompareResult unmarshals the compare result from a CallToolResult.
func parseCompareResult(t *testing.T, result *gomcp.CallToolResult) *compareResult {
	t.Helper()
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	textContent := result.Content[0].(*gomcp.TextContent)
	var out compareResult
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal compare result: %v", err)
	}
	return &out
}

func TestCompare_Success_DifferentResponses(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	u, _ := url.Parse("http://example.com/api/test")

	// Flow A: 200 OK with JSON body
	entryA := saveTestEntry(t, store,
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  45 * time.Millisecond,
		},
		&flow.Flow{
			Sequence: 0, Direction: "send", Timestamp: time.Now(),
			Method: "GET", URL: u,
		},
		&flow.Flow{
			Sequence: 1, Direction: "receive", Timestamp: time.Now(),
			StatusCode: 200,
			Headers: map[string][]string{
				"Content-Type": {"application/json"},
				"Set-Cookie":   {"session=abc"},
				"X-Common":     {"value-a"},
			},
			Body: []byte(`{"data":{"id":1},"pagination":{"page":1},"status":"ok"}`),
		},
	)

	// Flow B: 403 Forbidden with JSON body (different keys)
	entryB := saveTestEntry(t, store,
		&flow.Stream{
			Protocol:  "HTTP/1.x",
			Timestamp: time.Now(),
			Duration:  5012 * time.Millisecond,
		},
		&flow.Flow{
			Sequence: 0, Direction: "send", Timestamp: time.Now(),
			Method: "GET", URL: u,
		},
		&flow.Flow{
			Sequence: 1, Direction: "receive", Timestamp: time.Now(),
			StatusCode: 403,
			Headers: map[string][]string{
				"Content-Type": {"application/json"},
				"X-Error-Code": {"FORBIDDEN"},
				"X-Common":     {"value-b"},
			},
			Body: []byte(`{"error":"forbidden","error_code":"FORBIDDEN","status":"error"}`),
		},
	)

	cs := setupTestSession(t, nil, store)

	result := compareCallTool(t, cs, map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": entryA.Session.ID,
			"flow_id_b": entryB.Session.ID,
		},
	})

	out := parseCompareResult(t, result)

	// Status code
	if out.StatusCode == nil {
		t.Fatal("expected status_code to be present")
	}
	if out.StatusCode.A != 200 || out.StatusCode.B != 403 {
		t.Errorf("status_code: got A=%d B=%d, want A=200 B=403", out.StatusCode.A, out.StatusCode.B)
	}
	if !out.StatusCode.Changed {
		t.Error("expected status_code.changed to be true")
	}

	// Body length
	if out.BodyLength == nil {
		t.Fatal("expected body_length to be present")
	}
	if out.BodyLength.A != len(`{"data":{"id":1},"pagination":{"page":1},"status":"ok"}`) {
		t.Errorf("body_length.a: got %d", out.BodyLength.A)
	}

	// Headers added
	if !containsString(out.HeadersAdded, "X-Error-Code") {
		t.Errorf("expected X-Error-Code in headers_added, got %v", out.HeadersAdded)
	}

	// Headers removed
	if !containsString(out.HeadersRemoved, "Set-Cookie") {
		t.Errorf("expected Set-Cookie in headers_removed, got %v", out.HeadersRemoved)
	}

	// Headers changed
	if out.HeadersChanged == nil {
		t.Fatal("expected headers_changed to be present")
	}
	if diff, ok := out.HeadersChanged["X-Common"]; !ok {
		t.Error("expected X-Common in headers_changed")
	} else if diff.A != "value-a" || diff.B != "value-b" {
		t.Errorf("X-Common diff: got A=%q B=%q", diff.A, diff.B)
	}

	// Timing
	if out.TimingMs == nil {
		t.Fatal("expected timing_ms to be present")
	}
	if out.TimingMs.A != 45 || out.TimingMs.B != 5012 {
		t.Errorf("timing_ms: got A=%d B=%d, want A=45 B=5012", out.TimingMs.A, out.TimingMs.B)
	}
	if out.TimingMs.Delta != 4967 {
		t.Errorf("timing_ms.delta: got %d, want 4967", out.TimingMs.Delta)
	}

	// Body diff
	if out.Body == nil {
		t.Fatal("expected body to be present")
	}
	if out.Body.ContentType != "application/json" {
		t.Errorf("body.content_type: got %q, want application/json", out.Body.ContentType)
	}
	if out.Body.Identical {
		t.Error("expected body.identical to be false")
	}

	// JSON diff
	if out.Body.JSONDiff == nil {
		t.Fatal("expected body.json_diff to be present")
	}
	if !containsString(out.Body.JSONDiff.KeysAdded, "error") {
		t.Errorf("expected 'error' in keys_added, got %v", out.Body.JSONDiff.KeysAdded)
	}
	if !containsString(out.Body.JSONDiff.KeysAdded, "error_code") {
		t.Errorf("expected 'error_code' in keys_added, got %v", out.Body.JSONDiff.KeysAdded)
	}
	if !containsString(out.Body.JSONDiff.KeysRemoved, "data") {
		t.Errorf("expected 'data' in keys_removed, got %v", out.Body.JSONDiff.KeysRemoved)
	}
	if !containsString(out.Body.JSONDiff.KeysRemoved, "pagination") {
		t.Errorf("expected 'pagination' in keys_removed, got %v", out.Body.JSONDiff.KeysRemoved)
	}
	if !containsString(out.Body.JSONDiff.KeysChanged, "status") {
		t.Errorf("expected 'status' in keys_changed, got %v", out.Body.JSONDiff.KeysChanged)
	}
}

func TestCompare_Success_IdenticalResponses(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	u, _ := url.Parse("http://example.com/test")

	body := []byte(`{"ok":true}`)
	headers := map[string][]string{"Content-Type": {"application/json"}}

	entryA := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 50 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", Timestamp: time.Now(), StatusCode: 200, Headers: headers, Body: body},
	)
	entryB := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 50 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", Timestamp: time.Now(), StatusCode: 200, Headers: headers, Body: body},
	)

	cs := setupTestSession(t, nil, store)

	result := compareCallTool(t, cs, map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": entryA.Session.ID,
			"flow_id_b": entryB.Session.ID,
		},
	})

	out := parseCompareResult(t, result)

	if out.StatusCode.Changed {
		t.Error("expected status_code.changed to be false for identical responses")
	}
	if out.BodyLength.Delta != 0 {
		t.Errorf("expected body_length.delta to be 0, got %d", out.BodyLength.Delta)
	}
	if !out.Body.Identical {
		t.Error("expected body.identical to be true")
	}
	if out.Body.JSONDiff != nil {
		t.Error("expected body.json_diff to be nil for identical JSON")
	}
	if len(out.HeadersAdded) != 0 {
		t.Errorf("expected no headers_added, got %v", out.HeadersAdded)
	}
	if len(out.HeadersRemoved) != 0 {
		t.Errorf("expected no headers_removed, got %v", out.HeadersRemoved)
	}
	if out.HeadersChanged != nil {
		t.Errorf("expected no headers_changed, got %v", out.HeadersChanged)
	}
}

func TestCompare_HTMLResponse_NoJSONDiff(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	u, _ := url.Parse("http://example.com/page")

	entryA := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTPS", Timestamp: time.Now(), Duration: 100 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{
			Sequence: 1, Direction: "receive", Timestamp: time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/html"}},
			Body:       []byte("<html><body>Hello</body></html>"),
		},
	)
	entryB := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTPS", Timestamp: time.Now(), Duration: 200 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{
			Sequence: 1, Direction: "receive", Timestamp: time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/html"}},
			Body:       []byte("<html><body>World</body></html>"),
		},
	)

	cs := setupTestSession(t, nil, store)

	result := compareCallTool(t, cs, map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": entryA.Session.ID,
			"flow_id_b": entryB.Session.ID,
		},
	})

	out := parseCompareResult(t, result)

	if out.Body.ContentType != "text/html" {
		t.Errorf("expected content_type text/html, got %q", out.Body.ContentType)
	}
	if out.Body.Identical {
		t.Error("expected body.identical to be false")
	}
	if out.Body.JSONDiff != nil {
		t.Error("expected no json_diff for HTML content")
	}
}

func TestCompare_MissingFlowID(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupTestSession(t, nil, store)

	tests := []struct {
		name   string
		params map[string]any
	}{
		{
			name:   "missing flow_id_a",
			params: map[string]any{"flow_id_b": "some-id"},
		},
		{
			name:   "missing flow_id_b",
			params: map[string]any{"flow_id_a": "some-id"},
		},
		{
			name:   "missing both",
			params: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareCallTool(t, cs, map[string]any{
				"action": "compare",
				"params": tt.params,
			})
			if !result.IsError {
				t.Error("expected error for missing flow ID")
			}
		})
	}
}

func TestCompare_NonexistentFlow(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	u, _ := url.Parse("http://example.com/test")

	entry := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 50 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", Timestamp: time.Now(), StatusCode: 200, Body: []byte("ok")},
	)

	cs := setupTestSession(t, nil, store)

	tests := []struct {
		name    string
		flowIDA string
		flowIDB string
	}{
		{
			name:    "flow A does not exist",
			flowIDA: "nonexistent-id",
			flowIDB: entry.Session.ID,
		},
		{
			name:    "flow B does not exist",
			flowIDA: entry.Session.ID,
			flowIDB: "nonexistent-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareCallTool(t, cs, map[string]any{
				"action": "compare",
				"params": map[string]any{
					"flow_id_a": tt.flowIDA,
					"flow_id_b": tt.flowIDB,
				},
			})
			if !result.IsError {
				t.Error("expected error for nonexistent flow")
			}
		})
	}
}

func TestCompare_FlowWithNoReceiveMessage(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	u, _ := url.Parse("http://example.com/test")

	// Flow with only a send message (no receive)
	entryNoRecv := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 50 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		nil, // no receive message
	)

	entryNormal := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 50 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", Timestamp: time.Now(), StatusCode: 200, Body: []byte("ok")},
	)

	cs := setupTestSession(t, nil, store)

	result := compareCallTool(t, cs, map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": entryNoRecv.Session.ID,
			"flow_id_b": entryNormal.Session.ID,
		},
	})
	if !result.IsError {
		t.Error("expected error when flow has no receive messages")
	}
}

func TestCompare_NilStore(t *testing.T) {
	t.Parallel()
	// Create a session without a store.
	cs := setupTestSession(t, nil)

	result := compareCallTool(t, cs, map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": "a",
			"flow_id_b": "b",
		},
	})
	if !result.IsError {
		t.Error("expected error when store is nil")
	}
}

func TestCompare_EmptyBodies(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	u, _ := url.Parse("http://example.com/empty")

	entryA := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 10 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", Timestamp: time.Now(), StatusCode: 204, Body: nil},
	)
	entryB := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 10 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{Sequence: 1, Direction: "receive", Timestamp: time.Now(), StatusCode: 204, Body: nil},
	)

	cs := setupTestSession(t, nil, store)

	result := compareCallTool(t, cs, map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": entryA.Session.ID,
			"flow_id_b": entryB.Session.ID,
		},
	})

	out := parseCompareResult(t, result)

	if out.BodyLength.A != 0 || out.BodyLength.B != 0 {
		t.Errorf("expected body lengths to be 0, got A=%d B=%d", out.BodyLength.A, out.BodyLength.B)
	}
	if !out.Body.Identical {
		t.Error("expected identical bodies for two nil bodies")
	}
}

func TestCompare_JSONWithCharsetContentType(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	u, _ := url.Parse("http://example.com/api")

	entryA := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 10 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{
			Sequence: 1, Direction: "receive", Timestamp: time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/json; charset=utf-8"}},
			Body:       []byte(`{"a":1}`),
		},
	)
	entryB := saveTestEntry(t, store,
		&flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now(), Duration: 10 * time.Millisecond},
		&flow.Flow{Sequence: 0, Direction: "send", Timestamp: time.Now(), Method: "GET", URL: u},
		&flow.Flow{
			Sequence: 1, Direction: "receive", Timestamp: time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/json; charset=utf-8"}},
			Body:       []byte(`{"b":2}`),
		},
	)

	cs := setupTestSession(t, nil, store)

	result := compareCallTool(t, cs, map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": entryA.Session.ID,
			"flow_id_b": entryB.Session.ID,
		},
	})

	out := parseCompareResult(t, result)

	// The content type with charset should still trigger JSON diff.
	if out.Body.JSONDiff == nil {
		t.Error("expected json_diff for application/json; charset=utf-8")
	}
}

// --- Unit tests for internal functions ---

func TestIsJSONContentType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"text/json", true},
		{"application/vnd.api+json", true},
		{"application/hal+json", true},
		{"application/vnd.api+json; charset=utf-8", true},
		{"text/html", false},
		{"text/plain", false},
		{"application/xml", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			if got := isJSONContentType(tt.ct); got != tt.want {
				t.Errorf("isJSONContentType(%q) = %v, want %v", tt.ct, got, tt.want)
			}
		})
	}
}

func TestFlattenJSONKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "simple object",
			body: `{"a":1,"b":"two","c":null}`,
			want: []string{"a", "b", "c"},
		},
		{
			name: "empty object",
			body: `{}`,
			want: []string{},
		},
		{
			name: "not an object (array)",
			body: `[1,2,3]`,
			want: nil,
		},
		{
			name: "invalid json",
			body: `not json`,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flattenJSONKeys([]byte(tt.body))
			if tt.want == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
				return
			}
			for i, key := range got {
				if key != tt.want[i] {
					t.Errorf("key[%d] = %q, want %q", i, key, tt.want[i])
				}
			}
		})
	}
}

func TestCompareHeaders(t *testing.T) {
	t.Parallel()
	a := map[string][]string{
		"Content-Type": {"text/html"},
		"Set-Cookie":   {"session=abc"},
		"X-Common":     {"old"},
	}
	b := map[string][]string{
		"Content-Type": {"text/html"},
		"X-Error-Code": {"403"},
		"X-Common":     {"new"},
	}

	added, removed, changed := compareHeaders(a, b)

	if !containsString(added, "X-Error-Code") {
		t.Errorf("expected X-Error-Code in added, got %v", added)
	}
	if !containsString(removed, "Set-Cookie") {
		t.Errorf("expected Set-Cookie in removed, got %v", removed)
	}
	if diff, ok := changed["X-Common"]; !ok {
		t.Error("expected X-Common in changed")
	} else if diff.A != "old" || diff.B != "new" {
		t.Errorf("X-Common diff: got A=%q B=%q", diff.A, diff.B)
	}
	if _, ok := changed["Content-Type"]; ok {
		t.Error("Content-Type should not be in changed (identical)")
	}
}

func TestComputeJSONKeyDiff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		bodyA       string
		bodyB       string
		wantAdded   []string
		wantRemoved []string
		wantChanged []string
		wantNil     bool
	}{
		{
			name:        "keys added and removed",
			bodyA:       `{"data":1,"pagination":2,"status":"ok"}`,
			bodyB:       `{"error":"no","error_code":403,"status":"error"}`,
			wantAdded:   []string{"error", "error_code"},
			wantRemoved: []string{"data", "pagination"},
			wantChanged: []string{"status"},
		},
		{
			name:    "identical objects",
			bodyA:   `{"a":1}`,
			bodyB:   `{"a":1}`,
			wantNil: true,
		},
		{
			name:    "invalid json A",
			bodyA:   `not json`,
			bodyB:   `{"a":1}`,
			wantNil: true,
		},
		{
			name:    "invalid json B",
			bodyA:   `{"a":1}`,
			bodyB:   `not json`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeJSONKeyDiff([]byte(tt.bodyA), []byte(tt.bodyB))
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil json_diff")
			}
			if !stringSliceEqual(got.KeysAdded, tt.wantAdded) {
				t.Errorf("keys_added: got %v, want %v", got.KeysAdded, tt.wantAdded)
			}
			if !stringSliceEqual(got.KeysRemoved, tt.wantRemoved) {
				t.Errorf("keys_removed: got %v, want %v", got.KeysRemoved, tt.wantRemoved)
			}
			if !stringSliceEqual(got.KeysChanged, tt.wantChanged) {
				t.Errorf("keys_changed: got %v, want %v", got.KeysChanged, tt.wantChanged)
			}
		})
	}
}

func TestBytesEqual(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []byte{}, []byte{}, true},
		{"nil vs empty", nil, []byte{}, true},
		{"equal", []byte("hello"), []byte("hello"), true},
		{"different length", []byte("hi"), []byte("hello"), false},
		{"same length different", []byte("aaa"), []byte("aab"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bytes.Equal(tt.a, tt.b); got != tt.want {
				t.Errorf("bytes.Equal(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// containsString checks if a string slice contains a given string.
func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// stringSliceEqual checks if two sorted string slices are equal.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

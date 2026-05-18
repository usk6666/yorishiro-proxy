// Package mcp query_wire_level_advisory_test.go — coverage for the
// USK-931 wire_level_advisory hint emitted on query responses when the
// default semantic wire_level filter (USK-921) hid overlay rows.
//
// The advisory is informational only — the wire copy of the overlay
// rows is unchanged on disk and re-fetchable via
// filter.wire_level=all (or any specific overlay value). These tests
// cover:
//
//   - the buildWireLevelAdvisory helper (pure unit shape)
//   - integration round-trip through the MCP transport for all three
//     query handlers (query flow, query flows, query messages)
//   - the gate on filter.wire_level (advisory absent when the caller
//     opted in to overlays)
package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestBuildWireLevelAdvisory exercises the pure-helper shape: emit
// gates, zero-entry pruning, and the constant Hint/Filter values.
func TestBuildWireLevelAdvisory(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		filter      *queryFilter
		hidden      map[string]int
		wantNil     bool
		wantHidden  map[string]int
		wantFilter  string
		wantHintHas string
	}{
		{
			name:    "nil_filter_no_overlay_rows",
			filter:  nil,
			hidden:  nil,
			wantNil: true,
		},
		{
			name:    "nil_filter_empty_hidden_map",
			filter:  nil,
			hidden:  map[string]int{},
			wantNil: true,
		},
		{
			name:    "nil_filter_with_h2frame_overlays",
			filter:  nil,
			hidden:  map[string]int{flow.WireLevelH2Frame: 3},
			wantNil: false,
			wantHidden: map[string]int{
				flow.WireLevelH2Frame: 3,
			},
			wantFilter:  wireLevelAdvisoryDefaultLabel,
			wantHintHas: "wire_level",
		},
		{
			name:    "nil_filter_multi_overlay",
			filter:  nil,
			hidden:  map[string]int{flow.WireLevelH2Frame: 3, flow.WireLevelGRPCLPMFrame: 7},
			wantNil: false,
			wantHidden: map[string]int{
				flow.WireLevelH2Frame:      3,
				flow.WireLevelGRPCLPMFrame: 7,
			},
			wantFilter: wireLevelAdvisoryDefaultLabel,
		},
		{
			name:    "zero_entries_pruned",
			filter:  nil,
			hidden:  map[string]int{flow.WireLevelH2Frame: 0, flow.WireLevelGRPCLPMFrame: 4},
			wantNil: false,
			wantHidden: map[string]int{
				flow.WireLevelGRPCLPMFrame: 4,
			},
		},
		{
			name:    "all_zero_entries_pruned_to_nil",
			filter:  nil,
			hidden:  map[string]int{flow.WireLevelH2Frame: 0},
			wantNil: true,
		},
		{
			name:    "explicit_opt_in_suppresses_advisory_even_with_hidden_rows",
			filter:  &queryFilter{WireLevel: "all"},
			hidden:  map[string]int{flow.WireLevelH2Frame: 3},
			wantNil: true,
		},
		{
			name:    "explicit_overlay_opt_in_suppresses_advisory",
			filter:  &queryFilter{WireLevel: flow.WireLevelH2Frame},
			hidden:  map[string]int{flow.WireLevelGRPCLPMFrame: 2},
			wantNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildWireLevelAdvisory(tc.filter, tc.hidden)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("buildWireLevelAdvisory returned %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("buildWireLevelAdvisory returned nil, want non-nil")
			}
			if got.Filter != tc.wantFilter && tc.wantFilter != "" {
				t.Errorf("Filter = %q, want %q", got.Filter, tc.wantFilter)
			}
			if len(got.Hidden) != len(tc.wantHidden) {
				t.Errorf("Hidden = %+v, want %+v", got.Hidden, tc.wantHidden)
			}
			for k, want := range tc.wantHidden {
				if got.Hidden[k] != want {
					t.Errorf("Hidden[%q] = %d, want %d", k, got.Hidden[k], want)
				}
			}
			if got.Hint == "" {
				t.Errorf("Hint is empty")
			}
		})
	}
}

// saveOverlayStream stores a Stream with one semantic Send envelope, one
// semantic Receive envelope, and two overlay rows (h2-frame + lpm).
// Mirrors makeMixedWireLevelSession but lives here so tests stay
// independent of the manage-export test fixtures.
func saveOverlayStream(t *testing.T, store flow.Store, id, protocol string) {
	t.Helper()
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  protocol,
		State:     "complete",
		Timestamp: ts,
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	rows := []*flow.Flow{
		{
			ID: "msg-sem-send-" + id, StreamID: id, Sequence: 0, Direction: "send",
			Timestamp: ts, Method: "POST", WireLevel: flow.WireLevelSemantic,
		},
		{
			ID: "msg-h2f-send-" + id, StreamID: id, Sequence: 1, Direction: "send",
			Timestamp: ts, WireLevel: flow.WireLevelH2Frame, RawBytes: []byte("h2f"),
		},
		{
			ID: "msg-lpm-send-" + id, StreamID: id, Sequence: 2, Direction: "send",
			Timestamp: ts, WireLevel: flow.WireLevelGRPCLPMFrame, RawBytes: []byte("lpm"),
		},
		{
			ID: "msg-sem-recv-" + id, StreamID: id, Sequence: 3, Direction: "receive",
			Timestamp: ts, WireLevel: flow.WireLevelSemantic,
		},
	}
	for _, r := range rows {
		if err := store.SaveFlow(ctx, r); err != nil {
			t.Fatalf("SaveFlow %s: %v", r.ID, err)
		}
	}
}

// saveSemanticOnlyStream stores a Stream with only semantic envelopes
// (no overlays) — used to verify the advisory is absent on default
// queries when no overlay rows exist.
func saveSemanticOnlyStream(t *testing.T, store flow.Store, id string) {
	t.Helper()
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "http",
		State:     "complete",
		Timestamp: ts,
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	rows := []*flow.Flow{
		{
			ID: "msg-send-" + id, StreamID: id, Sequence: 0, Direction: "send",
			Timestamp: ts, Method: "GET", WireLevel: flow.WireLevelSemantic,
		},
		{
			ID: "msg-recv-" + id, StreamID: id, Sequence: 1, Direction: "receive",
			Timestamp: ts, StatusCode: 200, WireLevel: flow.WireLevelSemantic,
		},
	}
	for _, r := range rows {
		if err := store.SaveFlow(ctx, r); err != nil {
			t.Fatalf("SaveFlow %s: %v", r.ID, err)
		}
	}
}

// queryCallTool wraps the MCP query tool call so tests can assert the
// JSON-encoded transport payload shape — confirming the advisory
// survives the MCP boundary serialization (the design review's
// JSON-RPC round-trip check).
func queryCallTool(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(query): %v", err)
	}
	return result
}

func TestQueryWireLevelAdvisory_QueryFlow_DefaultShowsAdvisory(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	saveOverlayStream(t, store, "stream-qf-default", "grpc")

	result := queryCallTool(t, cs, map[string]any{
		"resource": "flow",
		"id":       "stream-qf-default",
	})
	if result.IsError {
		t.Fatalf("query flow returned error: %v", result.Content)
	}
	text := extractTextContent(result)
	var qr queryFlowResult
	if err := json.Unmarshal([]byte(text), &qr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if qr.WireLevelAdvisory == nil {
		t.Fatalf("expected WireLevelAdvisory, got nil; payload=%s", text)
	}
	if got := qr.WireLevelAdvisory.Hidden[flow.WireLevelH2Frame]; got != 1 {
		t.Errorf("Hidden[h2-frame] = %d, want 1", got)
	}
	if got := qr.WireLevelAdvisory.Hidden[flow.WireLevelGRPCLPMFrame]; got != 1 {
		t.Errorf("Hidden[grpc-lpm-frame] = %d, want 1", got)
	}
	// Confirm the on-wire JSON field name matches the schema contract
	// — load-bearing for AI agent consumers.
	if !jsonHasField(text, "wire_level_advisory") {
		t.Errorf("JSON missing wire_level_advisory field; payload=%s", text)
	}
	if !jsonHasField(text, "hidden_overlay_rows") {
		t.Errorf("JSON missing hidden_overlay_rows field; payload=%s", text)
	}
}

func TestQueryWireLevelAdvisory_QueryFlow_NoOverlayRowsAbsentAdvisory(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	saveSemanticOnlyStream(t, store, "stream-qf-semonly")

	result := queryCallTool(t, cs, map[string]any{
		"resource": "flow",
		"id":       "stream-qf-semonly",
	})
	text := extractTextContent(result)
	var qr queryFlowResult
	if err := json.Unmarshal([]byte(text), &qr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if qr.WireLevelAdvisory != nil {
		t.Errorf("expected nil WireLevelAdvisory on semantic-only stream, got %+v", qr.WireLevelAdvisory)
	}
	if jsonHasField(text, "wire_level_advisory") {
		t.Errorf("expected omitempty to drop wire_level_advisory from JSON; payload=%s", text)
	}
}

func TestQueryWireLevelAdvisory_QueryFlow_ExplicitOptInSuppresses(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	saveOverlayStream(t, store, "stream-qf-explicit", "grpc")

	for _, wl := range []string{"all", flow.WireLevelH2Frame, flow.WireLevelGRPCLPMFrame} {
		t.Run("wire_level="+wl, func(t *testing.T) {
			result := queryCallTool(t, cs, map[string]any{
				"resource": "flow",
				"id":       "stream-qf-explicit",
				"filter":   map[string]any{"wire_level": wl},
			})
			text := extractTextContent(result)
			var qr queryFlowResult
			if err := json.Unmarshal([]byte(text), &qr); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if qr.WireLevelAdvisory != nil {
				t.Errorf("expected nil advisory on explicit wire_level=%s, got %+v", wl, qr.WireLevelAdvisory)
			}
		})
	}
}

func TestQueryWireLevelAdvisory_QueryFlows_AggregatesAcrossStreams(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	saveOverlayStream(t, store, "stream-qfs-1", "grpc")
	saveOverlayStream(t, store, "stream-qfs-2", "grpc")
	saveSemanticOnlyStream(t, store, "stream-qfs-3")

	result := queryCallTool(t, cs, map[string]any{
		"resource": "flows",
	})
	text := extractTextContent(result)
	var qr queryFlowsResult
	if err := json.Unmarshal([]byte(text), &qr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if qr.WireLevelAdvisory == nil {
		t.Fatalf("expected WireLevelAdvisory, got nil; payload=%s", text)
	}
	// Two overlay streams * (1 h2-frame + 1 grpc-lpm-frame) = 2 each.
	if got := qr.WireLevelAdvisory.Hidden[flow.WireLevelH2Frame]; got != 2 {
		t.Errorf("aggregated Hidden[h2-frame] = %d, want 2", got)
	}
	if got := qr.WireLevelAdvisory.Hidden[flow.WireLevelGRPCLPMFrame]; got != 2 {
		t.Errorf("aggregated Hidden[grpc-lpm-frame] = %d, want 2", got)
	}
}

func TestQueryWireLevelAdvisory_QueryMessages_DefaultShowsAdvisory(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	saveOverlayStream(t, store, "stream-qm-default", "grpc")

	result := queryCallTool(t, cs, map[string]any{
		"resource": "messages",
		"id":       "stream-qm-default",
	})
	text := extractTextContent(result)
	var qr queryMessagesResult
	if err := json.Unmarshal([]byte(text), &qr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if qr.WireLevelAdvisory == nil {
		t.Fatalf("expected WireLevelAdvisory, got nil; payload=%s", text)
	}
	if got := qr.WireLevelAdvisory.Hidden[flow.WireLevelH2Frame]; got != 1 {
		t.Errorf("Hidden[h2-frame] = %d, want 1", got)
	}
}

func TestQueryWireLevelAdvisory_QueryMessages_ExplicitOptInSuppresses(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	saveOverlayStream(t, store, "stream-qm-explicit", "grpc")

	result := queryCallTool(t, cs, map[string]any{
		"resource": "messages",
		"id":       "stream-qm-explicit",
		"filter":   map[string]any{"wire_level": "all"},
	})
	text := extractTextContent(result)
	var qr queryMessagesResult
	if err := json.Unmarshal([]byte(text), &qr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if qr.WireLevelAdvisory != nil {
		t.Errorf("expected nil advisory on explicit opt-in, got %+v", qr.WireLevelAdvisory)
	}
}

// jsonHasField is a coarse JSON-string field probe — sufficient for
// asserting the on-wire schema contract on small fixtures. Uses a
// substring match rather than a full unmarshal so we exercise the raw
// serialized payload (catches omitempty mistakes and field renames).
func jsonHasField(payload, field string) bool {
	needle := "\"" + field + "\""
	for i := 0; i+len(needle) <= len(payload); i++ {
		if payload[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

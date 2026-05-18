package mcp

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// seedFlowWithMixedWireLevels creates a Stream and Flows mixing semantic
// and wire-level overlay rows (h2-frame, grpc-lpm-frame) under the same
// (stream_id, sequence, direction, variant) so the schemaV14 UNIQUE
// constraint accepts them. Mirrors the live recording shape of a
// tcp_forwards gRPC unary RPC where every semantic GRPCStart/Data/End
// envelope is shadowed by overlay rows produced by
// session.GRPCH2DataFrameRecordOption + session.GRPCLPMRecordOption.
//
// Returns the stream ID and the expected (semantic count, h2-frame count,
// grpc-lpm-frame count) tuple so the test can pivot on each axis.
func seedFlowWithMixedWireLevels(t *testing.T, store flow.Store, id string) (string, int, int, int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "grpc",
		Scheme:    "http",
		State:     "complete",
		Timestamp: now,
		Duration:  150 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	parsedURL, _ := url.Parse("http://example.com/svc.Echo/Unary")

	// Five canonical L7 semantic rows: Send Start + Send Data + Recv Start
	// + Recv Data + Recv End. This is the user-observed "5 messages" count
	// from the USK-921 repro.
	semantic := []*flow.Flow{
		{
			ID: id + "-send-start", StreamID: id, Sequence: 0, Direction: "send",
			Timestamp: now, Method: "POST", URL: parsedURL,
			Headers:   map[string][]string{":path": {"/svc.Echo/Unary"}},
			Metadata:  map[string]string{"grpc_event": "start"},
			WireLevel: flow.WireLevelSemantic,
		},
		{
			ID: id + "-send-data", StreamID: id, Sequence: 1, Direction: "send",
			Timestamp: now,
			Body:      []byte("send-payload"),
			Metadata:  map[string]string{"grpc_event": "data"},
			WireLevel: flow.WireLevelSemantic,
		},
		{
			ID: id + "-recv-start", StreamID: id, Sequence: 0, Direction: "receive",
			Timestamp: now, StatusCode: 200,
			Headers:   map[string][]string{":status": {"200"}},
			Metadata:  map[string]string{"grpc_event": "start"},
			WireLevel: flow.WireLevelSemantic,
		},
		{
			ID: id + "-recv-data", StreamID: id, Sequence: 1, Direction: "receive",
			Timestamp: now,
			Body:      []byte("recv-payload"),
			Metadata:  map[string]string{"grpc_event": "data"},
			WireLevel: flow.WireLevelSemantic,
		},
		{
			ID: id + "-recv-end", StreamID: id, Sequence: 2, Direction: "receive",
			Timestamp: now,
			Metadata:  map[string]string{"grpc_event": "end"},
			WireLevel: flow.WireLevelSemantic,
		},
	}

	// Two h2-frame overlay rows: one per Data envelope, sharing the same
	// (sequence, direction) as the semantic Data envelope. The widened
	// UNIQUE on (stream_id, sequence, direction, variant, wire_level)
	// accepts the coexistence.
	h2Frames := []*flow.Flow{
		{
			ID: id + "-send-data-h2", StreamID: id, Sequence: 1, Direction: "send",
			Timestamp: now,
			RawBytes:  []byte("h2-frame-bytes-send"),
			WireLevel: flow.WireLevelH2Frame,
		},
		{
			ID: id + "-recv-data-h2", StreamID: id, Sequence: 1, Direction: "receive",
			Timestamp: now,
			RawBytes:  []byte("h2-frame-bytes-recv"),
			WireLevel: flow.WireLevelH2Frame,
		},
	}

	// Two grpc-lpm-frame overlay rows: same coexistence rules.
	lpmFrames := []*flow.Flow{
		{
			ID: id + "-send-data-lpm", StreamID: id, Sequence: 1, Direction: "send",
			Timestamp: now,
			RawBytes:  []byte("lpm-bytes-send"),
			WireLevel: flow.WireLevelGRPCLPMFrame,
		},
		{
			ID: id + "-recv-data-lpm", StreamID: id, Sequence: 1, Direction: "receive",
			Timestamp: now,
			RawBytes:  []byte("lpm-bytes-recv"),
			WireLevel: flow.WireLevelGRPCLPMFrame,
		},
	}

	for _, f := range semantic {
		if err := store.SaveFlow(ctx, f); err != nil {
			t.Fatalf("SaveFlow(semantic %s): %v", f.ID, err)
		}
	}
	for _, f := range h2Frames {
		if err := store.SaveFlow(ctx, f); err != nil {
			t.Fatalf("SaveFlow(h2-frame %s): %v", f.ID, err)
		}
	}
	for _, f := range lpmFrames {
		if err := store.SaveFlow(ctx, f); err != nil {
			t.Fatalf("SaveFlow(lpm-frame %s): %v", f.ID, err)
		}
	}

	return id, len(semantic), len(h2Frames), len(lpmFrames)
}

// TestQuery_Messages_DefaultWireLevelHidesOverlays asserts that the
// USK-921 fix excludes wire-level overlay rows (h2-frame, grpc-lpm-frame)
// from the messages response by default. Without the fix the user-
// observed "9 messages" inflation reappears.
func TestQuery_Messages_DefaultWireLevelHidesOverlays(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	id, semCount, h2Count, lpmCount := seedFlowWithMixedWireLevels(t, store, "wl-default")
	totalRows := semCount + h2Count + lpmCount

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "messages", ID: id})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != semCount {
		t.Errorf("count = %d, want %d (only semantic envelopes)", out.Count, semCount)
	}
	if out.Total != semCount {
		t.Errorf("total = %d, want %d (only semantic envelopes)", out.Total, semCount)
	}
	if got := len(out.Messages); got != semCount {
		t.Errorf("messages len = %d, want %d", got, semCount)
	}
	for _, m := range out.Messages {
		if m.WireLevel != "" {
			t.Errorf("entry %s wire_level = %q, want empty (semantic-only response)", m.ID, m.WireLevel)
		}
	}

	// Sanity belt — the DB does carry the overlay rows; only the MCP
	// projection hides them. Confirms the test fixture has the expected
	// total before the filter is applied.
	all, err := store.GetFlows(context.Background(), id, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows(no filter): %v", err)
	}
	if len(all) != totalRows {
		t.Errorf("DB row count = %d, want %d (semantic+h2+lpm)", len(all), totalRows)
	}
}

// TestQuery_Messages_ExplicitWireLevelOverlay asserts that opting in to a
// single overlay (filter.wire_level=h2-frame) returns only those rows and
// surfaces the discriminator on each entry.
func TestQuery_Messages_ExplicitWireLevelOverlay(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	id, _, h2Count, _ := seedFlowWithMixedWireLevels(t, store, "wl-h2")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       id,
		Filter:   &queryFilter{WireLevel: flow.WireLevelH2Frame},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != h2Count {
		t.Errorf("count = %d, want %d (h2-frame only)", out.Count, h2Count)
	}
	for _, m := range out.Messages {
		if m.WireLevel != flow.WireLevelH2Frame {
			t.Errorf("entry %s wire_level = %q, want %q", m.ID, m.WireLevel, flow.WireLevelH2Frame)
		}
	}
}

// TestQuery_Messages_WireLevelAllReturnsEverything asserts the "all"
// opt-out surfaces every wire_level (semantic + overlays).
func TestQuery_Messages_WireLevelAllReturnsEverything(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	id, semCount, h2Count, lpmCount := seedFlowWithMixedWireLevels(t, store, "wl-all")
	totalRows := semCount + h2Count + lpmCount

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       id,
		Filter:   &queryFilter{WireLevel: "all"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryMessagesResult
	unmarshalQueryResult(t, result, &out)

	if out.Count != totalRows {
		t.Errorf("count = %d, want %d (every wire_level)", out.Count, totalRows)
	}
	// Spot-check that at least one of each discriminator shows up.
	var sawSemantic, sawH2, sawLPM bool
	for _, m := range out.Messages {
		switch m.WireLevel {
		case "":
			sawSemantic = true // semantic rows hide the discriminator via omitempty
		case flow.WireLevelH2Frame:
			sawH2 = true
		case flow.WireLevelGRPCLPMFrame:
			sawLPM = true
		}
	}
	if !sawSemantic || !sawH2 || !sawLPM {
		t.Errorf("wire_level mix = (sem=%v h2=%v lpm=%v), want all three", sawSemantic, sawH2, sawLPM)
	}
}

// TestQuery_Messages_WireLevelInvalid asserts that an unknown wire_level
// value surfaces a structured error listing the canonical enum members,
// matching the validateEnum contract every other filter axis uses.
func TestQuery_Messages_WireLevelInvalid(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedFlowWithMixedWireLevels(t, store, "wl-invalid")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "messages",
		ID:       "wl-invalid",
		Filter:   &queryFilter{WireLevel: "bogus"},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for invalid wire_level value")
	}
	text := extractTextContent(result)
	if !strings.Contains(text, `invalid wire_level "bogus"`) {
		t.Errorf("error message %q should mention invalid wire_level", text)
	}
	// Spot-check the canonical enum members surface so the AI agent
	// sees a usable remediation hint.
	for _, want := range []string{"semantic", "h2-frame", "grpc-lpm-frame", "all"} {
		if !strings.Contains(text, want) {
			t.Errorf("error message %q should list canonical value %q", text, want)
		}
	}
}

// TestQuery_Flow_DefaultWireLevelHidesOverlays asserts the flow resource
// (single-flow detail) reports MessageCount over the semantic-only
// projection by default — the same defect path the user hit when running
// `query flow` on the tcp_forwards gRPC stream.
func TestQuery_Flow_DefaultWireLevelHidesOverlays(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	id, semCount, _, _ := seedFlowWithMixedWireLevels(t, store, "wl-flow")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flow", ID: id})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	if out.MessageCount != semCount {
		t.Errorf("message_count = %d, want %d (semantic only)", out.MessageCount, semCount)
	}
	// MessagePreview only fires for streaming flows (more than 2
	// messages). With semCount=5 it should populate; assert each entry
	// has no overlay discriminator.
	if len(out.MessagePreview) == 0 {
		t.Fatalf("message_preview empty; expected populated for %d-message streaming flow", semCount)
	}
	for _, m := range out.MessagePreview {
		if m.WireLevel != "" {
			t.Errorf("preview entry %s wire_level = %q, want empty (semantic-only)", m.ID, m.WireLevel)
		}
	}
}

// TestQuery_Flow_WireLevelAllInflatesCount asserts that opting in to
// "all" re-includes the overlay rows in MessageCount + MessagePreview,
// proving the filter is wired into both projections.
func TestQuery_Flow_WireLevelAllInflatesCount(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	id, semCount, h2Count, lpmCount := seedFlowWithMixedWireLevels(t, store, "wl-flow-all")
	totalRows := semCount + h2Count + lpmCount

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flow",
		ID:       id,
		Filter:   &queryFilter{WireLevel: "all"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowResult
	unmarshalQueryResult(t, result, &out)

	if out.MessageCount != totalRows {
		t.Errorf("message_count = %d, want %d (every wire_level)", out.MessageCount, totalRows)
	}
}

// TestQuery_Flows_DefaultWireLevelHidesOverlays asserts the flows
// (paginated list) resource computes per-flow MessageCount from semantic
// rows only by default, mirroring the messages / flow handlers.
func TestQuery_Flows_DefaultWireLevelHidesOverlays(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	id, semCount, _, _ := seedFlowWithMixedWireLevels(t, store, "wl-flows")

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{Resource: "flows"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	var found *queryFlowsEntry
	for i := range out.Flows {
		if out.Flows[i].ID == id {
			found = &out.Flows[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("seeded flow %s missing from flows list (got %d entries)", id, len(out.Flows))
	}
	if found.MessageCount != semCount {
		t.Errorf("message_count = %d, want %d (semantic only)", found.MessageCount, semCount)
	}
}

// TestQuery_Flows_WireLevelAllInflatesCount asserts the flows resource
// honours filter.wire_level=all and re-includes the overlay rows in the
// per-flow MessageCount aggregate.
func TestQuery_Flows_WireLevelAllInflatesCount(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	id, semCount, h2Count, lpmCount := seedFlowWithMixedWireLevels(t, store, "wl-flows-all")
	totalRows := semCount + h2Count + lpmCount

	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{WireLevel: "all"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}
	var out queryFlowsResult
	unmarshalQueryResult(t, result, &out)

	var found *queryFlowsEntry
	for i := range out.Flows {
		if out.Flows[i].ID == id {
			found = &out.Flows[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("seeded flow %s missing from flows list", id)
	}
	if found.MessageCount != totalRows {
		t.Errorf("message_count = %d, want %d (every wire_level)", found.MessageCount, totalRows)
	}
}

// TestResolveWireLevelFilter covers the helper unit-level: empty / unset
// → semantic default, "all" → empty (no predicate), valid overlay →
// pass-through, invalid → enum error.
func TestResolveWireLevelFilter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		filter  *queryFilter
		want    string
		wantErr bool
	}{
		{"nil filter defaults to semantic", nil, flow.WireLevelSemantic, false},
		{"empty value defaults to semantic", &queryFilter{}, flow.WireLevelSemantic, false},
		{"explicit semantic passes through", &queryFilter{WireLevel: flow.WireLevelSemantic}, flow.WireLevelSemantic, false},
		{"h2-frame passes through", &queryFilter{WireLevel: flow.WireLevelH2Frame}, flow.WireLevelH2Frame, false},
		{"h1-chunk passes through", &queryFilter{WireLevel: flow.WireLevelHTTP1Chunk}, flow.WireLevelHTTP1Chunk, false},
		{"grpc-lpm-frame passes through", &queryFilter{WireLevel: flow.WireLevelGRPCLPMFrame}, flow.WireLevelGRPCLPMFrame, false},
		{"grpcweb-base64 passes through", &queryFilter{WireLevel: flow.WireLevelGRPCWebBase64}, flow.WireLevelGRPCWebBase64, false},
		{"all disables predicate", &queryFilter{WireLevel: "all"}, "", false},
		{"unknown value rejected", &queryFilter{WireLevel: "ws-frame"}, "", true},
		{"case-sensitive rejection", &queryFilter{WireLevel: "Semantic"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveWireLevelFilter(tt.filter)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

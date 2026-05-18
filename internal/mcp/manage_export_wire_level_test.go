// Package mcp manage_export_wire_level_test.go — unit + integration
// coverage for the export_flows wire_level filter (USK-932).
//
// USK-921 made MCP `query` default to `wire_level=semantic`; USK-932
// extends the same default to the JSONL exporter so forensic JSONL output
// no longer ships per-frame overlay rows (h2-frame / grpc-lpm-frame /
// h1-chunk / grpcweb-base64) unless the caller passes wire_level="all"
// (or one of the overlay values to isolate a single diagnostic view).
//
// The HAR exporter ignores opts.WireLevel — HAR 1.2 has no slot for
// per-frame overlays and HAR enforces semantic-only internally via
// filterSemanticFlows — so these tests focus on the JSONL path.
package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestResolveExportWireLevel covers the validation + default resolution
// shared by the JSONL exporter. Mirrors resolveWireLevelFilter (query
// tool) so the two surfaces stay in lockstep.
func TestResolveExportWireLevel(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		filter    *exportFilter
		want      string
		wantErr   bool
		errSubstr string
	}{
		{
			name:   "nil_filter_defaults_to_semantic",
			filter: nil,
			want:   flow.WireLevelSemantic,
		},
		{
			name:   "empty_value_defaults_to_semantic",
			filter: &exportFilter{WireLevel: ""},
			want:   flow.WireLevelSemantic,
		},
		{
			name:   "all_disables_predicate",
			filter: &exportFilter{WireLevel: "all"},
			want:   "",
		},
		{
			name:   "explicit_semantic_passes_through",
			filter: &exportFilter{WireLevel: flow.WireLevelSemantic},
			want:   flow.WireLevelSemantic,
		},
		{
			name:   "h2_frame_passes_through",
			filter: &exportFilter{WireLevel: flow.WireLevelH2Frame},
			want:   flow.WireLevelH2Frame,
		},
		{
			name:   "h1_chunk_passes_through",
			filter: &exportFilter{WireLevel: flow.WireLevelHTTP1Chunk},
			want:   flow.WireLevelHTTP1Chunk,
		},
		{
			name:   "grpc_lpm_passes_through",
			filter: &exportFilter{WireLevel: flow.WireLevelGRPCLPMFrame},
			want:   flow.WireLevelGRPCLPMFrame,
		},
		{
			name:   "grpcweb_base64_passes_through",
			filter: &exportFilter{WireLevel: flow.WireLevelGRPCWebBase64},
			want:   flow.WireLevelGRPCWebBase64,
		},
		{
			name:      "unknown_value_rejected",
			filter:    &exportFilter{WireLevel: "raw-frame"},
			wantErr:   true,
			errSubstr: "invalid wire_level",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveExportWireLevel(tc.filter)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveExportWireLevel(%+v) = %q, nil; want error containing %q", tc.filter, got, tc.errSubstr)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveExportWireLevel(%+v) returned unexpected error: %v", tc.filter, err)
			}
			if got != tc.want {
				t.Errorf("resolveExportWireLevel(%+v) = %q, want %q", tc.filter, got, tc.want)
			}
		})
	}
}

// makeMixedWireLevelSession creates a stream with one semantic Send
// envelope, one semantic Receive envelope, AND two overlay rows
// (h2-frame, grpc-lpm-frame). This shape mirrors the gRPC-over-h2
// recording path where one Start envelope coexists with per-frame
// overlay rows under the same stream_id.
func makeMixedWireLevelSession(t *testing.T, store flow.Store, id string) {
	t.Helper()
	ctx := context.Background()
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	st := &flow.Stream{
		ID:        id,
		ConnID:    "conn-" + id,
		Protocol:  "grpc",
		State:     "complete",
		Timestamp: ts,
		Duration:  100 * time.Millisecond,
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	rows := []*flow.Flow{
		{
			ID:        "msg-semantic-send-" + id,
			StreamID:  id,
			Sequence:  0,
			Direction: "send",
			Timestamp: ts,
			Method:    "POST",
			WireLevel: flow.WireLevelSemantic,
		},
		{
			ID:        "msg-h2frame-send-" + id,
			StreamID:  id,
			Sequence:  1,
			Direction: "send",
			Timestamp: ts,
			WireLevel: flow.WireLevelH2Frame,
			RawBytes:  []byte("h2-frame-payload"),
		},
		{
			ID:        "msg-lpm-send-" + id,
			StreamID:  id,
			Sequence:  2,
			Direction: "send",
			Timestamp: ts,
			WireLevel: flow.WireLevelGRPCLPMFrame,
			RawBytes:  []byte("\x00\x00\x00\x00\x04lpm!"),
		},
		{
			ID:        "msg-semantic-recv-" + id,
			StreamID:  id,
			Sequence:  3,
			Direction: "receive",
			Timestamp: ts,
			WireLevel: flow.WireLevelSemantic,
		},
	}
	for _, r := range rows {
		if err := store.SaveFlow(ctx, r); err != nil {
			t.Fatalf("SaveFlow %s: %v", r.ID, err)
		}
	}
}

// parseJSONLExport unmarshals each line of a JSONL export blob into an
// ExportRecord. Returns the records in encounter order.
func parseJSONLExport(t *testing.T, data string) []flow.ExportRecord {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(data))
	var records []flow.ExportRecord
	for dec.More() {
		var rec flow.ExportRecord
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode JSONL line: %v", err)
		}
		records = append(records, rec)
	}
	return records
}

// extractExportResult unmarshals the manage tool's inline export response
// payload into executeExportFlowsResult.
func extractExportResult(t *testing.T, result *gomcp.CallToolResult) *executeExportFlowsResult {
	t.Helper()
	if result.IsError {
		t.Fatalf("export returned error: %v", result.Content)
	}
	text := extractTextContent(result)
	var er executeExportFlowsResult
	if err := json.Unmarshal([]byte(text), &er); err != nil {
		t.Fatalf("unmarshal export result %q: %v", text, err)
	}
	return &er
}

// TestExportFlows_DefaultSemantic verifies that the JSONL export
// defaults to wire_level=semantic — overlay rows are excluded unless the
// caller explicitly opts in (USK-932).
func TestExportFlows_DefaultSemantic(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeMixedWireLevelSession(t, store, "sess-default-semantic")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{},
	})
	er := extractExportResult(t, result)
	if er.ExportedCount != 1 {
		t.Fatalf("ExportedCount = %d, want 1", er.ExportedCount)
	}
	records := parseJSONLExport(t, er.Data)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	for _, f := range records[0].Flows {
		if f.WireLevel != "" && f.WireLevel != flow.WireLevelSemantic {
			t.Errorf("default export should exclude overlay rows; got flow %q with wire_level %q", f.ID, f.WireLevel)
		}
	}
	// The mixed-stream fixture has two semantic rows; verify both made it
	// through and overlay rows did not.
	if got := len(records[0].Flows); got != 2 {
		t.Errorf("expected 2 semantic flows, got %d", got)
	}
}

// TestExportFlows_WireLevelAll verifies that wire_level="all" disables
// the predicate and ships every overlay row alongside the semantic
// envelopes (USK-932 forensic opt-in path).
func TestExportFlows_WireLevelAll(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeMixedWireLevelSession(t, store, "sess-wire-all")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"wire_level": "all",
			},
		},
	})
	er := extractExportResult(t, result)
	records := parseJSONLExport(t, er.Data)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if got := len(records[0].Flows); got != 4 {
		t.Errorf("expected 4 flows (semantic + h2-frame + lpm + semantic recv), got %d", got)
	}
	// Verify overlay rows actually round-tripped with their wire_level
	// stamp preserved.
	seen := map[string]bool{}
	for _, f := range records[0].Flows {
		seen[f.WireLevel] = true
	}
	if !seen[flow.WireLevelH2Frame] {
		t.Errorf("expected h2-frame overlay row in wire_level=all export, missing")
	}
	if !seen[flow.WireLevelGRPCLPMFrame] {
		t.Errorf("expected grpc-lpm-frame overlay row in wire_level=all export, missing")
	}
}

// TestExportFlows_WireLevelExplicitOverlay verifies that passing a
// specific overlay value isolates that single wire_level view in the
// export.
func TestExportFlows_WireLevelExplicitOverlay(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeMixedWireLevelSession(t, store, "sess-wire-h2frame")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"wire_level": flow.WireLevelH2Frame,
			},
		},
	})
	er := extractExportResult(t, result)
	records := parseJSONLExport(t, er.Data)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if got := len(records[0].Flows); got != 1 {
		t.Errorf("expected exactly 1 h2-frame flow, got %d", got)
	}
	if records[0].Flows[0].WireLevel != flow.WireLevelH2Frame {
		t.Errorf("expected wire_level=h2-frame, got %q", records[0].Flows[0].WireLevel)
	}
	// Verify the raw bytes survived the round trip (overlay diagnostic
	// value is the raw frame payload, not the semantic message).
	wantRaw := base64.StdEncoding.EncodeToString([]byte("h2-frame-payload"))
	if records[0].Flows[0].RawBytes != wantRaw {
		t.Errorf("expected base64 raw_bytes %q, got %q", wantRaw, records[0].Flows[0].RawBytes)
	}
}

// TestExportFlows_InvalidWireLevel verifies the enum validation surface.
func TestExportFlows_InvalidWireLevel(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	makeMixedWireLevelSession(t, store, "sess-invalid-wire")

	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"filter": map[string]any{
				"wire_level": "bogus-overlay",
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for invalid wire_level, got success")
	}
	text := extractTextContent(result)
	if !strings.Contains(text, "wire_level") {
		t.Errorf("error text %q does not mention wire_level", text)
	}
}

// TestExportFlows_HARIgnoresWireLevel verifies the HAR exporter's data
// model is unaffected by the wire_level field — HAR has no slot for
// per-frame overlays and applies semantic-only internally. Passing
// wire_level=h2-frame to HAR must still produce a valid HAR (or fall
// back to whatever HAR's own semantic projection yields), not a
// stream-of-overlay-frames output.
func TestExportFlows_HARIgnoresWireLevel(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ca := newTestCA(t)
	cs := setupTestSession(t, ca, store)

	// Use the HTTP-shaped helper so HAR's protocol gate passes (gRPC is
	// filtered out by harStreamIncluded).
	makeExportTestSession(t, store, "sess-har-wire-all")

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "out.har")
	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"format":      "har",
			"output_path": outputPath,
			"filter": map[string]any{
				"wire_level": "all",
			},
		},
	})
	// The expectation is that HAR ignores wire_level (it does not affect
	// HAR semantics), so the call must succeed.
	if result.IsError {
		t.Fatalf("HAR export should ignore wire_level filter, got error: %v", result.Content)
	}
}

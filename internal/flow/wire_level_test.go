package flow

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestSQLiteStore_WireLevel_Roundtrip exercises schemaV14:
//   - Flow rows with explicit WireLevelH2Frame round-trip through the
//     SQL layer (saved + reloaded by id and by stream).
//   - Pre-V14 callers that leave WireLevel="" persist as "semantic" via
//     the column default; reads stamp Flow.WireLevel back to "semantic".
//   - The widened UNIQUE constraint (stream_id, sequence, direction,
//     variant, wire_level) accepts a semantic+frame pair sharing the
//     same (stream_id, sequence, direction, variant), proving the
//     frame-level overlay can coexist with the semantic envelope.
func TestSQLiteStore_WireLevel_Roundtrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	ts := time.Now().UTC()
	st := &Stream{Protocol: "http", State: "active", Timestamp: ts}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	// Semantic envelope (the canonical post-swap WS Receive event).
	semantic := &Flow{
		StreamID:  st.ID,
		Sequence:  1,
		Direction: "receive",
		Timestamp: ts,
		// WireLevel intentionally left empty: caller didn't supply,
		// expect column default 'semantic' on persist and "semantic"
		// on read-back via scanFlow's empty-string backstop.
	}
	if err := store.SaveFlow(ctx, semantic); err != nil {
		t.Fatalf("SaveFlow(semantic): %v", err)
	}

	// Frame envelope sharing the same (stream_id, sequence, direction, variant).
	frame := &Flow{
		StreamID:  st.ID,
		Sequence:  1,
		Direction: "receive",
		Timestamp: ts,
		RawBytes:  []byte("frame-payload-bytes"),
		WireLevel: WireLevelH2Frame,
	}
	if err := store.SaveFlow(ctx, frame); err != nil {
		t.Fatalf("SaveFlow(h2-frame): %v", err)
	}

	// Read back: both rows live under the same stream.
	all, err := store.GetFlows(ctx, st.ID, FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows(no filter): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 rows (semantic + frame), got %d", len(all))
	}

	// WireLevel filter isolates the frame envelope.
	framesOnly, err := store.GetFlows(ctx, st.ID, FlowListOptions{WireLevel: WireLevelH2Frame})
	if err != nil {
		t.Fatalf("GetFlows(h2-frame): %v", err)
	}
	if len(framesOnly) != 1 {
		t.Fatalf("expected 1 h2-frame row, got %d", len(framesOnly))
	}
	if framesOnly[0].WireLevel != WireLevelH2Frame {
		t.Errorf("wire_level = %q, want %q", framesOnly[0].WireLevel, WireLevelH2Frame)
	}
	if string(framesOnly[0].RawBytes) != "frame-payload-bytes" {
		t.Errorf("raw_bytes = %q, want %q", string(framesOnly[0].RawBytes), "frame-payload-bytes")
	}

	// WireLevel filter isolates the semantic envelope; empty-string
	// callers persist as semantic and read back the same.
	semanticOnly, err := store.GetFlows(ctx, st.ID, FlowListOptions{WireLevel: WireLevelSemantic})
	if err != nil {
		t.Fatalf("GetFlows(semantic): %v", err)
	}
	if len(semanticOnly) != 1 {
		t.Fatalf("expected 1 semantic row, got %d", len(semanticOnly))
	}
	if semanticOnly[0].WireLevel != WireLevelSemantic {
		t.Errorf("wire_level = %q, want %q", semanticOnly[0].WireLevel, WireLevelSemantic)
	}

	// GetFlow by ID round-trips the frame envelope's WireLevel.
	frameByID, err := store.GetFlow(ctx, frame.ID)
	if err != nil {
		t.Fatalf("GetFlow(frame): %v", err)
	}
	if frameByID.WireLevel != WireLevelH2Frame {
		t.Errorf("GetFlow wire_level = %q, want %q", frameByID.WireLevel, WireLevelH2Frame)
	}
}

// TestMigrate_V14_Idempotent re-opens an existing DB after migrate runs and
// verifies the wire_level column is present on the flows table.
func TestMigrate_V14_Idempotent(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "v14_idempotent.db")
	logger := testutil.DiscardLogger()

	store1, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore (first open): %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("Close (first): %v", err)
	}

	store2, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore (re-open): %v", err)
	}
	t.Cleanup(func() { store2.Close() })

	// Confirm the column exists by selecting it explicitly.
	var n int
	row := store2.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('flows') WHERE name = 'wire_level'`)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("query pragma_table_info: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 wire_level column, got %d", n)
	}

	// Confirm the index exists.
	row = store2.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_flows_wire_level'`)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("query sqlite_master idx: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected idx_flows_wire_level index, got %d", n)
	}

	// Confirm schema_version is at 14 (or later).
	var version int
	row = store2.db.QueryRow(`SELECT MAX(version) FROM schema_version`)
	if err := row.Scan(&version); err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version < 14 {
		t.Fatalf("schema_version = %d, want >= 14", version)
	}
}

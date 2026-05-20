package flow

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestSQLiteStore_GetFlows_WireOrderBeatsSequence pins USK-935: GetFlows
// must order rows by wire-observed timestamp, not by the per-direction
// sequence counter alone. gRPC, gRPC-Web, and WebSocket Channels number
// SEND and RECV independently (both start at 0), so multiple flows can
// share the same Sequence value. Pre-fix `ORDER BY sequence ASC` left
// the tie-break to SQLite (non-deterministic), causing the WebUI
// Messages timeline to render RECV before SEND when the rowid happened
// to land that way. The fix orders by (timestamp, sequence, direction);
// this test mirrors the real-DB reproduction in the Issue body.
func TestSQLiteStore_GetFlows_WireOrderBeatsSequence(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	base, err := time.Parse(time.RFC3339Nano, "2026-05-20T13:53:01.000000000Z")
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}

	// Mirrors the Issue's real-DB reproduction (stream 58d99d96-...).
	// Per-direction sequence counter: SEND uses 0,1; RECV uses 0,1,2.
	// Wire-observed order is SEND(.112) → SEND(.118) → RECV(.120) →
	// RECV(.131a) → RECV(.131b). Without the fix, SQLite would order
	// these rows by sequence alone — RECV seq=0 (.120) lands ahead of
	// SEND seq=1 (.118), reproducing the WebUI bug.
	type entry struct {
		seq       int
		direction string
		offsetMs  int
		extraNs   int
		insertIdx int // controls INSERT order (rowid) to amplify the tie
	}
	// NOTE: time.RFC3339Nano trims trailing zeros from the fractional
	// second part (e.g. 131ms+0ns serializes as "...01.131Z" but
	// 131ms+500ns serializes as "...01.1310005Z"), so BINARY collation
	// can reverse two times that share the same millisecond when one
	// has sub-microsecond precision and the other does not. The
	// timestamps below all carry the same fractional-second width to
	// keep the encoded strings monotonically ordered. SQLite text
	// comparison is the underlying storage; the real proxy data path
	// uses time.Now() which always populates the nanosecond bits.
	wireOrder := []entry{
		{seq: 0, direction: "send", offsetMs: 112, extraNs: 100, insertIdx: 0},
		{seq: 1, direction: "send", offsetMs: 118, extraNs: 200, insertIdx: 2},
		{seq: 0, direction: "receive", offsetMs: 120, extraNs: 300, insertIdx: 1},
		{seq: 1, direction: "receive", offsetMs: 131, extraNs: 400, insertIdx: 3},
		{seq: 2, direction: "receive", offsetMs: 131, extraNs: 500, insertIdx: 4},
	}

	// Build INSERT order that is intentionally out of wire order so the
	// fix is testing the ORDER BY clause, not insertion order.
	insertOrder := make([]entry, len(wireOrder))
	for _, e := range wireOrder {
		insertOrder[e.insertIdx] = e
	}

	fl := &Stream{Protocol: "grpc", Timestamp: base}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	for _, e := range insertOrder {
		ts := base.Add(time.Duration(e.offsetMs)*time.Millisecond + time.Duration(e.extraNs)*time.Nanosecond)
		f := &Flow{
			StreamID:  fl.ID,
			Sequence:  e.seq,
			Direction: e.direction,
			Timestamp: ts,
		}
		if err := store.SaveFlow(ctx, f); err != nil {
			t.Fatalf("SaveFlow seq=%d dir=%s: %v", e.seq, e.direction, err)
		}
	}

	got, err := store.GetFlows(ctx, fl.ID, FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(got) != len(wireOrder) {
		t.Fatalf("GetFlows returned %d flows, want %d", len(got), len(wireOrder))
	}

	for i, want := range wireOrder {
		if got[i].Sequence != want.seq || got[i].Direction != want.direction {
			t.Errorf("flow[%d] = (seq=%d, dir=%s), want (seq=%d, dir=%s)",
				i, got[i].Sequence, got[i].Direction, want.seq, want.direction)
		}
	}
}

// TestSQLiteStore_GetFlows_WireOrder_DeterministicTieBreak verifies the
// (sequence, direction) tail of the ORDER BY clause produces a
// deterministic order when two flows share the same timestamp.
// envelopeToFlow stamps Timestamp via time.Now() so collisions are
// rare in practice, but RFC3339Nano truncation and quick back-to-back
// writes can still produce identical column values; the tie-break
// guarantees the test suite — and downstream consumers (HAR, JSONL,
// MCP query, WebUI) — observe a stable order across repeats.
func TestSQLiteStore_GetFlows_WireOrder_DeterministicTieBreak(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	ts := time.Date(2026, 5, 20, 13, 53, 1, 0, time.UTC)

	fl := &Stream{Protocol: "websocket", Timestamp: ts}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	// Same timestamp on all rows so the ORDER BY tie-break drives the
	// result order. Insertion order is intentionally reversed.
	if err := store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 1, Direction: "send", Timestamp: ts}); err != nil {
		t.Fatalf("SaveFlow send seq=1: %v", err)
	}
	if err := store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 0, Direction: "receive", Timestamp: ts}); err != nil {
		t.Fatalf("SaveFlow recv seq=0: %v", err)
	}
	if err := store.SaveFlow(ctx, &Flow{StreamID: fl.ID, Sequence: 0, Direction: "send", Timestamp: ts}); err != nil {
		t.Fatalf("SaveFlow send seq=0: %v", err)
	}

	// Expected order under `timestamp ASC, sequence ASC, direction ASC`:
	//   (ts, seq=0, "receive") — direction "receive" sorts before "send"
	//   (ts, seq=0, "send")
	//   (ts, seq=1, "send")
	type want struct {
		seq int
		dir string
	}
	expected := []want{
		{seq: 0, dir: "receive"},
		{seq: 0, dir: "send"},
		{seq: 1, dir: "send"},
	}

	got, err := store.GetFlows(ctx, fl.ID, FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(got) != len(expected) {
		t.Fatalf("GetFlows returned %d flows, want %d", len(got), len(expected))
	}
	for i, w := range expected {
		if got[i].Sequence != w.seq || got[i].Direction != w.dir {
			t.Errorf("flow[%d] = (seq=%d, dir=%s), want (seq=%d, dir=%s)",
				i, got[i].Sequence, got[i].Direction, w.seq, w.dir)
		}
	}
}

// TestSQLiteStore_GetFlows_WireOrder_WebSocketInterleaved pins the WS
// limb of USK-935. WebSocket sessions instantiate two ws.Layer per
// session (one client-side, one upstream-side), each with an independent
// per-direction sequence counter (see internal/layer/ws/channel.go
// nextSeq). A symmetric chat-style WS exchange therefore writes
// (send=0, ts1) → (recv=0, ts2) → (send=1, ts3) → (recv=1, ts4),
// where send-seq collides with recv-seq. Pre-fix GetFlows returned
// these in an undefined order; the fix orders them by timestamp ASC
// then by (sequence, direction).
func TestSQLiteStore_GetFlows_WireOrder_WebSocketInterleaved(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	base := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)

	fl := &Stream{Protocol: "websocket", Timestamp: base}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	type frame struct {
		seq       int
		direction string
		offsetMs  int
		// insertIdx controls SaveFlow order, intentionally out of
		// chronological order to amplify SQLite's tie ambiguity on
		// `ORDER BY sequence ASC` alone.
		insertIdx int
	}
	// Wire-observed order: client speaks first, server replies, client
	// follows up, server closes. Both sides share sequence values
	// 0/1/2 because nextSeq is independent per ws.Layer.
	wireOrder := []frame{
		{seq: 0, direction: "send", offsetMs: 10, insertIdx: 3},
		{seq: 0, direction: "receive", offsetMs: 22, insertIdx: 0},
		{seq: 1, direction: "send", offsetMs: 40, insertIdx: 2},
		{seq: 1, direction: "receive", offsetMs: 55, insertIdx: 1},
		{seq: 2, direction: "send", offsetMs: 80, insertIdx: 4},
	}

	insertOrder := make([]frame, len(wireOrder))
	for _, f := range wireOrder {
		insertOrder[f.insertIdx] = f
	}
	for _, f := range insertOrder {
		ts := base.Add(time.Duration(f.offsetMs) * time.Millisecond)
		if err := store.SaveFlow(ctx, &Flow{
			StreamID:  fl.ID,
			Sequence:  f.seq,
			Direction: f.direction,
			Timestamp: ts,
		}); err != nil {
			t.Fatalf("SaveFlow seq=%d dir=%s: %v", f.seq, f.direction, err)
		}
	}

	got, err := store.GetFlows(ctx, fl.ID, FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(got) != len(wireOrder) {
		t.Fatalf("GetFlows returned %d flows, want %d", len(got), len(wireOrder))
	}
	for i, want := range wireOrder {
		if got[i].Sequence != want.seq || got[i].Direction != want.direction {
			t.Errorf("flow[%d] = (seq=%d, dir=%s), want (seq=%d, dir=%s)",
				i, got[i].Sequence, got[i].Direction, want.seq, want.direction)
		}
	}

	// FilterByDirection still walks per-direction in sequence order —
	// the fix must not regress that contract.
	sends, err := store.GetFlows(ctx, fl.ID, FlowListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("GetFlows send: %v", err)
	}
	if len(sends) != 3 {
		t.Fatalf("send count = %d, want 3", len(sends))
	}
	for i, f := range sends {
		if f.Sequence != i {
			t.Errorf("send[%d].Sequence = %d, want %d (per-direction counter must remain monotonic)", i, f.Sequence, i)
		}
	}
	recvs, err := store.GetFlows(ctx, fl.ID, FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetFlows receive: %v", err)
	}
	if len(recvs) != 2 {
		t.Fatalf("receive count = %d, want 2", len(recvs))
	}
	for i, f := range recvs {
		if f.Sequence != i {
			t.Errorf("receive[%d].Sequence = %d, want %d (per-direction counter must remain monotonic)", i, f.Sequence, i)
		}
	}
}

// TestMigrate_V16_Idempotent re-opens an existing DB after migrate runs
// and verifies the idx_flows_stream_id_timestamp composite index is
// present, the schema_version is at 16 or later, and a second open of
// the same file does not error (the index DDL uses IF NOT EXISTS).
func TestMigrate_V16_Idempotent(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "v16_idempotent.db")
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

	// Composite index from schemaV16 exists exactly once.
	var n int
	row := store2.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_flows_stream_id_timestamp'`)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("query sqlite_master idx: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected idx_flows_stream_id_timestamp index, got %d", n)
	}

	// schema_version is at 16 or later.
	var version int
	row = store2.db.QueryRow(`SELECT MAX(version) FROM schema_version`)
	if err := row.Scan(&version); err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	if version < 16 {
		t.Fatalf("schema_version = %d, want >= 16", version)
	}
}

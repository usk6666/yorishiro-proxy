package flow

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestSchemaV19_MigrationFromV18_AddsListenerAndUpstreamProxy pins the
// schemaV19 migration: a stream row inserted at V18 must survive the
// migration with empty listener_name / upstream_proxy (no fabricated
// backfill), the listener_name index must exist, and new rows must
// round-trip both columns.
func TestSchemaV19_MigrationFromV18_AddsListenerAndUpstreamProxy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v18_to_v19.db")
	ctx := context.Background()

	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	steps := []struct {
		ddl        string
		needsFKOff bool
	}{
		{bootstrapSQL, false},
		{schemaV1, false},
		{schemaV2, false},
		{schemaV3, false},
		{schemaV4, false},
		{schemaV5, false},
		{schemaV6, false},
		{schemaV7, true},
		{schemaV8, true},
		{schemaV9, false},
		{schemaV10, false},
		{schemaV11, true},
		{schemaV12, false},
		{schemaV13, false},
		{schemaV14, true},
		{schemaV15, false},
		{schemaV16, false},
		{schemaV17, false},
		{schemaV18, false},
	}
	for _, step := range steps {
		if step.needsFKOff {
			if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
				t.Fatalf("disable FK: %v", err)
			}
		}
		if _, err := db.ExecContext(ctx, step.ddl); err != nil {
			t.Fatalf("apply schema: %v", err)
		}
		if step.needsFKOff {
			if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
				t.Fatalf("re-enable FK: %v", err)
			}
		}
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (18)"); err != nil {
		t.Fatalf("seed schema_version: %v", err)
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO streams (id, conn_id, protocol, scheme, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, failure_reason, origin, tls_client_ja3, tls_client_ja4)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"v18-stream", "conn-v18", "http", "https", "complete", ts, 10, "{}", "10.0.0.1:1234", "10.0.0.2:443", "", "", "", "", "", nil, nil, nil, "", "proxy", "", "",
	); err != nil {
		t.Fatalf("insert v18 stream: %v", err)
	}
	db.Close()

	store, err := NewSQLiteStore(ctx, dbPath, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore (v19 migration): %v", err)
	}
	defer store.Close()

	got, err := store.GetStream(ctx, "v18-stream")
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.ListenerName != "" {
		t.Errorf("migrated ListenerName = %q, want empty (no backfill)", got.ListenerName)
	}
	if got.ConnInfo == nil || got.ConnInfo.ClientAddr != "10.0.0.1:1234" || got.ConnInfo.ServerAddr != "10.0.0.2:443" {
		t.Errorf("migrated ConnInfo = %+v, want pre-existing addresses intact", got.ConnInfo)
	}
	if got.ConnInfo != nil && got.ConnInfo.UpstreamProxy != "" {
		t.Errorf("migrated UpstreamProxy = %q, want empty", got.ConnInfo.UpstreamProxy)
	}

	// New rows round-trip both columns.
	st := &Stream{
		ID: "v19-stream", ConnID: "c", Protocol: "http", State: "active", Timestamp: time.Now(),
		ListenerName: "worker-a",
		ConnInfo: &ConnectionInfo{
			ClientAddr: "127.0.0.1:5555", ServerAddr: "127.0.0.1:3128", UpstreamProxy: "http://127.0.0.1:3128",
		},
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	rt, err := store.GetStream(ctx, "v19-stream")
	if err != nil {
		t.Fatalf("GetStream v19: %v", err)
	}
	if rt.ListenerName != "worker-a" {
		t.Errorf("round-trip ListenerName = %q, want worker-a", rt.ListenerName)
	}
	if rt.ConnInfo == nil || rt.ConnInfo.UpstreamProxy != "http://127.0.0.1:3128" {
		t.Errorf("round-trip ConnInfo = %+v, want UpstreamProxy http://127.0.0.1:3128", rt.ConnInfo)
	}

	checkDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open check db: %v", err)
	}
	defer checkDB.Close()
	var version int
	if err := checkDB.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != 19 {
		t.Errorf("schema version = %d, want 19", version)
	}
	var idx string
	if err := checkDB.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_streams_listener_name'`).Scan(&idx); err != nil {
		t.Errorf("idx_streams_listener_name missing: %v", err)
	}
}

func TestSQLiteStore_UpdateStream_UpstreamProxy(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()
	if err := store.SaveStream(ctx, &Stream{
		ID: "s1", Protocol: "http", State: "active", Timestamp: time.Now(),
		ConnInfo: &ConnectionInfo{ClientAddr: "127.0.0.1:1"},
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.UpdateStream(ctx, "s1", StreamUpdate{ServerAddr: "127.0.0.1:3128", UpstreamProxy: "socks5://127.0.0.1:3128"}); err != nil {
		t.Fatalf("UpdateStream: %v", err)
	}
	got, err := store.GetStream(ctx, "s1")
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	want := ConnectionInfo{ClientAddr: "127.0.0.1:1", ServerAddr: "127.0.0.1:3128", UpstreamProxy: "socks5://127.0.0.1:3128"}
	if got.ConnInfo == nil || *got.ConnInfo != want {
		t.Errorf("ConnInfo = %+v, want %+v", got.ConnInfo, want)
	}
}

func seedListenerStreams(t *testing.T, store *SQLiteStore) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i, s := range []struct{ id, listener string }{
		{"aaaaaaaa-0000-4000-8000-000000000001", "w1"},
		{"aaaaaaaa-0000-4000-8000-000000000002", "w2"},
		{"aaaaaaaa-0000-4000-8000-000000000003", "w1"},
		{"aaaaaaaa-0000-4000-8000-000000000004", ""},
	} {
		if err := store.SaveStream(ctx, &Stream{
			ID: s.id, ConnID: "c", Protocol: "http", Scheme: "http", State: "complete",
			Timestamp:    base.Add(time.Duration(i) * time.Second),
			ListenerName: s.listener,
			ConnInfo: &ConnectionInfo{
				ClientAddr:    "127.0.0.1:4000",
				ServerAddr:    "127.0.0.1:3128",
				UpstreamProxy: "http://127.0.0.1:3128",
			},
		}); err != nil {
			t.Fatalf("SaveStream: %v", err)
		}
	}
}

func TestSQLiteStore_ListStreams_ListenerNameFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedListenerStreams(t, store)
	ctx := context.Background()

	tests := []struct {
		listener string
		want     int
	}{
		{"w1", 2},
		{"w2", 1},
		{"w", 0}, // exact match, not prefix
		{"", 4},  // filter disabled
	}
	for _, tt := range tests {
		got, err := store.ListStreams(ctx, StreamListOptions{ListenerName: tt.listener})
		if err != nil {
			t.Fatalf("ListStreams(%q): %v", tt.listener, err)
		}
		if len(got) != tt.want {
			t.Errorf("ListStreams(ListenerName=%q) = %d streams, want %d", tt.listener, len(got), tt.want)
		}
		for _, st := range got {
			if tt.listener != "" && st.ListenerName != tt.listener {
				t.Errorf("ListStreams(%q) returned stream with ListenerName %q", tt.listener, st.ListenerName)
			}
		}
		n, err := store.CountStreams(ctx, StreamListOptions{ListenerName: tt.listener})
		if err != nil {
			t.Fatalf("CountStreams(%q): %v", tt.listener, err)
		}
		if n != tt.want {
			t.Errorf("CountStreams(ListenerName=%q) = %d, want %d", tt.listener, n, tt.want)
		}
	}
}

func TestExportImport_ListenerNameAndConnAddrsRoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	seedListenerStreams(t, store)
	ctx := context.Background()

	var buf bytes.Buffer
	if _, err := ExportStreams(ctx, store, &buf, ExportOptions{}); err != nil {
		t.Fatalf("ExportStreams: %v", err)
	}
	exported := buf.String()

	// The JSONL line carries the three fields verbatim.
	sawListener := false
	for _, line := range strings.Split(strings.TrimSpace(exported), "\n") {
		var rec struct {
			Stream struct {
				ID           string `json:"id"`
				ListenerName string `json:"listener_name"`
				ConnInfo     struct {
					ClientAddr    string `json:"client_addr"`
					ServerAddr    string `json:"server_addr"`
					UpstreamProxy string `json:"upstream_proxy"`
				} `json:"conn_info"`
			} `json:"stream"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode export line: %v", err)
		}
		if rec.Stream.ListenerName == "w1" {
			sawListener = true
		}
		if rec.Stream.ConnInfo.ClientAddr != "127.0.0.1:4000" || rec.Stream.ConnInfo.ServerAddr != "127.0.0.1:3128" ||
			rec.Stream.ConnInfo.UpstreamProxy != "http://127.0.0.1:3128" {
			t.Errorf("export line conn_info = %+v, want client/server/upstream_proxy", rec.Stream.ConnInfo)
		}
	}
	if !sawListener {
		t.Errorf("no exported line carried listener_name=w1; export=%s", exported)
	}

	store2 := newTestStore(t)
	res, err := ImportStreams(ctx, store2, strings.NewReader(exported), ImportOptions{OnConflict: ConflictSkip})
	if err != nil {
		t.Fatalf("ImportStreams: %v", err)
	}
	if res.Imported != 4 {
		t.Fatalf("imported = %d, want 4 (errors=%+v)", res.Imported, res.ErrorDetails)
	}
	got, err := store2.ListStreams(ctx, StreamListOptions{ListenerName: "w1"})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("imported w1 streams = %d, want 2", len(got))
	}
	for _, st := range got {
		if st.ConnInfo == nil || st.ConnInfo.UpstreamProxy != "http://127.0.0.1:3128" || st.ConnInfo.ClientAddr != "127.0.0.1:4000" {
			t.Errorf("imported ConnInfo = %+v, want addresses + upstream_proxy round-tripped", st.ConnInfo)
		}
	}
}

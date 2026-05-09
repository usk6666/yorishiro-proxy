package flow

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestSchemaV13_MigrationFromV12_BackfillsEmptyHTTPVersion pins the
// schemaV13 migration: a flow row inserted while the database was at
// V12 (no http_version column) must round-trip cleanly with an empty
// HTTPVersion after the migration runs. The schemaV13 ALTER adds
// http_version TEXT NOT NULL DEFAULT ”; SQLite applies the default
// to existing rows so the backfill is automatic — this test pins
// that behaviour against future schema rewrites that might forget to
// carry it through. Empty is the contract for pre-USK-788 rows.
func TestSchemaV13_MigrationFromV12_BackfillsEmptyHTTPVersion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v12_to_v13.db")
	logger := testutil.DiscardLogger()
	ctx := context.Background()

	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	migrationsToV12 := []struct {
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
	}
	for _, step := range migrationsToV12 {
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
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (12)"); err != nil {
		t.Fatalf("seed schema_version: %v", err)
	}

	// Insert a stream row + a flow row at V12 — no http_version column
	// exists yet on flows.
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO streams (id, conn_id, protocol, scheme, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, failure_reason, origin)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"v12-stream", "conn-v12", "HTTPS", "https", "complete", ts, 100,
		"{}", "", "", "", "", "", "", "", nil, nil, nil, "", "proxy",
	); err != nil {
		t.Fatalf("insert v12 stream: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO flows (id, stream_id, sequence, direction, variant, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata, trailers)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"v12-flow", "v12-stream", 0, "send", "", ts, "{}", nil, nil, 0, "GET", "http://example.com/", 0, "{}", "{}",
	); err != nil {
		t.Fatalf("insert v12 flow: %v", err)
	}
	db.Close()

	// Reopen via NewSQLiteStore — the migrator runs schemaV13 and the
	// existing flow row backfills to http_version='' through the
	// column DEFAULT.
	store, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore (v13 migration): %v", err)
	}
	defer store.Close()

	got, err := store.GetFlow(ctx, "v12-flow")
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if got.HTTPVersion != "" {
		t.Errorf("backfilled HTTPVersion = %q, want empty", got.HTTPVersion)
	}

	// Sanity: the schema version is now V13.
	checkDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open check db: %v", err)
	}
	defer checkDB.Close()
	var version int
	if err := checkDB.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version); err != nil {
		t.Fatalf("query version: %v", err)
	}
	if version != latestVersion() {
		t.Errorf("schema version = %d, want %d", version, latestVersion())
	}
}

// TestSQLiteStore_HTTPVersion_RoundTrip verifies each canonical
// HTTPVersion value round-trips through SaveFlow → GetFlow verbatim.
// Empty is included to pin the no-op write semantics for non-HTTP
// flows and pre-USK-788 callers that have not yet been updated.
func TestSQLiteStore_HTTPVersion_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		httpVersion string
	}{
		{name: "empty (non-HTTP / legacy)", httpVersion: ""},
		{name: "http/1.0", httpVersion: "http/1.0"},
		{name: "http/1.1", httpVersion: "http/1.1"},
		{name: "h2", httpVersion: "h2"},
		{name: "h2c", httpVersion: "h2c"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			ctx := context.Background()
			st := &Stream{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now().UTC(),
			}
			if err := store.SaveStream(ctx, st); err != nil {
				t.Fatalf("SaveStream: %v", err)
			}
			f := &Flow{
				StreamID:    st.ID,
				Sequence:    0,
				Direction:   "send",
				Timestamp:   time.Now().UTC(),
				Method:      "GET",
				HTTPVersion: tc.httpVersion,
			}
			if err := store.SaveFlow(ctx, f); err != nil {
				t.Fatalf("SaveFlow: %v", err)
			}
			got, err := store.GetFlow(ctx, f.ID)
			if err != nil {
				t.Fatalf("GetFlow: %v", err)
			}
			if got.HTTPVersion != tc.httpVersion {
				t.Errorf("HTTPVersion round-trip = %q, want %q", got.HTTPVersion, tc.httpVersion)
			}
		})
	}
}

// TestSQLiteStore_HTTPVersion_FilterIndex verifies the
// idx_flows_http_version index exists after migration. The index is the
// reason USK-792's manage export_flows / delete_flows http_version
// filter can run as a predicate scan instead of a full table scan.
func TestSQLiteStore_HTTPVersion_FilterIndex(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	row := store.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_flows_http_version'`)
	var name string
	if err := row.Scan(&name); err != nil {
		t.Fatalf("idx_flows_http_version not found: %v", err)
	}
	if name != "idx_flows_http_version" {
		t.Errorf("got index name %q, want idx_flows_http_version", name)
	}
}

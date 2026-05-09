package flow

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestSchemaV12_MigrationFromV11_BackfillsOriginProxy verifies the
// schemaV12 migration: a stream row inserted while the database was at
// V11 (no origin column) must round-trip cleanly to OriginProxy after
// the migration runs. The schemaV12 ALTER adds origin TEXT NOT NULL
// DEFAULT 'proxy'; SQLite applies the default to existing rows so the
// backfill is automatic — this test pins that behaviour against future
// schema rewrites that might forget to carry it through.
func TestSchemaV12_MigrationFromV11_BackfillsOriginProxy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v11_to_v12.db")
	logger := testutil.DiscardLogger()
	ctx := context.Background()

	// Stand up the database at V11 manually so we can insert a stream row
	// before V12 runs. PRAGMA foreign_keys must be ON throughout because
	// V7/V8/V11 recreate FK-referencing tables (matches NewSQLiteStore).
	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	migrationsToV11 := []struct {
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
	}
	for _, step := range migrationsToV11 {
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
	if _, err := db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (11)"); err != nil {
		t.Fatalf("seed schema_version: %v", err)
	}

	// Insert a stream row at V11 — no origin column exists yet.
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO streams (id, conn_id, protocol, scheme, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, failure_reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"v11-stream", "conn-v11", "HTTPS", "https", "complete", ts, 100, "{}", "", "", "", "", "", "", "", nil, nil, nil, "",
	); err != nil {
		t.Fatalf("insert v11 stream: %v", err)
	}
	db.Close()

	// Reopen via NewSQLiteStore — the migrator runs schemaV12 and the
	// existing row backfills to origin='proxy' through the column DEFAULT.
	store, err := NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore (v12 migration): %v", err)
	}
	defer store.Close()

	got, err := store.GetStream(ctx, "v11-stream")
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.Origin != OriginProxy {
		t.Errorf("backfilled Origin = %q, want %q", got.Origin, OriginProxy)
	}

	// Sanity: the schema version is now V12.
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

// TestSQLiteStore_Origin_RoundTrip verifies that each Origin enum value
// round-trips through SaveStream → GetStream verbatim. Empty Origin on
// the in-memory Stream is normalised to OriginProxy by saveStreamSync;
// this is the contract the resend / proxy / fuzz callers rely on.
func TestSQLiteStore_Origin_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   Origin
		want Origin
	}{
		{name: "default empty becomes proxy", in: "", want: OriginProxy},
		{name: "explicit proxy", in: OriginProxy, want: OriginProxy},
		{name: "resend", in: OriginResend, want: OriginResend},
		{name: "fuzz reserved", in: OriginFuzz, want: OriginFuzz},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := newTestStore(t)
			ctx := context.Background()
			st := &Stream{
				Protocol:  "HTTP/1.x",
				Timestamp: time.Now().UTC(),
				Origin:    tc.in,
			}
			if err := store.SaveStream(ctx, st); err != nil {
				t.Fatalf("SaveStream: %v", err)
			}
			got, err := store.GetStream(ctx, st.ID)
			if err != nil {
				t.Fatalf("GetStream: %v", err)
			}
			if got.Origin != tc.want {
				t.Errorf("Origin round-trip = %q, want %q", got.Origin, tc.want)
			}
		})
	}
}

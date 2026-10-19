package flow

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// testStoreTemplateVersion is the schema version recorded when
// testStoreTemplate was built. It is written inside the template's sync.Once
// and read only after Bytes has returned, so the Once provides the
// happens-before edge.
var testStoreTemplateVersion int

// testStoreTemplate is a database built by the real migration chain once per
// test process. newTestStore hands every test a byte copy of it, so each
// copy is already at the latest schema version. A fresh migrate+open costs
// about a second under -race; a copy+open costs a few milliseconds.
//
// internal/flow/flowtest carries the same helper for other packages; it
// cannot be used here because it imports package flow.
var testStoreTemplate = testutil.NewFileTemplate("flow store", func(dir string) (string, error) {
	ctx := context.Background()
	path := filepath.Join(dir, "template.db")
	store, err := NewSQLiteStore(ctx, path, testutil.DiscardLogger())
	if err != nil {
		return "", fmt.Errorf("NewSQLiteStore: %w", err)
	}
	v, verr := getCurrentVersion(ctx, store.DB())
	if cerr := store.Close(); cerr != nil {
		return "", fmt.Errorf("close template store: %w", cerr)
	}
	if verr != nil {
		return "", verr
	}
	testStoreTemplateVersion = v
	return path, nil
})

// copyTestStoreTemplate writes a copy of the migrated template to dbPath and
// verifies, before anything opens it through NewSQLiteStore, that the copy
// is at the template's schema version — i.e. migrate() will find no step to
// apply.
func copyTestStoreTemplate(t *testing.T, dbPath string) {
	t.Helper()
	testStoreTemplate.CopyTo(t, dbPath)
	if v := rawSchemaVersion(t, dbPath); v != testStoreTemplateVersion {
		t.Fatalf("copied store is at schema version %d, template was built at %d", v, testStoreTemplateVersion)
	}
}

// rawSchemaVersion opens the database at path without migrating it and
// returns its recorded schema version.
func rawSchemaVersion(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()
	v, err := getCurrentVersion(context.Background(), db)
	if err != nil {
		t.Fatalf("read schema version of %s: %v", path, err)
	}
	return v
}

type masterRow struct {
	Type, Name, TblName, SQL string
}

func sqliteMaster(t *testing.T, db *sql.DB) []masterRow {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		"SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name")
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()
	var out []masterRow
	for rows.Next() {
		var r masterRow
		if err := rows.Scan(&r.Type, &r.Name, &r.TblName, &r.SQL); err != nil {
			t.Fatalf("scan sqlite_master: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate sqlite_master: %v", err)
	}
	return out
}

// TestTemplateStore_SchemaMatchesMigrationChain: a store created from the
// template has exactly the schema a store freshly built by the migration
// chain has, and is at latestVersion(). The journal_mode == wal assertion
// does not guard the template file itself (NewSQLiteStore's DSN forces
// journal_mode(WAL) on every open); it guards that the template-backed
// helper opens its copy through NewSQLiteStore with that WAL DSN.
func TestTemplateStore_SchemaMatchesMigrationChain(t *testing.T) {
	ctx := context.Background()
	fromTemplate := newTestStore(t)

	fresh, err := NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "fresh.db"), testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore (fresh): %v", err)
	}
	t.Cleanup(func() { fresh.Close() })

	got := sqliteMaster(t, fromTemplate.DB())
	want := sqliteMaster(t, fresh.DB())
	if len(want) == 0 {
		t.Fatal("freshly migrated store has an empty sqlite_master")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("template-derived schema differs from migration-chain schema\n got: %v\nwant: %v", got, want)
	}

	v, err := getCurrentVersion(ctx, fromTemplate.DB())
	if err != nil {
		t.Fatalf("getCurrentVersion: %v", err)
	}
	if v != latestVersion() {
		t.Errorf("template-derived schema version = %d, want latestVersion() = %d", v, latestVersion())
	}

	var mode string
	if err := fromTemplate.DB().QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

// TestTemplateStore_BuiltOnceAndNoMigrationApplied: creating several stores
// builds the template exactly once, and every copy is already at the
// template version (= latestVersion()) before NewSQLiteStore opens it, so no
// migration step is applied per test.
func TestTemplateStore_BuiltOnceAndNoMigrationApplied(t *testing.T) {
	for i := 0; i < 3; i++ {
		newTestStore(t)
	}
	if n := testStoreTemplate.Builds(); n != 1 {
		t.Fatalf("template built %d times, want exactly 1", n)
	}
	if testStoreTemplateVersion != latestVersion() {
		t.Fatalf("template built at schema version %d, want latestVersion() = %d", testStoreTemplateVersion, latestVersion())
	}

	// The per-copy pre-open check: a copy written by the helper is at the
	// latest version while still unopened.
	dbPath := filepath.Join(t.TempDir(), "unopened.db")
	copyTestStoreTemplate(t, dbPath)
	if v := rawSchemaVersion(t, dbPath); v != latestVersion() {
		t.Fatalf("unopened copy at schema version %d, want %d", v, latestVersion())
	}
}

// TestTemplateStore_StoresAreIndependent: a write in one template-derived
// store is not visible in another, including across parallel tests.
func TestTemplateStore_StoresAreIndependent(t *testing.T) {
	for _, name := range []string{"a", "b", "c"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := newTestStore(t)
			n, err := s.CountStreams(ctx, StreamListOptions{})
			if err != nil {
				t.Fatalf("CountStreams: %v", err)
			}
			if n != 0 {
				t.Fatalf("fresh store already has %d streams; stores share state", n)
			}
			if err := s.SaveStream(ctx, &Stream{ID: "stream-" + name, Protocol: "raw", State: "complete", Timestamp: time.Now()}); err != nil {
				t.Fatalf("SaveStream: %v", err)
			}
			n, err = s.CountStreams(ctx, StreamListOptions{})
			if err != nil {
				t.Fatalf("CountStreams after save: %v", err)
			}
			if n != 1 {
				t.Fatalf("store has %d streams after one save, want 1", n)
			}
		})
	}
}

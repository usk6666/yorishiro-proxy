// Package flowtest provides test helpers for code that needs a real
// flow.SQLiteStore.
//
// Running the full schema migration chain costs about a second per store
// under -race, and hundreds of tests each need a fresh store. NewStore
// therefore builds one migrated database per test process and gives every
// caller its own byte copy of it: the copy is already at the latest schema
// version, so opening it applies no migration step.
//
// This package is for tests only; production code must not import it.
// Package flow's own in-package tests cannot import it (that would be an
// import cycle) and carry an equivalent helper in sqlite_test.go.
package flowtest

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// templateVersion is the schema version recorded when the template was
// built. It is written inside the template's sync.Once and only read after
// Bytes has returned, so the Once provides the happens-before edge.
var templateVersion int

var template = testutil.NewFileTemplate("flow store", func(dir string) (string, error) {
	ctx := context.Background()
	path := filepath.Join(dir, "template.db")
	store, err := flow.NewSQLiteStore(ctx, path, testutil.DiscardLogger())
	if err != nil {
		return "", fmt.Errorf("NewSQLiteStore: %w", err)
	}
	v, verr := queryVersion(ctx, store.DB())
	if cerr := store.Close(); cerr != nil {
		return "", fmt.Errorf("close template store: %w", cerr)
	}
	if verr != nil {
		return "", verr
	}
	templateVersion = v
	return path, nil
})

// NewStore returns a fresh, empty flow.SQLiteStore backed by a private copy
// of the migrated template database in t.TempDir(). The store is closed via
// t.Cleanup. Stores returned by separate calls share nothing.
func NewStore(t testing.TB) *flow.SQLiteStore {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	template.CopyTo(t, dbPath)

	// The copy must already be at the template's schema version, so that
	// NewSQLiteStore's migrate() finds nothing to apply.
	v, err := FileSchemaVersion(ctx, dbPath)
	if err != nil {
		t.Fatalf("flowtest: %v", err)
	}
	if v != templateVersion {
		t.Fatalf("flowtest: copied store is at schema version %d, template was built at %d", v, templateVersion)
	}

	store, err := flow.NewSQLiteStore(ctx, dbPath, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// TemplateBuilds reports how many times the migrated template database has
// been built in this test process (0 or 1).
func TemplateBuilds() int64 {
	return template.Builds()
}

// TemplateVersion returns the schema version the template was built at,
// building the template if necessary.
func TemplateVersion() (int, error) {
	if _, err := template.Bytes(); err != nil {
		return 0, err
	}
	return templateVersion, nil
}

// FileSchemaVersion opens the SQLite database at path without running any
// migration and returns the version recorded in its schema_version table.
func FileSchemaVersion(ctx context.Context, path string) (int, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer db.Close()
	return queryVersion(ctx, db)
}

func queryVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("query schema version: %w", err)
	}
	return v, nil
}

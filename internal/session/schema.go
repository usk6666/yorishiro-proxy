package session

import (
	"context"
	"database/sql"
	"fmt"
)

const bootstrapSQL = `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);`

const schemaV1 = `
CREATE TABLE IF NOT EXISTS sessions (
	id              TEXT PRIMARY KEY,
	protocol        TEXT NOT NULL,
	method          TEXT NOT NULL DEFAULT '',
	url             TEXT NOT NULL DEFAULT '',
	request_headers TEXT NOT NULL DEFAULT '{}',
	request_body    BLOB,
	response_status INTEGER NOT NULL DEFAULT 0,
	response_headers TEXT NOT NULL DEFAULT '{}',
	response_body   BLOB,
	timestamp       DATETIME NOT NULL,
	duration_ms     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_method ON sessions(method);
CREATE INDEX IF NOT EXISTS idx_sessions_url ON sessions(url);
CREATE INDEX IF NOT EXISTS idx_sessions_response_status ON sessions(response_status);
`

var migrations = map[int]string{
	1: schemaV1,
	2: `ALTER TABLE sessions ADD COLUMN request_body_truncated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN response_body_truncated INTEGER NOT NULL DEFAULT 0;`,
	3: `CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol);
CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions(timestamp);`,
	4: `ALTER TABLE sessions ADD COLUMN conn_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sessions_conn_id ON sessions(conn_id);`,
}

func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, bootstrapSQL); err != nil {
		return fmt.Errorf("bootstrap schema_version: %w", err)
	}

	current, err := getCurrentVersion(ctx, db)
	if err != nil {
		return fmt.Errorf("get current version: %w", err)
	}

	latest := latestVersion()
	if current > latest {
		return fmt.Errorf("database schema version %d is newer than latest known version %d", current, latest)
	}

	for v := current + 1; v <= latest; v++ {
		ddl, ok := migrations[v]
		if !ok {
			continue
		}
		if err := execMigration(ctx, db, v, ddl, current == 0 && v == 1); err != nil {
			return fmt.Errorf("migration to version %d: %w", v, err)
		}
	}

	return nil
}

func getCurrentVersion(ctx context.Context, db *sql.DB) (int, error) {
	var version int
	err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("query schema version: %w", err)
	}
	return version, nil
}

func latestVersion() int {
	max := 0
	for v := range migrations {
		if v > max {
			max = v
		}
	}
	return max
}

func execMigration(ctx context.Context, db *sql.DB, version int, ddl string, isInitial bool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("execute DDL: %w", err)
	}

	if isInitial {
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (?)", version); err != nil {
			return fmt.Errorf("insert schema version: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, "UPDATE schema_version SET version = ?", version); err != nil {
			return fmt.Errorf("update schema version: %w", err)
		}
	}

	return tx.Commit()
}

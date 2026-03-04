package flow

import (
	"context"
	"database/sql"
	"fmt"
)

const bootstrapSQL = `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);`

const schemaV1 = `
CREATE TABLE IF NOT EXISTS sessions (
	id              TEXT PRIMARY KEY,
	conn_id         TEXT NOT NULL DEFAULT '',
	protocol        TEXT NOT NULL,
	session_type    TEXT NOT NULL DEFAULT 'unary',
	state           TEXT NOT NULL DEFAULT 'complete',
	timestamp       DATETIME NOT NULL,
	duration_ms     INTEGER NOT NULL DEFAULT 0,
	tags            TEXT NOT NULL DEFAULT '{}',
	client_addr     TEXT NOT NULL DEFAULT '',
	server_addr     TEXT NOT NULL DEFAULT '',
	tls_version     TEXT NOT NULL DEFAULT '',
	tls_cipher      TEXT NOT NULL DEFAULT '',
	tls_alpn        TEXT NOT NULL DEFAULT '',
	tls_server_cert_subject TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol);
CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions(timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_conn_id ON sessions(conn_id);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);
CREATE INDEX IF NOT EXISTS idx_sessions_session_type ON sessions(session_type);

CREATE TABLE IF NOT EXISTS messages (
	id              TEXT PRIMARY KEY,
	session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
	sequence        INTEGER NOT NULL,
	direction       TEXT NOT NULL,
	timestamp       DATETIME NOT NULL,
	headers         TEXT NOT NULL DEFAULT '{}',
	body            BLOB,
	raw_bytes       BLOB,
	body_truncated  INTEGER NOT NULL DEFAULT 0,
	method          TEXT NOT NULL DEFAULT '',
	url             TEXT NOT NULL DEFAULT '',
	status_code     INTEGER NOT NULL DEFAULT 0,
	metadata        TEXT NOT NULL DEFAULT '{}',
	UNIQUE(session_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_messages_session_id ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_direction ON messages(direction);
CREATE INDEX IF NOT EXISTS idx_messages_method ON messages(method);
CREATE INDEX IF NOT EXISTS idx_messages_url ON messages(url);
CREATE INDEX IF NOT EXISTS idx_messages_status_code ON messages(status_code);
`

const schemaV2 = `
-- Fuzz job management
CREATE TABLE IF NOT EXISTS fuzz_jobs (
	id              TEXT PRIMARY KEY,
	session_id      TEXT NOT NULL,
	config          TEXT NOT NULL,
	status          TEXT NOT NULL,
	tag             TEXT NOT NULL DEFAULT '',
	created_at      DATETIME NOT NULL,
	completed_at    DATETIME,
	total           INTEGER NOT NULL DEFAULT 0,
	completed_count INTEGER NOT NULL DEFAULT 0,
	error_count     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_fuzz_jobs_status ON fuzz_jobs(status);
CREATE INDEX IF NOT EXISTS idx_fuzz_jobs_tag ON fuzz_jobs(tag);

-- Fuzz results (each payload submission result)
CREATE TABLE IF NOT EXISTS fuzz_results (
	id              TEXT PRIMARY KEY,
	fuzz_id         TEXT NOT NULL REFERENCES fuzz_jobs(id) ON DELETE CASCADE,
	index_num       INTEGER NOT NULL,
	session_id      TEXT NOT NULL DEFAULT '',
	payloads        TEXT NOT NULL,
	status_code     INTEGER,
	response_length INTEGER,
	duration_ms     INTEGER,
	error           TEXT,

	UNIQUE(fuzz_id, index_num)
);

CREATE INDEX IF NOT EXISTS idx_fuzz_results_fuzz_id ON fuzz_results(fuzz_id);
CREATE INDEX IF NOT EXISTS idx_fuzz_results_status_code ON fuzz_results(status_code);

CREATE TABLE IF NOT EXISTS macros (
	name        TEXT PRIMARY KEY,
	description TEXT NOT NULL DEFAULT '',
	config      TEXT NOT NULL,
	created_at  DATETIME NOT NULL,
	updated_at  DATETIME NOT NULL
);
`

const schemaV3 = `
ALTER TABLE sessions ADD COLUMN blocked_by TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_sessions_blocked_by ON sessions(blocked_by);
`

// schemaV4 renames the flows table to flows, session_id columns to flow_id,
// and session_type to flow_type across all tables, adopting mitmproxy-style "flow" terminology.
const schemaV4 = `
ALTER TABLE sessions RENAME TO flows;
ALTER TABLE flows RENAME COLUMN session_type TO flow_type;
ALTER TABLE messages RENAME COLUMN session_id TO flow_id;
ALTER TABLE fuzz_jobs RENAME COLUMN session_id TO flow_id;
ALTER TABLE fuzz_results RENAME COLUMN session_id TO flow_id;
`

var migrations = map[int]string{
	1: schemaV1,
	2: schemaV2,
	3: schemaV3,
	4: schemaV4,
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

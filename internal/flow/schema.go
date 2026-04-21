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

// schemaV5 adds per-phase timing columns (send/wait/receive) to flows.
// These are nullable (INTEGER with no NOT NULL) for backward compatibility
// with existing flows and protocols where timing is not applicable (e.g., Raw TCP).
const schemaV5 = `
ALTER TABLE flows ADD COLUMN send_ms INTEGER;
ALTER TABLE flows ADD COLUMN wait_ms INTEGER;
ALTER TABLE flows ADD COLUMN receive_ms INTEGER;
`

// schemaV6 adds the scheme column to flows to separate transport/TLS
// information (https, http, wss, ws, tcp) from the application protocol.
const schemaV6 = `
ALTER TABLE flows ADD COLUMN scheme TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_flows_scheme ON flows(scheme);
`

// schemaV7 renames the data model: flows→streams, messages→flows.
// - Table "flows" is renamed to "streams"
// - Table "messages" is renamed to "flows"
// - Column "flow_id" in the new "flows" table is renamed to "stream_id"
// - Column "flow_type" is dropped from streams (MITM proxy cannot distinguish unary/streaming)
// - Indexes are recreated for the new table/column names
//
// SQLite does not support DROP COLUMN before 3.35.0, so we recreate the streams
// table without the flow_type column.
const schemaV7 = `
-- Step 1: Rename flows → streams_old (temporary)
ALTER TABLE flows RENAME TO streams_old;

-- Step 2: Recreate streams table WITHOUT flow_type column
CREATE TABLE streams (
	id              TEXT PRIMARY KEY,
	conn_id         TEXT NOT NULL DEFAULT '',
	protocol        TEXT NOT NULL,
	state           TEXT NOT NULL DEFAULT 'complete',
	timestamp       DATETIME NOT NULL,
	duration_ms     INTEGER NOT NULL DEFAULT 0,
	tags            TEXT NOT NULL DEFAULT '{}',
	client_addr     TEXT NOT NULL DEFAULT '',
	server_addr     TEXT NOT NULL DEFAULT '',
	tls_version     TEXT NOT NULL DEFAULT '',
	tls_cipher      TEXT NOT NULL DEFAULT '',
	tls_alpn        TEXT NOT NULL DEFAULT '',
	tls_server_cert_subject TEXT NOT NULL DEFAULT '',
	blocked_by      TEXT NOT NULL DEFAULT '',
	send_ms         INTEGER,
	wait_ms         INTEGER,
	receive_ms      INTEGER,
	scheme          TEXT NOT NULL DEFAULT ''
);

-- Step 3: Copy data from streams_old to streams (excluding flow_type)
INSERT INTO streams (id, conn_id, protocol, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, scheme)
SELECT id, conn_id, protocol, state, timestamp, duration_ms, tags, client_addr, server_addr, tls_version, tls_cipher, tls_alpn, tls_server_cert_subject, blocked_by, send_ms, wait_ms, receive_ms, scheme
FROM streams_old;

-- Step 4: Drop old table
DROP TABLE streams_old;

-- Step 5: Create indexes for streams
CREATE INDEX IF NOT EXISTS idx_streams_protocol ON streams(protocol);
CREATE INDEX IF NOT EXISTS idx_streams_timestamp ON streams(timestamp);
CREATE INDEX IF NOT EXISTS idx_streams_conn_id ON streams(conn_id);
CREATE INDEX IF NOT EXISTS idx_streams_state ON streams(state);
CREATE INDEX IF NOT EXISTS idx_streams_blocked_by ON streams(blocked_by);
CREATE INDEX IF NOT EXISTS idx_streams_scheme ON streams(scheme);

-- Step 6: Recreate flows table from messages with updated FK and column name
-- We recreate instead of ALTER TABLE RENAME to fix the FK reference
-- (old messages.flow_id REFERENCES flows(id) → new flows.stream_id REFERENCES streams(id))
CREATE TABLE flows (
	id              TEXT PRIMARY KEY,
	stream_id       TEXT NOT NULL REFERENCES streams(id) ON DELETE CASCADE,
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
	UNIQUE(stream_id, sequence)
);

-- Step 7: Copy data from messages to flows (renaming flow_id → stream_id)
INSERT INTO flows (id, stream_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata)
SELECT id, flow_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata
FROM messages;

-- Step 8: Drop old messages table
DROP TABLE messages;

-- Step 9: Create indexes for flows
CREATE INDEX IF NOT EXISTS idx_flows_stream_id ON flows(stream_id);
CREATE INDEX IF NOT EXISTS idx_flows_direction ON flows(direction);
CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
CREATE INDEX IF NOT EXISTS idx_flows_url ON flows(url);
CREATE INDEX IF NOT EXISTS idx_flows_status_code ON flows(status_code);

-- Step 10: Update fuzz_jobs and fuzz_results flow_id references
-- These still reference stream IDs (the old "flow" concept), so rename to stream_id
ALTER TABLE fuzz_jobs RENAME COLUMN flow_id TO stream_id;
ALTER TABLE fuzz_results RENAME COLUMN flow_id TO stream_id;
`

// schemaV8 changes the unique constraint on flows from (stream_id, sequence)
// to (stream_id, sequence, direction). This is needed because bidirectional
// protocols like TCP use the same StreamID for both send and receive flows,
// and each direction maintains its own independent sequence counter.
// HTTP/1.x naturally avoids collisions (request seq=0, response seq=1) but
// TCP sends seq=0,1,2... and receives seq=0,1,2... within the same stream.
const schemaV8 = `
-- Recreate flows table with updated unique constraint
CREATE TABLE flows_new (
	id              TEXT PRIMARY KEY,
	stream_id       TEXT NOT NULL REFERENCES streams(id) ON DELETE CASCADE,
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
	UNIQUE(stream_id, sequence, direction)
);

INSERT INTO flows_new (id, stream_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata)
SELECT id, stream_id, sequence, direction, timestamp, headers, body, raw_bytes, body_truncated, method, url, status_code, metadata
FROM flows;

DROP TABLE flows;
ALTER TABLE flows_new RENAME TO flows;

CREATE INDEX IF NOT EXISTS idx_flows_stream_id ON flows(stream_id);
CREATE INDEX IF NOT EXISTS idx_flows_direction ON flows(direction);
CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
CREATE INDEX IF NOT EXISTS idx_flows_url ON flows(url);
CREATE INDEX IF NOT EXISTS idx_flows_status_code ON flows(status_code);
`

// schemaV9 adds the failure_reason column to streams for classification of
// stream-level errors (refused / canceled / protocol / internal). Populated
// by SessionOptions.OnComplete when err wraps a *layer.StreamError. Empty
// when the stream completed normally or when the error has no classification.
const schemaV9 = `
ALTER TABLE streams ADD COLUMN failure_reason TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_streams_failure_reason ON streams(failure_reason);
`

// schemaV10 adds the trailers column to flows for HTTP message trailers
// (HTTP/2 trailer-HEADERS, HTTP/1.1 chunked trailers). JSON-encoded
// map[string][]string, matching the headers column shape. Empty for
// non-HTTP protocols and for messages without trailers.
const schemaV10 = `
ALTER TABLE flows ADD COLUMN trailers TEXT NOT NULL DEFAULT '{}';
`

var migrations = map[int]string{
	1:  schemaV1,
	2:  schemaV2,
	3:  schemaV3,
	4:  schemaV4,
	5:  schemaV5,
	6:  schemaV6,
	7:  schemaV7,
	8:  schemaV8,
	9:  schemaV9,
	10: schemaV10,
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
		// V7 renames tables that are FK targets, so foreign keys must be
		// temporarily disabled. PRAGMA cannot run inside a transaction, so
		// we toggle it outside the migration transaction.
		// Migrations that recreate FK-referencing tables require foreign keys
		// to be temporarily disabled. PRAGMA cannot run inside a transaction.
		needsFKOff := v == 7 || v == 8
		if needsFKOff {
			if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
				return fmt.Errorf("disable foreign keys for migration v%d: %w", v, err)
			}
		}
		if err := execMigration(ctx, db, v, ddl, current == 0 && v == 1); err != nil {
			return fmt.Errorf("migration to version %d: %w", v, err)
		}
		if needsFKOff {
			if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
				return fmt.Errorf("re-enable foreign keys after migration v%d: %w", v, err)
			}
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

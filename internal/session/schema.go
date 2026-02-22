package session

const schemaVersion = 1

const createSchema = `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER NOT NULL
);

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

# query

Unified information query tool. Retrieve sessions, session details, messages, proxy status, configuration, or CA certificate.

## Parameters

### resource (string, required)
The resource to query. One of: `sessions`, `session`, `messages`, `status`, `config`, `ca_cert`, `intercept_queue`, `macros`, `macro`.

### id (string, conditional)
Session ID or macro name. Required for `session`, `messages`, and `macro` resources.

### filter (object, optional)
Filter options for the `sessions` resource.
- **protocol** (string): Protocol filter (e.g. `"HTTP/1.x"`, `"HTTPS"`).
- **method** (string): HTTP method filter (e.g. `"GET"`, `"POST"`).
- **url_pattern** (string): URL substring match (e.g. `"/api/"`).
- **status_code** (integer): HTTP status code filter (e.g. `200`, `404`).

### limit (integer, optional)
Maximum number of items to return. Default: 50, max: 1000. Applies to `sessions` and `messages`.

### offset (integer, optional)
Number of items to skip for pagination. Must be >= 0. Applies to `sessions` and `messages`.

## Resource Details

### sessions
List recorded proxy sessions with optional filtering and pagination.

Returns: `sessions[]` (id, protocol, session_type, state, method, url, status_code, message_count, timestamp, duration_ms), `count`, `total`.

### session
Get full details of a single session including request/response headers, bodies, and connection info.

Requires: `id` (session ID).

Returns: id, conn_id, protocol, session_type, state, method, url, request/response headers and bodies, raw bytes (base64), connection info, timestamps.

### messages
Get paginated messages within a session.

Requires: `id` (session ID). Supports `limit` and `offset`.

Returns: `messages[]` (id, sequence, direction, method, url, status_code, headers, body, body_encoding, timestamp), `count`, `total`.

- **body_encoding**: `"text"` for UTF-8 safe bodies, `"base64"` for binary content.

### status
Get current proxy status and health metrics. No additional parameters.

Returns: running, listen_addr, active_connections, total_sessions, db_size_bytes, uptime_seconds, ca_initialized.

### config
Get current configuration including capture scope and TLS passthrough. No additional parameters.

Returns: capture_scope (includes, excludes), tls_passthrough (patterns, count).

### ca_cert
Get the CA certificate PEM and metadata. No additional parameters.

Returns: pem, fingerprint, subject, not_after.

### intercept_queue
List intercepted requests currently waiting in the intercept queue.

Supports `limit` for limiting the number of returned items.

Returns: `items[]` (id, method, url, headers, body, body_encoding, timestamp, matched_rules), `count`.

## Usage Examples

### List all sessions
```json
{"resource": "sessions"}
```

### Filter sessions by method and URL
```json
{
  "resource": "sessions",
  "filter": {"method": "POST", "url_pattern": "/api/login"},
  "limit": 10
}
```

### Get session details
```json
{"resource": "session", "id": "abc-123"}
```

### Get session messages with pagination
```json
{"resource": "messages", "id": "abc-123", "limit": 20, "offset": 0}
```

### Check proxy status
```json
{"resource": "status"}
```

### Get current config
```json
{"resource": "config"}
```

### Export CA certificate
```json
{"resource": "ca_cert"}
```

### List intercepted requests
```json
{"resource": "intercept_queue"}
```

### List intercepted requests with limit
```json
{"resource": "intercept_queue", "limit": 5}
```

### macros
List all stored macro definitions with summary information.

Returns: `macros[]` (name, description, step_count, created_at, updated_at), `count`.

### macro
Get full details of a single macro definition including all steps, extraction rules, and guards.

Requires: `id` (macro name).

Returns: name, description, steps[], initial_vars, timeout_ms, created_at, updated_at.

### List all macros
```json
{"resource": "macros"}
```

### Get macro details
```json
{"resource": "macro", "id": "auth-flow"}
```

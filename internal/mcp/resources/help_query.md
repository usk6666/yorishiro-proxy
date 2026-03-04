# query

Unified information query tool. Retrieve flows, flow details, messages, proxy status, configuration, or CA certificate.

## Parameters

### resource (string, required)
The resource to query. One of: `flows`, `flow`, `messages`, `status`, `config`, `ca_cert`, `intercept_queue`, `macros`, `macro`, `fuzz_jobs`, `fuzz_results`.

### id (string, conditional)
Flow ID or macro name. Required for `flow`, `messages`, and `macro` resources.

### fuzz_id (string, conditional)
Fuzz job ID. Required for `fuzz_results` resource.

### filter (object, optional)
Filter options for the `flows`, `messages`, `fuzz_jobs`, and `fuzz_results` resources.
- **protocol** (string): Protocol filter for flows (e.g. `"HTTP/1.x"`, `"HTTPS"`, `"WebSocket"`, `"HTTP/2"`, `"gRPC"`, `"TCP"`).
- **method** (string): HTTP method filter for flows (e.g. `"GET"`, `"POST"`).
- **url_pattern** (string): URL substring match for flows (e.g. `"/api/"`).
- **status_code** (integer): HTTP status code filter for flows and fuzz_results (e.g. `200`, `404`).
- **blocked_by** (string): Filter for blocked flows (e.g. `"target_scope"`, `"intercept_drop"`).
- **state** (string): Flow lifecycle state filter (`"active"`, `"complete"`, `"error"`).
- **direction** (string): Message direction filter for the `messages` resource (`"send"` or `"receive"`).
- **body_contains** (string): Response body substring filter for fuzz_results.
- **status** (string): Job status filter for fuzz_jobs (e.g. `"running"`, `"completed"`).
- **tag** (string): Job tag filter for fuzz_jobs (exact match).

### fields (array of strings, optional)
Controls which fields are returned in the response for `fuzz_jobs` and `fuzz_results` resources.
If omitted, all fields are returned. Metadata fields (`count`, `total`, `summary`) are always included.

### sort_by (string, optional)
Field to sort results by for the `fuzz_results` resource.
Supported values: `index_num` (default), `status_code`, `duration_ms`, `response_length`.

### limit (integer, optional)
Maximum number of items to return. Default: 50, max: 1000. Applies to `flows`, `messages`, `fuzz_jobs`, and `fuzz_results`.

### offset (integer, optional)
Number of items to skip for pagination. Must be >= 0. Applies to `flows`, `messages`, `fuzz_jobs`, and `fuzz_results`.

## Resource Details

### flows
List recorded proxy flows with optional filtering and pagination.

Each flow entry includes a `protocol_summary` field with protocol-specific information:
- **WebSocket**: `message_count`, `last_frame_type` (Text/Binary/Close/Ping/Pong)
- **HTTP/2**: `stream_count`, `scheme`
- **gRPC**: `service`, `method`, `grpc_status`, `grpc_status_name`
- **TCP**: `send_bytes`, `receive_bytes`

Returns: `flows[]` (id, protocol, flow_type, state, method, url, status_code, message_count, protocol_summary, timestamp, duration_ms), `count`, `total`.

### flow
Get full details of a single flow including request/response headers, bodies, and connection info.

Flow state indicates the lifecycle stage:
- `"active"`: In progress (send recorded, awaiting receive)
- `"complete"`: Finished successfully
- `"error"`: Failed (e.g. 502 error, upstream connection failure)

When intercept/transform modifies a request, the flow contains variant messages. The `original_request` field is populated with the pre-modification request data for diff comparison. The main request fields show the modified (actually sent) version.

For streaming flows (`flow_type` != `"unary"`), the response includes:
- `message_preview`: The first 10 messages with full details (body, metadata, etc.)
- `message_count`: Total number of messages in the flow
- `protocol_summary`: Protocol-specific summary information

Use the `messages` resource with `limit`/`offset` to page through all messages.

Requires: `id` (flow ID).

Returns: id, conn_id, protocol, flow_type, state, method, url, request/response headers and bodies, raw bytes (base64), connection info, protocol_summary, message_preview (for streaming), original_request (for variant flows), timestamps.

### messages
Get paginated messages within a flow. Supports direction filtering for streaming protocols.

Requires: `id` (flow ID). Supports `limit`, `offset`, and `filter.direction`.

Returns: `messages[]` (id, sequence, direction, method, url, status_code, headers, body, body_encoding, metadata, timestamp), `count`, `total`.

- **body_encoding**: `"text"` for UTF-8 safe bodies, `"base64"` for binary content.
- **metadata**: Protocol-specific fields (e.g. WebSocket `opcode`, gRPC `service`/`method`/`grpc_status`).

### status
Get current proxy status and health metrics. No additional parameters.

Returns: running, listen_addr, active_connections, total_flows, db_size_bytes, uptime_seconds, ca_initialized.

### config
Get current configuration including capture scope, TLS passthrough, TCP forwards, and enabled protocols. No additional parameters.

Returns: capture_scope (includes, excludes), tls_passthrough (patterns, count), tcp_forwards (port->target map), enabled_protocols (list).

### ca_cert
Get the CA certificate PEM, metadata, and persistence state. No additional parameters.

Returns: pem, fingerprint, subject, not_after, persisted, cert_path, install_hint.

- **persisted** (boolean): Whether the CA certificate is saved to disk.
- **cert_path** (string): File path of the persisted CA certificate (empty if ephemeral).
- **install_hint** (string): Guidance for installing the CA certificate into the trust store (empty if ephemeral).

### intercept_queue
List intercepted requests currently waiting in the intercept queue.

Supports `limit` for limiting the number of returned items.

Returns: `items[]` (id, method, url, headers, body, body_encoding, timestamp, matched_rules), `count`.

## Usage Examples

### List all flows
```json
{"resource": "flows"}
```

### Filter flows by protocol
```json
{
  "resource": "flows",
  "filter": {"protocol": "WebSocket"}
}
```

### Filter gRPC flows
```json
{
  "resource": "flows",
  "filter": {"protocol": "gRPC"}
}
```

### Filter flows by method and URL
```json
{
  "resource": "flows",
  "filter": {"method": "POST", "url_pattern": "/api/login"},
  "limit": 10
}
```

### Filter flows by state (e.g. active or error)
```json
{
  "resource": "flows",
  "filter": {"state": "error"}
}
```

### Filter blocked flows
```json
{
  "resource": "flows",
  "filter": {"blocked_by": "intercept_drop"}
}
```

### Get flow details
```json
{"resource": "flow", "id": "abc-123"}
```

### Get flow messages with pagination
```json
{"resource": "messages", "id": "abc-123", "limit": 20, "offset": 0}
```

### Filter messages by direction (send only)
```json
{
  "resource": "messages",
  "id": "abc-123",
  "filter": {"direction": "send"},
  "limit": 50
}
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

### fuzz_jobs
List fuzz jobs with optional filtering by status and tag.

Supports `filter.status`, `filter.tag`, `fields`, `limit`, and `offset`.

Returns: `jobs[]` (id, flow_id, status, tag, total, completed_count, error_count, created_at, completed_at), `count`, `total`.

### fuzz_results
Get results for a specific fuzz job with filtering, sorting, pagination, and aggregate summary.

Requires: `fuzz_id` (fuzz job ID). Supports `filter.status_code`, `filter.body_contains`, `fields`, `sort_by`, `limit`, and `offset`.

Returns: `results[]` (id, fuzz_id, index, flow_id, payloads, status_code, response_length, duration_ms, error), `count`, `total`, `summary` (status_distribution, avg_duration_ms, total_duration_ms).

### List fuzz jobs
```json
{"resource": "fuzz_jobs"}
```

### List running fuzz jobs
```json
{"resource": "fuzz_jobs", "filter": {"status": "running"}}
```

### Get fuzz results with filtering
```json
{
  "resource": "fuzz_results",
  "fuzz_id": "fuzz-789",
  "filter": {"status_code": 200, "body_contains": "admin"},
  "fields": ["index", "flow_id", "payloads", "status_code", "duration_ms"],
  "sort_by": "status_code",
  "limit": 50,
  "offset": 0
}
```

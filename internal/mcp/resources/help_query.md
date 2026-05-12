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
- **protocol** (string): Protocol filter for flows. Canonical values only (`"http"`, `"ws"`, `"grpc"`, `"grpc-web"`, `"sse"`, `"raw"`, `"tls-handshake"`); legacy spellings (`"HTTP/1.x"`, `"HTTPS"`, `"HTTP/2"`, `"WebSocket"`, `"gRPC"`, `"gRPC-Web"`, `"TCP"`, `"SOCKS5+*"`) are rejected as of USK-705.
- **scheme** (string): URL scheme / transport filter for flows (e.g. `"https"`, `"http"`, `"wss"`, `"ws"`, `"tcp"`). Use to find TLS flows: `"https"` returns HTTP/1.x, HTTP/2, gRPC flows over TLS. WebSocket over TLS uses `"wss"`, not `"https"`.
- **http_version** (string): HTTP wire-version filter for flows (`"http/1.0"`, `"http/1.1"`, `"h2"`, `"h2c"`). Matches when at least one flow on the stream recorded that version. Use `""` (explicit empty string) to match pre-USK-788 rows that lack a recorded version. Mirrors the `manage` tool's filter axis (USK-792).
- **method** (string): HTTP method filter for flows (e.g. `"GET"`, `"POST"`).
- **url_pattern** (string): URL substring match for flows (e.g. `"/api/"`).
- **status_code** (integer): HTTP status code filter for flows and fuzz_results (e.g. `200`, `404`).
- **blocked_by** (string): Filter for blocked flows (e.g. `"target_scope"`, `"intercept_drop"`, `"rate_limit"`, `"safety_filter"`).
- **origin** (string): Stream origin classification filter (`"proxy"` for live MITM traffic, `"resend"` for resend_* MCP tool streams, `"fuzz"` reserved for fuzz campaigns).
- **state** (string): Flow lifecycle state filter (`"active"`, `"complete"`, `"error"`).
- **conn_id** (string): Connection ID filter for flows (exact match). Use to find all flows from the same connection.
- **host** (string): Host filter for flows. Matches against the `server_addr` or the host portion of the request URL (e.g. `"example.com"`).
- **direction** (string): Message direction filter for the `messages` resource (`"send"` or `"receive"`).
- **body_contains** (string): Response body substring filter for fuzz_results.
- **outliers_only** (boolean): Return only outlier fuzz results (detected by status_code, body_length, or timing deviation).
- **status** (string): Job status filter for fuzz_jobs (`"running"`, `"paused"`, `"completed"`, `"cancelled"`, `"error"`).
- **tag** (string): Job tag filter for fuzz_jobs (exact match).

### fields (array of strings, optional)
Controls which fields are returned in the response for `fuzz_jobs` and `fuzz_results` resources.
If omitted, all fields are returned. Metadata fields (`count`, `total`, `summary`) are always included.

### sort_by (string, optional)
Field to sort results by.
- For `flows` resource: `timestamp` (default), `duration_ms`.
- For `fuzz_results` resource: `index_num` (default), `status_code`, `duration_ms`, `response_length`.

### limit (integer, optional)
Maximum number of items to return. Default: 50, max: 1000. Applies to `flows`, `messages`, `fuzz_jobs`, and `fuzz_results`.

### offset (integer, optional)
Number of items to skip for pagination. Must be >= 0. Applies to `flows`, `messages`, `fuzz_jobs`, and `fuzz_results`.

### decode_bodies (boolean, optional, default `true`)
Decode HTTP `Content-Encoding` (`gzip`, `deflate`, `br`, `zstd`) bodies in `flow` and `messages` responses. When `true`, additive `*_body_decoded` / `*_body_encoding_applied` fields are populated alongside the original wire-form `*_body` fields. Set to `false` to skip decompression.

The original (compressed) body is always returned in `*_body` regardless of this flag, preserving wire fidelity for downstream tools and `resend_*`. Decode failures (unknown codec, malformed input, decoded size > 16 MiB cap, multi-codec chain) surface a `*_body_decode_anomaly` field; the wire-form body is left intact.

## Resource Details

### flows
List recorded proxy flows with optional filtering and pagination.

Each flow entry includes a `protocol_summary` field with protocol-specific information (dispatched by canonical `Stream.Protocol`):
- **`ws`**: `message_count`, `last_frame_type` (Text/Binary/Close/Ping/Pong)
- **`grpc`, `grpc-web`**: `service`, `method`, `grpc_status`, `grpc_status_name`
- **`raw`**: `send_bytes`, `receive_bytes`
- **`http`, `sse`, `tls-handshake`**: no protocol_summary entry

Returns: `flows[]` (id, protocol, state, method, url, status_code, message_count, protocol_summary, timestamp, duration_ms), `count`, `total`.

### flow
Get full details of a single flow including request/response headers, bodies, and connection info.

Flow state indicates the lifecycle stage:
- `"active"`: In progress (send recorded, awaiting receive)
- `"complete"`: Finished successfully
- `"error"`: Failed (e.g. 502 error, upstream connection failure)

When intercept/transform modifies a request, the flow contains variant messages. The `original_request` field is populated with the pre-modification request data for diff comparison. The main request fields show the modified (actually sent) version.

For streaming flows (message_count > 2), the response includes:
- `message_preview`: The first 10 messages with full details (body, metadata, etc.)
- `message_count`: Total number of messages in the flow
- `protocol_summary`: Protocol-specific summary information

Use the `messages` resource with `limit`/`offset` to page through all messages.

Requires: `id` (flow ID).

Returns: id, conn_id, protocol, state, method, url, request/response headers and bodies, raw bytes (base64), connection info, protocol_summary, message_preview (for streaming), original_request (for variant flows), timestamps.

When `decode_bodies` is `true` (the default) and the body has a recognised `Content-Encoding`, the response also includes `request_body_decoded` / `response_body_decoded` (plaintext after Output Filter masking), `request_body_decoded_encoding` / `response_body_decoded_encoding` (`text` or `base64`), `request_body_encoding_applied` / `response_body_encoding_applied` (codec name, e.g. `gzip`). On decode failure, `request_body_decode_anomaly` / `response_body_decode_anomaly` carry `{type, detail}` (`unknown_encoding`, `malformed`, `size_exceeded`, `chain_rejected`, `truncated_decode`).

### messages
Get paginated messages within a flow. Supports direction filtering for streaming protocols.

Requires: `id` (flow ID). Supports `limit`, `offset`, and `filter.direction`.

Returns: `messages[]` (id, sequence, direction, method, url, status_code, headers, body, body_encoding, metadata, timestamp), `count`, `total`.

- **body_encoding**: `"text"` for UTF-8 safe bodies, `"base64"` for binary content.
- **metadata**: Protocol-specific fields (e.g. WebSocket `opcode`, gRPC `service`/`method`/`grpc_status`).

### status
Get current proxy status and health metrics. No additional parameters.

Returns: running, listen_addr, active_connections, total_flows, db_size_bytes, uptime_seconds, ca_initialized, tls_fingerprint.

### config
Get current configuration including upstream proxy, TLS passthrough, TCP forwards, enabled protocols, and runtime knobs. No additional parameters.

Returns: upstream_proxy, tls_passthrough (patterns, count), tcp_forwards (port->target map), enabled_protocols (list), socks5_enabled, client_cert, safety_filter (enabled, input_rules, output_rules), max_connections, peek_timeout_ms, request_timeout_ms, tls_fingerprint, capture_scope (includes, excludes).

> Note: `target_scope` (transmission gate) is intentionally NOT echoed here — it is owned by the `security` MCP tool and queried via `security` with `action: "get_target_scope"`. `capture_scope` (recording-only filter, USK-776) IS echoed here.

### ca_cert
Get the CA certificate PEM, metadata, and persistence state. No additional parameters.

Returns: pem, fingerprint, subject, not_after, persisted, cert_path, install_hint.

- **persisted** (boolean): Whether the CA certificate is saved to disk.
- **cert_path** (string): File path of the persisted CA certificate (empty if ephemeral).
- **install_hint** (string): Guidance for installing the CA certificate into the trust store (empty if ephemeral).

### intercept_queue
List intercepted requests, responses, and WebSocket frames currently waiting in the intercept queue.

Supports `limit` for limiting the number of returned items.

Each item has a `protocol` field (`"http"` or `"websocket"`) and a `phase` field (`"request"`, `"response"`, or `"websocket_frame"`).

Returns for HTTP items: `items[]` (id, phase, protocol, method, url, status_code, headers, body, body_encoding, timestamp, matched_rules), `count`.

Returns for WebSocket items: `items[]` (id, phase, protocol, opcode, direction, flow_id, upgrade_url, sequence, body, body_encoding, timestamp, matched_rules), `count`.

## Usage Examples

### List all flows
```json
{"resource": "flows"}
```

### Filter flows by protocol
```json
{
  "resource": "flows",
  "filter": {"protocol": "ws"}
}
```

### Filter gRPC flows
```json
{
  "resource": "flows",
  "filter": {"protocol": "grpc"}
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

### Filter flows by connection ID
```json
{
  "resource": "flows",
  "filter": {"conn_id": "abc-conn-123"}
}
```

### Filter flows by host
```json
{
  "resource": "flows",
  "filter": {"host": "example.com"}
}
```

### Filter flows by scheme (TLS flows)
```json
{
  "resource": "flows",
  "filter": {"scheme": "https"}
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
Get results for a specific fuzz job with filtering, sorting, pagination, aggregate statistics, and outlier detection.

Requires: `fuzz_id` (fuzz job ID). Supports `filter.status_code`, `filter.body_contains`, `filter.outliers_only`, `fields`, `sort_by`, `limit`, and `offset`.

The `summary` includes:
- **total_results**: Total number of matching results.
- **statistics**: Aggregate statistics with `status_code_distribution` (map of status code to count), `body_length` and `timing_ms` distributions (each with `min`, `max`, `median`, `stddev`).
- **outliers**: Result IDs that deviate from the baseline:
  - `by_status_code`: Results with a status code different from the most frequent one.
  - `by_body_length`: Results with body length outside median +/- 2 standard deviations.
  - `by_timing`: Results with timing outside median +/- 2 standard deviations.

Use `filter.outliers_only: true` to return only outlier results.

Returns: `results[]` (id, fuzz_id, index, flow_id, payloads, status_code, response_length, duration_ms, error), `count`, `total`, `summary` (total_results, statistics, outliers).

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

### Get fuzz results with aggregate statistics and outliers
```json
{
  "resource": "fuzz_results",
  "fuzz_id": "fuzz-789"
}
```

### Get only outlier fuzz results
```json
{
  "resource": "fuzz_results",
  "fuzz_id": "fuzz-789",
  "filter": {"outliers_only": true}
}
```

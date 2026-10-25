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
- **protocol** (string): Protocol filter for flows. Canonical values only (`"http"`, `"ws"`, `"grpc"`, `"grpc-web"`, `"sse"`, `"raw"`, `"tls-handshake"`); legacy spellings (`"HTTP/1.x"`, `"HTTPS"`, `"HTTP/2"`, `"WebSocket"`, `"gRPC"`, `"gRPC-Web"`, `"TCP"`, `"SOCKS5+*"`) are rejected as of USK-705. The value is matched exactly against `Stream.Protocol` (no family expansion), so rows recorded under a legacy spelling (from older databases or JSONL imports) are not returned.
- **scheme** (string): `Stream.Scheme` filter — wire-observed handshake transport. Accepted values: `"https"`, `"http"`, `"tcp"`. Use `"https"` to find all TLS flows (HTTP/1.x, HTTP/2, gRPC, WS-over-TLS). To target WebSocket flows use `filter.protocol="ws"`; combine `protocol="ws"` with `scheme="https"` for WS-over-TLS only. Values `"ws"` / `"wss"` are rejected as of USK-864 (per USK-848, Stream.Scheme records the handshake transport, not the application protocol).
- **http_version** (string): HTTP wire-version filter for flows (`"http/1.0"`, `"http/1.1"`, `"h2"`, `"h2c"`). Matches the stream's head HTTP version — the value shown as `flows[].http_version` (a WebSocket / SSE stream matches the version of its Upgrade / request head). Use `""` (explicit empty string) to match streams with no HTTP version — non-HTTP protocols (gRPC, gRPC-Web, raw, tls-handshake), rows recorded before the field existed, and streams with no recorded flows. Mirrors the `manage` tool's filter axis (USK-792).
- **method** (string): HTTP method filter for flows (e.g. `"GET"`, `"POST"`).
- **url_pattern** (string): URL substring match for flows (e.g. `"/api/"`).
- **status_code** (integer): HTTP status code filter for flows and fuzz_results (e.g. `200`, `404`).
- **blocked_by** (string): Filter for blocked flows. One of `"target_scope"`, `"intercept_drop"`, `"intercept_cancelled"`, `"rate_limit"`, `"safety_filter"`, `"budget"`, `"capacity"`. `"intercept_cancelled"` streams are intercept holds that ended without an `intercept` action because the connection or proxy went away while held (`proxy_stop`, session teardown, the peer direction failing): state `error`, the Stream `id` equals the held entry's `stream_id`, and — like the other blocked_by values — no Flow rows carry the held content. `"capacity"` streams are connections the proxy refused because `max_connections` was reached: state `error`, no `server_addr` (no upstream socket existed), `tags.target` = the request-target as received (CONNECT authority, HTTP/1.x request-target — a full URL in absolute form — or TCP forward target); `filter.host` matches it. They are written at most ~10/s and only for targets inside `capture_scope`; the full count is in `status` → `connection_rejections`.
- **origin** (string): Stream origin classification filter (`"proxy"` for live MITM traffic, `"resend"` for resend_* MCP tool streams, `"fuzz"` reserved for fuzz campaigns).
- **state** (string): Flow lifecycle state filter (`"active"`, `"complete"`, `"error"`).
- **conn_id** (string): Connection ID filter for flows (exact match). Use to find all flows from the same connection.
- **listener_name** (string): Listener filter for flows (exact match). Selects the streams accepted by the listener started with `proxy_start` `name` (`"default"` when no name was given); TCP-forward streams carry their parent listener's name. Streams from `resend_*` / fuzz and rows recorded before this field existed have an empty `listener_name` and never match.
- **host** (string): Host filter for flows. Matches against the `server_addr`, the requested destination in `tags.target` (error / audit streams that never reached an upstream socket: `upstream_tls_error`, `client_tls_error`, proxy-closed request heads, `capacity` rejections), or the host portion of the request URL (e.g. `"example.com"`). Because `server_addr` is the upstream socket's peer, a stream reached through an upstream proxy matches the proxy's host here.
- **direction** (string): Message direction filter for the `messages` resource (`"send"` or `"receive"`).
- **body_contains** (string): Response body substring filter (byte-exact, case-sensitive). Matches when the substring appears in either the raw recorded receive body or its Content-Encoding-decoded form (`gzip`, `x-gzip`, `deflate`, `br`, `zstd`). Stacked / unknown codings and bodies that fail to decode (including bodies truncated at storage time) are matched on the raw bytes only. fuzz_results only; rejected on `flows`.
- **outliers_only** (boolean): Return only outlier fuzz results (detected by status_code, body_length, or timing deviation). fuzz_results only; rejected on `flows`.
- **status** (string): Job status filter (`"running"`, `"paused"`, `"completed"`, `"cancelled"`, `"error"`). fuzz_jobs only; rejected on `flows` (use `state` for the flow lifecycle state).
- **tag** (string): Exact-match tag filter (case-sensitive, not trimmed). fuzz_jobs: the job tag. flows: `Stream.Tags["tag"]`, the label `resend_*` / `fuzz_*` record from their `tag` parameter. Attempts that failed before completion may be untagged.

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
Decode protocol-specific bodies in `flow` and `messages` responses. When `true`, additive `*_body_decoded` / `*_body_encoding_applied` fields are populated alongside the original wire-form `*_body` fields. Set to `false` to skip all decoding.

Three decode paths are supported:

- **HTTP `Content-Encoding`** (`gzip`, `deflate`, `br`, `zstd`): the wire-form body is decompressed into `*_body_decoded` with `*_body_decoded_encoding` set to `text` or `base64`, and `*_body_encoding_applied` set to the codec name (e.g. `gzip`).
- **gRPC schema-aware proto** (USK-923): when the flow's `(grpc_service, grpc_method)` matches a schema registered via the `grpc_schema` tool, gRPC Data envelopes decode via `protoreflect.DynamicMessage` + `protojson` with the original `.proto` field names. `*_body_decoded_encoding="proto-json"`. `*_body_encoding_applied="proto-json"`. The same JSON shape is accepted back by `resend_grpc` (`body_encoding="proto-json"`) — note that `protojson` drops fields not in the schema, so the round-trip is lossy for unknown wire fields (call `docs(topic="grpc_schema")`).
- **gRPC schemaless proto** (USK-922): when no schema matches the flow, gRPC Data envelopes (`metadata.grpc_event="data"`) — including gRPC and gRPC-Web — get a schemaless JSON projection of the proto wire payload via `internal/encoding/protobuf.Decode`. `*_body_decoded` contains JSON with sorted keys formatted as `"<fieldNumber hex>:<ordinal hex>:<wireType>"` (e.g. `"0001:0000:String"`, `"0002:0001:Varint"`, `"0003:0002:embedded message"`). `*_body_decoded_encoding="proto-schemaless-json"`. `*_body_encoding_applied="proto-schemaless"`. The same JSON shape is accepted back by `resend_grpc` (`body_encoding="proto-schemaless-json"`) for round-trip mutation without hand-computing wire bytes.

The original wire-form body is always returned in `*_body` regardless of this flag, preserving wire fidelity for downstream tools and `resend_*`. Decode failures surface a `*_body_decode_anomaly` field; the wire-form body is left intact. Anomaly types include `unknown_encoding`, `malformed`, `size_exceeded`, `chain_rejected`, `truncated_decode` (HTTP path), `proto_malformed` (gRPC schemaless path), and `proto_schema_mismatch` (gRPC schema-aware hit but wire bytes did not parse against the registered descriptor — the response then falls back to schemaless and surfaces this anomaly alongside).

> **Schemaless gRPC heuristic ambiguity**: the proto wire format encodes embedded messages, packed-repeated varints, and raw bytes with the same wire type (length-delimited). The schemaless decoder picks one interpretation heuristically (printable UTF-8 → `String`; otherwise embedded → repeated → bytes); ambiguous payloads may surface as the wrong type. Register a schema via the `grpc_schema` tool to switch the affected service to schema-aware (`proto-json`) decoding; until then, use the raw wire bytes (`body` with `body_encoding="base64"`) when the schemaless projection is ambiguous.

### include_bodies (boolean, optional, default `true`)
Include message body fields in the `flow` and `messages` responses. Set to `false` to suppress every body field (`*_body`, `*_body_encoding`, `*_body_decoded*`, `raw_request`, `raw_response`, and the per-message `raw_bytes` / `raw_bytes_encoding`) and return metadata only. Headers, status, method, URL, timestamps, and the record-time `*_body_truncated` flag are preserved.

Mirrors `manage.export_flows.include_bodies`. Useful when a single flow's body is large enough to push the MCP tool response over the per-tool token limit; the response then advertises that suppression occurred via `*_body_truncated_by_query=true` and `*_body_original_size` for each side, so the caller knows what was elided.

### body_max_bytes (integer, optional, default `0`)
Cap each per-side body — and each per-side decoded body, independently — to at most this many bytes. `0` disables the cap. Truncation is applied to the body **byte slice before base64 encoding** so the response never base64-mid-quadruple-splits.

The same cap applies to the per-message `raw_bytes` of a bodyless message (see [messages](#messages)); `raw_bytes_size` then still reports the stored length.

When the cap fires, the response sets `*_body_truncated_by_query=true` and reports the pre-truncation byte length under `*_body_original_size` (wire-form side) and / or `*_body_decoded_original_size` (decoded side). Headers / metadata are unaffected. Distinct from the record-time `*_body_truncated` flag, which reflects the storage-time `MaxBodySize` cap from the pipeline `RecordStep`.

The `messages` resource also exposes the same fields (`body_truncated`, `body_truncated_by_query`, `body_original_size`, `body_decoded_original_size`) per message entry. The `body_truncated` field carries the record-time `Flow.BodyTruncated` value regardless of the query-time params.

When the caller does not pass either `include_bodies` or `body_max_bytes` and the response contains a body above 256 KiB, the result includes a one-line `advisory` field suggesting the params.

## Resource Details

### flows
List recorded proxy flows with optional filtering and pagination.

Each flow entry includes a `protocol_summary` field with protocol-specific information (dispatched by canonical `Stream.Protocol`):
- **`ws`**: `message_count`, `last_frame_type` (Text/Binary/Close/Ping/Pong)
- **`grpc`, `grpc-web`**: `service`, `method`, `grpc_status`, `grpc_status_name`
- **`raw`**: `send_bytes`, `receive_bytes`
- **`http`, `sse`, `tls-handshake`**: no protocol_summary entry

Returns: `flows[]` (id, protocol, http_version, state, method, url, status_code, message_count, protocol_summary, timestamp, duration_ms), `count`, `total`.

`http_version` is the wire HTTP version of the head message (`http/1.0`, `http/1.1`, `h2`, `h2c`), identical to the `flow` resource's. WebSocket and SSE streams report the version of their HTTP head. It is absent for non-HTTP streams (gRPC, gRPC-Web, raw, tls-handshake) and for rows recorded before the field existed. Unlike `message_count`, it does not depend on `filter.wire_level`.

### flow
Get full details of a single flow including request/response headers, bodies, and connection info.

Flow state indicates the lifecycle stage:
- `"active"`: In progress (send recorded, awaiting receive)
- `"complete"`: Finished successfully
- `"error"`: Failed (e.g. 502 error, upstream connection failure)

HTTP/1.x request heads (including `CONNECT` requests) the proxy itself closed before the request was complete are recorded as `"error"` flows with `tags.closed_by = "proxy"` and one of these `failure_reason` values:
- `request_head_timeout`: the request line + headers did not arrive within `request_timeout_ms` (`tags.request_timeout_ms` is the value in force). A keep-alive connection that closes or goes idle with zero bytes of a next request is not recorded.
- `request_line_too_long`: the request line exceeded the parser limit; the proxy answered `414 URI Too Long`.
- `request_header_too_large`: the header section exceeded the parser limit; the proxy answered `431 Request Header Fields Too Large`.

- `connect_request_timeout`: a `CONNECT` request did not arrive within `request_timeout_ms` (`tags.phase = "connect_request"`; no response is sent). A `CONNECT` request line or header section over the parser limit is recorded as `request_line_too_long` / `request_header_too_large` with `tags.phase = "connect_request"`, also without a response (the connection is closed silently, not answered 414 / 431). `tags.target` is set only when the request-target was a complete `host:port`.

`tags.phase` is `request_line` or `headers` (or `connect_request`, above). `raw_request` holds the bytes received, capped at `max_raw_capture_size`; the send message's `metadata.raw_truncated = "true"` marks a capture cut at the cap and `metadata.raw_captured_bytes` gives its length. For 414 / 431 the returned response is in `response_status_code` / `raw_response` (message `metadata.proxy_generated = "true"`); `tags.wrote_response = "false"` means the response could not be written. A plain-HTTP forward request whose first 4000 bytes did not complete the header section within `request_timeout_ms` is recorded as `request_head_timeout` together with the `400 Bad Request` the proxy returned for it (same `raw_response` / `proxy_generated` shape). Such a flow shares `conn_id` with the earlier requests on the same connection. These flows are written even when the client never completes a request, so a client can create them by sending a partial or oversized request head; `capture_scope` (which hosts are recorded) and `max_raw_capture_size` (how many bytes each flow keeps) bound what is stored.

A client-side TLS MITM handshake (CONNECT, SOCKS5 or `tcp_forwards` with `tls: true`) that did not finish within `request_timeout_ms` keeps `failure_reason: "client_tls_error"` and additionally carries `tags.phase = "tls_handshake"`, `tags.closed_by = "proxy"`, `tags.timeout = "request_timeout"` and `tags.request_timeout_ms`. A `client_tls_error` without these tags was ended by the client (e.g. it rejected the MITM certificate). On `tcp_forwards` with `tls: true` a connection that never sends a byte also ends this way, so it is recorded with the timeout tags too.

The top-level fields (`method`, `url`, `request_headers`, `request_body`, `raw_request`, and the `response_*` / `raw_response` counterparts) come from the head message of each direction: the request and the final response of an HTTP exchange (an interim `1xx` response such as `100 Continue` or `103 Early Hints` is skipped; `101` is not), the Upgrade request / `101` (or the `CONNECT` request / `2xx` for WebSocket over HTTP/2) of a WebSocket, the Start message of a gRPC / gRPC-Web stream (`url` = the RPC path, `request_headers` = the request metadata, `response_status_code` = the HTTP `:status`; the protobuf payload is on the Data messages), the request / response head of an SSE stream, and the first chunk of each direction of a Raw TCP stream. Each side's fields come from that one message. Frames, Data messages, events and later chunks are in `message_preview` / `messages`. The `flows` list reports `method` / `url` / `status_code` from the same head messages. `filter.wire_level` does not change the top level: it is always built from semantic messages.

When intercept/transform modifies a head message (an HTTP request or response, a WebSocket Upgrade request / `101`, a gRPC Start), the flow contains a variant pair for it. `original_request` / `original_response` hold the pre-modification message for diff comparison, and the top-level fields show the modified (actually sent) version. `original_request` / `original_response` appear only for such a variant pair; an unmodified flow has neither, however many messages it has. A modified frame, Data message or event is not reflected at the top level: both rows of its pair are in `message_preview` / `messages`, with `metadata.variant = "original"` and `metadata.variant = "modified"` at the same `sequence` and `direction`.

For streaming flows (message_count > 2), the response includes:
- `message_preview`: The first 10 messages with full details (body, metadata, etc.)
- `message_count`: Total number of messages in the flow
- `protocol_summary`: Protocol-specific summary information

Use the `messages` resource with `limit`/`offset` to page through all messages.

Requires: `id` (flow ID).

Returns: id, conn_id, protocol, http_version (wire version of the head message; absent for non-HTTP streams), state, listener_name, method, url, request/response headers and bodies, raw bytes (base64), connection info, protocol_summary, message_preview (for streaming), original_request / original_response (only when a head message was modified), timestamps.

Connection info (`conn_info`) on live streams:
- `client_addr`: the peer address of the client socket the listener accepted.
- `server_addr`: the peer address of the upstream socket the proxy actually connected — never a requested hostname. When `upstream_proxy` is set this is the upstream proxy's address, not the final destination (the destination is in `url`). It is filled from the first upstream response envelope, so a stream that never received anything from upstream (dial failure, blocked before forwarding, `upstream_tls_error`, `client_tls_error`, proxy-closed request heads, `capacity` rejections) has none; for those error / audit streams the requested destination is `tags.target`.
- `upstream_proxy`: the upstream proxy the connection went through, as `scheme://host:port` with credentials removed; absent for a direct connection.

`listener_name` (also on each `flows[]` entry) is the name of the listener that accepted the connection — the `proxy_start` `name`, or `"default"`. On live streams it comes from configuration, not from the traffic, so a client cannot change it. Streams brought in with `manage` `import_flows` keep whatever `listener_name` / `upstream_proxy` the imported file contains.

The `url` field (here, in `flows[]`, in `messages[]` and in `original_request`) carries the request path in wire form — percent-encoding exactly as sent, not decoded. A JSON string cannot carry bytes that are not valid UTF-8, so any such path or query bytes are shown `%XX`-escaped (upper-case hex, e.g. the wire byte `0xFF` appears as `%FF`); every other byte is verbatim. `resend_http` with `flow_id` still replays the original wire bytes, not the escaped text.

When `decode_bodies` is `true` (the default) and the body is decodable, the response also includes `request_body_decoded` / `response_body_decoded` (plaintext / proto-json / proto-schemaless JSON after Output Filter masking), `request_body_decoded_encoding` / `response_body_decoded_encoding` (`text`, `base64`, `proto-json`, or `proto-schemaless-json`), and `request_body_encoding_applied` / `response_body_encoding_applied` (codec name — `gzip` / `br` / `deflate` / `zstd` for HTTP `Content-Encoding`, `proto-json` for schema-aware gRPC Data envelopes, or `proto-schemaless` for schemaless gRPC Data envelopes). On decode failure, `request_body_decode_anomaly` / `response_body_decode_anomaly` carry `{type, detail}`: HTTP path uses `unknown_encoding`, `malformed`, `size_exceeded`, `chain_rejected`, `truncated_decode`; gRPC path uses `proto_malformed` or `proto_schema_mismatch` (schema-aware path hit but wire bytes failed to parse — schemaless fallback still runs). gRPC Data envelopes are not head messages, so their decoded forms appear on the `message_preview` / `messages` entries (`body_decoded`, `body_decoded_encoding`, `body_encoding_applied`, `body_decode_anomaly`), not at the top level.

### messages
Get paginated messages within a flow. Supports direction filtering for streaming protocols.

Requires: `id` (flow ID). Supports `limit`, `offset`, and `filter.direction`.

Returns: `messages[]` (id, sequence, direction, method, url, status_code, headers, body, body_encoding, metadata, timestamp, body_truncated, optionally raw_bytes / raw_bytes_encoding / raw_bytes_size for a bodyless message, optionally body_truncated_by_query / body_original_size / body_decoded_original_size when `include_bodies` / `body_max_bytes` apply), `count`, `total`, optional `advisory`.

- **body**: The L7 body only — never the raw wire bytes. A message without a body (an HTTP/1.x or HTTP/2 `GET`, a WebSocket upgrade or `101`, gRPC Start / End, a WebSocket frame with an empty payload) has `body=""` and no `body_original_size`. Raw TCP chunks carry their bytes in `body`.
- **body_encoding**: `"text"` for UTF-8 safe bodies, `"base64"` for binary content.
- **raw_bytes** / **raw_bytes_encoding** / **raw_bytes_size**: Present only on a message that has no body but has recorded wire bytes. `raw_bytes` is the recorded wire bytes, always base64 (`raw_bytes_encoding="base64"`) — e.g. the HTTP/1.x request head, or the HPACK-encoded HEADERS block for HTTP/2 / gRPC. `raw_bytes_size` is the recorded length. Wire-level overlay rows (`filter.wire_level` = `h2-frame` / `h1-chunk` / `grpc-lpm-frame` / `grpcweb-base64`) carry their frame bytes here, not in `body`. Body-bearing messages do not repeat their wire bytes. `include_bodies=false` omits `raw_bytes` (keeps `raw_bytes_size`); `body_max_bytes` caps it and sets `body_truncated_by_query=true`. Output Filter masking applies (call `docs(topic="security")`). The same fields appear on `flow`'s `message_preview` entries.
- **metadata**: Protocol-specific fields (e.g. WebSocket `opcode`, gRPC `service`/`method`/`grpc_status`).
- **body_truncated**: Record-time truncation flag mirrored from `Flow.BodyTruncated` — set when the storage-time `MaxBodySize` cap fired.
- **body_truncated_by_query**: Response-time truncation flag set when `include_bodies=false` or `body_max_bytes=N` capped the bytes returned to the caller. Distinct from `body_truncated`.

### status
Get current proxy status and health metrics. No additional parameters.

Returns: running, listen_addr, active_connections, total_flows, db_size_bytes, uptime_seconds, ca_initialized, tls_fingerprint, export_dir (the directory `manage` export_flows / import_flows file paths are confined to), connection_rejections (connections refused because `max_connections` was reached, counted since server start: `total`, `last_at`, `by_kind` {http1, connect, socks5, http2, tcp, unknown}, `recent[]` newest first (at, listener, forward_port, remote_addr, detected_kind, method, target, target_truncated, wrote_503, max_connections, recorded), `unrecorded` (audit streams shed by the write rate cap or a full recorder queue), `out_of_scope` (not recorded because `capture_scope` excludes the target, or the target names no host while a hostname exclude rule is set)).

### config
Get current configuration including upstream proxy, TLS passthrough, TCP forwards, and runtime knobs. No additional parameters.

Returns: upstream_proxy, tls_passthrough (patterns, count), tcp_forwards (port->target map), socks5_enabled, client_cert, safety_filter (enabled, input_rules, output_rules), max_connections, peek_timeout_ms, request_timeout_ms, tls_fingerprint, capture_scope (includes, excludes), export_dir (the directory `manage` export_flows / import_flows file paths are confined to).

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

### Filter flows by listener
```json
{
  "resource": "flows",
  "filter": {"listener_name": "worker-a"}
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

`filter.body_contains` searches every receive flow of the result's stream, raw and Content-Encoding-decoded (gzip / deflate / br / zstd), so a payload reflected in a compressed response is found. When it is set, `total`, `summary`, and `outliers_only` are all computed over the body-matched results.

The match runs against the recorded bytes (raw and decoded) **before** Output Filter masking, so a `body_contains` hit can confirm content that `query` output shows masked; the masking applies only to returned data, not to the filter predicate.

Cost: with `body_contains`, every candidate's receive bodies are read and decoded (up to 16 MiB each) on every call, including each page of a paginated listing. Narrow the candidate set with `filter.status_code` where possible.

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

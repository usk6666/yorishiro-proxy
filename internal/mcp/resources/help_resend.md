# resend

Resend and replay recorded proxy requests with optional mutations.

## Parameters

### action (string, required)
The action to perform. One of: `resend`, `resend_raw`, `tcp_replay`, `compare`.

> **Note:** `replay` is a deprecated alias for `resend`; `replay_raw` is a deprecated alias for `resend_raw`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### resend
Resend a recorded HTTP/HTTP2/WebSocket request with optional mutations. Records the result as a new flow.

**Multi-protocol support:**
- **HTTP/1.x and HTTPS**: Standard HTTP resend with full mutation support.
- **HTTP/2**: Resends the request using HTTP/1.1 (fallback). All mutation options apply.
- **WebSocket**: Requires `message_sequence` to identify the message to resend. Sends the message body over a raw TCP connection. Supports `override_body`, `override_body_base64`, `target_addr`, and `use_tls`.

**Parameters:**
- **flow_id** (string, required): ID of the flow to resend.
- **message_sequence** (integer, optional): Message sequence number for WebSocket/streaming resend. Required for WebSocket flows.
- **override_method** (string, optional): Override the HTTP method (e.g. `"POST"`).
- **override_url** (string, optional): Override the target URL. Must include scheme and host (e.g. `"https://other.target.com/api/v2"`).
- **override_headers** (object, optional): Header overrides as key-value pairs. Replaces matching headers.
- **add_headers** (object, optional): Headers to add. Appended to existing values for the same key, enabling multi-value headers.
- **remove_headers** (array of strings, optional): Header names to remove.
- **override_body** (string, optional): Override the request body (text).
- **override_body_base64** (string, optional): Override the request body (Base64-encoded binary). Mutually exclusive with `override_body`.
- **body_patches** (array, optional): Partial body modifications. Each patch is either `{"json_path": "$.key", "value": "new"}` or `{"regex": "pattern", "replace": "replacement"}`. An optional `"encoding"` array can be added to apply codec transformations to the patch value before applying. Codecs are applied in order as a pipeline — e.g. `["url_encode_query", "base64"]` first URL-encodes the value, then Base64-encodes the result. Maximum 10 codecs per chain. Ignored when `override_body` or `override_body_base64` is set. Available codecs: base64, base64url, url_encode_query, url_encode_path, url_encode_full, double_url_encode, hex, html_entity, html_escape, unicode_escape, md5, sha256, lower, upper.
- **override_host** (string, optional): TCP connection target as `"host:port"`, independent of the URL host. Subject to SSRF protection.
- **follow_redirects** (boolean, optional): Follow HTTP redirects automatically (default: `false`).
- **timeout_ms** (integer, optional): Request timeout in milliseconds (default: `30000`).
- **dry_run** (boolean, optional): If `true`, return a preview of the modified request without actually sending it.
- **tag** (string, optional): Tag to attach to the result flow for identification.

**Header mutation order:** `remove_headers` -> `override_headers` -> `add_headers`.

**Body mutation priority:** `override_body`/`override_body_base64` (full replace) > `body_patches` (partial) > original body.

Returns: new_flow_id, status_code, response_headers, response_body, response_body_encoding, duration_ms, tag.

In dry-run mode, returns: dry_run, request_preview (method, url, headers, body, body_encoding).

### resend_raw
Resend the raw bytes from a recorded flow over TCP/TLS. Useful for testing HTTP smuggling or protocol-level issues.

**Parameters:**
- **flow_id** (string, required): ID of the flow to resend.
- **target_addr** (string, optional): Target address as `"host:port"`. Defaults to the original flow's target.
- **use_tls** (boolean, optional): Force TLS on/off. Defaults to the original flow's protocol.
- **timeout_ms** (integer, optional): Request timeout in milliseconds (default: `30000`).

Returns: response_data (base64), response_size, duration_ms.

### tcp_replay
Replay a Raw TCP flow by sending all recorded send messages sequentially to the target. Records the exchange as a new TCP flow.

**Parameters:**
- **flow_id** (string, required): ID of the TCP flow to replay.
- **target_addr** (string, optional): Target address as `"host:port"`. Defaults to the original flow's server address.
- **use_tls** (boolean, optional): Use TLS for the connection. Default: `false`.
- **timeout_ms** (integer, optional): Connection timeout in milliseconds (default: `30000`).
- **tag** (string, optional): Tag to attach to the result flow.

Returns: new_flow_id, messages_sent, messages_received, total_bytes_sent, total_bytes_received, duration_ms, tag.

### compare
Compare two flows structurally. Returns a summary of differences in status code, headers, body length, timing, and (for JSON responses) key-level diffs. Designed as a triage tool — use `query messages` for full body content.

**Parameters:**
- **flow_id_a** (string, required): ID of the first flow to compare.
- **flow_id_b** (string, required): ID of the second flow to compare.

Returns: status_code (a, b, changed), body_length (a, b, delta), headers_added, headers_removed, headers_changed, timing_ms (a, b, delta), body (content_type, identical, json_diff).

For JSON responses, `body.json_diff` includes: keys_added, keys_removed, keys_changed (top-level keys only).

For non-JSON responses, only `body.identical` and size delta are provided.

## Hooks (pre_send / post_receive)

The `resend` action supports optional hooks that execute macros before sending the request (`pre_send`) and after receiving the response (`post_receive`). Hooks are specified via the `hooks` parameter.

**Hook parameters:**
- **hooks.pre_send** (object, optional): Hook executed before the main request.
  - **macro** (string, required): Name of the stored macro to execute.
  - **vars** (object, optional): Runtime variable overrides for the macro.
  - **run_interval** (string, optional): When the hook fires. For pre_send: `"always"` (default), `"once"`, `"every_n"`, `"on_error"`.
  - **n** (integer): Interval count for `"every_n"`.
- **hooks.post_receive** (object, optional): Hook executed after the main response.
  - **macro** (string, required): Name of the stored macro to execute.
  - **vars** (object, optional): Runtime variable overrides for the macro.
  - **run_interval** (string, optional): When the hook fires. For post_receive: `"always"` (default), `"on_status"`, `"on_match"`.
  - **status_codes** (array of integers): Status codes for `"on_status"`.
  - **match_pattern** (string): Regex pattern for `"on_match"`.
  - **pass_response** (boolean, optional): Pass `__response_status` and `__response_body` as vars to the macro.

## Usage Examples

### Resend with method override
```json
{
  "action": "resend",
  "params": {
    "flow_id": "abc-123",
    "override_method": "PUT",
    "override_headers": {"Content-Type": "application/json"}
  }
}
```

### Raw TCP resend
```json
{
  "action": "resend_raw",
  "params": {
    "flow_id": "abc-123",
    "target_addr": "target.com:443",
    "use_tls": true
  }
}
```

### Replay Raw TCP flow
```json
{
  "action": "tcp_replay",
  "params": {
    "flow_id": "tcp-flow-456",
    "target_addr": "db.target.com:3306",
    "tag": "tcp-replay"
  }
}
```

### Dry-run preview
```json
{
  "action": "resend",
  "params": {
    "flow_id": "abc-123",
    "override_method": "POST",
    "body_patches": [{"json_path": "$.user.role", "value": "admin"}],
    "dry_run": true
  }
}
```

### Resend with encoded body patch
```json
{
  "action": "resend",
  "params": {
    "flow_id": "abc-123",
    "body_patches": [
      {"json_path": "$.token", "value": "test-payload", "encoding": ["base64"]},
      {"regex": "csrf_token=[^&]+", "replace": "csrf_token=injected", "encoding": ["url_encode_query"]}
    ]
  }
}
```

### Compare two flows
```json
{
  "action": "compare",
  "params": {
    "flow_id_a": "original-flow-123",
    "flow_id_b": "mutated-flow-456"
  }
}
```

### Resend WebSocket message
```json
{
  "action": "resend",
  "params": {
    "flow_id": "ws-flow-123",
    "message_sequence": 2,
    "target_addr": "ws.target.com:443",
    "use_tls": true
  }
}
```

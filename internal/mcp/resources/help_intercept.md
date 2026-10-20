# intercept

Act on an envelope held in the intercept queue: an HTTP request or response, a WebSocket frame, a gRPC Start / Data event, an SSE event, or a raw TCP chunk. Items are held by `intercept_rules` (see `proxy_start` / `configure`) and listed with `query` `resource: "intercept_queue"`.

## Parameters

### action (string, required)
One of `release`, `modify_and_forward`, `drop`.

### params (object, required)
Routing parameters. `params` is required for every action, and it accepts only these three fields:
- **intercept_id** (string, required): ID of the held item, taken from the `id` field of a `query` `resource: "intercept_queue"` item.
- **mode** (string, optional): `"structured"` (default) or `"raw"`. Only `modify_and_forward` reads it; `release` and `drop` ignore it. See "Raw override" below.
- **raw_override_base64** (string, optional): Base64-encoded bytes to forward when `mode` is `"raw"` (decoded size max 10 MiB). See "Raw override" below.

Modifications are **not** placed in `params`. They go in a top-level typed payload named after the held item's type:

| Held item (`protocol` in `intercept_queue`) | Payload key |
|---|---|
| `http` (HTTP/1.x or HTTP/2 request or response) | `http` |
| `websocket` | `ws` |
| `grpc_start` | `grpc_start` |
| `grpc_data` | `grpc_data` |
| `sse` | `sse` |
| `raw` | `raw` |

Send exactly the payload that matches the held item. A mismatch (for example a `ws` payload for an HTTP hold) is rejected with `held envelope is HTTP; expected http payload` and the item stays held, so you can retry. A `grpc_end` hold (trailers) cannot be modified: `release` or `drop` it. Every payload rejects unknown fields; omitted fields leave the held value unchanged.

### http (object, optional)
For an HTTP request or response.
- **method**, **scheme**, **authority**, **path**, **raw_query** (string): Request-side overrides. `raw_query` has no leading `?`.
- **status** (integer), **status_reason** (string): Response-side overrides. `status_reason` is the HTTP/1.x reason phrase.
- **headers** (array of `{name, value}`): The new header list. It **replaces the held header list in full** — it is not a merge, and there is no add / remove. To change one header, copy the held `http.headers` from `intercept_queue`, edit it, and send the whole list. On HTTP/1.x, order and duplicates follow your list. An entry whose name matches a held wire header ignoring case reuses that header, so the wire name casing is kept and only the value changes (`host` sent against a held `Host` goes out as `Host`); each held header is reused at most once. Any other entry is sent with the name exactly as you supply it. HTTP/2 lowercases header names on the wire (RFC 9113) and drops connection-specific headers (`connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`). An entry with an empty name, or with CR / LF in a name or value, is rejected; empty values are allowed.
- **trailers** (array of `{name, value}`): The new trailer list, with the same full-replacement rules as `headers`.
- **body** (string): The new body. On HTTP/1.x any body change drops `Transfer-Encoding` and sets `Content-Length` to the new length.
- **body_encoding** (string): `"text"` (default) or `"base64"`, for `body`.
- **body_patches** (array): Patches applied in order, after `body` if both are given. Each entry is either `{"json_path": "$.a.b", "value": ...}` (dot path into a JSON body; array indexes are not supported) or `{"regex": "...", "replace": "..."}` (`$1`-style group references). Either form takes an optional `encoding` codec chain applied to the value / replacement.

On HTTP/1.x there is no switch to keep the old framing after a body change. To send a mismatched `Content-Length` / `Transfer-Encoding` pair (request smuggling tests):
- Change **only** `headers`, not the body: your header list is sent as given (for example add `Content-Length` to a held chunked request) and the held body bytes go out unchanged.
- Write the whole request in a plugin hook with `phase="post_pipeline"` via `msg["raw"]`: HTTP/1.x sends those bytes verbatim, with no framing fix-up.
- Send hand-written request bytes with `fuzz_raw` (`override_bytes` plus `target_addr`; no `flow_id` needed). Its bytes reach the wire verbatim, as do `resend_raw`'s, but `resend_raw` replays only recorded raw TCP flows, not HTTP ones.

### ws (object, optional)
For a WebSocket frame.
- **opcode**: Frame type, by name — `text`, `binary`, `close`, `ping`, `pong`, `continuation` — or as a number 0-15. From the CLI, pass a name (`ws.opcode=text`); `ws.opcode=1` is sent as the string `"1"` and rejected, use `ws.opcode:=1` for a number.
- **fin** (boolean): FIN bit.
- **payload** (string): The new frame payload.
- **body_encoding** (string): `"text"` (default) or `"base64"`, for `payload`.
- **close_code** (integer, 0-65535), **close_reason** (string): For Close frames.

### grpc_start (object, optional)
For the start of a gRPC call (the HEADERS of one side).
- **service**, **method** (string): The `:path` is rebuilt from them. `:authority` and `:scheme` cannot be changed.
- **encoding** (string): `grpc-encoding`.
- **metadata** (array of `{name, value}`): The new metadata list, a full replacement with the same rules as `http.headers`.

### grpc_data (object, optional)
For one gRPC message.
- **payload** (string): The decompressed message bytes. The 5-byte length prefix is regenerated.
- **payload_encoding** (string): `"text"` (default) or `"base64"`.
- **compressed** (boolean): The compressed flag in the length prefix.
- **end_stream** (boolean): END_STREAM on the carrying HTTP/2 DATA frame.

### sse (object, optional)
For one Server-Sent Event.
- **event**, **id** (string): Must not contain CR or LF.
- **data** (string): `\n` splits it into several `data:` lines; CR is rejected.
- **retry_ms** (integer): Reconnection interval; `0` removes the `retry:` line.

### raw (object, optional)
For a raw TCP chunk. Use either `bytes_override` or `patches`, not both (sending both is rejected before the item is touched).
- **bytes_override** (string): Replacement bytes (max 10 MiB).
- **bytes_encoding** (string): `"text"` (default) or `"base64"`, for `bytes_override`.
- **patches** (array): Byte patches applied in order. Each entry is `{"offset": N, "data_base64": "..."}`, `{"find_base64": "...", "replace_base64": "..."}`, or `{"find_text": "...", "replace_text": "..."}`.

## Actions

### release
Forward the held item unchanged. Needs only `params.intercept_id`.

### modify_and_forward
Apply the typed payload and forward the result. The modified item is checked again against the target scope and the SafetyFilter before it is sent, and both the original and the modified variant are recorded.

### drop
Discard the held item.
- HTTP (request or response): the client receives `403 Forbidden` (`blocked_by: intercept_drop`).
- Native gRPC request Start / Data: the call ends with `grpc-status: 7` (PERMISSION_DENIED) and `grpc-message: blocked by intercept_drop`.
- WebSocket frames, gRPC-Web, gRPC responses, SSE events and raw chunks are discarded.

### Raw override
With `"params": {"mode": "raw", "raw_override_base64": "..."}`, `modify_and_forward` forwards the decoded bytes in place of the held item, without a typed payload. Use it only on `raw` holds — for those, `raw.bytes_override` does the same and is the preferred form. On other holds (HTTP, WebSocket, gRPC, SSE) it currently breaks the connection (tracked in USK-1169).

## Return value

`release` and `modify_and_forward` return `intercept_id`, `action`, `status` (`"released"` / `"forwarded"`), `protocol`, `direction`, `matched_rules`, `flow_id`, `stream_id` and `forwarded_at_unix_ms`. `drop` returns the same fields with `status: "dropped"` and without `forwarded_at_unix_ms`. If the upstream half-closes after a long hold, the stream is tagged `intercept_hold_outcome=upstream_closed_after_intercept_release` (inspect it with `query` `resource: "stream"`).

## Intercepted Item Fields

`query` `resource: "intercept_queue"` returns `items`, each with:
- **id**: The value for `params.intercept_id`.
- **protocol**: `http`, `websocket`, `grpc_start`, `grpc_data`, `grpc_end`, `sse` or `raw`. Except for `sse`, it names which of the fields below is present.
- **direction**: `send` (client to server) or `receive` (server to client).
- **held_at**, **matched_rules**, **flow_id**, **stream_id**.
- One of:
  - **http**: `method`, `scheme`, `authority`, `path`, `raw_query`, `status`, `status_reason`, `headers`, `trailers` (ordered `{name, value}` lists), `body`, `body_encoding`.
  - **ws**: `opcode` (lowercase name, e.g. `text`), `fin`, `masked`, `compressed`, `close_code`, `close_reason`, `payload`, `payload_encoding`.
  - **grpc_start**: `service`, `method`, `encoding`, `content_type`, `metadata`.
  - **grpc_data**: `service`, `method`, `compressed`, `end_stream`, `wire_length`, `payload`, `payload_encoding`.
  - **grpc_end**: `status`, `message`, `trailers`.
  - **raw**: `bytes`, `bytes_encoding`.
- **raw_bytes_available**, **raw_bytes_size**, **raw_bytes**, **raw_bytes_encoding**: The wire bytes as observed.

## Usage Examples

### Release a held item
```json
{
  "action": "release",
  "params": {"intercept_id": "int-abc-123"}
}
```

### Modify and forward an HTTP request
```json
{
  "action": "modify_and_forward",
  "params": {"intercept_id": "int-abc-123"},
  "http": {
    "method": "POST",
    "path": "/api/admin",
    "body": "{\"role\":\"admin\"}"
  }
}
```

### Replace the headers of an HTTP request
`headers` is the complete new list: every header you leave out is removed.
```json
{
  "action": "modify_and_forward",
  "params": {"intercept_id": "int-abc-123"},
  "http": {
    "headers": [
      {"name": "Host", "value": "example.com"},
      {"name": "Authorization", "value": "Bearer injected-token"},
      {"name": "Content-Type", "value": "application/json"}
    ]
  }
}
```

### Patch a JSON request body
```json
{
  "action": "modify_and_forward",
  "params": {"intercept_id": "int-abc-123"},
  "http": {
    "body_patches": [{"json_path": "$.user.role", "value": "admin"}]
  }
}
```

### Change an HTTP response status and body
```json
{
  "action": "modify_and_forward",
  "params": {"intercept_id": "int-def-456"},
  "http": {
    "status": 500,
    "status_reason": "Internal Server Error",
    "body": "error"
  }
}
```

### Drop a held item
```json
{
  "action": "drop",
  "params": {"intercept_id": "int-abc-123"}
}
```

### Modify and forward a WebSocket text frame
```json
{
  "action": "modify_and_forward",
  "params": {"intercept_id": "ws-frame-456"},
  "ws": {
    "opcode": "text",
    "payload": "{\"action\":\"modified\",\"data\":\"injected\"}"
  }
}
```

### Modify and forward a WebSocket binary frame
```json
{
  "action": "modify_and_forward",
  "params": {"intercept_id": "ws-frame-456"},
  "ws": {
    "opcode": "binary",
    "payload": "AAECAw==",
    "body_encoding": "base64"
  }
}
```

### Replace the bytes of a raw TCP chunk
```json
{
  "action": "modify_and_forward",
  "params": {"intercept_id": "raw-789"},
  "raw": {
    "bytes_override": "SEVMTE8NCg==",
    "bytes_encoding": "base64"
  }
}
```

### From the CLI
Typed payload fields are dot-path keys; arrays of objects are JSON:
```bash
yorishiro-proxy client intercept action=modify_and_forward params.intercept_id=int-abc-123 http.method=POST http.path=/api/admin http.body='{"role":"admin"}'
yorishiro-proxy client intercept action=modify_and_forward params.intercept_id=int-abc-123 http.headers='[{"name":"Host","value":"example.com"},{"name":"Authorization","value":"Bearer injected-token"}]'
yorishiro-proxy client intercept action=modify_and_forward params.intercept_id=ws-frame-456 ws.opcode=text ws.payload=hello
```

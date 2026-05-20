# Replay a Recorded Request with Modifications

Single-shot replay of a recorded request with selective header / body modifications, using the typed `resend_*` tool that matches the protocol. Useful for one-off verification before launching a fuzz sweep.

## Inputs

- `target_flow_id`: recorded `flow_id` to replay. Required.
- `mods_description`: short description of what you want to change (e.g. "swap Authorization to <low-priv> token", "set body $.role to 'admin'"). Required.

If any required field is empty, ask the user.

## Plan

### 1. Identify the protocol

```json
// query
{"resource": "flow", "id": "{{target_flow_id}}"}
```

- `http/1.1` / `h2` → `resend_http`
- `ws` → `resend_ws`
- `grpc` / `grpc-web` → `resend_grpc`
- `raw` → `resend_raw`

### 2. HTTP replay with header / body modifications

```json
// resend_http
{
  "flow_id": "{{target_flow_id}}",
  "headers": [
    {"name": "Authorization", "value": "Bearer <new-token>"},
    {"name": "X-Forwarded-For", "value": "127.0.0.1"}
  ],
  "body_patches": [
    {"json_path": "$.user_id", "value": 999},
    {"json_path": "$.role", "value": "admin"}
  ],
  "tag": "{{mods_description}}"
}
```

Notes:
- `headers[]` **replaces** the recorded headers entirely. Copy every header you want to keep — anything you omit will not be sent.
- To delete a header, just omit it from `headers[]`.
- `body_patches` uses JSONPath. To replace the entire body, use `override_body` with a raw string.

### 3. WebSocket frame replay

```json
// resend_ws
{
  "flow_id": "{{target_flow_id}}",
  "opcode": "text",
  "payload": "<new payload>",
  "tag": "{{mods_description}}"
}
```

`opcode` is one of `text`, `binary`, `ping`, `pong`, `close`. For `binary`, pass `payload_encoding: "base64"`.

### 4. gRPC unary RPC replay

```json
// resend_grpc
{
  "flow_id": "{{target_flow_id}}",
  "messages": [
    {"payload": "<base64-LPM-frame>", "payload_encoding": "base64"}
  ],
  "metadata": [
    {"name": "authorization", "value": "Bearer <new-token>"}
  ],
  "tag": "{{mods_description}}"
}
```

### 5. Raw TCP replay (HTTP Request Smuggling, etc.)

```json
// resend_raw
{
  "flow_id": "{{target_flow_id}}",
  "target_addr": "api.target.example.com:443",
  "use_tls": true,
  "override_bytes": "<base64-encoded-raw-request>",
  "override_bytes_encoding": "base64",
  "tag": "{{mods_description}}"
}
```

Use `resend_raw` when you specifically want to bypass HTTP parsing — e.g. for request smuggling research, malformed framing, deliberate header injection.

### 6. Inspect the result

```json
// query
{"resource": "flow", "id": "<flow-id-returned-by-resend>"}
```

Check status code, response headers, response body, and (for time-sensitive checks) the `duration_ms` field.

## When to use this vs `fuzz_*`

- One value, one verification → `resend_*`.
- Same shape with many variants → `fuzz_*` (see the `fuzz-endpoint` playbook).
- Many positions changing together → multiple `resend_*` calls.

# resend_ws

Resend a single WebSocket frame via a freshly dialled upstream connection. Schema fields mirror `envelope.WSMessage` (opcode/fin/payload/close_code/close_reason/compressed) so AI agents address WebSocket frames by structured field instead of round-tripping an opaque `message_sequence` index.

`resend_ws` is the typed N7/N8 successor to the legacy multi-protocol `resend` tool. It restricts itself to WebSocket flows; non-WS `flow_id`s are rejected with an explicit pointer to `resend_http` / `resend_grpc` / `resend_raw`.

## Pipeline placement (RFC-001 §9.3)

Each resend traverses `PluginStepPost -> RecordStep`. `PluginStepPre` and `InterceptStep` are bypassed.

## Upstream connection

A fresh TCP (+ TLS for `wss`) dial -> HTTP/1.1 Upgrade dance via the http1 Layer (no `net/http`) -> DetachStream -> ws Layer in `RoleClient`. The Layer regenerates a fresh per-frame mask key for client->server frames per RFC 6455 §5.3, so `mask` and `masked` fields on the input are informational only on Send.

## Two operating modes

### Mode A: replay a recorded flow (`flow_id` set)

The recorded WebSocket upgrade Stream is loaded; the original send Flow's URL + Headers populate the upgrade dance (Sec-WebSocket-Protocol echo, Cookie, Authorization, etc.); the receive Flow at sequence 1 supplies the negotiated `Sec-WebSocket-Extensions` value used to enable per-message-deflate. `target_addr` may be supplied to redirect the dial target while preserving the recovered `:authority`.

### Mode B: from-scratch (`flow_id` empty)

`target_addr` and `path` are REQUIRED. No extension negotiation happens; `compressed=true` is rejected because no extension was negotiated.

## Parameters

### flow_id (string, optional)
Recorded WebSocket stream id. When set, the upgrade dance inherits URL/headers/extensions from the recorded flow.

### target_addr (string, conditional)
Upstream `host:port`. Overrides the dial target while preserving the recovered `:authority`. REQUIRED when `flow_id` is empty. CR/LF in `target_addr` is rejected (CWE-93).

### scheme (string, conditional)
`"ws"` or `"wss"`. Required when `flow_id` is empty (defaults to `"ws"`).

### path (string, conditional)
Upgrade request path. Required when `flow_id` is empty. CR/LF rejected.

### raw_query (string, optional)
Upgrade request raw query string without the leading `?`. CR/LF rejected.

### opcode (string, REQUIRED)
Frame opcode. One of: `"text"`, `"binary"`, `"close"`, `"ping"`, `"pong"`. Validated at the schema boundary.

### fin (boolean, optional)
FIN bit. Defaults to `true`.

### payload (string, optional)
Frame payload interpreted per `body_encoding`. Empty when omitted unless `payload_set=true`.

### body_encoding (string, optional)
`"text"` (default) or `"base64"`. Required when payload is non-textual.

### payload_set (boolean, optional)
Set to `true` to send an empty payload. Otherwise an empty `payload` field is treated as no override.

### masked (boolean, optional)
Informational. The upstream-facing layer auto-masks per RFC 6455 §5.3 regardless of this value.

### mask (string, optional)
Informational 4-byte mask key (hex or base64 per `body_encoding`). Ignored on Send for client->server frames.

### close_code (integer, optional)
RFC 6455 status code for Close frames.

### close_reason (string, optional)
Optional UTF-8 reason for Close frames.

### compressed (boolean, optional)
Per-message-deflate (RFC 7692). Requires the upgrade to negotiate deflate via `flow_id`.

### timeout_ms (integer, optional)
Per-call timeout covering dial+upgrade+send+receive. Default `30000`.

### tls_fingerprint (string, optional)
Informational v1; per-call selection deferred.

### tag (string, optional)
Tag stored on the new flow's `Tags` map.

## Result fields

- `stream_id` — new Stream record holding the resend send + every received frame
- `opcode` / `fin` — terminating frame metadata (first non-control frame OR Close)
- `payload` / `payload_encoding` — terminating frame payload
- `compressed` — terminating frame compressed flag
- `close_code` / `close_reason` — populated when the upstream sent Close
- `duration_ms` / `tag`

## Examples

### Replay a recorded text frame with a different payload
```json
{
  "flow_id": "ws-abc-123",
  "opcode": "text",
  "payload": "{\"action\":\"subscribe\",\"channel\":\"admin\"}"
}
```

### From-scratch ping
```json
{
  "target_addr": "ws.target.com:443",
  "scheme": "wss",
  "path": "/socket",
  "opcode": "ping",
  "payload": ""
}
```

### Send a binary frame from scratch
```json
{
  "target_addr": "ws.target.com:443",
  "scheme": "wss",
  "path": "/binary",
  "opcode": "binary",
  "payload": "AAECAwQF",
  "body_encoding": "base64"
}
```

### Send a close frame with reason
```json
{
  "flow_id": "ws-abc-123",
  "opcode": "close",
  "close_code": 1000,
  "close_reason": "client requested"
}
```

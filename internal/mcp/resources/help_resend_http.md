# resend_http

Resend or construct a single HTTP request via a freshly dialled upstream connection. Schema fields mirror `envelope.HTTPMessage` (method/scheme/authority/path/raw_query/headers/body) so AI agents address HTTP fields by name instead of round-tripping a single opaque URL string.

`resend_http` is the typed N7/N8 successor to the legacy multi-protocol `resend` tool. It restricts itself to HTTP/1.x and HTTP/2 flows; non-HTTP `flow_id`s are rejected with an explicit pointer to `resend_ws` / `resend_grpc` / `resend_raw`.

## Pipeline placement (RFC-001 §9.3)

Each resend traverses `PluginStepPost -> RecordStep`. `PluginStepPre` and `InterceptStep` are bypassed so signing and last-mile post-mutation hooks fire exactly once on the resent envelope while pre_pipeline annotation hooks (which observe pristine wire-fresh data) stay quiet on resends.

## Two operating modes

### Mode A: replay a recorded flow (`flow_id` set)

When `flow_id` is set, the original recorded send is loaded from the Stream store and any field the caller omits is inherited from the recorded envelope (method / scheme / authority / path / raw_query / headers / body). User-supplied fields override the recorded values on a per-field basis.

### Mode B: from-scratch (`flow_id` empty)

When `flow_id` is empty, `method`, `scheme`, `authority`, and `path` are all REQUIRED up-front. Headers and body must be supplied explicitly (or are sent empty).

## Parameters

### flow_id (string, optional)
Recorded HTTP stream id. When set, omitted fields are inherited from the original send. Non-HTTP `flow_id`s are rejected.

### method (string, conditional)
HTTP method (e.g. `"GET"`, `"POST"`). Required when `flow_id` is empty.

### scheme (string, conditional)
`"http"` or `"https"`. Required when `flow_id` is empty.

### authority (string, conditional)
Host / `:authority` value (e.g. `"example.com:8443"`). Required when `flow_id` is empty. Used both in the request line/`:authority` and as the default Host header when none is supplied.

### path (string, conditional)
Request path including the leading slash. Required when `flow_id` is empty.

### raw_query (string, optional)
Raw query string WITHOUT the leading `?`.

### headers (array of `{name, value}`, optional)
Ordered header list. Preserves wire case, order, and duplicates per RFC-001 §3.1 wire-fidelity. Headers are NOT a map — duplicates with different casing are two distinct headers. When supplied, replaces the inherited header list wholesale.

### body (string, optional)
Request body interpreted per `body_encoding`. Default empty.

### body_encoding (string, optional)
`"text"` (default) or `"base64"`. Use `"base64"` for binary payloads.

### body_set (boolean, optional)
Set to `true` to override the body to empty (zero-length). Otherwise an omitted/empty `body` field is treated as "no override — keep recorded body" when `flow_id` is set.

### body_patches (array, optional)
Body modifications applied on top of any body replacement. Each entry must have either `json_path`+`value` or `regex`+`replace` (mutually exclusive). Optional `encoding` chain is applied to the patch value.

### override_host (string, optional)
Redirect the dial target (`host:port`) while preserving the request's `Host`/`:authority`. Useful for wrong-server-routing tests.

### follow_redirects (boolean, optional)
Currently unsupported. Setting `true` returns an explicit error.

### timeout_ms (integer, optional)
Per-request timeout in milliseconds. Default `30000` (30 s).

### tls_fingerprint (string, optional)
Informational v1: per-call selection is deferred. Server uses its configured fingerprint regardless and emits a warning log.

### tag (string, optional)
Tag stored on the new flow's `Tags` map. Useful for grouping resends.

## Result fields

- `stream_id` — new Stream record holding the resend-time send + receive flows
- `status_code` — HTTP response status
- `headers` — ordered `[{name, value}]` list
- `body` / `body_encoding` — response body, masked by SafetyFilter Output Filter when active
- `duration_ms` — wall-clock duration of the call
- `tag` — echoed back when supplied

## Examples

### Replay a recorded flow with a different Authorization header
```json
{
  "flow_id": "abc-123",
  "headers": [
    {"name": "Host", "value": "api.target.com"},
    {"name": "Authorization", "value": "Bearer other-user-token"},
    {"name": "Accept", "value": "application/json"}
  ]
}
```

### Replay with a JSON body patch
```json
{
  "flow_id": "abc-123",
  "body_patches": [
    {"json_path": "$.role", "value": "admin"}
  ]
}
```

### From-scratch POST
```json
{
  "method": "POST",
  "scheme": "https",
  "authority": "api.target.com",
  "path": "/v1/users",
  "headers": [
    {"name": "Host", "value": "api.target.com"},
    {"name": "Content-Type", "value": "application/json"},
    {"name": "Authorization", "value": "Bearer ..."}
  ],
  "body": "{\"name\":\"alice\"}",
  "body_encoding": "text"
}
```

### Wrong-server routing (preserve `:authority`, dial elsewhere)
```json
{
  "flow_id": "abc-123",
  "override_host": "internal-host:443"
}
```

### Send a binary body
```json
{
  "method": "POST",
  "scheme": "https",
  "authority": "upload.example.com",
  "path": "/v1/blob",
  "body": "iVBORw0KGgoAAAANS...",
  "body_encoding": "base64"
}
```

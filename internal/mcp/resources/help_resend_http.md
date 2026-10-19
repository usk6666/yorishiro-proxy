# resend_http

Resend or construct a single HTTP request via a freshly dialled upstream connection. Schema fields mirror `envelope.HTTPMessage` (method/scheme/authority/path/raw_query/headers/body) so AI agents address HTTP fields by name instead of round-tripping a single opaque URL string.

`resend_http` is the typed N7/N8 successor to the legacy multi-protocol `resend` tool. It restricts itself to HTTP/1.x and HTTP/2 flows; non-HTTP `flow_id`s are rejected with an explicit pointer to `resend_ws` / `resend_grpc` / `resend_raw`.

## Wire protocol (HTTP/1.1 vs HTTP/2)

The resend goes out over the protocol the original flow used — it is not silently downgraded:

| Source of the decision | Result |
|------------------------|--------|
| `http_version` supplied | that protocol (`http/1.1`, `h2` or `h2c`) |
| `flow_id` whose recorded `http_version` is `h2` / `h2c` | HTTP/2: `h2` (TLS, ALPN) when the resolved scheme is `https`, `h2c` (cleartext, prior knowledge) when it is `http` |
| anything else (HTTP/1.x flow, unversioned flow, from-scratch request) | `http/1.1` |

- **HTTP/2 over TLS (`h2`)** offers the server's configured ALPN list unchanged (the uTLS browser profile's own list, or `["h2","http/1.1"]`), so the ClientHello matches the live proxy path, and requires the upstream to select `h2`. If it selects anything else the call fails with an error naming the negotiated ALPN — pass `http_version: "http/1.1"` to send the request over HTTP/1.1 deliberately. The HTTP/2 SETTINGS and pseudo-header order follow the configured `tls_fingerprint` like the live path.
- **HTTP/2 headers**: the request target is sent as `:method` / `:scheme` / `:authority` / `:path` built from `method` / `scheme` / `authority` / `path`+`raw_query`. No `Host` header is added; a `host` header in the header list is sent as an ordinary header. Header names are lowercased on the wire (RFC 9113 §8.2.1) and connection-specific headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-Connection`, `TE` other than `trailers`) are stripped — relevant when an HTTP/1.x flow is forced to `h2`. The recorded send flow still lists them (it is recorded before the request is encoded).
- **HTTP/1.1** pins ALPN to `http/1.1` and adds a `Host` header from `authority` when the header list has none.
- The new flows record the protocol actually used in `http_version` (`http/1.1`, `h2`, `h2c`).
- 1xx interim responses (`100 Continue`, `103 Early Hints`, ...) are recorded as their own receive flows; `status_code` / `headers` / `body` in the result are the final response's.
- Not covered: WebSocket over HTTP/2 (RFC 8441) — use `resend_ws`. The recorded order of HTTP/2 pseudo-headers and the original header order across names are not replayed (headers are stored as a map); supply `headers` explicitly to control order.

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
Host / `:authority` value (e.g. `"example.com:8443"`). Required when `flow_id` is empty. Sent as `:authority` over HTTP/2; over HTTP/1.1 it is the default Host header when none is supplied.

### path (string, conditional)
Request path including the leading slash. Required when `flow_id` is empty. Sent and recorded exactly as given (wire form): percent-encoding is neither decoded nor added, so `/a%2Fb` goes out as `/a%2Fb` and `/a b` as `/a b`. When inherited from `flow_id`, the recorded wire-form path is replayed byte-for-byte.

A literal `?` embedded in `path` is auto-split into `path` + `raw_query`: the prefix before the first `?` becomes the new `path` and the suffix (without the `?`) routes to `raw_query`. This lets callers paste a full path-with-query in one field (`curl --url` style). Supplying **both** `raw_query` AND a `?` in `path` is rejected with an explicit error — drop one and resubmit.

> Why auto-split? A literal `?` in `path` would otherwise be indistinguishable from the query delimiter in the recorded `Flow.URL`; before USK-1139 it was recorded as `%3F` (USK-859). The wire was always correct — only the recorded URL drifted.

### raw_query (string, optional)
Raw query string WITHOUT the leading `?`. Mutually exclusive with embedding a query in `path`.

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

### http_version (string, optional)
Wire protocol for the upstream send: `"http/1.1"`, `"h2"` (requires scheme `https`; ALPN `h2`) or `"h2c"` (requires scheme `http`; HTTP/2 with prior knowledge). Default: the recorded flow's protocol (see "Wire protocol" above), else `http/1.1`. Use `"http/1.1"` to downgrade an HTTP/2 flow explicitly, or `"h2"` to send a from-scratch request over HTTP/2.

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

### Replay an HTTP/2 flow over HTTP/1.1 on purpose
```json
{
  "flow_id": "abc-123",
  "http_version": "http/1.1"
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

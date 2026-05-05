# fuzz_http

Synchronously fuzz an HTTP request with `HTTPMessage`-typed positions. Each variant traverses the same self-contained `PluginStepPost -> RecordStep` pipeline as `resend_http` (`PluginStepPre` is bypassed per RFC-001 §9.3).

The schema mirrors `resend_http` plus a `positions[]` list. The cartesian product of all positions yields the variant sequence (capped at **1000 variants per call**). Variants are executed sequentially with a fresh dial per variant.

Larger fuzz jobs that need concurrency, rate limiting, or overload monitoring should use the legacy `fuzz` tool (asynchronous job runner) which coexists in parallel until N9 retires it.

## Position path syntax (HTTPMessage-typed)

| Path | HTTPMessage field |
|------|-------------------|
| `method` | `HTTPMessage.Method` |
| `scheme` | `HTTPMessage.Scheme` |
| `authority` | `HTTPMessage.Authority` |
| `path` | `HTTPMessage.Path` |
| `raw_query` | `HTTPMessage.RawQuery` |
| `body` | `HTTPMessage.Body` (string interpretation) |
| `headers[N].name` | `HTTPMessage.Headers[N].Name` |
| `headers[N].value` | `HTTPMessage.Headers[N].Value` |

`headers[N]` indexes into the inherited or user-supplied base header list — the index must exist in the base list for the substitution to apply.

## Two operating modes

### Mode A: replay-fuzz (`flow_id` set)

When `flow_id` is set, the recorded send seeds the per-variant base envelope; user-supplied fields override before any positions apply. Same behaviour as `resend_http` `flow_id` mode.

### Mode B: from-scratch fuzz (`flow_id` empty)

`method`, `scheme`, `authority`, and `path` are REQUIRED up-front (same rule as `resend_http`).

## Parameters

`fuzz_http` inherits every `resend_http` field verbatim:

- `flow_id`, `method`, `scheme`, `authority`, `path`, `raw_query`, `headers[]`, `body`, `body_encoding`, `body_set`, `body_patches[]`, `override_host`, `tls_fingerprint`, `timeout_ms`, `tag`

See [help_resend_http](yorishiro://help/resend_http) for the inherited fields. Documentation here is on fuzz-specific fields only.

### positions (array, REQUIRED)
Ordered position list; at least one entry. Each position has:
- **path** (string, REQUIRED): typed path into HTTPMessage. One of: `method | scheme | authority | path | raw_query | body | headers[N].name | headers[N].value`.
- **payloads** (array of strings, REQUIRED): list of values to substitute at this path; at least one element.
- **encoding** (string, optional): `"text"` (default) or `"base64"`. Applies to every payload in this position.

### stop_on_5xx (boolean, optional)
When `true`, abort the remaining variants once any variant returns a 5xx response.

### timeout_ms (integer, optional)
Per-VARIANT timeout in milliseconds. Default `30000`.

## Result fields

- `total_variants` — cartesian product count (capped at 1000)
- `completed_variants` — variants actually executed (may be less than `total_variants` when `stop_on_5xx` triggers)
- `stopped_reason` — non-empty when stopped early (e.g. `"stop_on_5xx triggered"`)
- `variants[]` — per-variant compact rows:
  - `index` (int): variant index (0-based)
  - `stream_id` (string): variant's Stream record ID
  - `status_code` (int)
  - `body_size` (int): response body byte length (full body retrievable via `query` keyed by `stream_id`)
  - `payloads` (object): position path -> chosen payload, for correlation
  - `error` (string): non-empty on per-variant failure
  - `duration_ms` (int)
- `duration_ms` / `tag`

## Examples

### Single header fuzz
```json
{
  "flow_id": "abc-123",
  "positions": [
    {
      "path": "headers[1].value",
      "payloads": ["alice", "bob", "admin", "../../../etc/passwd"]
    }
  ]
}
```

### Path traversal payload list, stop on 5xx
```json
{
  "flow_id": "abc-123",
  "positions": [
    {
      "path": "path",
      "payloads": [
        "/api/users/1",
        "/api/users/../admin",
        "/api/users/%2e%2e%2fadmin"
      ]
    }
  ],
  "stop_on_5xx": true
}
```

### Two-position cartesian product (method x body)
```json
{
  "method": "GET",
  "scheme": "https",
  "authority": "api.target.com",
  "path": "/v1/echo",
  "headers": [
    {"name": "Host", "value": "api.target.com"},
    {"name": "Content-Type", "value": "application/json"}
  ],
  "positions": [
    {
      "path": "method",
      "payloads": ["GET", "POST", "PUT", "DELETE"]
    },
    {
      "path": "body",
      "payloads": ["{}", "{\"a\":1}", "{\"b\":\"<script>alert(1)</script>\"}"]
    }
  ]
}
```

### Base64 binary payload at a single position
```json
{
  "flow_id": "abc-123",
  "positions": [
    {
      "path": "body",
      "encoding": "base64",
      "payloads": ["AAECAwQF", "//////8="]
    }
  ]
}
```

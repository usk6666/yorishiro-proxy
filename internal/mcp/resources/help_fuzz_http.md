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

`headers[N]` indexes into the inherited or user-supplied base header list — the index must exist in the base list for the substitution to apply. The `Host:` header that is auto-injected from `authority` when the input headers list omits it is NOT addressable via `headers[N]`; use the `authority` path to fuzz Host (USK-830).

## Two operating modes

### Mode A: replay-fuzz (`flow_id` set)

When `flow_id` is set, the recorded send seeds the per-variant base envelope; user-supplied fields override before any positions apply. Same behaviour as `resend_http` `flow_id` mode.

### Mode B: from-scratch fuzz (`flow_id` empty)

`method`, `scheme`, `authority`, and `path` are REQUIRED up-front (same rule as `resend_http`).

## Parameters

`fuzz_http` inherits every `resend_http` field verbatim:

- `flow_id`, `method`, `scheme`, `authority`, `path`, `raw_query`, `headers[]`, `body`, `body_encoding`, `body_set`, `body_patches[]`, `override_host`, `tls_fingerprint`, `timeout_ms`, `tag`

See [help_resend_http](yorishiro://help/resend_http) for the inherited fields. Documentation here is on fuzz-specific fields only.

> `path` accepts a literal `?` and auto-splits into `path` + `raw_query` at the MCP boundary (USK-859). Supplying both `raw_query` AND a `?` in `path` is rejected. The split applies once to the base envelope; per-position payloads written into `path` or `raw_query` via the `positions[]` mechanism are passed through verbatim (the package-level "Payload passthrough" rule in `fuzz_http_helpers.go`).

### positions (array, REQUIRED)
Ordered position list; at least one entry. Each position has:
- **path** (string, REQUIRED): typed path into HTTPMessage. One of: `method | scheme | authority | path | raw_query | body | headers[N].name | headers[N].value`.
- **payloads** (array of strings, REQUIRED): list of values to substitute at this path; at least one element.
- **encoding** (string, optional): `"text"` (default) or `"base64"`. Applies to every payload in this position.

### stop_on_5xx (boolean, optional)
When `true`, abort the remaining variants once any variant returns a 5xx response.

### timeout_ms (integer, optional)
Per-VARIANT timeout in milliseconds. Default `30000`.

### pre_macro / post_macro (object, optional)

Pre and post macro hooks dispatched around variants by name. Both fields take the same shape (USK-960, USK-961):

- **name** (string, REQUIRED): the stored macro name (defined via the `macro` tool's `define_macro` action).
- **scope** (string, optional): `"iteration"` (default) or `"job"`. See "Macro hook scopes" below.
- **on_error** (string, optional): `"skip"` (default) | `"abort"` | `"continue"`. See "OnError semantics" below.

The hook macro shares the per-iteration (or per-job) KV Store with the fuzz request — `§var§` templates in the request inherit pre-macro extracts, and post-macros (scope=iteration only) receive `__response_status` / `__response_body` / `__response_headers__<lower(name)>__` reserved keys.

#### Macro hook scopes

| Scope | Pre fires | Post fires | KV Store lifetime | `__response_*` keys | `§__iteration§` / `§__nonce§` |
|-------|-----------|------------|-------------------|---------------------|-------------------------------|
| `iteration` (default) | Before each variant's send | After each variant's response | Fresh per variant | Visible to post | Seeded each iteration |
| `job` | Once before the variant loop | Once after the variant loop (incl. `stop_on_5xx` exit) | Shared across the whole job | NOT visible | NOT seeded |

Mix-scope is supported — `pre_macro` and `post_macro` may pick their scope independently. The job-scope KV Store is merged into each iteration's per-variant store at iteration start; per-iteration reserved keys then overwrite any conflicting job keys ("iteration wins"). So `pre_macro { scope: "job" }` extracting `session_token` makes `§session_token§` resolvable in every variant's request templates.

> `run_interval` is `scope="iteration"` only — the engine knob for `every_n` / `on_status` / etc. dispatch is meaningful only when the hook fires per-variant. `scope="job"` hooks fire exactly once by construction (the call site, not `run_interval`, owns the single-fire guarantee); once the `run_interval` field is publicly surfaced on the fuzz_http hook config, pairing it with `scope="job"` will be rejected at validation time.

#### OnError semantics

| OnError | pre / scope=iteration | pre / scope=job | post / either scope |
|---------|----------------------|-----------------|--------------------|
| `skip` (default) | Skip the variant: don't send, don't run post. Record `fuzz_macro_results.status="skipped"`. | Skip the entire job — `completed_variants=0`, `stopped_reason="pre_macro hook skipped (scope=job, on_error=skip): ..."`. | Record `fuzz_macro_results.status="error"`. Never aborts the run. |
| `abort` | Abort the whole fuzz run with an error. | Abort the whole job before any variant runs. | Record `fuzz_macro_results.status="error"`. Never aborts (post-job runs after the loop has completed; nothing left to abort). |
| `continue` | Log warn + record error row, proceed with whatever the kvStore captured; templates may carry unresolved `§var§` literals (surfaced in `fuzz_results.error`). | Log warn + record error row, proceed with variant loop. | Same as `skip` for post. |

#### fuzz_macro_results schema notes

The `fuzz_macro_results` table (one row per hook invocation) keys on `(fuzz_id, index_num, hook_name)`:

- **`index_num`** is the 0-based variant index for `scope="iteration"` rows.
- **`index_num = -1`** is the sentinel for `scope="job"` rows — pre-job and post-job each emit a single row at `index_num=-1`. This avoids a schema migration. There are no external consumers (the `query` MCP tool does not surface `fuzz_macro_results` today); the sentinel is consumed only by internal tooling.

## Result fields

- `fuzz_id` (string, UUID) — primary key of the `fuzz_jobs` row created for this run. Chain with `query { resource: "fuzz_results", filter: { fuzz_id: "...", outliers_only: true } }` to surface outlier variants without re-running the fuzz job (USK-827 + USK-278).
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

## Aggregation: outlier-driven triage (recommended workflow)

`fuzz_http` populates the `fuzz_jobs` / `fuzz_results` tables for every sync run, so AI agents can issue many variants then triage statistically:

1. `fuzz_http { positions: [...], stop_on_5xx: false }` -> capture `fuzz_id` from the response.
2. `query { resource: "fuzz_results", fuzz_id: "<id>" }` -> summary statistics (status code distribution, median/stddev for body length + timing) live under `summary.statistics`.
3. `query { resource: "fuzz_results", fuzz_id: "<id>", filter: { outliers_only: true } }` -> just the variants that deviate from the baseline (different status code OR body length/timing outside median +/- 2*stddev).
4. Drill down on any outlier with `query { resource: "flow", id: <variant.stream_id> }` to see the full request + response wire bytes.

Variant Streams are stamped `origin = "fuzz"`, so `query { resource: "flows", filter: { origin: "fuzz" } }` cleanly separates fuzz-originated streams from live MITM capture.

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

### Mix-scope macro hooks: login once, fuzz N, summarise once
```json
{
  "method": "GET",
  "scheme": "https",
  "authority": "api.target.com",
  "path": "/v1/profile",
  "headers": [
    {"name": "Host", "value": "api.target.com"},
    {"name": "Authorization", "value": "Bearer §session_token§"}
  ],
  "positions": [
    {"path": "headers[1].value", "payloads": ["Bearer §session_token§", "Bearer §session_token§ "]}
  ],
  "pre_macro":  {"name": "login-once", "scope": "job"},
  "post_macro": {"name": "audit-summary", "scope": "job"}
}
```
`pre_macro` (scope=job) runs once before the variant loop, extracts `session_token` into the job-scoped KV Store; every variant then sees `§session_token§` in the templated `Authorization` header. `post_macro` (scope=job) runs once after the loop completes — it can summarise the run via its own template against the job-scoped KV Store.

# fuzz_grpc

Synchronously fuzz a gRPC unary RPC with `GRPCStart`/`GRPCData`-typed positions. Each variant traverses the same self-contained `PluginStepPost -> RecordStep` pipeline as `resend_grpc` (`PluginStepPre` is bypassed per RFC-001 §9.3) and is dialled as a fresh independent stream.

The schema mirrors `resend_grpc` plus a `positions[]` list. The cartesian product of all positions yields the variant sequence (capped at **1000 variants per call**). Each variant becomes one independent gRPC stream — fresh ConnID, fresh StreamID, fresh dial — so per-variant state observed by analysts (Stream rows, `PluginStepPost` firing) is symmetric with the `resend_grpc` surface.

`PluginStepPost` fires per Start + per Data envelope per variant. End is observation-only — the surface table marks `("grpc","on_end") = PhaseSupportNone`.

## Position path syntax (typed reference into the GRPCStart + GRPCData envelope shape)

| Path | Field |
|------|-------|
| `service` | `GRPCStartMessage.Service` |
| `method` | `GRPCStartMessage.Method` |
| `metadata[N].name` | `GRPCStartMessage.Metadata[N].Name` |
| `metadata[N].value` | `GRPCStartMessage.Metadata[N].Value` |
| `messages[N].payload` | `GRPCDataMessage.Payload` (variant N) — raw bytes |
| `messages[N].payload.<FFFF:OOOO:type>` | One scalar proto field inside a `proto-schemaless-json` payload (USK-925) |

`scheme` / `target_addr` / `encoding` are intentionally NOT fuzz positions — they affect connection setup and would change the dial target rather than the on-wire envelope content. Callers that need to fuzz across schemes should issue separate `fuzz_grpc` calls.

### JSON-path positions (`messages[N].payload.<key>`)

When the targeted message uses `body_encoding="proto-schemaless-json"`, individual proto fields can be fuzzed by appending the `FFFF:OOOO:type` key after `.payload.`. The path syntax follows the proto-schemaless surface introduced by USK-922 — `FFFF` is the protobuf field number (4-digit lowercase hex), `OOOO` is the ordinal (4-digit lowercase hex, in input-order), and `type` is the wire-type label (`String`, `Varint`, `32-bit`, `64-bit`, `bytes`). Composite types (`repeated`, `embedded message`) are not supported in v1 — they require a structurally-typed payload but the fuzz iterator supplies one string per position.

Per-position payload interpretation:

| Target wire type | Payload format |
|-------------------|----------------|
| `String` | UTF-8 text, used verbatim (JSON-string-quoted internally) |
| `bytes` | Colon-separated hex (matches Decode emission, e.g. `de:ad:be:ef`) |
| `Varint`, `64-bit` | Base-10 integer (signed allowed; two's-complement round-trips via uint64) |
| `32-bit` | Base-10 integer that fits in `uint32` |

Multiple JSON-path positions on the same message share a single re-encode — for variant V, all matched proto fields are mutated in the original JSON tree before `protobuf.Encode` rewrites the LPM payload.

A bytes-level `messages[N].payload` position and a JSON-path `messages[N].payload.<key>` position **cannot coexist** for the same N — the bytes form would silently overwrite the JSON-mutation result. Pick one.

### Re-open trigger note (USK-924)

The proto-schemaless-json fuzz path makes `internal/encoding/protobuf.Encode` consume position-mutated JSON every variant. Encode now caps the embedded-message recursion depth symmetrically with Decode (`maxRecursionDepth = 64`, CWE-674); a deeply-nested JSON-path mutation surfaces the cap as `recursion depth N exceeds maximum 64` on the offending variant rather than the proxy walking the goroutine stack.

## Two operating modes

### Mode A: replay-fuzz (`flow_id` set)

The recorded send-direction GRPCStart Flow seeds the per-variant base envelope; user-supplied fields override before any positions apply.

### Mode B: from-scratch fuzz (`flow_id` empty)

`target_addr`, `service`, and `method` are REQUIRED up-front. No encoding state is inherited.

## Parameters

`fuzz_grpc` inherits every `resend_grpc` field verbatim:

- `flow_id`, `target_addr`, `scheme`, `service`, `method`, `metadata[]`, `encoding`, `accept_encoding[]`, `messages[]`, `trailer_metadata[]`, `tls_fingerprint`, `tag`, `timeout_ms`

See [help_resend_grpc](yorishiro://help/resend_grpc) for the inherited fields. Documentation here is on fuzz-specific fields only.

### positions (array, REQUIRED)
Ordered position list; at least one entry. Each position has:
- **path** (string, REQUIRED): typed path. One of: `service | method | metadata[N].name | metadata[N].value | messages[N].payload`.
- **payloads** (array of strings, REQUIRED): list of values to substitute at this path; at least one element.
- **encoding** (string, optional): `"text"` (default) or `"base64"`. Applies to every payload in this position.

`messages[N]` and `metadata[N]` index into the inherited or user-supplied base list.

### stop_on_non_ok (boolean, optional)
When `true`, abort the remaining variants once any variant returns a non-OK gRPC status (or terminates without a trailer).

### timeout_ms (integer, optional)
Per-VARIANT timeout in milliseconds. Default `30000`.

### pre_macro / post_macro (object, optional)

Pre and post macro hooks dispatched around variants by name. Both fields take the same shape as `fuzz_http` (USK-985, gRPC sibling of USK-960/961/981):

- **name** (string, REQUIRED): the stored macro name (defined via the `macro` tool's `define_macro` action).
- **scope** (string, optional): `"iteration"` (default) or `"job"`. See "Macro hook scopes" below.
- **on_error** (string, optional): `"skip"` (default) | `"abort"` | `"continue"`. Same semantics as `fuzz_http` — see the [fuzz_http help-doc](yorishiro://help/fuzz_http) for the full matrix.
- **vars** (object string→string, optional): static kvStore overrides injected before the macro runs. Keys with the reserved prefix (`__`) are silently dropped.
- **run_interval** (string, optional): hook firing cadence — **`scope="iteration"` only**. Rejected with an error when paired with `scope="job"` (job-scope hooks fire exactly once by construction).
  - pre_macro legal values: `"always"` (default) | `"once"` | `"every_n"` | `"on_error"`.
  - post_macro legal values: `"always"` (default) | `"on_status"` | `"on_match"`.
- **n** (integer, optional): companion to pre_macro `run_interval="every_n"`. Required when `run_interval="every_n"`; must be ≥ 1.
- **status_codes** (array of integer, optional): companion to post_macro `run_interval="on_status"`. Required when `run_interval="on_status"`. **The status domain is gRPC, not HTTP** — see below.
- **match_pattern** (string, optional): companion to post_macro `run_interval="on_match"`. Matched against the concatenated DATA payload bytes (capped at 64 KiB). Required when `run_interval="on_match"`.

`run_interval="on_error"` semantics (USK-988): pre_macro fires when the previous variant returned **either** a transport-level error (`runErr != nil` — dial failure, TLS / HTTP/2 preface failure, deadline) **OR** a non-OK gRPC trailer status code (1-16 per `google.golang.org/grpc/codes`). gRPC's status domain is 0-16, so the engine's HTTP-flavored `lastStatusCode >= 400` rule does not apply here — both gRPC error layers are folded into the trigger at the fuzz_grpc adapter site (MITM Principle #2 — protocol-canonical). Iter-0 never fires because there is no previous variant to react to. Pre-wire abort iterations (pre_macro skip, pre_macro abort) consume a counter slot but leave the previous wire-completed iteration's error signal in place, so the gate still reacts to the most recent real outcome.

#### gRPC firing points

| Hook | Iteration unit | When it fires |
|------|----------------|---------------|
| `pre_macro` (`scope=iteration`) | 1 variant = 1 unary RPC | Before dial (i.e. before TLS handshake / HTTP/2 SETTINGS) |
| `post_macro` (`scope=iteration`) | 1 variant = 1 unary RPC | After the end trailer is received (or after stream termination on abnormal close) |
| `pre_macro` (`scope=job`) | Whole job | Once before the variant loop starts |
| `post_macro` (`scope=job`) | Whole job | Once after the variant loop completes — on natural exhaustion or `stop_on_non_ok` exit, **NOT on ctx cancel** |

#### __response_* reserved keys (gRPC)

`post_macro` with `scope=iteration` receives these reserved keys in the per-variant kvStore (overwritten on each iteration):

| Key | Type | gRPC source |
|-----|------|-------------|
| `__response_status` | uint32 → decimal string | gRPC end-trailer status code (0..16 per `google.golang.org/grpc/codes`) |
| `__response_status_message` | string | gRPC end-trailer `status_message` field (empty on OK) |
| `__response_body` | bytes → string | Concatenation of every receive-direction DATA payload, **capped at 64 KiB at capture time** |
| `__response_message_count` | int → decimal string | Number of receive-direction DATA envelopes |
| `__response_total_bytes` | int → decimal string | Pre-truncation byte sum across every receive-direction DATA payload — matches `fuzz_results.response_length` |

> **`__response_status` is the gRPC status code, NOT an HTTP status.** Operators supplying `run_interval="on_status"` with `status_codes: [...]` must supply gRPC codes — `[0]` for OK, `[14]` for UNAVAILABLE, `[16]` for UNAUTHENTICATED, etc. Supplying HTTP codes (200, 503) will silently fail to match because the gRPC RPC's wire status is in the 0-16 domain. See `google.golang.org/grpc/codes` for the canonical enum:
> ```
> 0 OK | 1 Cancelled | 2 Unknown | 3 InvalidArgument | 4 DeadlineExceeded |
> 5 NotFound | 6 AlreadyExists | 7 PermissionDenied | 8 ResourceExhausted |
> 9 FailedPrecondition | 10 Aborted | 11 OutOfRange | 12 Unimplemented |
> 13 Internal | 14 Unavailable | 15 DataLoss | 16 Unauthenticated
> ```
> Header-projected keys (`__response_headers__<lower(name)>__`) and trailer-metadata keys are **NOT** populated by `fuzz_grpc` v1 — trailer-metadata wiring is deferred to follow-up. The recorded Flow under `row.stream_id` retains the full trailer metadata for drill-down via the `query` tool.

#### Macro hook scopes

Same shape as `fuzz_http`. See the [fuzz_http help-doc](yorishiro://help/fuzz_http) "Macro hook scopes" section for the full matrix. Quick summary:

| Scope | Pre fires | Post fires | KV Store lifetime | `__response_*` keys | `§__iteration§` / `§__nonce§` |
|-------|-----------|------------|-------------------|---------------------|-------------------------------|
| `iteration` (default) | Before each variant's dial | After each variant's end-trailer | Fresh per variant | Visible to post | Seeded each iteration |
| `job` | Once before the variant loop | Once after the variant loop (incl. `stop_on_non_ok` exit) | Shared across the whole job | NOT visible | NOT seeded |

Mix-scope is supported — `pre_macro` and `post_macro` may pick their scope independently.

#### fuzz_macro_results schema notes

The `fuzz_macro_results` table (one row per hook invocation) keys on `(fuzz_id, index_num, hook_name)`:

- **`index_num`** is the 0-based variant index for `scope="iteration"` rows.
- **`index_num = -1`** is the sentinel for `scope="job"` rows.

## Result fields

- `fuzz_id` (string, UUID) — primary key of the `fuzz_jobs` row created for this run. Chain with `query { resource: "fuzz_results", filter: { fuzz_id: "...", outliers_only: true } }` to surface outlier variants without re-running the fuzz job (USK-835 + USK-278; parity with `fuzz_http` USK-827).
- `total_variants`, `completed_variants`, `stopped_reason`
- `variants[]` — per-variant compact rows:
  - `index`, `stream_id`
  - `status` (uint32): gRPC status code (0 = OK)
  - `status_message` (string)
  - `response_message_count` (int): number of receive-direction Data envelopes
  - `response_total_bytes` (int): summed response Data byte length (full payloads retrievable via `query` keyed by `stream_id`)
  - `payloads` (object): position path -> chosen payload, for correlation
  - `error` / `duration_ms`
- `duration_ms` / `tag`

## Aggregation: outlier-driven triage (recommended workflow)

`fuzz_grpc` populates the `fuzz_jobs` / `fuzz_results` tables for every sync run, so AI agents can issue many variants then triage statistically:

1. `fuzz_grpc { positions: [...], stop_on_non_ok: false }` -> capture `fuzz_id` from the response.
2. `query { resource: "fuzz_results", fuzz_id: "<id>" }` -> summary statistics (status code distribution, median/stddev for response byte length + timing) live under `summary.statistics`.
3. `query { resource: "fuzz_results", fuzz_id: "<id>", filter: { outliers_only: true } }` -> just the variants that deviate from the baseline (different status code OR response length/timing outside median +/- 2*stddev).
4. Drill down on any outlier with `query { resource: "flow", id: <variant.stream_id> }` to see the full gRPC envelope sequence (Start + Data + End) and wire bytes.

The aggregation maps per-protocol fields uniformly: `status_code` in `fuzz_results` receives `int(row.status)` (gRPC status code), and `response_length` receives `row.response_total_bytes` (sum of receive-side Data payload bytes).

Variant Streams are stamped `origin = "fuzz"`, so `query { resource: "flows", filter: { origin: "fuzz" } }` cleanly separates fuzz-originated streams from live MITM capture.

## Examples

### Fuzz a metadata header value
```json
{
  "flow_id": "grpc-abc-123",
  "metadata": [
    {"name": "authorization", "value": "Bearer A"},
    {"name": "x-request-id", "value": "abc"}
  ],
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ],
  "positions": [
    {
      "path": "metadata[0].value",
      "payloads": [
        "Bearer A",
        "Bearer admin",
        "Bearer ../../etc/passwd",
        ""
      ]
    }
  ],
  "stop_on_non_ok": true
}
```

### From-scratch unary RPC, fuzz the request body
```json
{
  "target_addr": "grpc.target.com:443",
  "scheme": "https",
  "service": "pkg.Greeter",
  "method": "SayHello",
  "metadata": [
    {"name": "authorization", "value": "Bearer ..."}
  ],
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ],
  "positions": [
    {
      "path": "messages[0].payload",
      "encoding": "base64",
      "payloads": [
        "CgVhbGljZQ==",
        "CgZhZG1pbjE=",
        ""
      ]
    }
  ]
}
```

### JSON-path fuzz on a proto-schemaless-json payload (USK-925)
```json
{
  "target_addr": "grpc.target.com:443",
  "scheme": "https",
  "service": "pkg.Greeter",
  "method": "SayHello",
  "messages": [
    {
      "payload": "{\"0001:0000:String\":\"alice\",\"0002:0001:Varint\":42}",
      "body_encoding": "proto-schemaless-json"
    }
  ],
  "positions": [
    {
      "path": "messages[0].payload.0001:0000:String",
      "payloads": ["alice", "bob", "../../etc/passwd", "<script>"]
    },
    {
      "path": "messages[0].payload.0002:0001:Varint",
      "payloads": ["0", "1", "2147483647", "-1"]
    }
  ]
}
```
Both positions target the same message — the per-variant re-encode merges both mutations into one proto wire payload.

### Two-position (method x first message payload)
```json
{
  "target_addr": "grpc.target.com:443",
  "scheme": "https",
  "service": "pkg.Greeter",
  "method": "SayHello",
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ],
  "positions": [
    {
      "path": "method",
      "payloads": ["SayHello", "SayHelloAdmin", "Reset", "Drop"]
    },
    {
      "path": "messages[0].payload",
      "encoding": "base64",
      "payloads": ["CgVhbGljZQ==", "AAEC"]
    }
  ]
}
```

### Mix-scope macro hooks: login once, fuzz N RPCs, summarise once
```json
{
  "target_addr": "grpc.target.com:443",
  "scheme": "https",
  "service": "pkg.Greeter",
  "method": "SayHello",
  "metadata": [
    {"name": "authorization", "value": "Bearer §session_token§"}
  ],
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ],
  "positions": [
    {"path": "metadata[0].value", "payloads": ["Bearer §session_token§", "Bearer §session_token§ "]}
  ],
  "pre_macro":  {"name": "login-once", "scope": "job"},
  "post_macro": {"name": "audit-summary", "scope": "job"}
}
```
`pre_macro` (scope=job) runs once before the variant loop, extracts `session_token` into the job-scoped KV Store; every variant then sees `§session_token§` in the templated `authorization` metadata. `post_macro` (scope=job) runs once after the loop completes.

### Post macro gated on gRPC UNAVAILABLE (status code 14)
```json
{
  "target_addr": "grpc.target.com:443",
  "scheme": "https",
  "service": "pkg.Greeter",
  "method": "SayHello",
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ],
  "positions": [
    {"path": "messages[0].payload", "encoding": "base64", "payloads": ["CgVhbGljZQ==", "AAEC", "////"]}
  ],
  "post_macro": {
    "name": "alert-on-unavailable",
    "run_interval": "on_status",
    "status_codes": [14]
  }
}
```
`status_codes: [14]` matches the **gRPC** UNAVAILABLE code per `google.golang.org/grpc/codes` — NOT HTTP 503. Supplying `[503]` here would silently never fire because `__response_status` carries the gRPC code, not the HTTP-equivalent.

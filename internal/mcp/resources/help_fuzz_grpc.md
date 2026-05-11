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
| `messages[N].payload` | `GRPCDataMessage.Payload` (variant N) |

`scheme` / `target_addr` / `encoding` are intentionally NOT fuzz positions — they affect connection setup and would change the dial target rather than the on-wire envelope content. Callers that need to fuzz across schemes should issue separate `fuzz_grpc` calls.

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

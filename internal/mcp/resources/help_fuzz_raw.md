# fuzz_raw

Synchronously fuzz a raw byte payload with `RawMessage`-typed positions. Each variant traverses the same self-contained `PluginStepPost -> RecordStep` pipeline as `resend_raw` (`PluginStepPre` is bypassed per RFC-001 §9.3). Variants are executed sequentially with a fresh dial per variant.

`fuzz_raw` is the central tool for HTTP request smuggling and other byte-level fuzz scenarios — it is the only `fuzz_*` sibling that lets callers vary arbitrary bytes anywhere in the wire payload, not just typed L7 fields.

## Wire fidelity invariant

Wire bytes (`override_bytes`, `patches[].data`, position payloads, recovered `Flow.RawBytes`) reach the wire VERBATIM. CR/LF guards or any other content-level normalization are NEVER applied. This is the central HTTP smuggling fuzzing surface.

## Position path syntax (RawMessage-typed)

| Path | Behaviour |
|------|-----------|
| `payload` | replace the entire `RawMessage.Bytes` for the variant |
| `patches[N].data` | replace patch N's `data` field for the variant (`N` ∈ `[0, len(patches))`) |

`payload` wins over the recovered/override base bytes when both are present (the position payload becomes the variant bytes wholesale). `patches[N].data` mutates the input `patches[N].data` field for the variant; base+patches assembly proceeds as in `resend_raw`.

## Three operating modes

Unlike `resend_raw` (where `flow_id` is REQUIRED), `fuzz_raw` makes `flow_id` OPTIONAL and owns the from-scratch byte-injection path. Callers can either:

- supply `flow_id` (recovered `RawMessage` seeds the base bytes), or
- supply `override_bytes` (the entire base payload), or
- have a `payload` position with payloads listed (the variant payload itself defines the bytes — base bytes can be empty).

## Parameters

`fuzz_raw` inherits every `resend_raw` field (with `flow_id` relaxed to optional):

- `flow_id` (optional), `target_addr` (REQUIRED), `use_tls`, `sni`, `override_bytes`, `override_bytes_encoding`, `override_bytes_set`, `patches[]`, `insecure_skip_verify`, `tls_fingerprint`, `tag`, `timeout_ms`

See [help_resend_raw](yorishiro://help/resend_raw) for the inherited fields. Documentation here is on fuzz-specific fields only.

### positions (array, REQUIRED)
Ordered position list; at least one entry. Each position has:
- **path** (string, REQUIRED): typed path. One of: `payload | patches[N].data`.
- **payloads** (array of strings, REQUIRED): list of values to substitute at this path; at least one element.
- **encoding** (string, optional): `"text"` (default) or `"base64"`. Applies to every payload in this position. base64 is required for binary payloads (smuggling templates often contain control bytes).

### stop_on_error (boolean, optional)
When `true`, abort the remaining variants once any variant fails (network error, timeout, or pipeline drop).

### timeout_ms (integer, optional)
Per-VARIANT timeout in milliseconds. Default `30000`.

### pre_macro / post_macro (object, optional)

Pre and post macro hooks dispatched around variants by name (USK-986). Both fields take the same shape as the `fuzz_http` siblings (USK-960 / USK-961 / USK-981):

- **name** (string, REQUIRED): the stored macro name (defined via the `macro` tool's `define_macro` action).
- **scope** (string, optional): `"iteration"` (default) or `"job"`. See "Macro hook scopes" below.
- **on_error** (string, optional): `"skip"` (default) | `"abort"` | `"continue"`.
- **vars** (object string→string, optional): static kvStore overrides injected before the macro runs. Keys with the reserved prefix (`__`) are **silently dropped** so a `vars` entry cannot shadow runtime-populated keys.
- **run_interval** (string, optional): hook firing cadence — **`scope="iteration"` only**.
  - pre_macro legal values: `"always"` (default) | `"once"` | `"every_n"` | `"on_error"`.
  - post_macro legal values: `"always"` (default) | `"on_match"`.
- **n** (integer, optional): companion to pre_macro `run_interval="every_n"`. Required when `run_interval="every_n"`; must be ≥ 1.
- **match_pattern** (string, optional): companion to post_macro `run_interval="on_match"`. The buffer matched is `__response_body` (received bytes, 64 KiB cap).

`run_interval="on_error"` semantics (USK-989): pre_macro fires when the previous iteration's transport-level send/receive failed (`runErr != nil`). Raw has no L7 status concept, so HTTP-style 4xx/5xx triggers do not apply — only transport errors (dial failure, write/read failure, deadline) qualify. Iter-0 never fires because there is no previous iteration to react to. Pre-wire abort iterations (pre_macro skip, pre_macro abort) consume a counter slot but leave the previous wire-completed iteration's error signal in place, so the gate still reacts to the most recent real outcome.

#### Adaptor note — raw has no L7 status

Raw is the "+1 adaptor" in the typed-fuzz macro family. Raw is a byte stream, not a request/response transaction — it has no L7 status code and no header set. The following keys / values are therefore raw-specific:

| Reserved key | Behaviour on fuzz_raw |
|--------------|-----------------------|
| `__response_body` | YES — received bytes, capped at 64 KiB (independent of the row's 16 MiB `truncated` cap). |
| `__response_chunks` | YES — receive-loop envelope count, base-10 decimal string. |
| `__response_truncated` | YES — `"true"` if the receive loop hit the 16 MiB response cap, `"false"` otherwise. |
| `__response_status` | **NOT injected** (raw has no L7 status — MITM principle: do not invent hypothetical surface). |
| `__response_headers__<lower(name)>__` | **NOT injected** (raw has no headers). |

And the corresponding `run_interval` adjustment:

- `run_interval="on_status"` is **REJECTED at MCP-tool input parse** with the verbatim error message `fuzz_raw: post_macro run_interval="on_status" not supported (raw has no L7 status)` (and the matching pre-side `fuzz_raw: pre_macro run_interval="on_status" not supported (raw has no L7 status)`).
- Use `run_interval="on_match"` with a `match_pattern` regex against `__response_body` to gate post_macro on response-byte content.

#### Macro hook scopes

| Scope | Pre fires | Post fires | KV Store lifetime | `__response_*` keys | `§__iteration§` / `§__nonce§` |
|-------|-----------|------------|-------------------|---------------------|-------------------------------|
| `iteration` (default) | Before each variant's dial | After each variant's receive loop (EOF or response cap) | Fresh per variant | Visible to post (raw subset: body/chunks/truncated) | Seeded each iteration |
| `job` | Once before the variant loop | Once after the variant loop (incl. `stop_on_error` exit) | Shared across the whole job | NOT visible | NOT seeded |

Mix-scope is supported — `pre_macro` and `post_macro` may pick their scope independently. `run_interval` paired with `scope="job"` is **rejected at MCP-tool input parse** (job-scope hooks fire exactly once by construction).

## Result fields

- `fuzz_id` (string, UUID) — primary key of the `fuzz_jobs` row created for this run. Chain with `query { resource: "fuzz_results", filter: { fuzz_id: "...", outliers_only: true } }` to surface outlier variants without re-running the fuzz job (USK-837 + USK-278, parity with USK-827 for `fuzz_http`).
- `total_variants`, `completed_variants`, `stopped_reason`
- `variants[]` — per-variant compact rows:
  - `index`, `stream_id`
  - `response_size` (int): total received byte count
  - `response_chunks` (int): envelope count
  - `truncated` (bool): receive loop hit the response cap
  - `payloads` (object): position path -> chosen payload
  - `error` / `duration_ms`
- `duration_ms` / `tag`

## Aggregation: outlier-driven triage (recommended workflow)

`fuzz_raw` populates the `fuzz_jobs` / `fuzz_results` tables for every sync run, so AI agents can issue many variants then triage statistically:

1. `fuzz_raw { positions: [...], stop_on_error: false }` -> capture `fuzz_id` from the response.
2. `query { resource: "fuzz_results", fuzz_id: "<id>" }` -> summary statistics (response length distribution, median/stddev for response_length + timing) live under `summary.statistics`. Note: `status_code` is always `0` for Raw (no L7 status concept), so outlier detection on `fuzz_raw` runs is driven by `response_length` / `duration_ms` / `error` rather than status divergence.
3. `query { resource: "fuzz_results", fuzz_id: "<id>", filter: { outliers_only: true } }` -> just the variants that deviate from the baseline (response length/timing outside median +/- 2*stddev, or non-empty error).
4. Drill down on any outlier with `query { resource: "flow", id: <variant.stream_id> }` to see the full request + response wire bytes.

Variant Streams are stamped `origin = "fuzz"`, so `query { resource: "flows", filter: { origin: "fuzz" } }` cleanly separates fuzz-originated streams from live MITM capture and `resend_*`-originated streams.

## Examples

### From-scratch HTTP request smuggling fuzz (CL/TE templates)
```json
{
  "target_addr": "target.example.com:443",
  "use_tls": true,
  "positions": [
    {
      "path": "payload",
      "encoding": "base64",
      "payloads": [
        "UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiB0YXJnZXQNCkNvbnRlbnQtTGVuZ3RoOiA2DQpUcmFuc2Zlci1FbmNvZGluZzogY2h1bmtlZA0KDQowDQoNCkc=",
        "UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiB0YXJnZXQNCkNvbnRlbnQtTGVuZ3RoOiAxMQ0KVHJhbnNmZXItRW5jb2Rpbmc6IGNodW5rZWQNCg0KMA0KRw0KDQo="
      ]
    }
  ],
  "stop_on_error": true
}
```

### Replay-fuzz: vary one offset patch's data byte
```json
{
  "flow_id": "raw-abc-123",
  "target_addr": "target.example.com:443",
  "use_tls": true,
  "patches": [
    {"offset": 16, "data": "QQ==", "data_encoding": "base64"}
  ],
  "positions": [
    {
      "path": "patches[0].data",
      "encoding": "base64",
      "payloads": ["QQ==", "QkM=", "AA=="]
    }
  ]
}
```

### Two-position cartesian product on a from-scratch base
```json
{
  "target_addr": "127.0.0.1:8080",
  "override_bytes": "GET / HTTP/1.1\r\nHost: target\r\n\r\n",
  "override_bytes_encoding": "text",
  "patches": [
    {"offset": 4, "data": "X", "data_encoding": "text"},
    {"offset": 12, "data": "Y", "data_encoding": "text"}
  ],
  "positions": [
    {"path": "patches[0].data", "payloads": ["A", "B"]},
    {"path": "patches[1].data", "payloads": ["X", "Y", "Z"]}
  ]
}
```

### Fuzz with no base — payload position supplies every variant's bytes
```json
{
  "target_addr": "127.0.0.1:8080",
  "positions": [
    {
      "path": "payload",
      "payloads": [
        "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: b\r\n\r\n",
        "GET /admin HTTP/1.1\r\nHost: a\r\n\r\n"
      ]
    }
  ]
}
```

# fuzz_ws

Synchronously fuzz a WebSocket frame with `WSMessage`-typed positions. Each variant traverses the same self-contained `PluginStepPost -> RecordStep` pipeline as `resend_ws` (`PluginStepPre` is bypassed per RFC-001 §9.3) on a freshly dialled + upgraded WebSocket connection.

The schema mirrors `resend_ws` plus a `positions[]` list. The cartesian product of all positions yields the variant sequence (capped at **1000 variants per call**). Each variant gets its own TCP connection, upgrade dance, and Stream row. Auto-Pong replies for incoming Pings are emitted by the receive loop (mirroring `resend_ws`); the variant terminates on the first non-control frame OR a Close frame OR ctx timeout.

## Position path syntax (WSMessage-typed)

| Path | WSMessage field |
|------|------------------|
| `payload` | `WSMessage.Payload` (interpreted per encoding) |
| `close_reason` | `WSMessage.CloseReason` |

## Two operating modes

### Mode A: replay-fuzz (`flow_id` set)

When `flow_id` is set, the upgrade Stream's send/receive Flows seed the upgrade-dance URL/headers and the negotiated `Sec-WebSocket-Extensions` value used by deflate.

### Mode B: from-scratch fuzz (`flow_id` empty)

`target_addr` and `path` are REQUIRED up-front. `compressed=true` is rejected because no extension was negotiated.

## Parameters

`fuzz_ws` inherits every `resend_ws` field verbatim:

- `flow_id`, `target_addr`, `scheme`, `path`, `raw_query`, `opcode`, `fin`, `payload`, `body_encoding`, `payload_set`, `masked`, `mask`, `close_code`, `close_reason`, `compressed`, `tls_fingerprint`, `tag`, `timeout_ms`

See [help_resend_ws](yorishiro://help/resend_ws) for the inherited fields. Documentation here is on fuzz-specific fields only.

### positions (array, REQUIRED)
Ordered position list; at least one entry. Each position has:
- **path** (string, REQUIRED): typed path into WSMessage. One of: `payload | close_reason`.
- **payloads** (array of strings, REQUIRED): list of values to substitute at this path; at least one element.
- **encoding** (string, optional): `"text"` (default) or `"base64"`. Applies to every payload in this position.

### stop_on_close (boolean, optional)
When `true`, abort the remaining variants once any variant receives a Close frame from upstream.

### timeout_ms (integer, optional)
Per-VARIANT timeout in milliseconds. Default `30000`.

### pre_macro / post_macro (object, optional)

Pre and post macro hooks dispatched around variants by name (USK-984 — same shape as the fuzz_http macro hooks). Both fields take the same object structure:

- **name** (string, REQUIRED): the stored macro name (defined via the `macro` tool's `define_macro` action).
- **scope** (string, optional): `"iteration"` (default) or `"job"`. See "Macro hook scopes" below.
- **on_error** (string, optional): `"skip"` (default) | `"abort"` | `"continue"`. See "OnError semantics" below.
- **vars** (object string→string, optional): static kvStore overrides injected before the macro runs. For `scope="iteration"` the map is injected into every variant's per-iteration kvStore (after the job-store copy, before reserved-key seeding). For `scope="job"` it is injected once into the job kvStore at job start. Keys with the reserved prefix (`__`) are **silently dropped** at injection time so a `vars` entry cannot shadow runtime-populated keys (`__iteration`, `__nonce`, `__response_*`).
- **run_interval** (string, optional): hook firing cadence — **`scope="iteration"` only**. Rejected with an error when paired with `scope="job"`.
  - pre_macro legal values: `"always"` (default) | `"once"` | `"every_n"` | `"on_error"`.
  - post_macro legal values: `"always"` (default) | `"on_status"` | `"on_match"`.
  - `on_error` semantics (USK-987): fires when the previous variant had a transport error (dial / upgrade / receive failure). WebSocket close-frame codes (RFC 6455 §7.4) do **NOT** trigger on_error — close frames are L7 graceful-shutdown signals, not error signals. If you need close-code-driven re-auth, file a follow-up Issue with a concrete reproducer. Does **NOT** fire on iteration 0 — there is no previous request to react to. Use for reactive flows like "re-dial / re-handshake after a transport failure". The trigger looks at the previous iteration only; consecutive errors will fire the hook on every iteration after the first error, while a single error fires it exactly once on the next iteration.
- **n** (integer, optional): companion to pre_macro `run_interval="every_n"`.
- **status_codes** (array of integer, optional): companion to post_macro `run_interval="on_status"`. For fuzz_ws this matches the terminating frame's RFC 6455 close_code (uint16). Include `0` in the list to match variants where the terminating frame is NOT a Close frame (text / binary / etc.).
- **match_pattern** (string, optional): companion to post_macro `run_interval="on_match"`. For fuzz_ws this matches the close_reason text — WebSocket frames do not have a body equivalent on the macro path.

The hook macro shares the per-iteration (or per-job) KV Store with the fuzz request. The post macro (scope=iteration only) receives WS-specific reserved keys:

| Reserved key | Source | Cap |
|--------------|--------|-----|
| `__response_status` | numeric close_code (proxy for L7 status) | — |
| `__response_opcode` | terminating frame opcode name (`text`, `binary`, `close`, …) | — |
| `__response_payload` | terminating frame payload bytes | 64 KiB (CWE-770 — matches `__response_body`'s cap for HTTP; the WS Layer caps a single frame at 16 MiB but kvStore values feed template expansion at every downstream macro invocation) |
| `__response_close_code` | RFC 6455 close_code as decimal string. `0` denotes "no close frame" — the terminating frame is a text / binary / etc. frame. | — |
| `__response_close_reason` | RFC 6455 close_reason UTF-8 text (per spec ≤ 125 bytes — no DoS surface) | — |

`__response_headers__<lower(name)>__` is **not applicable** for fuzz_ws — WebSocket frames have no header surface.

#### Macro hook scopes

| Scope | Pre fires | Post fires | KV Store lifetime | `__response_*` keys | `§__iteration§` / `§__nonce§` |
|-------|-----------|------------|-------------------|---------------------|-------------------------------|
| `iteration` (default) | Before each variant's dial + upgrade | After each variant's terminating frame | Fresh per variant | Visible to post | Seeded each iteration |
| `job` | Once before the variant loop | Once after the variant loop (incl. `stop_on_close` exit) | Shared across the whole job | NOT visible | NOT seeded |

Mix-scope is supported — `pre_macro` and `post_macro` may pick their scope independently. The job-scope KV Store is merged into each iteration's per-variant store at iteration start; per-iteration reserved keys then overwrite any conflicting job keys ("iteration wins"). So `pre_macro { scope: "job" }` extracting `session_token` makes `§session_token§` resolvable in every variant's `positions[].payloads` template tokens.

> `run_interval` is `scope="iteration"` only. Pairing `run_interval` with `scope="job"` is rejected at MCP-tool input parse with the error `"run_interval is only valid for scope=iteration; for scope=job the hook fires exactly once"`.

#### OnError semantics

| OnError | pre / scope=iteration | pre / scope=job | post / either scope |
|---------|----------------------|-----------------|--------------------|
| `skip` (default) | Skip the variant: don't send, don't run post. Record `fuzz_macro_results.status="skipped"`. | Skip the entire job — `completed_variants=0`, `stopped_reason="pre_macro hook skipped (scope=job, on_error=skip): ..."`. | Record `fuzz_macro_results.status="error"`. Never aborts the run. |
| `abort` | Abort the whole fuzz run with an error. | Abort the whole job before any variant runs. | Record `fuzz_macro_results.status="error"`. Never aborts. |
| `continue` | Log warn + record error row, proceed with whatever the kvStore captured; templates may carry unresolved `§var§` literals. | Log warn + record error row, proceed with variant loop. | Same as `skip` for post. |

#### fuzz_macro_results schema notes

The `fuzz_macro_results` table (one row per hook invocation) keys on `(fuzz_id, index_num, hook_name)`:

- **`index_num`** is the 0-based variant index for `scope="iteration"` rows.
- **`index_num = -1`** is the sentinel for `scope="job"` rows.

## Result fields

- `fuzz_id` (string, UUID) — primary key of the `fuzz_jobs` row created for this run. Chain with `query { resource: "fuzz_results", filter: { fuzz_id: "...", outliers_only: true } }` to surface outlier variants without re-running the fuzz job (USK-836 + USK-278).
- `total_variants`, `completed_variants`, `stopped_reason`
- `variants[]` — per-variant compact rows:
  - `index`, `stream_id`
  - `opcode`, `fin` — terminating frame metadata
  - `payload_size` (int): terminating frame payload byte length. Full payload retrievable via `query` keyed by `stream_id`. (Storing the full payload would let a malicious upstream amplify memory use up to 1000 × 16 MiB; CWE-770. `close_reason` stays on the row because RFC 6455 §5.5.1 caps Close payloads at 125 bytes.)
  - `compressed` (bool)
  - `close_code` (uint16) / `close_reason` (string)
  - `payloads` (object): position path -> chosen payload, for correlation
  - `error` / `duration_ms`
- `duration_ms` / `tag`

## Aggregation: outlier-driven triage (recommended workflow)

`fuzz_ws` populates the `fuzz_jobs` / `fuzz_results` tables for every sync run, so AI agents can issue many variants then triage statistically:

1. `fuzz_ws { positions: [...], stop_on_close: false }` -> capture `fuzz_id` from the response.
2. `query { resource: "fuzz_results", fuzz_id: "<id>" }` -> summary statistics live under `summary.statistics`. For WebSocket runs, `status_code` carries `int(row.close_code)` — 0 when the terminating frame is not a Close frame — and `response_length` carries the terminating frame's payload byte length.
3. `query { resource: "fuzz_results", fuzz_id: "<id>", filter: { outliers_only: true } }` -> just the variants that deviate from the baseline (different close code OR payload length/timing outside median +/- 2*stddev).
4. Drill down on any outlier with `query { resource: "flow", id: <variant.stream_id> }` to see the full upgrade dance + frame wire bytes.

Variant Streams are stamped `origin = "fuzz"`, so `query { resource: "flows", filter: { origin: "fuzz" } }` cleanly separates fuzz-originated streams from live MITM capture.

## Examples

### Fuzz a text frame payload from scratch
```json
{
  "target_addr": "ws.target.com:443",
  "scheme": "wss",
  "path": "/socket",
  "opcode": "text",
  "positions": [
    {
      "path": "payload",
      "payloads": [
        "{\"action\":\"subscribe\",\"channel\":\"a\"}",
        "{\"action\":\"subscribe\",\"channel\":\"admin\"}",
        "{\"action\":\"unauthorized\"}"
      ]
    }
  ]
}
```

### Fuzz a close frame's reason text against a recorded flow
```json
{
  "flow_id": "ws-abc-123",
  "opcode": "close",
  "close_code": 1000,
  "positions": [
    {
      "path": "close_reason",
      "payloads": ["bye", " ", "<script>alert(1)</script>"]
    }
  ]
}
```

### Two-position fuzz (payload x close_reason) on Close frames
```json
{
  "flow_id": "ws-abc-123",
  "opcode": "close",
  "close_code": 1000,
  "positions": [
    {"path": "payload", "payloads": ["a", "b"]},
    {"path": "close_reason", "payloads": ["x", "y", "z"]}
  ],
  "stop_on_close": true
}
```

### Binary payload fuzz (base64-encoded bytes per variant)
```json
{
  "target_addr": "ws.target.com:443",
  "scheme": "wss",
  "path": "/binary",
  "opcode": "binary",
  "positions": [
    {
      "path": "payload",
      "encoding": "base64",
      "payloads": ["AAECAwQF", "//////8=", "fwAAAAAA"]
    }
  ]
}
```

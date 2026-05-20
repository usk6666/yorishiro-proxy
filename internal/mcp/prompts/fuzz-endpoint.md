# Fuzz an Endpoint — General Workflow

General-purpose fuzzing workflow for a recorded request. Picks the typed fuzz tool (`fuzz_http` / `fuzz_ws` / `fuzz_grpc` / `fuzz_raw`) that matches the captured flow's protocol.

## Inputs

- `target_flow_id`: recorded `flow_id` to fuzz against. Required.
- `position_path`: typed position path matching the protocol (see "Position path reference" below). Required.
- `payload_set`: a name or short description of what to test (e.g. `boundary-numbers`, `path-traversal`, `unicode-edge`). Used as the fuzz `tag`. Required.

If any required field is empty, ask the user.

## Plan

### 1. Identify the protocol

```json
// query
{"resource": "flow", "id": "{{target_flow_id}}"}
```

Inspect the `protocol` field on the flow:
- `http/1.1` or `h2` → use `fuzz_http`.
- `ws` → use `fuzz_ws`.
- `grpc` or `grpc-web` → use `fuzz_grpc`.
- `raw` → use `fuzz_raw`.

### 2. Pick the position path

See "Position path reference" for the protocol-specific path syntax.

### 3. Build the payload list

Author payloads appropriate to `{{payload_set}}`. Keep the list small at first (5–10 entries) — large sweeps are cheaper to iterate on once you've confirmed the position is correct.

### 4. Run the fuzz

Example for HTTP:

```json
// fuzz_http
{
  "flow_id": "{{target_flow_id}}",
  "positions": [
    {
      "path": "{{position_path}}",
      "payloads": [
        "<payload-1>",
        "<payload-2>",
        "<payload-3>"
      ]
    }
  ],
  "tag": "{{payload_set}}"
}
```

For WS / gRPC / Raw, the call shape is the same — only the tool name and `positions[].path` differ.

### 5. Sort, filter, and inspect results

```json
// query
{
  "resource": "fuzz_results",
  "fuzz_id": "<fuzz-id-from-step-4>",
  "sort_by": "status_code",
  "limit": 200,
  "fields": ["index", "payloads", "status_code", "duration_ms", "response_length"]
}
```

Useful narrowing filters:
- `filter.status_code` — only specific status codes.
- `filter.body_contains` — only responses containing a substring.
- `filter.outliers_only: true` — only entries whose duration / size deviates from the median.

Drill into a specific result's flow:

```json
// query
{"resource": "flow", "id": "<result-flow-id>"}
```

## Position path reference

| Tool | Path | Use case |
|------|------|----------|
| `fuzz_http` | `method` | Replace HTTP method (GET, POST, ...) |
| `fuzz_http` | `scheme` | Replace request scheme |
| `fuzz_http` | `authority` | Replace Host / `:authority` |
| `fuzz_http` | `path` | Replace the request path |
| `fuzz_http` | `raw_query` | Replace the raw query string (no leading `?`) |
| `fuzz_http` | `body` | Replace the request body |
| `fuzz_http` | `headers[N].name` | Replace the Nth header's name |
| `fuzz_http` | `headers[N].value` | Replace the Nth header's value |
| `fuzz_ws` | `payload` | Replace the WS frame payload |
| `fuzz_ws` | `close_reason` | Replace the WS close reason |
| `fuzz_grpc` | `service`, `method` | Replace the gRPC service / method name |
| `fuzz_grpc` | `metadata[N].name`, `metadata[N].value` | Replace gRPC metadata |
| `fuzz_grpc` | `messages[N].payload` | Replace gRPC request message bytes |
| `fuzz_raw` | `payload` | Replace the entire raw byte buffer |
| `fuzz_raw` | `patches[N].data` | Patch a byte range |

Each payload is interpreted per the position's `encoding` field (`text` default; use `base64` for binary). To delete a header slot entirely, fall back to `resend_http` with a rebuilt `headers` array.

## Safety reminder

If the endpoint is state-changing (POST/PUT/PATCH/DELETE), avoid payloads that could destroy data:
- Do not send `DROP`, `DELETE FROM`, `UPDATE`, `INSERT`, `ALTER`, `TRUNCATE`.
- Avoid `OR 1=1` style condition modification (mass-update risk).
- Prefer time-based / error-based probes when you must touch a side-effecting endpoint.

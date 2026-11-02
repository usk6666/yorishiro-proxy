# manage

Manage flow data and CA certificates.

## Parameters

### action (string, required)
The action to execute. One of: `delete_flows`, `export_flows`, `import_flows`, `regenerate_ca_cert`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### delete_flows
Delete flows by ID, by age, by filter (protocol / scheme / http_version), or all at once.

**Parameters:**
- **flow_id** (string, optional): Delete a specific flow by ID.
- **older_than_days** (integer, optional): Delete flows older than this many days. Must be >= 1. Requires `confirm: true`.
- **protocol** (string, optional): Filter axis — matches `Stream.Protocol` exactly. Canonical values: `"http"`, `"ws"`, `"grpc"`, `"grpc-web"`, `"sse"`, `"raw"`, `"tls-handshake"`. Mirrors `query.filter.protocol`. Requires `confirm: true`.
- **scheme** (string, optional): Filter axis — matches `Stream.Scheme` (wire-observed handshake transport) exactly. Canonical values: `"http"`, `"https"`, `"tcp"`. Use `"https"` to delete only TLS flows (cleartext untouched). To target WebSocket flows, combine `protocol="ws"` with `scheme="https"` for WS-over-TLS only. Values `"ws"` / `"wss"` are rejected as of USK-864 (per USK-848, Stream.Scheme records the handshake transport, not the application protocol). Mirrors `query.filter.scheme`. Requires `confirm: true`.
- **http_version** (string, optional): Filter axis — matches the stream's head HTTP version (the value `query` shows as `flows[].http_version`). Canonical values: `"http/1.0"`, `"http/1.1"`, `"h2"`, `"h2c"`. The explicit empty string `""` matches streams with no HTTP version — non-HTTP protocols (gRPC, gRPC-Web, raw, tls-handshake), rows recorded before the field existed, and streams with no recorded flows. Mirrors `query.filter.http_version`. Requires `confirm: true`.
- **confirm** (boolean): Required for any bulk deletion (older_than_days, filter axes, or delete-all). Set to `true` to proceed.

`protocol`, `scheme`, and `http_version` combine with AND when multiple are supplied. One of `flow_id`, `older_than_days`, any filter axis (with confirm), or `confirm` (for delete-all) must be specified.

Returns: deleted_count, cutoff_time (for age-based deletion).

### regenerate_ca_cert
Regenerate the CA certificate. Behavior depends on the CA initialization mode:

- **Auto-persist mode** (default): Generates a new CA and saves it to the default path (`~/.yorishiro-proxy/ca/`). Users must re-install the CA certificate.
- **Ephemeral mode** (`--ca-ephemeral`): Generates a new CA in memory only. Lost on restart.
- **Explicit mode** (`-ca-cert`/`-ca-key`): Returns an error. User-provided CA files are not overwritten.

No parameters required.

Returns: fingerprint, subject, not_after, persisted, cert_path, install_hint.

### export_flows
Export flows to JSONL or HAR (HTTP Archive 1.2) format with optional filtering.

**Parameters:**
- **format** (string, optional): Export format. `"jsonl"` (default) for JSONL or `"har"` for HAR 1.2.
- **filter** (object, optional): Flow filter criteria. Filter axes mirror the `query` tool so analysts can export the same set of flows they were inspecting.
  - **protocol** (string, optional): Filter by `Stream.Protocol`. Canonical values: `"http"`, `"ws"`, `"grpc"`, `"grpc-web"`, `"sse"`, `"raw"`, `"tls-handshake"`.
  - **scheme** (string, optional): Filter by `Stream.Scheme` (wire-observed handshake transport). Canonical values: `"http"`, `"https"`, `"tcp"`. Use `"https"` to export only TLS flows. To target WebSocket flows, combine `protocol="ws"` with `scheme="https"` for WS-over-TLS only. Values `"ws"` / `"wss"` are rejected as of USK-864.
  - **http_version** (string, optional): Filter by the stream's head HTTP version (the value `query` shows as `flows[].http_version`). Canonical values: `"http/1.0"`, `"http/1.1"`, `"h2"`, `"h2c"`. The explicit empty string `""` matches streams with no HTTP version — non-HTTP protocols (gRPC, gRPC-Web, raw, tls-handshake), rows recorded before the field existed, and streams with no recorded flows.
  - **url_pattern** (string, optional): Filter by URL substring.
  - **time_after** (string, optional): Include flows after this time (RFC3339 format).
  - **time_before** (string, optional): Include flows before this time (RFC3339 format).
- **include_bodies** (boolean, optional): Include message body and raw_bytes in export (default: `true`). Set to `false` for metadata-only export.
- **output_path** (string, optional for JSONL, **required for HAR**): File path to write the export data, confined to the server's export directory (see "File paths" below). Pass a relative name such as `"flows.har"`. JSONL supports inline output when omitted; HAR always requires a file path.

**Format details:**
- **JSONL**: Each line is a complete JSON object containing a flow and its messages. Supports inline and file output.
- **HAR**: HTTP Archive 1.2 format. Single JSON object compatible with browser DevTools, Burp Suite, and OWASP ZAP. File output only. Raw TCP and gRPC flows are excluded. WebSocket flows include `_webSocketMessages` custom field. Binary bodies are base64-encoded with `content.encoding: "base64"`.
- **URLs** (both formats): the request path is exported in wire form (percent-encoding as sent). JSON cannot carry bytes that are not valid UTF-8, so such path / query bytes are written `%XX`-escaped (e.g. the wire byte `0xFF` as `%FF`); all other bytes are verbatim. This is the one lossy case: importing such a JSONL row stores the escaped text, not the original byte.

Returns: exported_count, format, output_path (if file output), data (if inline output).

### import_flows
Import flows from a JSONL file. Each line must be a valid export record with version "1".

**Parameters:**
- **input_path** (string, required): File path to read the JSONL import data, confined to the server's export directory (see "File paths" below), e.g. `"flows.jsonl"`.
- **on_conflict** (string, optional): What to do when a line's stream ID is already stored. `"skip"` (default) keeps the stored stream and ignores the line; `"replace"` deletes the stored stream and re-imports it; `"merge"` updates the stored stream from the line (the latest line wins for state, tags, failure_reason, timings, TLS fields; conn_id, timestamp, origin, listener_name and client_addr keep their stored values) and inserts the line's flows whose IDs are not stored yet. `"merge"` is idempotent — importing the same lines again changes nothing — and is the policy for flow sink files (below), where one stream spans many lines. Under `"merge"` a line whose flow names another stream than the line's stream is an error.

Flow sink `"gap"` lines are skipped under every policy. Imported rows are not re-emitted by this server's own flow sink.

Returns: imported (new streams), skipped, merged (lines merged into a stored stream; `"merge"` only), errors, source.

### Flow sink files
A server started with a `flow_sink` block in its `-config` file streams every committed record to `<dir>/flows.jsonl` as it is written: one line per stream creation, stream update and saved flow (recording, `resend_*`, `fuzz_*`, budget and capacity audit rows; not rows written by `import_flows`). SQLite stays the system of record; the sink is a best-effort replica for an off-host consumer. The directory is set by the operator at boot only — no MCP tool can change it, and it may not overlap the export directory, so `manage` can neither read nor plant files there. To bring sink lines into an instance, copy them into its export directory and run `import_flows` with `on_conflict: "merge"` (a line is subject to the same import line-size limit as an `export_flows` line, derived from `max_body_size`).

```json
{"flow_sink": {"dir": "/var/lib/yorishiro/sink", "max_file_bytes": 67108864, "max_files": 0,
               "queue_max_events": 4096, "queue_max_bytes": 268435456,
               "include_bodies": true, "wire_level": "semantic", "fsync": false}}
```

Only `dir` is required; the values shown are the defaults. `wire_level` takes the `export_flows` vocabulary (`semantic` default, one overlay level, or `all`).

**The sink is not masked.** The SafetyFilter Output Filter applies only where an MCP tool returns recorded data; sink lines carry bodies and raw bytes exactly as recorded. Protect the directory like the database: `flows.jsonl` is kept at mode 0600, a symlinked `flows.jsonl` is refused, and a directory accessible by group/other is reported with a warning.

**Line format** — a superset of the `export_flows` JSONL record (`version` `"1"`), so every line imports:
- `event`: `stream_created`, `stream_updated`, `flow_saved` or `gap`.
- `stream`: the stream's snapshot as stored when the line was written (so it can be newer than the event; the latest line per stream ID wins). `flows`: empty, or the one saved flow (headers, body and `raw_bytes` base64 as stored; an intercept variant pair is two lines).
- `seq`: per-run event number from 1; `run_id`: one per server process; `emitted_at`: write time (RFC 3339, UTC).
- A flow whose body + raw bytes exceed `queue_max_bytes` is written without them, with `body_omitted` / `body_size` / `body_sha256` and `raw_bytes_omitted` / `raw_bytes_size` / `raw_bytes_sha256`; importing it (either payload omitted) marks the flow `body_truncated`.

**Loss is detectable, not prevented.** The proxy never waits for the sink: when the in-memory queue (`queue_max_events` / `queue_max_bytes`) is full, the event is dropped. The next line written is then preceded by `{"event":"gap","gap":{"dropped":N,"dropped_bytes":B,"first_seq":F,"last_seq":L}}` covering exactly the missing `seq` numbers (also written at shutdown for drops no later event reported). `query { resource: "status" }` reports `flow_sink` {dir, run_id, emitted, dropped_events, dropped_bytes, write_errors}. A `seq` jump with no gap line means lines were lost after writing (for example a crash before `fsync`).

**Rotation** — when the next line would take `flows.jsonl` past `max_file_bytes`, the file is renamed to `flows-<UTC timestamp>-<n>.jsonl` (names sort chronologically) and a new `flows.jsonl` is started, so a line never spans two files and a rotated file is complete. A non-empty `flows.jsonl` found at startup (an earlier run's, possibly ending in a torn line after a crash) is rotated away first. The consumer reads rotated files and deletes them when ingested; the proxy deletes rotated files itself only with `max_files` > 0 (oldest first). At shutdown, queued lines are flushed for up to 5 s.

### File paths (output_path / input_path)
Every file `export_flows` writes and `import_flows` reads lives in one **export directory** on the proxy server's filesystem. The operator sets it at server start with `-export-dir` / `YP_EXPORT_DIR` (default `~/.yorishiro-proxy/exports/`); no MCP tool can change it. `query { resource: "status" }` (and `resource: "config"`) reports it as `export_dir`, which is how HTTP-remote callers learn where their files land.

- A **relative** path resolves against the export directory: `"flows.har"`, `"run1/flows.jsonl"`. This is the recommended form.
- An **absolute** path is accepted only if it lies inside the export directory, spelled as reported in `export_dir` (or as its symlink-resolved real path). An absolute path that reaches the directory through some other symlinked alias is rejected; use a relative path instead.
- Anything else — an absolute path elsewhere, a `..` escape, a symlink inside the directory that points outside it — is rejected with `path "..." resolves outside export directory <dir>; set -export-dir / YP_EXPORT_DIR or use a path relative to it`.
- A symlink as the final component is rejected with `file path must not be a symbolic link: <path>`.
- Subdirectories must already exist; they are not created. Re-exporting to an existing name overwrites it.
- The returned `output_path` / `source` is the absolute path inside the export directory.

The server refuses to start if the export directory contains its config file, target policy file, CA certificate/key, database, log file, server.json, WebUI directory, plugin scripts or TLS client certificate / key / CA bundle files, so an export can never overwrite them.

**Operators:** `-export-dir` must be a **dedicated directory used only for exports**. The boot check only knows the proxy's own files; anything else inside the directory can be overwritten by an MCP caller. For example, a directory such as `~/.config` would let an agent replace shell or autostart files (code execution on the next login). `$HOME` itself is refused because it contains `~/.yorishiro-proxy/`. (Before USK-1127, relative paths resolved against the server process's working directory and absolute paths were unrestricted — that USK-868 contract is superseded.)

## Usage Examples

### Delete single flow
```json
{
  "action": "delete_flows",
  "params": {"flow_id": "abc-123"}
}
```

### Delete old flows
```json
{
  "action": "delete_flows",
  "params": {"older_than_days": 30, "confirm": true}
}
```

### Delete all flows
```json
{
  "action": "delete_flows",
  "params": {"confirm": true}
}
```

### Delete only HTTPS flows (cleartext untouched)
```json
{
  "action": "delete_flows",
  "params": {"scheme": "https", "confirm": true}
}
```

### Delete only HTTP/2 flows
```json
{
  "action": "delete_flows",
  "params": {"http_version": "h2", "confirm": true}
}
```

### Delete combination (AND): HTTP family over TLS on h2
```json
{
  "action": "delete_flows",
  "params": {
    "protocol": "http",
    "scheme": "https",
    "http_version": "h2",
    "confirm": true
  }
}
```

### Regenerate CA certificate
```json
{
  "action": "regenerate_ca_cert",
  "params": {}
}
```

### Export all flows to file
```json
{
  "action": "export_flows",
  "params": {
    "format": "jsonl",
    "include_bodies": true,
    "output_path": "export.jsonl"
  }
}
```

### Export flows to HAR file
```json
{
  "action": "export_flows",
  "params": {
    "format": "har",
    "include_bodies": true,
    "output_path": "export.har"
  }
}
```

### Export filtered flows to HAR
```json
{
  "action": "export_flows",
  "params": {
    "format": "har",
    "filter": {
      "protocol": "http",
      "url_pattern": "/api/"
    },
    "output_path": "api-flows.har"
  }
}
```

### Export only HTTPS flows to JSONL
```json
{
  "action": "export_flows",
  "params": {
    "format": "jsonl",
    "filter": {"scheme": "https"},
    "output_path": "https-flows.jsonl"
  }
}
```

### Export only HTTP/2 flows to JSONL
```json
{
  "action": "export_flows",
  "params": {
    "format": "jsonl",
    "filter": {"http_version": "h2"},
    "output_path": "h2-flows.jsonl"
  }
}
```

### Export filtered flows (metadata only)
```json
{
  "action": "export_flows",
  "params": {
    "format": "jsonl",
    "filter": {
      "protocol": "http",
      "url_pattern": "/api/",
      "time_after": "2026-02-01T00:00:00Z",
      "time_before": "2026-02-28T23:59:59Z"
    },
    "include_bodies": false
  }
}
```

### Import flows (skip duplicates)
```json
{
  "action": "import_flows",
  "params": {
    "input_path": "export.jsonl",
    "on_conflict": "skip"
  }
}
```

### Import flows (replace duplicates)
```json
{
  "action": "import_flows",
  "params": {
    "input_path": "export.jsonl",
    "on_conflict": "replace"
  }
}
```

### Import a flow sink file
```json
{
  "action": "import_flows",
  "params": {
    "input_path": "flows-20261101T120000.000000000Z-000001.jsonl",
    "on_conflict": "merge"
  }
}
```

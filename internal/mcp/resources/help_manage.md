# manage

Manage flow data and CA certificates.

## Parameters

### action (string, required)
The action to execute. One of: `delete_flows`, `export_flows`, `import_flows`, `regenerate_ca_cert`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### delete_flows
Delete flows by ID, by age, by protocol, or all at once.

**Parameters:**
- **flow_id** (string, optional): Delete a specific flow by ID.
- **older_than_days** (integer, optional): Delete flows older than this many days. Must be >= 1. Requires `confirm: true`.
- **protocol** (string, optional): Delete flows by protocol (e.g. `"TCP"`, `"WebSocket"`). Requires `confirm: true`.
- **confirm** (boolean): Required for bulk deletion (older_than_days, protocol, or all). Set to `true` to proceed.

One of `flow_id`, `older_than_days`, `protocol` (with confirm), or `confirm` (for delete-all) must be specified.

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
- **filter** (object, optional): Flow filter criteria:
  - **protocol** (string, optional): Filter by protocol (e.g. `"HTTPS"`, `"HTTP/1.x"`).
  - **url_pattern** (string, optional): Filter by URL substring.
  - **time_after** (string, optional): Include flows after this time (RFC3339 format).
  - **time_before** (string, optional): Include flows before this time (RFC3339 format).
- **include_bodies** (boolean, optional): Include message body and raw_bytes in export (default: `true`). Set to `false` for metadata-only export.
- **output_path** (string, optional for JSONL, **required for HAR**): File path to write the export data. JSONL supports inline output when omitted; HAR always requires a file path.

**Format details:**
- **JSONL**: Each line is a complete JSON object containing a flow and its messages. Supports inline and file output.
- **HAR**: HTTP Archive 1.2 format. Single JSON object compatible with browser DevTools, Burp Suite, and OWASP ZAP. File output only. Raw TCP and gRPC flows are excluded. WebSocket flows include `_webSocketMessages` custom field. Binary bodies are base64-encoded with `content.encoding: "base64"`.

Returns: exported_count, format, output_path (if file output), data (if inline output).

### import_flows
Import flows from a JSONL file. Each line must be a valid export record with version "1".

**Parameters:**
- **input_path** (string, required): File path to read the JSONL import data.
- **on_conflict** (string, optional): Conflict resolution policy for duplicate flow IDs. `"skip"` (default) skips existing flows; `"replace"` deletes and re-imports.

Returns: imported, skipped, errors, source.

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
    "output_path": "/tmp/export.jsonl"
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
    "output_path": "/tmp/export.har"
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
      "protocol": "HTTPS",
      "url_pattern": "/api/"
    },
    "output_path": "/tmp/api-flows.har"
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
      "protocol": "HTTPS",
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
    "input_path": "/tmp/export.jsonl",
    "on_conflict": "skip"
  }
}
```

### Import flows (replace duplicates)
```json
{
  "action": "import_flows",
  "params": {
    "input_path": "/tmp/export.jsonl",
    "on_conflict": "replace"
  }
}
```

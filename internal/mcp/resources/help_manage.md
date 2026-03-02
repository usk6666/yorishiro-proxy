# manage

Manage session data and CA certificates.

## Parameters

### action (string, required)
The action to execute. One of: `delete_sessions`, `export_sessions`, `import_sessions`, `regenerate_ca_cert`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### delete_sessions
Delete sessions by ID, by age, by protocol, or all at once.

**Parameters:**
- **session_id** (string, optional): Delete a specific session by ID.
- **older_than_days** (integer, optional): Delete sessions older than this many days. Must be >= 1. Requires `confirm: true`.
- **protocol** (string, optional): Delete sessions by protocol (e.g. `"TCP"`, `"WebSocket"`). Requires `confirm: true`.
- **confirm** (boolean): Required for bulk deletion (older_than_days, protocol, or all). Set to `true` to proceed.

One of `session_id`, `older_than_days`, `protocol` (with confirm), or `confirm` (for delete-all) must be specified.

Returns: deleted_count, cutoff_time (for age-based deletion).

### regenerate_ca_cert
Regenerate the CA certificate. Behavior depends on the CA initialization mode:

- **Auto-persist mode** (default): Generates a new CA and saves it to the default path (`~/.yorishiro-proxy/ca/`). Users must re-install the CA certificate.
- **Ephemeral mode** (`--ca-ephemeral`): Generates a new CA in memory only. Lost on restart.
- **Explicit mode** (`-ca-cert`/`-ca-key`): Returns an error. User-provided CA files are not overwritten.

No parameters required.

Returns: fingerprint, subject, not_after, persisted, cert_path, install_hint.

### export_sessions
Export sessions to JSONL format with optional filtering. Each line in the output is a complete JSON object containing a session and its messages.

**Parameters:**
- **format** (string, optional): Export format. Currently only `"jsonl"` is supported (default: `"jsonl"`).
- **filter** (object, optional): Session filter criteria:
  - **protocol** (string, optional): Filter by protocol (e.g. `"HTTPS"`, `"HTTP/1.x"`).
  - **url_pattern** (string, optional): Filter by URL substring.
  - **time_after** (string, optional): Include sessions after this time (RFC3339 format).
  - **time_before** (string, optional): Include sessions before this time (RFC3339 format).
- **include_bodies** (boolean, optional): Include message body and raw_bytes in export (default: `true`). Set to `false` for metadata-only export.
- **output_path** (string, optional): File path to write the export data. If not specified, data is returned inline in the MCP response.

Returns: exported_count, format, output_path (if file output), data (if inline output).

### import_sessions
Import sessions from a JSONL file. Each line must be a valid export record with version "1".

**Parameters:**
- **input_path** (string, required): File path to read the JSONL import data.
- **on_conflict** (string, optional): Conflict resolution policy for duplicate session IDs. `"skip"` (default) skips existing sessions; `"replace"` deletes and re-imports.

Returns: imported, skipped, errors, source.

## Usage Examples

### Delete single session
```json
{
  "action": "delete_sessions",
  "params": {"session_id": "abc-123"}
}
```

### Delete old sessions
```json
{
  "action": "delete_sessions",
  "params": {"older_than_days": 30, "confirm": true}
}
```

### Delete all sessions
```json
{
  "action": "delete_sessions",
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

### Export all sessions to file
```json
{
  "action": "export_sessions",
  "params": {
    "format": "jsonl",
    "include_bodies": true,
    "output_path": "/tmp/export.jsonl"
  }
}
```

### Export filtered sessions (metadata only)
```json
{
  "action": "export_sessions",
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

### Import sessions (skip duplicates)
```json
{
  "action": "import_sessions",
  "params": {
    "input_path": "/tmp/export.jsonl",
    "on_conflict": "skip"
  }
}
```

### Import sessions (replace duplicates)
```json
{
  "action": "import_sessions",
  "params": {
    "input_path": "/tmp/export.jsonl",
    "on_conflict": "replace"
  }
}
```

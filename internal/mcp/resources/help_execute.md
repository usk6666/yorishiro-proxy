# execute

Execute an action on recorded proxy data. Supports replaying captured requests and managing session data.

## Parameters

### action (string, required)
The action to execute. One of: `replay`, `replay_raw`, `delete_sessions`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### replay
Replay a recorded HTTP request with optional overrides. Records the result as a new session.

**Parameters:**
- **session_id** (string, required): ID of the session to replay.
- **override_method** (string, optional): Override the HTTP method (e.g. `"POST"`).
- **override_url** (string, optional): Override the target URL. Must include scheme and host (e.g. `"https://other.target.com/api/v2"`).
- **override_headers** (object, optional): Header overrides as key-value pairs. Replaces matching headers (e.g. `{"Authorization": "Bearer new-token"}`).
- **override_body** (string, optional): Override the request body.

Returns: new_session_id, status_code, response_headers, response_body, response_body_encoding, duration_ms.

### replay_raw
Replay the raw bytes from a recorded session over TCP/TLS. Useful for testing HTTP smuggling or protocol-level issues.

**Parameters:**
- **session_id** (string, required): ID of the session to replay.
- **target_addr** (string, optional): Target address as `"host:port"`. Defaults to the original session's target.
- **use_tls** (boolean, optional): Force TLS on/off. Defaults to the original session's protocol.

Returns: response_data (base64), response_size, duration_ms.

### delete_sessions
Delete sessions by ID, by age, or all at once.

**Parameters:**
- **session_id** (string, optional): Delete a specific session by ID.
- **older_than_days** (integer, optional): Delete sessions older than this many days. Must be >= 1. Requires `confirm: true`.
- **confirm** (boolean): Required for bulk deletion (older_than_days or all). Set to `true` to proceed.

One of `session_id`, `older_than_days`, or `confirm` (for delete-all) must be specified.

Returns: deleted_count, cutoff_time (for age-based deletion).

## Usage Examples

### Replay with method override
```json
{
  "action": "replay",
  "params": {
    "session_id": "abc-123",
    "override_method": "PUT",
    "override_headers": {"Content-Type": "application/json"}
  }
}
```

### Raw TCP replay
```json
{
  "action": "replay_raw",
  "params": {
    "session_id": "abc-123",
    "target_addr": "target.com:443",
    "use_tls": true
  }
}
```

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

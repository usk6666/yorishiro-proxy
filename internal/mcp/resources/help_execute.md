# execute

Execute an action on recorded proxy data. Supports resending captured requests with mutations and managing session data.

## Parameters

### action (string, required)
The action to execute. One of: `resend`, `resend_raw`, `delete_sessions`, `release`, `modify_and_forward`, `drop`.

> **Note:** `replay` and `replay_raw` are accepted as deprecated aliases for `resend` and `resend_raw`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### resend
Resend a recorded HTTP request with optional mutations. Records the result as a new session.

**Parameters:**
- **session_id** (string, required): ID of the session to resend.
- **override_method** (string, optional): Override the HTTP method (e.g. `"POST"`).
- **override_url** (string, optional): Override the target URL. Must include scheme and host (e.g. `"https://other.target.com/api/v2"`).
- **override_headers** (object, optional): Header overrides as key-value pairs. Replaces matching headers.
- **add_headers** (object, optional): Headers to add. Appended to existing values for the same key, enabling multi-value headers.
- **remove_headers** (array of strings, optional): Header names to remove.
- **override_body** (string, optional): Override the request body (text).
- **override_body_base64** (string, optional): Override the request body (Base64-encoded binary). Mutually exclusive with `override_body`.
- **body_patches** (array, optional): Partial body modifications. Each patch is either `{"json_path": "$.key", "value": "new"}` or `{"regex": "pattern", "replace": "replacement"}`. Ignored when `override_body` or `override_body_base64` is set.
- **override_host** (string, optional): TCP connection target as `"host:port"`, independent of the URL host. Subject to SSRF protection.
- **follow_redirects** (boolean, optional): Follow HTTP redirects automatically (default: `false`).
- **timeout_ms** (integer, optional): Request timeout in milliseconds (default: `30000`).
- **dry_run** (boolean, optional): If `true`, return a preview of the modified request without actually sending it.
- **tag** (string, optional): Tag to attach to the result session for identification.

**Header mutation order:** `remove_headers` -> `override_headers` -> `add_headers`.

**Body mutation priority:** `override_body`/`override_body_base64` (full replace) > `body_patches` (partial) > original body.

Returns: new_session_id, status_code, response_headers, response_body, response_body_encoding, duration_ms, tag.

In dry-run mode, returns: dry_run, request_preview (method, url, headers, body, body_encoding).

### resend_raw
Resend the raw bytes from a recorded session over TCP/TLS. Useful for testing HTTP smuggling or protocol-level issues.

**Parameters:**
- **session_id** (string, required): ID of the session to resend.
- **target_addr** (string, optional): Target address as `"host:port"`. Defaults to the original session's target.
- **use_tls** (boolean, optional): Force TLS on/off. Defaults to the original session's protocol.
- **timeout_ms** (integer, optional): Request timeout in milliseconds (default: `30000`).

Returns: response_data (base64), response_size, duration_ms.

### delete_sessions
Delete sessions by ID, by age, or all at once.

**Parameters:**
- **session_id** (string, optional): Delete a specific session by ID.
- **older_than_days** (integer, optional): Delete sessions older than this many days. Must be >= 1. Requires `confirm: true`.
- **confirm** (boolean): Required for bulk deletion (older_than_days or all). Set to `true` to proceed.

One of `session_id`, `older_than_days`, or `confirm` (for delete-all) must be specified.

Returns: deleted_count, cutoff_time (for age-based deletion).

### release
Release an intercepted request, allowing it to proceed to the upstream server unmodified.

**Parameters:**
- **intercept_id** (string, required): ID of the intercepted request from the intercept queue.

Returns: intercept_id, action, status.

### modify_and_forward
Modify an intercepted request and forward it to the upstream server with the specified changes.

**Parameters:**
- **intercept_id** (string, required): ID of the intercepted request from the intercept queue.
- **override_method** (string, optional): Override the HTTP method.
- **override_url** (string, optional): Override the target URL.
- **override_headers** (object, optional): Header overrides as key-value pairs.
- **add_headers** (object, optional): Headers to add (appended to existing values).
- **remove_headers** (array of strings, optional): Header names to remove.
- **override_body** (string, optional): Override the request body.

Returns: intercept_id, action, status.

### drop
Drop an intercepted request, returning a 502 Bad Gateway response to the client.

**Parameters:**
- **intercept_id** (string, required): ID of the intercepted request from the intercept queue.

Returns: intercept_id, action, status.

## Usage Examples

### Resend with method override
```json
{
  "action": "resend",
  "params": {
    "session_id": "abc-123",
    "override_method": "PUT",
    "override_headers": {"Content-Type": "application/json"}
  }
}
```

### Resend with header mutations
```json
{
  "action": "resend",
  "params": {
    "session_id": "abc-123",
    "remove_headers": ["X-Unwanted"],
    "override_headers": {"Authorization": "Bearer new-token"},
    "add_headers": {"X-Custom": "value"}
  }
}
```

### Resend with body patches (JSON path)
```json
{
  "action": "resend",
  "params": {
    "session_id": "abc-123",
    "body_patches": [
      {"json_path": "$.user.name", "value": "injected"},
      {"regex": "csrf_token=[^&]+", "replace": "csrf_token=newvalue"}
    ]
  }
}
```

### Resend with Base64 body override
```json
{
  "action": "resend",
  "params": {
    "session_id": "abc-123",
    "override_body_base64": "SGVsbG8gV29ybGQ="
  }
}
```

### Dry-run preview
```json
{
  "action": "resend",
  "params": {
    "session_id": "abc-123",
    "override_method": "POST",
    "body_patches": [{"json_path": "$.user.role", "value": "admin"}],
    "dry_run": true
  }
}
```

### Resend to different host
```json
{
  "action": "resend",
  "params": {
    "session_id": "abc-123",
    "override_host": "staging.target.com:8443",
    "tag": "staging-test"
  }
}
```

### Raw TCP resend
```json
{
  "action": "resend_raw",
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

### Release intercepted request
```json
{
  "action": "release",
  "params": {"intercept_id": "int-abc-123"}
}
```

### Modify and forward intercepted request
```json
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "int-abc-123",
    "override_method": "POST",
    "override_headers": {"Authorization": "Bearer injected-token"},
    "override_body": "{\"role\":\"admin\"}"
  }
}
```

### Drop intercepted request
```json
{
  "action": "drop",
  "params": {"intercept_id": "int-abc-123"}
}
```

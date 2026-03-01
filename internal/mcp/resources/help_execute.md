# execute

Execute an action on recorded proxy data. Supports resending captured requests with mutations and managing session data.

## Parameters

### action (string, required)
The action to execute. One of: `resend`, `resend_raw`, `tcp_replay`, `delete_sessions`, `release`, `modify_and_forward`, `drop`, `fuzz`, `fuzz_pause`, `fuzz_resume`, `fuzz_cancel`, `define_macro`, `run_macro`, `delete_macro`, `regenerate_ca_cert`, `export_sessions`, `import_sessions`.

> **Note:** `replay` is a deprecated alias for `resend`; `replay_raw` is a deprecated alias for `resend_raw`.

### params (object, required)
Action-specific parameters (see below).

## Actions

### resend
Resend a recorded HTTP/HTTP2/WebSocket request with optional mutations. Records the result as a new session.

**Multi-protocol support:**
- **HTTP/1.x and HTTPS**: Standard HTTP resend with full mutation support.
- **HTTP/2**: Resends the request using HTTP/1.1 (fallback). All mutation options apply.
- **WebSocket**: Requires `message_sequence` to identify the message to resend. Sends the message body over a raw TCP connection. Supports `override_body`, `override_body_base64`, `target_addr`, and `use_tls`.

**Parameters:**
- **session_id** (string, required): ID of the session to resend.
- **message_sequence** (integer, optional): Message sequence number for WebSocket/streaming resend. Required for WebSocket sessions.
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

### tcp_replay
Replay a Raw TCP session by sending all recorded send messages sequentially to the target. Records the exchange as a new TCP session.

**Parameters:**
- **session_id** (string, required): ID of the TCP session to replay.
- **target_addr** (string, optional): Target address as `"host:port"`. Defaults to the original session's server address.
- **use_tls** (boolean, optional): Use TLS for the connection. Default: `false`.
- **timeout_ms** (integer, optional): Connection timeout in milliseconds (default: `30000`).
- **tag** (string, optional): Tag to attach to the result session.

Returns: new_session_id, messages_sent, messages_received, total_bytes_sent, total_bytes_received, duration_ms, tag.

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

### fuzz
Start an asynchronous fuzz campaign against a recorded session. Returns fuzz_id immediately. Use `fuzz_pause`, `fuzz_resume`, `fuzz_cancel` for job control. Query `fuzz_results` resource for progress.

**Parameters:**
- **session_id** (string, required): ID of the template session to fuzz.
- **attack_type** (string, required): Fuzzing strategy. `"sequential"` tests one position at a time; `"parallel"` applies payloads to all positions simultaneously (zip).
- **positions** (array, required): Payload injection points. Each position specifies:
  - **id** (string, required): Unique position identifier (e.g. `"pos-0"`).
  - **location** (string, required): Where to inject: `header`, `path`, `query`, `body_regex`, `body_json`, `cookie`.
  - **name** (string): Header name, query key, or cookie name (required for header/query/cookie).
  - **json_path** (string): JSON path for body_json location (e.g. `"$.password"`).
  - **mode** (string, optional): Operation mode: `replace` (default), `add`, or `remove`.
  - **match** (string, optional): Regex pattern for partial replacement. Capture groups replace only the group.
  - **payload_set** (string): Name of the payload set to use (not required for remove mode).
- **payload_sets** (object, required): Named payload sets. Each set specifies:
  - **type** (string, required): `wordlist`, `file`, `range`, or `sequence`.
  - **values** (array): Payload strings (for wordlist).
  - **path** (string): Relative path under `~/.katashiro-proxy/wordlists/` (for file).
  - **start**, **end**, **step** (integer): Range parameters (for range/sequence).
  - **format** (string): Format string (for sequence, e.g. `"user%04d"`).
- **concurrency** (integer, optional): Number of concurrent workers (default: `1`).
- **rate_limit_rps** (number, optional): Requests per second limit. `0` means unlimited.
- **delay_ms** (integer, optional): Fixed delay between requests in milliseconds.
- **timeout_ms** (integer, optional): Per-request timeout in milliseconds (default: `10000`).
- **max_retries** (integer, optional): Retry count per failed request (default: `0`).
- **stop_on** (object, optional): Automatic stop conditions:
  - **status_codes** (array of integers): Stop when any of these HTTP status codes is received.
  - **error_count** (integer): Stop when cumulative error count reaches this value.
  - **latency_threshold_ms** (integer): Stop when sliding window median latency exceeds this value.
  - **latency_baseline_multiplier** (number): Stop when current median exceeds baseline median times this multiplier.
  - **latency_window** (integer): Sliding window size for latency detection (default: `10`).
- **tag** (string, optional): Tag to label the fuzz job.

Returns: fuzz_id, status, total_requests, tag, message.

### fuzz_pause
Pause a running fuzz job. Workers will stop after completing their current request.

**Parameters:**
- **fuzz_id** (string, required): ID of the fuzz job to pause.

Returns: fuzz_id, action, status.

### fuzz_resume
Resume a paused fuzz job.

**Parameters:**
- **fuzz_id** (string, required): ID of the fuzz job to resume.

Returns: fuzz_id, action, status.

### fuzz_cancel
Cancel a running or paused fuzz job. The job will be terminated and marked as cancelled.

**Parameters:**
- **fuzz_id** (string, required): ID of the fuzz job to cancel.

Returns: fuzz_id, action, status.

### regenerate_ca_cert
Regenerate the CA certificate. Behavior depends on the CA initialization mode:

- **Auto-persist mode** (default): Generates a new CA and saves it to the default path (`~/.katashiro-proxy/ca/`). Users must re-install the CA certificate.
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

### Fuzz with sequential attack
```json
{
  "action": "fuzz",
  "params": {
    "session_id": "abc-123",
    "attack_type": "sequential",
    "positions": [
      {
        "id": "pos-0",
        "location": "header",
        "name": "Authorization",
        "mode": "replace",
        "match": "Bearer (.*)",
        "payload_set": "tokens"
      }
    ],
    "payload_sets": {
      "tokens": {
        "type": "wordlist",
        "values": ["token1", "token2", "admin-token"]
      }
    },
    "tag": "auth-test"
  }
}
```

### Fuzz with parallel attack
```json
{
  "action": "fuzz",
  "params": {
    "session_id": "abc-123",
    "attack_type": "parallel",
    "positions": [
      {"id": "pos-0", "location": "query", "name": "username", "payload_set": "users"},
      {"id": "pos-1", "location": "body_json", "json_path": "$.password", "payload_set": "passwords"}
    ],
    "payload_sets": {
      "users": {"type": "wordlist", "values": ["admin", "root", "user"]},
      "passwords": {"type": "wordlist", "values": ["pass1", "pass2", "pass3"]}
    }
  }
}
```

### define_macro
Save a macro definition (upsert) with steps, extraction rules, and guards. If a macro with the same name exists, it is updated.

**Parameters:**
- **name** (string, required): Unique macro identifier.
- **description** (string, optional): Human-readable description.
- **steps** (array, required): Ordered list of macro steps. Each step:
  - **id** (string, required): Unique step identifier within the macro.
  - **session_id** (string, required): Recorded session to use as a template.
  - **override_method** (string, optional): Override HTTP method.
  - **override_url** (string, optional): Override request URL. Supports `{{variable}}` templates.
  - **override_headers** (object, optional): Header overrides as key-value pairs. Supports templates.
  - **override_body** (string, optional): Override request body. Supports templates.
  - **on_error** (string, optional): Error handling: `"abort"` (default), `"skip"`, or `"retry"`.
  - **retry_count** (integer, optional): Retry count when on_error is "retry" (default: 3).
  - **retry_delay_ms** (integer, optional): Delay between retries in ms (default: 1000).
  - **timeout_ms** (integer, optional): Step timeout in ms (default: 60000).
  - **extract** (array, optional): Value extraction rules. Each rule: `name`, `from` ("request"/"response"), `source` ("header"/"body"/"body_json"/"status"/"url"), `header_name`, `regex`, `group`, `json_path`, `default`, `required`.
  - **when** (object, optional): Step guard condition: `step`, `status_code`, `status_code_range`, `header_match`, `body_match`, `extracted_var`, `negate`.
- **initial_vars** (object, optional): Pre-populated KV Store entries.
- **macro_timeout_ms** (integer, optional): Overall macro timeout in ms (default: 300000).

Returns: name, step_count, created (true if new, false if updated).

### run_macro
Execute a stored macro for testing. The macro is loaded from DB and run with the macro engine.

**Parameters:**
- **name** (string, required): Name of the macro to run.
- **vars** (object, optional): Runtime variable overrides for the KV Store.

Returns: macro_name, status ("completed"/"error"/"timeout"), steps_executed, kv_store, step_results[], error.

### delete_macro
Remove a stored macro definition.

**Parameters:**
- **name** (string, required): Name of the macro to delete.

Returns: name, deleted.

## Macro Examples

### Define a macro
```json
{
  "action": "define_macro",
  "params": {
    "name": "auth-flow",
    "description": "Login and get CSRF token",
    "steps": [
      {
        "id": "login",
        "session_id": "recorded-login-session",
        "override_body": "username=admin&password={{password}}",
        "extract": [
          {
            "name": "session_cookie",
            "from": "response",
            "source": "header",
            "header_name": "Set-Cookie",
            "regex": "PHPSESSID=([^;]+)",
            "group": 1
          }
        ]
      },
      {
        "id": "get-csrf",
        "session_id": "recorded-csrf-session",
        "override_headers": {"Cookie": "PHPSESSID={{session_cookie}}"},
        "extract": [
          {
            "name": "csrf_token",
            "from": "response",
            "source": "body",
            "regex": "name=\"csrf\" value=\"([^\"]+)\"",
            "group": 1
          }
        ]
      }
    ],
    "initial_vars": {"password": "admin123"}
  }
}
```

### Run a macro
```json
{
  "action": "run_macro",
  "params": {
    "name": "auth-flow",
    "vars": {"password": "override-password"}
  }
}
```

### Delete a macro
```json
{
  "action": "delete_macro",
  "params": {"name": "auth-flow"}
}
```

## Hooks (pre_send / post_receive)

The `resend` and `fuzz` actions support optional hooks that execute macros before sending the request (`pre_send`) and after receiving the response (`post_receive`). Hooks are specified via the `hooks` parameter.

**Hook parameters:**
- **hooks.pre_send** (object, optional): Hook executed before the main request.
  - **macro** (string, required): Name of the stored macro to execute.
  - **vars** (object, optional): Runtime variable overrides for the macro.
  - **run_interval** (string, optional): When the hook fires. For pre_send: `"always"` (default), `"once"`, `"every_n"`, `"on_error"`.
  - **n** (integer): Interval count for `"every_n"`.
- **hooks.post_receive** (object, optional): Hook executed after the main response.
  - **macro** (string, required): Name of the stored macro to execute.
  - **vars** (object, optional): Runtime variable overrides for the macro.
  - **run_interval** (string, optional): When the hook fires. For post_receive: `"always"` (default), `"on_status"`, `"on_match"`.
  - **status_codes** (array of integers): Status codes for `"on_status"`.
  - **match_pattern** (string): Regex pattern for `"on_match"`.
  - **pass_response** (boolean, optional): Pass `__response_status` and `__response_body` as vars to the macro.

### KV Store sharing between hooks

Within a single iteration (resend call or fuzz iteration), the KV Store produced by the `pre_send` hook is automatically passed to the `post_receive` hook. This enables workflows where pre_send acquires resources that post_receive needs to clean up.

**Priority when merging vars:** If the pre_send KV Store and the post_receive hook's `vars` config contain the same key, the **pre_send KV Store value takes precedence**.

**Example: Login before each request, logout after**

```json
{
  "action": "fuzz",
  "params": {
    "session_id": "delete-endpoint",
    "attack_type": "sequential",
    "positions": [{"id": "pos-0", "location": "path", "match": "/items/(\\d+)", "payload_set": "ids"}],
    "payload_sets": {"ids": {"type": "range", "start": 1, "end": 100}},
    "hooks": {
      "pre_send": {
        "macro": "csrf-login",
        "run_interval": "always"
      },
      "post_receive": {
        "macro": "logout",
        "run_interval": "always"
      }
    }
  }
}
```

In this example, the `csrf-login` macro extracts `auth_session` into its KV Store. The fuzz request uses `{{auth_session}}` for template expansion. After the response, the `logout` macro also receives `auth_session` from the shared KV Store, enabling it to log out with the correct session cookie.

### Resend WebSocket message
```json
{
  "action": "resend",
  "params": {
    "session_id": "ws-session-123",
    "message_sequence": 2,
    "target_addr": "ws.target.com:443",
    "use_tls": true
  }
}
```

### Replay Raw TCP session
```json
{
  "action": "tcp_replay",
  "params": {
    "session_id": "tcp-session-456",
    "target_addr": "db.target.com:3306",
    "tag": "tcp-replay"
  }
}
```

### Resend HTTP/2 request (HTTP/1.1 fallback)
```json
{
  "action": "resend",
  "params": {
    "session_id": "h2-session-789",
    "override_headers": {"Authorization": "Bearer new-token"}
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

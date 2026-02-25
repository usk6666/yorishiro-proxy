# Vulnerability Assessment Workflow Examples

Common workflows for using katashiro-proxy as an AI-driven vulnerability assessment tool.

## Basic Setup

### 1. Start the proxy
```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080",
  "capture_scope": {
    "includes": [{"hostname": "target.example.com"}]
  }
}
```

### 2. Configure your HTTP client to use the proxy
Set `HTTP_PROXY=http://127.0.0.1:8080` and `HTTPS_PROXY=http://127.0.0.1:8080` in your client.

### 3. Export and install the CA certificate
```json
// query
{"resource": "ca_cert"}
```
Install the returned PEM certificate into the client's trust store for HTTPS interception.

## Authentication Testing

### Replay with different auth tokens
```json
// execute
{
  "action": "replay",
  "params": {
    "session_id": "<original-session-id>",
    "override_headers": {"Authorization": "Bearer <other-user-token>"}
  }
}
```

### Test without authentication
```json
// execute
{
  "action": "replay",
  "params": {
    "session_id": "<original-session-id>",
    "override_headers": {"Authorization": ""}
  }
}
```

## API Endpoint Discovery

### List all captured sessions
```json
// query
{"resource": "sessions", "limit": 100}
```

### Filter by API endpoints
```json
// query
{
  "resource": "sessions",
  "filter": {"url_pattern": "/api/", "method": "POST"}
}
```

### Inspect a specific request/response
```json
// query
{"resource": "session", "id": "<session-id>"}
```

## Parameter Tampering

### Replay with modified URL
```json
// execute
{
  "action": "replay",
  "params": {
    "session_id": "<session-id>",
    "override_url": "https://target.example.com/api/admin/users"
  }
}
```

### Replay with modified body
```json
// execute
{
  "action": "replay",
  "params": {
    "session_id": "<session-id>",
    "override_body": "{\"role\": \"admin\", \"user_id\": 1}"
  }
}
```

## HTTP Request Smuggling Analysis

### Replay raw bytes to preserve header formatting
```json
// execute
{
  "action": "replay_raw",
  "params": {
    "session_id": "<session-id>",
    "target_addr": "target.example.com:443",
    "use_tls": true
  }
}
```

## Scope Management

### Narrow scope during testing
```json
// configure
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com", "url_prefix": "/v2/"}],
    "add_excludes": [{"url_prefix": "/health"}]
  }
}
```

### Bypass TLS for pinned services
```json
// configure
{
  "tls_passthrough": {
    "add": ["*.googleapis.com", "telemetry.service.com"]
  }
}
```

## Session Cleanup

### Delete old sessions
```json
// execute
{
  "action": "delete_sessions",
  "params": {"older_than_days": 7, "confirm": true}
}
```

### Delete all sessions
```json
// execute
{
  "action": "delete_sessions",
  "params": {"confirm": true}
}
```

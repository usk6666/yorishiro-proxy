# Vulnerability Assessment Workflow Examples

Common workflows for using yorishiro-proxy as an AI-driven vulnerability assessment tool.

## Basic Setup

### 1. Start the proxy
```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080"
}
```

### 2. Configure your HTTP client to use the proxy
Set `HTTP_PROXY=http://127.0.0.1:8080` and `HTTPS_PROXY=http://127.0.0.1:8080` in your client.

### 3. Export and install the CA certificate
```json
// query
{"resource": "ca_cert"}
```
The response includes `persisted`, `cert_path`, and `install_hint` fields.
If `persisted` is true, install the certificate from `cert_path` into the client's trust store.
The CA is automatically saved to `~/.yorishiro-proxy/ca/ca.crt` on first startup, so subsequent restarts reuse the same CA without re-installation.

## CA Certificate Rotation

### Regenerate the CA certificate
```json
// manage
{
  "action": "regenerate_ca_cert",
  "params": {}
}
```
After regeneration, re-install the CA certificate from `cert_path` in the response.
In ephemeral mode (`--ca-ephemeral`), the new CA exists only in memory.

### Verify the new CA
```json
// query
{"resource": "ca_cert"}
```
Confirm the fingerprint has changed and `persisted` is true.

## Authentication Testing

### Resend with different auth tokens
```json
// resend_http
{
  "flow_id": "<original-flow-id>",
  "headers": [
    {"name": "Host", "value": "api.target.com"},
    {"name": "Authorization", "value": "Bearer <other-user-token>"}
  ]
}
```

### Test without authentication (remove auth header)
```json
// resend_http
{
  "flow_id": "<original-flow-id>",
  "headers": [
    {"name": "Host", "value": "api.target.com"}
  ]
}
```

## API Endpoint Discovery

### List all captured flows
```json
// query
{"resource": "flows", "limit": 100}
```

### Filter by API endpoints
```json
// query
{
  "resource": "flows",
  "filter": {"url_pattern": "/api/", "method": "POST"}
}
```

### Inspect a specific request/response
```json
// query
{"resource": "flow", "id": "<flow-id>"}
```

## Parameter Tampering

### Resend with modified URL
```json
// resend_http
{
  "flow_id": "<flow-id>",
  "scheme": "https",
  "authority": "target.example.com",
  "path": "/api/admin/users"
}
```

### Resend with modified body
```json
// resend_http
{
  "flow_id": "<flow-id>",
  "body": "{\"role\": \"admin\", \"user_id\": 1}",
  "body_encoding": "text"
}
```

## HTTP Request Smuggling Analysis

### Resend raw bytes verbatim to preserve header formatting
```json
// resend_raw
{
  "flow_id": "<flow-id>",
  "target_addr": "target.example.com:443",
  "use_tls": true
}
```

### Resend raw bytes with a single-byte offset patch
```json
// resend_raw
{
  "flow_id": "<flow-id>",
  "target_addr": "target.example.com:443",
  "use_tls": true,
  "patches": [
    {"offset": 16, "data": "QQ==", "data_encoding": "base64"}
  ]
}
```

### Fuzz raw bytes for CL/TE smuggling templates
```json
// fuzz_raw
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

## Typed Resend (HTTPMessage / WSMessage / GRPCStart-Data-End)

### Replay an HTTP flow with a different Authorization header
```json
// resend_http
{
  "flow_id": "<flow-id>",
  "headers": [
    {"name": "Host", "value": "api.target.com"},
    {"name": "Authorization", "value": "Bearer <other-user-token>"}
  ]
}
```

### Replay a WebSocket text frame with a new payload
```json
// resend_ws
{
  "flow_id": "<ws-flow-id>",
  "opcode": "text",
  "payload": "{\"action\":\"subscribe\",\"channel\":\"admin\"}"
}
```

### Replay a gRPC unary RPC with a modified request body
```json
// resend_grpc
{
  "flow_id": "<grpc-flow-id>",
  "messages": [
    {"payload": "CgZhZG1pbjE=", "body_encoding": "base64"}
  ]
}
```

## Typed Fuzz (cartesian product, capped at 1000 variants per call)

### Fuzz an HTTP header value across a payload list
```json
// fuzz_http
{
  "flow_id": "<flow-id>",
  "positions": [
    {
      "path": "headers[1].value",
      "payloads": ["alice", "bob", "admin", "../../../etc/passwd"]
    }
  ],
  "stop_on_5xx": true
}
```

### Fuzz a gRPC metadata value
```json
// fuzz_grpc
{
  "flow_id": "<grpc-flow-id>",
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ],
  "positions": [
    {
      "path": "metadata[0].value",
      "payloads": ["Bearer A", "Bearer admin", ""]
    }
  ]
}
```

### Fuzz a WebSocket close-frame reason
```json
// fuzz_ws
{
  "flow_id": "<ws-flow-id>",
  "opcode": "close",
  "close_code": 1000,
  "positions": [
    {
      "path": "close_reason",
      "payloads": ["bye", " ", "<script>alert(1)</script>"]
    }
  ]
}
```

## Plugin Introspection

### List loaded plugins, hook registrations, and (redacted) Vars
```json
// plugin_introspect
{}
```
The response contains a `plugins[]` array with `name`, `path`, `enabled`, ordered `registrations[]` (`{protocol, event, phase}`), and `vars` (with `redact_keys` already applied — secrets show as `"<redacted>"`).

## TLS Passthrough Management

### Bypass TLS for pinned services
```json
// configure
{
  "tls_passthrough": {
    "add": ["*.googleapis.com", "telemetry.service.com"]
  }
}
```

## Capture Scope (Recording-Only Filter)

`capture_scope` (USK-776) suppresses persistence of out-of-scope flows **without altering wire transmission**. Pages keep loading because all third-party requests still flow; only the in-scope flows reach the flow store. Distinct from `target_scope` (transmission gate) which would break page rendering.

### Start with a focused recording scope
```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080",
  "capture_scope": {
    "includes": [
      {"hostname": "api.target.com"},
      {"hostname": "*.target.com", "url_prefix": "/api/"}
    ],
    "excludes": [
      {"hostname": "static.target.com"},
      {"url_prefix": "/healthz"}
    ]
  }
}
```

### Add a CDN exclude rule at runtime (merge)
```json
// configure
{
  "operation": "merge",
  "capture_scope": {
    "add_excludes": [
      {"hostname": "*.cloudfront.net"}
    ]
  }
}
```

### Replace the entire capture scope with a known-good preset
```json
// configure
{
  "operation": "replace",
  "capture_scope": {
    "includes": [{"hostname": "*.target.com", "url_prefix": "/api/"}],
    "excludes": []
  }
}
```

### Read the active capture scope
```json
// query
{"resource": "config"}
// → response.capture_scope = {"includes":[…], "excludes":[…]}
```

## SOCKS5 / proxychains Workflow

### 1. Start proxy with SOCKS5 support
```json
// proxy_start
{
  "listen_addr": "127.0.0.1:1080"
}
```

### 2. Configure proxychains
Add the following to `/etc/proxychains.conf` (or `~/.proxychains/proxychains.conf`):
```
socks5 127.0.0.1 1080
```

### 3. Route tools through the proxy
Run any TCP-based tool through the proxy using proxychains:
```bash
proxychains nmap -sT -Pn target.example.com
proxychains curl https://target.example.com/api/
```

### 4. Enable SOCKS5 authentication (optional)
```json
// configure
{
  "socks5_auth": {
    "method": "password",
    "username": "proxyuser",
    "password": "proxypass"
  }
}
```
Update proxychains configuration to include credentials:
```
socks5 127.0.0.1 1080 proxyuser proxypass
```

### 5. Disable SOCKS5 authentication
```json
// configure
{
  "socks5_auth": {
    "method": "none"
  }
}
```

## SafetyFilter Configuration

### Enable default presets
Add the following to your config file (`-config config.json`):
```json
// config.json
{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "block",
      "rules": [
        {"preset": "destructive-sql"},
        {"preset": "destructive-os-command"}
      ]
    }
  }
}
```
This blocks destructive SQL statements (DROP TABLE, TRUNCATE, etc.) and OS commands (rm -rf, shutdown, etc.) before they reach the target.

### Add custom rules
```json
// config.json
{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "block",
      "rules": [
        {"preset": "destructive-sql"},
        {"preset": "destructive-os-command"},
        {
          "id": "custom-dangerous-api",
          "name": "Dangerous API endpoint",
          "pattern": "(?i)/api/v[0-9]+/(delete-all|reset|purge)",
          "targets": ["url"]
        },
        {
          "id": "custom-header-injection",
          "name": "Header injection pattern",
          "pattern": "(?i)(\\r\\n|%0d%0a)",
          "targets": ["headers"]
        }
      ]
    }
  }
}
```

### Test rules with log_only mode
Before enforcing rules, use `log_only` mode to observe what would be blocked without interrupting traffic:
```json
// config.json
{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "log_only",
      "rules": [
        {"preset": "destructive-sql"},
        {"preset": "destructive-os-command"}
      ]
    }
  }
}
```
Review the proxy logs for `safety_filter` entries. Once satisfied, change `action` to `"block"` and restart.

### Verify active rules at runtime
```json
// security
{"action": "get_safety_filter"}
```
Returns the list of compiled rules, their targets, actions, and whether SafetyFilter is enabled. Rules are immutable at runtime.

## Output Filter Configuration

> **Note**: Output Filter の config ファイル経由での設定は今後対応予定です (Coming soon)。
> 現在、Output Filter はプログラマティック API (`safety.Config`) のみサポートしています。
> 以下の設定例は将来の config ファイルサポート時の参考として掲載しています。

### Enable PII masking with default presets
Add the following to your config file (`-config config.json`):
```json
// config.json
{
  "safety_filter": {
    "enabled": true,
    "output": {
      "action": "mask",
      "rules": [
        {"preset": "credit-card"},
        {"preset": "email"},
        {"preset": "japan-phone"},
        {"preset": "japan-my-number"}
      ]
    }
  }
}
```
This masks credit card numbers, email addresses, phone numbers, and My Number in response bodies before returning data to AI agents. Raw data is preserved in the Flow Store.

### Combine input and output filters
```json
// config.json
{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "block",
      "rules": [
        {"preset": "destructive-sql"},
        {"preset": "destructive-os-command"}
      ]
    },
    "output": {
      "action": "mask",
      "rules": [
        {"preset": "credit-card"},
        {"preset": "email"}
      ]
    }
  }
}
```
Input filter blocks destructive payloads; output filter masks PII in responses.

### Add custom output masking rules

> **Note**: config ファイルでは per-rule の `action`/`replacement` フィールドは未対応です。
> セクションレベルの `action` が全ルールに適用されます。
> per-rule の `action`/`replacement` はプログラマティック API (`safety.Config`) で利用可能です。

```json
// config.json (Coming soon)
{
  "safety_filter": {
    "enabled": true,
    "output": {
      "action": "mask",
      "rules": [
        {"preset": "credit-card"},
        {"preset": "email"},
        {
          "id": "custom-api-key",
          "name": "API key pattern",
          "pattern": "sk-[a-zA-Z0-9]{32,}",
          "targets": ["body"],
          "replacement": "[MASKED:api_key]"
        },
        {
          "id": "custom-ssn",
          "name": "US Social Security Number",
          "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
          "targets": ["body"],
          "replacement": "[MASKED:ssn]"
        }
      ]
    }
  }
}
```

### Test output rules with log_only mode
Before enforcing masking, use `log_only` mode to observe what would be masked without modifying responses:
```json
// config.json
{
  "safety_filter": {
    "enabled": true,
    "output": {
      "action": "log_only",
      "rules": [
        {"preset": "credit-card"},
        {"preset": "email"}
      ]
    }
  }
}
```
Review the proxy logs for `safety_filter` entries. Once satisfied, change `action` to `"mask"` and restart.

## Flow Cleanup

### Delete old flows
```json
// manage
{
  "action": "delete_flows",
  "params": {"older_than_days": 7, "confirm": true}
}
```

### Delete all flows
```json
// manage
{
  "action": "delete_flows",
  "params": {"confirm": true}
}
```

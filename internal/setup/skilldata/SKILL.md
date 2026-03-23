---
description: "Vulnerability verification workflow using yorishiro-proxy"
user-invokable: true
---

# /yorishiro

A skill that supports vulnerability verification using yorishiro-proxy (MCP proxy).
Specialized for the use case of verifying vulnerabilities detected through source code review in a live environment.

## Triggers

Apply this skill when you receive instructions such as:

- "Verify the vulnerability" / "Test this endpoint"
- "Test IDOR/SQLi/XSS/CSRF"
- "Check authorization bypass" / "Verify privilege escalation"
- "Tamper and resend this request"
- "Run fuzzing"

## MCP Tools Overview

yorishiro-proxy provides 11 MCP tools:

| Tool | Purpose |
|------|---------|
| `proxy_start` | Start proxy, configure capture scope. Supports multi-listener and SOCKS5 |
| `proxy_stop` | Stop proxy. Stop by name for individual listeners, or omit to stop all |
| `configure` | Change running proxy settings (scope, TLS passthrough, intercept rules, auto-transform, upstream proxy, connection limits, SOCKS5 auth, etc.) |
| `query` | Unified information retrieval (resource: flows, flow, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results, technologies) |
| `resend` | Request resend/replay/compare (action: resend, resend_raw, tcp_replay, compare) |
| `manage` | Flow data management and CA certificate (action: delete_flows, export_flows, import_flows, regenerate_ca_cert) |
| `fuzz` | Fuzzing (action: fuzz, fuzz_pause, fuzz_resume, fuzz_cancel) |
| `macro` | Macro workflow (action: define_macro, run_macro, delete_macro) |
| `intercept` | Intercept operations. Supports both request/response phases (action: release, modify_and_forward, drop) |
| `security` | Target scope, rate limits, diagnostic budget, SafetyFilter control. Policy/Agent 2-layer structure (action: set_target_scope, update_target_scope, get_target_scope, test_target, set_rate_limits, get_rate_limits, set_budget, get_budget, get_safety_filter) |
| `plugin` | Starlark plugin management (action: list, reload, enable, disable) |

### MCP Resources

Detailed help and schemas for each tool are provided as MCP Resources.
To check tool parameters and usage examples, retrieve the resource at the following URIs:

**Help (usage, parameter descriptions, examples)**:
- `yorishiro://help/proxy_start`, `yorishiro://help/proxy_stop`
- `yorishiro://help/query`, `yorishiro://help/resend`, `yorishiro://help/manage`
- `yorishiro://help/fuzz`, `yorishiro://help/macro`, `yorishiro://help/intercept`
- `yorishiro://help/configure`, `yorishiro://help/security`
- `yorishiro://help/examples` (collection of usage examples by workflow)

**Schemas (JSON Schema)**:
- `yorishiro://schema/proxy_start`, `yorishiro://schema/query`
- `yorishiro://schema/resend`, `yorishiro://schema/manage`
- `yorishiro://schema/fuzz`, `yorishiro://schema/macro`
- `yorishiro://schema/intercept`, `yorishiro://schema/configure`

If you are unsure of the exact parameter structure, always consult the help resource first.

### proxy_start -- Start Proxy

```json
// Basic startup
{
  "listen_addr": "127.0.0.1:8080",
  "capture_scope": {
    "includes": [{"hostname": "target.example.com"}],
    "excludes": [{"hostname": "static.example.com"}]
  },
  "tls_passthrough": ["*.googleapis.com"]
}

// Multi-listener startup with additional options
{
  "name": "socks-listener",
  "listen_addr": "127.0.0.1:1080",
  "protocols": ["SOCKS5", "HTTPS", "HTTP/1.x"],
  "upstream_proxy": "http://corporate-proxy:3128",
  "max_connections": 256,
  "peek_timeout_ms": 5000,
  "request_timeout_ms": 30000
}
```

#### proxy_start Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Listener name (default: "default"). Used for identification with multiple listeners |
| `listen_addr` | string | Listen address (default: "127.0.0.1:8080") |
| `upstream_proxy` | string | Upstream proxy URL (http:// or socks5://[user:pass@]host:port) |
| `capture_scope` | object | Capture scope (includes/excludes) |
| `tls_passthrough` | string[] | TLS passthrough target patterns |
| `intercept_rules` | object[] | Intercept rules (id, enabled, direction, conditions) |
| `auto_transform` | object[] | Auto-transform rules (id, enabled, priority, direction, conditions, action) |
| `tcp_forwards` | map | TCP port forwarding (port -> upstream_host:port) |
| `protocols` | string[] | Enabled protocols (HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, SOCKS5, TCP) |
| `socks5_auth` | string | SOCKS5 authentication method ("none" or "password") |
| `socks5_username` | string | SOCKS5 username |
| `socks5_password` | string | SOCKS5 password |
| `max_connections` | int | Maximum concurrent connections (default: 128, range: 1-100000) |
| `peek_timeout_ms` | int | Protocol detection timeout (default: 30000) |
| `request_timeout_ms` | int | HTTP request header read timeout (default: 60000) |
| `tls_fingerprint` | string | TLS fingerprint profile ("chrome", "firefox", "safari", "edge", "random", "none". default: "chrome") |
| `client_cert` | string | PEM client certificate path (for mTLS, used with client_key) |
| `client_key` | string | PEM client private key path (for mTLS, used with client_cert) |

### proxy_stop -- Stop Proxy

```json
// Stop a specific listener
{"name": "socks-listener"}

// Stop all listeners
{}
```

### query -- Retrieve Information

```json
// Flow list
{"resource": "flows", "filter": {"url_pattern": "/api/"}, "limit": 50}

// Flow details
{"resource": "flow", "id": "<flow-id>"}

// State filter (active/complete/error)
{"resource": "flows", "filter": {"state": "complete", "tag": "idor-test"}}

// Protocol filter
{"resource": "flows", "filter": {"protocol": "SOCKS5+HTTPS"}}

// Blocked flows
{"resource": "flows", "filter": {"blocked_by": "target_scope"}}

// WebSocket/gRPC messages (direction filter)
{"resource": "messages", "id": "<flow-id>", "filter": {"direction": "send"}}

// Fuzz job list (status/tag filter)
{"resource": "fuzz_jobs", "filter": {"status": "running", "tag": "sqli-fuzz"}}

// Fuzz results
{"resource": "fuzz_results", "fuzz_id": "<fuzz-id>", "sort_by": "status_code"}

// Fuzz results — outliers only
{"resource": "fuzz_results", "fuzz_id": "<fuzz-id>", "filter": {"outliers_only": true}}

// Search flows by connection ID
{"resource": "flows", "filter": {"conn_id": "abc-conn-123"}}

// Search flows by host
{"resource": "flows", "filter": {"host": "example.com"}}

// Technology stack detection results
{"resource": "technologies"}
```

#### query Filter Parameters

| Parameter | Target Resource | Description |
|-----------|----------------|-------------|
| `protocol` | flows | Protocol name (HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP, SOCKS5+HTTPS, etc.) |
| `scheme` | flows | URL scheme / transport filter ("https", "http", "wss", "ws", "tcp"). Used to search TLS flows |
| `method` | flows | HTTP method |
| `url_pattern` | flows | URL substring search |
| `status_code` | flows, fuzz_results | HTTP response code |
| `state` | flows | Flow state ("active", "complete", "error") |
| `blocked_by` | flows | Block reason ("target_scope", "intercept_drop", "rate_limit", "safety_filter") |
| `conn_id` | flows | Connection ID exact match. Search flows from the same connection |
| `host` | flows | Hostname filter. Matches server_addr or host portion of URL |
| `technology` | flows | Technology stack name (case-insensitive substring match, e.g., "nginx") |
| `tag` | fuzz_jobs | Tag exact match |
| `direction` | messages | Message direction ("send", "receive") |
| `status` | fuzz_jobs | Job state ("running", "paused", "completed", "cancelled", "error") |
| `body_contains` | fuzz_results | Response body substring |
| `outliers_only` | fuzz_results | Return only outliers (detected by deviation in status code, body length, and timing) |

fuzz_results includes aggregate statistics (`summary.statistics`: status_code_distribution, body_length, timing_ms min/max/median/stddev) and outlier detection (`summary.outliers`: by_status_code, by_body_length, by_timing).

Flow details include `protocol_summary` (protocol-specific info), and streaming flows include `message_preview` (first 10 messages). Flows generated by resend have `variant: "modified"`.

### resend -- Request Resend & Compare

```json
// HTTP request resend (add/remove headers)
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>",
    "override_headers": {"Authorization": "Bearer <token>"},
    "add_headers": {"X-Forwarded-For": "127.0.0.1"},
    "remove_headers": ["Cookie"],
    "body_patches": [{"json_path": "$.user_id", "value": 999}],
    "follow_redirects": false,
    "tag": "idor-test"
  }
}

// Raw request resend (bypass HTTP parsing)
{
  "action": "resend_raw",
  "params": {
    "flow_id": "<flow-id>",
    "override_raw_base64": "<base64-encoded-raw-request>",
    "target_addr": "api.target.com:443",
    "use_tls": true,
    "tag": "smuggling-test"
  }
}

// TCP replay (resend messages from WebSocket/TCP flow)
{
  "action": "tcp_replay",
  "params": {
    "flow_id": "<websocket-flow-id>",
    "message_sequence": 3,
    "timeout_ms": 10000,
    "tag": "ws-replay"
  }
}

// Structured comparison of 2 flows
{
  "action": "compare",
  "params": {
    "flow_id_a": "<original-flow-id>",
    "flow_id_b": "<modified-flow-id>"
  }
}
```

#### resend Additional Parameters

| Parameter | Action | Description |
|-----------|--------|-------------|
| `override_method` | resend | Override HTTP method |
| `override_url` | resend | Override URL |
| `add_headers` | resend | Add headers |
| `remove_headers` | resend | Remove headers |
| `override_host` | resend | Override host (host:port format) |
| `follow_redirects` | resend | Follow redirects (default: false) |
| `message_sequence` | resend | WebSocket message sequence number (required for WebSocket flows) |
| `timeout_ms` | resend, resend_raw, tcp_replay | Timeout (milliseconds) |
| `override_raw_base64` | resend_raw | Base64-encoded raw request data |
| `target_addr` | resend_raw, tcp_replay | Target address (host:port, defaults to flow's connection target) |
| `use_tls` | resend_raw, tcp_replay | Use TLS flag |
| `patches` | resend_raw | Byte-level patches |
| `dry_run` | resend, resend_raw | Preview modifications without sending |
| `tag` | resend, resend_raw, tcp_replay | Tag applied to resulting flow |

### fuzz -- Fuzzing

```json
{
  "action": "fuzz",
  "params": {
    "flow_id": "<flow-id>",
    "attack_type": "sequential",
    "positions": [
      {
        "id": "pos-0",
        "location": "body_json",
        "json_path": "$.user_id",
        "payload_set": "user-ids"
      }
    ],
    "payload_sets": {
      "user-ids": {"type": "range", "start": 1, "end": 20, "step": 2}
    },
    "rate_limit_rps": 10,
    "delay_ms": 100,
    "timeout_ms": 15000,
    "max_retries": 2,
    "concurrency": 1,
    "tag": "idor-fuzz"
  }
}
```

#### fuzz Additional Parameters

| Parameter | Description |
|-----------|-------------|
| `rate_limit_rps` | RPS limit (0 = unlimited) |
| `delay_ms` | Fixed delay between requests (milliseconds) |
| `timeout_ms` | Request timeout (default: 30000) |
| `max_retries` | Retry count |
| `stop_on` | Automatic stop conditions |

#### PayloadSet types

| type | Fields | Description |
|------|--------|-------------|
| `wordlist` | `values` | List of strings |
| `file` | `path` | File path (one payload per line) |
| `range` | `start`, `end`, `step` | Integer range (step default: 1) |
| `sequence` | `start`, `end`, `format` | Formatted sequential numbers (e.g., "user%04d") |

### macro -- Macro Definition & Execution

```json
// Macro definition (conditional steps, retry, initial variables)
{
  "action": "define_macro",
  "params": {
    "name": "auth-flow",
    "initial_vars": {"base_url": "https://api.target.com"},
    "macro_timeout_ms": 30000,
    "steps": [
      {
        "id": "login",
        "flow_id": "<login-flow-id>",
        "retry_count": 2,
        "retry_delay_ms": 1000,
        "timeout_ms": 10000,
        "extract": [
          {
            "name": "session_cookie",
            "from": "response",
            "source": "header",
            "header_name": "Set-Cookie",
            "regex": "PHPSESSID=([^;]+)",
            "group": 1,
            "required": true
          },
          {
            "name": "user_data",
            "from": "response",
            "source": "body_json",
            "json_path": "$.data.id",
            "default": "unknown"
          }
        ]
      },
      {
        "id": "fetch-profile",
        "flow_id": "<profile-flow-id>",
        "when": {
          "step": "login",
          "status_code": 200
        }
      }
    ]
  }
}

// Run macro
{
  "action": "run_macro",
  "params": {"name": "auth-flow"}
}
```

#### extract Rule Additional Fields

| Field | Description |
|-------|-------------|
| `json_path` | Extract value by JSON path (when source: body_json) |
| `required` | If true, extraction failure causes the step to error |
| `default` | Default value when extraction fails |

#### when (Conditional Steps)

| Field | Description |
|-------|-------------|
| `step` | Referenced preceding step ID |
| `status_code` | Expected status code |
| `status_code_range` | Status code range (e.g., [200, 299]) |
| `header_match` | Header value match (map) |
| `body_match` | Body regex match |
| `extracted_var` | Check existence of extracted variable |
| `negate` | Invert condition |

### manage -- Flow Data Management

```json
// Delete flows (with protocol filter)
{"action": "delete_flows", "params": {"protocol": "TCP", "older_than_days": 7, "confirm": true}}

// Export flows (with filter and body control)
{
  "action": "export_flows",
  "params": {
    "format": "jsonl",
    "output_path": "/tmp/export.jsonl",
    "include_bodies": false,
    "filter": {"protocol": "HTTPS", "url_pattern": "/api/"}
  }
}

// Import flows (specify behavior on conflict)
{
  "action": "import_flows",
  "params": {
    "input_path": "/tmp/export.jsonl",
    "on_conflict": "replace"
  }
}
```

#### manage Additional Parameters

| Parameter | Action | Description |
|-----------|--------|-------------|
| `protocol` | delete_flows | Protocol filter |
| `include_bodies` | export_flows | Include message bodies (default: true) |
| `filter` | export_flows | Export filter (protocol, url_pattern, time range, etc.) |
| `on_conflict` | import_flows | Behavior on conflict ("skip" or "replace", default: skip) |

### intercept -- Intercept Operations

```json
// Request phase: modify and forward
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "<intercept-id>",
    "override_method": "PUT",
    "override_url": "/api/v2/users/1",
    "override_headers": {"Authorization": "Bearer injected-token"},
    "add_headers": {"X-Debug": "true"},
    "remove_headers": ["X-Request-Id"]
  }
}

// Response phase: modify status, headers, and body
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "<intercept-id>",
    "override_status": 200,
    "override_response_headers": {"Content-Type": "application/json"},
    "add_response_headers": {"X-Injected": "true"},
    "remove_response_headers": ["X-Frame-Options"],
    "override_response_body": "{\"admin\": true}"
  }
}

// Forward request as-is
{"action": "release", "params": {"intercept_id": "<intercept-id>"}}

// Drop request
{"action": "drop", "params": {"intercept_id": "<intercept-id>"}}

// Forward raw bytes in raw mode
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "<intercept-id>",
    "mode": "raw",
    "raw_override_base64": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg=="
  }
}
```

#### intercept Parameters

| Parameter | Phase | Description |
|-----------|-------|-------------|
| `override_method` | request | Override HTTP method |
| `override_url` | request | Override URL |
| `override_headers` | request | Override request headers |
| `add_headers` | request | Add request headers |
| `remove_headers` | request | Remove request headers |
| `override_body` | request | Override request body |
| `override_status` | response | Override status code |
| `override_response_headers` | response | Override response headers |
| `add_response_headers` | response | Add response headers |
| `remove_response_headers` | response | Remove response headers |
| `override_response_body` | response | Override response body |
| `override_body` | websocket_frame | Override WebSocket frame payload |
| `mode` | all | Forwarding mode ("structured" or "raw". default: "structured") |
| `raw_override_base64` | all (raw mode) | Base64-encoded raw bytes (for modify_and_forward in raw mode) |

### security -- Target Scope Control

yorishiro-proxy scope control uses a 2-layer structure:

- **Policy Layer**: Immutable scope defined in the config file. Cannot be changed by agents
- **Agent Layer**: Dynamically changeable via MCP tools. Only effective within Policy Layer constraints

```json
// Set target scope
{
  "action": "set_target_scope",
  "params": {
    "allows": [{"hostname": "api.target.com", "ports": [443], "schemes": ["https"], "path_prefix": "/api/v1"}],
    "denies": [{"hostname": "admin.target.com"}]
  }
}

// Update target scope (add to existing)
{
  "action": "update_target_scope",
  "params": {
    "add_allows": [{"hostname": "staging.target.com", "ports": [443]}],
    "add_denies": [{"hostname": "internal.target.com"}]
  }
}

// Get current scope
{"action": "get_target_scope"}

// Test scope evaluation for a URL
{
  "action": "test_target",
  "params": {"url": "https://api.target.com/v1/users"}
}

// Set rate limits (global 10 RPS, per-host 5 RPS)
{
  "action": "set_rate_limits",
  "params": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  }
}

// Get current rate limits
{"action": "get_rate_limits"}

// Set diagnostic budget (max 1000 requests, 30 minutes)
{
  "action": "set_budget",
  "params": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  }
}

// Get current budget and usage
{"action": "get_budget"}
```

#### Target Rule Parameters

| Parameter | Description |
|-----------|-------------|
| `hostname` | Hostname |
| `ports` | Port list (all ports if omitted) |
| `schemes` | Schemes (http, https, etc. All schemes if omitted) |
| `path_prefix` | Path prefix (all paths if omitted) |

#### Rate Limit Parameters

| Parameter | Description |
|-----------|-------------|
| `max_requests_per_second` | Global RPS limit (0 = unlimited) |
| `max_requests_per_host_per_second` | Per-host RPS limit (0 = unlimited) |

#### Diagnostic Budget Parameters

| Parameter | Description |
|-----------|-------------|
| `max_total_requests` | Maximum requests for the entire session (0 = unlimited) |
| `max_duration` | Maximum session duration (Go duration format, e.g., "30m", "1h". "0s" = unlimited) |

Rate limits and budget also use Policy/Agent 2-layer structure. The Agent Layer can only set limits at or below the Policy Layer. When the budget is exceeded, the proxy stops automatically.

### SafetyFilter (Input Filter)

SafetyFilter operates as a Policy Layer to prevent destructive payloads (DROP TABLE, rm -rf, etc.) from being sent to targets. It cannot be changed by AI agents and is defined in the config file (`config.json`).

#### Preset Selection Guide

| Preset | Use Case | Targets |
|--------|----------|---------|
| `destructive-sql` | Applications with SQL databases | DROP TABLE/DATABASE, TRUNCATE, unconditional DELETE/UPDATE, etc. |
| `destructive-os-command` | OS command injection verification | rm -rf, shutdown, mkfs, dd, format, etc. |

- Web application testing: Enable both presets (recommended)
- API-only testing: Select preset based on target
- Recommended workflow: Test in `log_only` mode first, then switch to `block` mode

#### Adding Custom Rules

In addition to presets, application-specific patterns can be added as custom rules:

```json
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
        }
      ]
    }
  }
}
```

#### Checking Current Settings

```json
// security
{"action": "get_safety_filter"}
```

`get_safety_filter` is read-only and returns the list of currently active rules and `immutable: true`.

### configure -- Change Proxy Settings

Dynamically change running proxy settings.

```json
// Change upstream proxy and connection limits (merge mode)
{
  "operation": "merge",
  "upstream_proxy": "socks5://proxy.internal:1080",
  "max_connections": 256,
  "peek_timeout_ms": 5000
}

// Configure intercept queue settings
{
  "intercept_queue": {
    "timeout_ms": 120000,
    "timeout_behavior": "auto_release"
  }
}

// Configure SOCKS5 authentication
{
  "socks5_auth": {
    "method": "password",
    "username": "user",
    "password": "pass"
  }
}
```

#### configure Parameters

| Parameter | Description |
|-----------|-------------|
| `operation` | "merge" (default) or "replace" |
| `upstream_proxy` | Upstream proxy URL |
| `capture_scope` | Capture scope |
| `tls_passthrough` | TLS passthrough settings |
| `intercept_rules` | Intercept rules |
| `intercept_queue` | Intercept queue (timeout_ms, timeout_behavior) |
| `auto_transform` | Auto-transform rules |
| `socks5_auth` | SOCKS5 authentication (method, username, password) |
| `max_connections` | Maximum concurrent connections (1-100000) |
| `peek_timeout_ms` | Protocol detection timeout (100-600000) |
| `request_timeout_ms` | HTTP request timeout (100-600000) |
| `tls_fingerprint` | Change TLS fingerprint profile |
| `budget` | Diagnostic budget (max_total_requests, max_duration) |
| `client_cert` | mTLS client certificate settings (cert_path, key_path) |

### plugin -- Plugin Management

```json
// List plugins
{"action": "list"}

// Reload a specific plugin
{"action": "reload", "params": {"name": "<plugin-name>"}}

// Reload all plugins
{"action": "reload"}

// Disable a plugin
{"action": "disable", "params": {"name": "<plugin-name>"}}

// Enable a plugin
{"action": "enable", "params": {"name": "<plugin-name>"}}
```

## Workflow Selection Decision Tree

```
Received instruction
  |
  +-- Need traffic capture?
  |     |
  |     +-- YES --> See references/playwright-capture.md
  |     +-- NO (flows already exist) --> Next
  |
  +-- Is the target operation stateful? (login required, CSRF token, DELETE API, etc.)
  |     |
  |     +-- YES --> See references/self-contained-iteration.md for Macro design
  |     +-- NO --> Execute directly with resend / fuzz
  |
  +-- Need to select attack payloads?
  |     |
  |     +-- YES --> See references/payload-patterns.md (always check "Safe Payload Selection Principles")
  |     +-- NO --> Next
  |
  +-- Single test or comprehensive test?
  |     |
  |     +-- Single verification --> resend tool
  |     +-- Comprehensive test --> fuzz tool (outlier detection: outliers_only filter)
  |     +-- Want to bypass HTTP parsing --> resend_raw (HTTP Request Smuggling, etc.)
  |     +-- WebSocket/TCP message resend --> tcp_replay
  |
  +-- Need response diff analysis?
  |     |
  |     +-- YES --> resend compare for structured comparison of 2 flows
  |     +-- NO --> Next
  |
  +-- Need rate limit / budget configuration?
  |     |
  |     +-- YES --> security set_rate_limits / set_budget
  |     +-- NO --> Next
  |
  +-- Need to check SafetyFilter settings?
  |     |
  |     +-- YES --> security get_safety_filter to check current rules
  |     +-- NO --> Next
  |
  +-- Protocol-specific operations?
        |
        +-- SOCKS5 traffic monitoring --> proxy_start with "SOCKS5" in protocols
        +-- Raw TCP data --> TCP port forwarding via tcp_forwards
```

For the complete verification workflow, see `references/verify-vulnerability.md`.

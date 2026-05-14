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

yorishiro-proxy provides 17 MCP tools. Resend and fuzz are split into protocol-typed tools (HTTP / WebSocket / gRPC / Raw) — each tool's schema mirrors its protocol's envelope shape, so there is no unified `action` discriminator.

| Tool | Purpose |
|------|---------|
| `proxy_start` | Start proxy. Supports multi-listener and SOCKS5 |
| `proxy_stop` | Stop proxy. Stop by name for individual listeners, or omit to stop all |
| `configure` | Change running proxy settings (TLS passthrough, intercept rules, intercept queue + per-protocol overrides, auto-transform, upstream proxy, connection limits, capture scope, SOCKS5 auth, etc.) |
| `query` | Unified information retrieval (resource: flows, flow, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results). Supports `include_bodies` / `body_max_bytes` for body-size control |
| `resend_http` | Resend / construct an HTTP request. Typed fields mirror HTTPMessage (method/scheme/authority/path/raw_query/headers/body) |
| `resend_ws` | Resend a single WebSocket frame on a freshly dialled+upgraded upstream connection |
| `resend_grpc` | Resend a gRPC unary RPC. `messages[]` is the request-side LPM list |
| `resend_raw` | Resend a recorded raw byte payload (smuggling / anomaly tests). flow_id is REQUIRED — use `fuzz_raw` for ad-hoc byte injection |
| `fuzz_http` | Synchronously fuzz an HTTP request. `positions[]` describes typed paths into HTTPMessage with payload lists; cartesian product capped at 1000 variants |
| `fuzz_ws` | Synchronously fuzz a WebSocket frame. `positions[]` targets `payload` / `close_reason` |
| `fuzz_grpc` | Synchronously fuzz a gRPC unary RPC. `positions[]` targets `service` / `method` / `metadata[N].name` / `metadata[N].value` / `messages[N].payload` |
| `fuzz_raw` | Synchronously fuzz a raw byte payload — the central HTTP smuggling fuzzing surface. flow_id is OPTIONAL |
| `manage` | Flow data management and CA certificate (action: delete_flows, export_flows, import_flows, regenerate_ca_cert). `output_path` / `input_path` are resolved relative to the proxy server process's working directory |
| `intercept` | Intercept operations. Supports both request/response phases (action: release, modify_and_forward, drop) |
| `security` | Target scope, rate limits, diagnostic budget, SafetyFilter control. Policy/Agent 2-layer structure (action: set_target_scope, update_target_scope, get_target_scope, test_target, set_rate_limits, get_rate_limits, set_budget, get_budget, get_safety_filter) |
| `macro` | Macro workflow (action: define_macro, run_macro, delete_macro) |
| `plugin_introspect` | Read-only list of loaded pluginv2 plugins with their (protocol, event, phase) hook registrations and redacted Vars |

### MCP Resources

Detailed help and schemas for each tool are provided as MCP Resources.
To check tool parameters and usage examples, retrieve the resource at the following URIs:

**Help (usage, parameter descriptions, examples)**:
- `yorishiro://help/proxy_start`, `yorishiro://help/proxy_stop`
- `yorishiro://help/query`, `yorishiro://help/manage`
- `yorishiro://help/resend_http`, `yorishiro://help/resend_ws`, `yorishiro://help/resend_grpc`, `yorishiro://help/resend_raw`
- `yorishiro://help/fuzz_http`, `yorishiro://help/fuzz_ws`, `yorishiro://help/fuzz_grpc`, `yorishiro://help/fuzz_raw`
- `yorishiro://help/macro`, `yorishiro://help/intercept`
- `yorishiro://help/configure`, `yorishiro://help/security`
- `yorishiro://help/plugin_introspect`
- `yorishiro://help/examples` (collection of usage examples by workflow)

**Schemas (JSON Schema)**:
- `yorishiro://schema/proxy_start`, `yorishiro://schema/query`
- `yorishiro://schema/manage`, `yorishiro://schema/macro`
- `yorishiro://schema/resend_http`, `yorishiro://schema/resend_ws`, `yorishiro://schema/resend_grpc`, `yorishiro://schema/resend_raw`
- `yorishiro://schema/fuzz_http`, `yorishiro://schema/fuzz_ws`, `yorishiro://schema/fuzz_grpc`, `yorishiro://schema/fuzz_raw`
- `yorishiro://schema/intercept`, `yorishiro://schema/configure`
- `yorishiro://schema/security`, `yorishiro://schema/plugin_introspect`

If you are unsure of the exact parameter structure, always consult the help resource first.

### proxy_start -- Start Proxy

```json
// Basic startup
{
  "listen_addr": "127.0.0.1:8080",
  "tls_passthrough": ["*.googleapis.com"]
}

// Multi-listener startup with additional options
{
  "name": "socks-listener",
  "listen_addr": "127.0.0.1:1080",
  "upstream_proxy": "http://corporate-proxy:3128",
  "max_connections": 256,
  "peek_timeout_ms": 5000,
  "request_timeout_ms": 30000,
  "max_concurrent_streams": 500
}
```

#### proxy_start Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Listener name (default: "default"). Used for identification with multiple listeners |
| `listen_addr` | string | Listen address (default: "127.0.0.1:8080") |
| `upstream_proxy` | string | Upstream proxy URL (http:// or socks5://[user:pass@]host:port) |
| `tls_passthrough` | string[] | TLS passthrough target patterns |
| `intercept_rules` | object[] | Intercept rules (id, enabled, direction, conditions) |
| `auto_transform` | object[] | Auto-transform rules (id, enabled, priority, direction, conditions, action) |
| `tcp_forwards` | map | TCP port forwarding (port -> upstream_host:port) |
| `socks5_auth` | string | SOCKS5 authentication method ("none" or "password") |
| `socks5_username` | string | SOCKS5 username |
| `socks5_password` | string | SOCKS5 password |
| `max_connections` | int | Maximum concurrent connections (default: 128, range: 1-100000) |
| `max_concurrent_streams` | int | HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS advertised to clients (1-65535; default: 500) |
| `peek_timeout_ms` | int | Protocol detection timeout (default: 30000) |
| `request_timeout_ms` | int | HTTP request header read timeout (default: 60000) |
| `tls_fingerprint` | string | TLS fingerprint profile ("chrome", "firefox", "safari", "edge", "random", "none". default: "chrome") |
| `client_cert` | string | PEM client certificate path (for mTLS, used with client_key) |
| `client_key` | string | PEM client private key path (for mTLS, used with client_cert) |
| `capture_scope` | object | Recording-only filter (USK-776). `{includes: [scope_rule], excludes: [scope_rule]}`. Each `scope_rule` has `hostname` (supports `*.example.com`), `url_prefix`, `method` (AND-evaluated). Out-of-scope flows are still proxied but not stored. Distinct from `target_scope` (transmission gate via `security` tool) |

#### Recording filter vs transmission gate

Two scopes exist with distinct responsibilities — pick the one that matches your goal:

| Concept | What it does | Where to set it | When to use |
|---------|-------------|-----------------|-------------|
| `capture_scope` (proxy_start / configure) | Suppresses **flow recording** for out-of-scope traffic. Wire transmission is unaffected. | `proxy_start.capture_scope` and `configure.capture_scope` | Browser-driven testing where 3rd-party CDNs / analytics / fonts are noise but pages must still load. |
| `target_scope` (security tool) | Suppresses **transmission** of out-of-scope traffic. Out-of-scope requests are blocked at the connector boundary. | `security` tool with `action: set_target_scope` / `update_target_scope` | When you intentionally want to prevent the proxy from contacting unscoped hosts (data exfiltration prevention, time-boxed engagement boundaries). |

Blocked flows (target_scope deny / rate_limit / safety_filter) are recorded by their respective recorder paths; capture_scope governs only the normal recording path.

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

// Protocol filter (canonical Message-type family: http, ws, grpc, grpc-web, sse, raw, tls-handshake)
{"resource": "flows", "filter": {"protocol": "http"}}

// WebSocket flow filter (WS Streams' Scheme stays "http"/"https" — the handshake transport)
{"resource": "flows", "filter": {"protocol": "ws"}}

// Combine protocol=ws with scheme=https to get WS-over-TLS only
{"resource": "flows", "filter": {"protocol": "ws", "scheme": "https"}}

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

// Body size control — suppress bodies entirely (metadata only)
{"resource": "flow", "id": "<flow-id>", "include_bodies": false}

// Body size control — cap each side at 4 KiB
{"resource": "flow", "id": "<flow-id>", "body_max_bytes": 4096}
```

#### query Filter Parameters

| Parameter | Target Resource | Description |
|-----------|----------------|-------------|
| `protocol` | flows | Protocol name (canonical Message-type family): http, ws, grpc, grpc-web, sse, raw, tls-handshake (legacy spellings rejected as of USK-705) |
| `scheme` | flows | Stream.Scheme filter — wire-observed handshake transport. Accepted values: `"http"`, `"https"`, `"tcp"`. WebSocket Streams retain `"http"` / `"https"` (handshake transport, not application protocol) — use `protocol="ws"` to filter WS flows, optionally combined with `scheme="https"` for WS-over-TLS only. Passing `"ws"` / `"wss"` is hard-rejected (USK-864) |
| `method` | flows | HTTP method |
| `url_pattern` | flows | URL substring search |
| `status_code` | flows, fuzz_results | HTTP response code |
| `state` | flows | Flow state ("active", "complete", "error") |
| `blocked_by` | flows | Block reason ("target_scope", "intercept_drop", "rate_limit", "safety_filter") |
| `conn_id` | flows | Connection ID exact match. Search flows from the same connection |
| `host` | flows | Hostname filter. Matches server_addr or host portion of URL |
| `tag` | fuzz_jobs | Tag exact match |
| `direction` | messages | Message direction ("send", "receive") |
| `status` | fuzz_jobs | Job state ("running", "paused", "completed", "cancelled", "error") |
| `body_contains` | fuzz_results | Response body substring |
| `outliers_only` | fuzz_results | Return only outliers (detected by deviation in status code, body length, and timing) |

#### query Body-Size Control (USK-862)

| Parameter | Description |
|-----------|-------------|
| `include_bodies` | Include message bodies in flow/messages responses (default: true). When false, body fields are suppressed; metadata, headers, and `body_truncated` remain |
| `body_max_bytes` | Truncate per-message body and `body_decoded` to at most this many bytes (0 = no cap, default). When applied, `body_truncated_by_query` is set and `body_original_size` / `body_decoded_original_size` report the pre-truncation lengths |

fuzz_results includes aggregate statistics (`summary.statistics`: status_code_distribution, body_length, timing_ms min/max/median/stddev) and outlier detection (`summary.outliers`: by_status_code, by_body_length, by_timing).

Flow details include `protocol_summary` (protocol-specific info), and streaming flows include `message_preview` (first 10 messages). Flows generated by resend have `variant: "modified"`.

### resend_http -- Resend / Construct an HTTP Request

```json
// Resend an existing HTTP flow with header/body overrides
{
  "flow_id": "<flow-id>",
  "headers": [
    {"name": "Authorization", "value": "Bearer <token>"},
    {"name": "X-Forwarded-For", "value": "127.0.0.1"}
  ],
  "body_patches": [{"json_path": "$.user_id", "value": 999}],
  "tag": "idor-test"
}

// Override target dial host while keeping the recorded :authority
{
  "flow_id": "<flow-id>",
  "override_host": "staging.target.com:443",
  "tag": "staging-replay"
}

// Construct an HTTP request from scratch (no flow_id)
{
  "method": "GET",
  "scheme": "https",
  "authority": "api.target.com",
  "path": "/v1/users/999",
  "headers": [{"name": "Authorization", "value": "Bearer <token>"}],
  "tag": "idor-from-scratch"
}
```

#### resend_http Parameters

| Parameter | Description |
|-----------|-------------|
| `flow_id` | Recorded stream id; when set, omitted fields are inherited from the original send |
| `method` | HTTP method (required when flow_id is empty) |
| `scheme` | http or https (required when flow_id is empty) |
| `authority` | Host / :authority value (required when flow_id is empty) |
| `path` | Request path (required when flow_id is empty). A literal `?` auto-splits into path + raw_query |
| `raw_query` | Raw query string without leading `?` |
| `headers` | Ordered `[{name, value}]` list preserving wire case/order/duplicates |
| `body` | Request body interpreted per body_encoding |
| `body_encoding` | text or base64 (default: text) |
| `body_set` | true to override body to empty (omitting body inherits the original when flow_id is set) |
| `body_patches` | Patches applied on top of any body replacement |
| `override_host` | Redirect the dial target while preserving the request's Host / :authority (host:port) |
| `timeout_ms` | Per-request timeout in ms (default: 30000) |
| `tag` | Tag stored on the new flow's Tags map |

### resend_ws -- Resend a WebSocket Frame

```json
// Resend a single WS frame on a fresh upgrade derived from the recorded flow
{
  "flow_id": "<websocket-flow-id>",
  "opcode": "text",
  "payload": "ping",
  "tag": "ws-replay"
}

// From-scratch WS frame (target_addr + path required)
{
  "target_addr": "ws.target.com:443",
  "scheme": "wss",
  "path": "/ws/notifications",
  "opcode": "binary",
  "payload": "AAECAw==",
  "body_encoding": "base64",
  "tag": "ws-from-scratch"
}
```

`opcode` is one of `text | binary | close | ping | pong`. For Close frames, set `close_code` and optionally `close_reason`. `compressed: true` (per-message-deflate) requires the recorded flow to have negotiated deflate via flow_id.

### resend_grpc -- Resend a gRPC Unary RPC

```json
{
  "flow_id": "<grpc-flow-id>",
  "metadata": [
    {"name": "authorization", "value": "Bearer <token>"}
  ],
  "messages": [
    {"payload": "CgVoZWxsbw==", "body_encoding": "base64"}
  ],
  "tag": "grpc-authz-test"
}
```

`messages[]` is the request-side LPM (length-prefixed message) list; at least one entry is required. When `flow_id` is set, `service` / `method` / `metadata` / `encoding` inherit from the recorded send; otherwise `target_addr + service + method` are required.

### resend_raw -- Resend Raw Bytes (Smuggling / Anomaly Tests)

```json
// Resend the recorded raw payload as-is
{
  "flow_id": "<raw-flow-id>",
  "target_addr": "api.target.com:443",
  "use_tls": true,
  "tag": "raw-replay"
}

// Replace the entire payload
{
  "flow_id": "<raw-flow-id>",
  "target_addr": "api.target.com:443",
  "use_tls": true,
  "override_bytes": "<base64-encoded-raw-request>",
  "override_bytes_encoding": "base64",
  "tag": "smuggling-test"
}

// Apply offset-based byte patches (mutually exclusive with override_bytes)
{
  "flow_id": "<raw-flow-id>",
  "target_addr": "api.target.com:443",
  "patches": [
    {"offset": 14, "data": "Content-Length: 9999", "data_encoding": "text"}
  ],
  "tag": "te-cl-smuggling"
}
```

`flow_id` is REQUIRED — for ad-hoc byte injection without a recorded flow, use `fuzz_raw`. Wire bytes are NEVER normalised — they reach the wire verbatim.

### fuzz_http -- Synchronously Fuzz an HTTP Request

```json
{
  "flow_id": "<flow-id>",
  "positions": [
    {
      "path": "body",
      "payloads": ["normalvalue", "' OR SLEEP(3)-- "],
      "encoding": "text"
    }
  ],
  "stop_on_5xx": false,
  "tag": "sqli-time-based"
}
```

`positions[]` is REQUIRED. Each position has a typed `path` into HTTPMessage:
`method | scheme | authority | path | raw_query | body | headers[N].name | headers[N].value`.
The cartesian product across positions yields the variant sequence (capped at 1000 per call).

### fuzz_ws -- Synchronously Fuzz a WebSocket Frame

```json
{
  "flow_id": "<websocket-flow-id>",
  "opcode": "text",
  "positions": [
    {
      "path": "payload",
      "payloads": ["", "AAAA", "<svg/onload=alert(1)>"]
    }
  ],
  "stop_on_close": false,
  "tag": "ws-fuzz"
}
```

`positions[]` typed paths: `payload | close_reason`. Cartesian product capped at 1000 variants. Each variant runs on its own fresh dial + upgrade.

### fuzz_grpc -- Synchronously Fuzz a gRPC Unary RPC

```json
{
  "flow_id": "<grpc-flow-id>",
  "messages": [{"payload": "CgVoZWxsbw==", "body_encoding": "base64"}],
  "positions": [
    {
      "path": "messages[0].payload",
      "payloads": ["CgA=", "CgVoZWxsbw==", "CgRoZWxw"],
      "encoding": "base64"
    }
  ],
  "stop_on_non_ok": false,
  "tag": "grpc-fuzz"
}
```

`positions[]` typed paths: `service | method | metadata[N].name | metadata[N].value | messages[N].payload`. Cartesian product capped at 1000 variants. Each variant runs on an independent gRPC stream.

### fuzz_raw -- Synchronously Fuzz a Raw Byte Payload

```json
// Use a captured raw flow as the base, vary one section
{
  "flow_id": "<raw-flow-id>",
  "target_addr": "api.target.com:443",
  "use_tls": true,
  "positions": [
    {
      "path": "payload",
      "payloads": [
        "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg==",
        "UE9TVCAvIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KDQo="
      ],
      "encoding": "base64"
    }
  ],
  "tag": "smuggling-fuzz"
}

// From scratch (no flow_id) — positions supply each variant's bytes
{
  "target_addr": "api.target.com:443",
  "use_tls": true,
  "positions": [
    {
      "path": "payload",
      "payloads": ["<base64-template-1>", "<base64-template-2>"],
      "encoding": "base64"
    }
  ],
  "tag": "smuggling-from-scratch"
}
```

`positions[]` typed paths: `payload | patches[N].data`. `flow_id` is OPTIONAL — when empty, `override_bytes` or a `payload` position must supply the variant bytes. Wire bytes are NEVER normalised.

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

`output_path` and `input_path` are resolved relative to the proxy server process's working directory — pass absolute paths when the server cwd is unknown to the caller (e.g. HTTP remote MCP).

```json
// Delete flows (with protocol filter; matches Stream.Protocol exactly)
{"action": "delete_flows", "params": {"protocol": "raw", "older_than_days": 7, "confirm": true}}

// Export flows (with filter and body control)
{
  "action": "export_flows",
  "params": {
    "format": "jsonl",
    "output_path": "/tmp/export.jsonl",
    "include_bodies": false,
    "filter": {"protocol": "http", "url_pattern": "/api/"}
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

#### Per-Protocol Hold-Timeout Overrides

The intercept queue's hold-timeout / timeout-behavior can be overridden per protocol via `configure.intercept_queue.protocol_overrides`. Valid keys are the canonical envelope.Protocol values: `http`, `ws`, `grpc`, `grpc-web`, `sse`, `raw`, `tls-handshake`. Useful when WebSocket / SSE streams need a longer hold than HTTP requests:

```json
// configure
{
  "operation": "merge",
  "intercept_queue": {
    "timeout_ms": 60000,
    "timeout_behavior": "auto_release",
    "protocol_overrides": {
      "ws":  {"timeout_ms": 600000, "timeout_behavior": "auto_release"},
      "sse": {"timeout_ms": 300000}
    }
  }
}
```

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

// Configure intercept queue settings (with per-protocol overrides)
{
  "intercept_queue": {
    "timeout_ms": 120000,
    "timeout_behavior": "auto_release",
    "protocol_overrides": {
      "ws":  {"timeout_ms": 600000},
      "sse": {"timeout_ms": 300000}
    }
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
| `tls_passthrough` | TLS passthrough settings |
| `intercept_rules` | Intercept rules |
| `intercept_queue` | Intercept queue (timeout_ms, timeout_behavior, protocol_overrides per envelope.Protocol) |
| `auto_transform` | Auto-transform rules |
| `socks5_auth` | SOCKS5 authentication (method, username, password) |
| `max_connections` | Maximum concurrent connections (1-100000) |
| `peek_timeout_ms` | Protocol detection timeout (100-600000) |
| `request_timeout_ms` | HTTP request timeout (100-600000) |
| `tls_fingerprint` | Change TLS fingerprint profile |
| `budget` | Diagnostic budget (max_total_requests, max_duration) |
| `client_cert` | mTLS client certificate settings (cert_path, key_path) |
| `capture_scope` | Recording-only observability filter (USK-776). Use `add_includes` / `remove_includes` / `add_excludes` / `remove_excludes` for `operation: merge`; `includes` / `excludes` for `operation: replace`. See the recording-vs-transmission table above. |

### plugin_introspect -- Plugin Introspection

`plugin_introspect` is read-only and takes no parameters. It returns the full list of loaded pluginv2 plugins together with each plugin's `(protocol, event, phase)` hook registrations and the redacted `PluginConfig.Vars` map.

```json
// List loaded plugins (no parameters)
{}
```

Use this when you need to confirm which plugins are active and which envelope events they observe. There is no MCP-level reload / enable / disable — plugin lifecycle is managed by the config file and the proxy boot sequence.

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
  |     +-- NO --> Execute directly with the matching resend_* / fuzz_* tool
  |
  +-- Need to select attack payloads?
  |     |
  |     +-- YES --> See references/payload-patterns.md (always check "Safe Payload Selection Principles")
  |     +-- NO --> Next
  |
  +-- Single test or comprehensive test?
  |     |
  |     +-- Single HTTP verification --> resend_http
  |     +-- Single WebSocket frame --> resend_ws
  |     +-- Single gRPC unary RPC --> resend_grpc
  |     +-- Raw byte replay (smuggling) --> resend_raw
  |     +-- Comprehensive HTTP test --> fuzz_http (outlier detection: outliers_only filter)
  |     +-- Comprehensive WS / gRPC / Raw fuzz --> fuzz_ws / fuzz_grpc / fuzz_raw
  |     +-- Want to bypass HTTP parsing / fuzz arbitrary bytes --> fuzz_raw (HTTP Request Smuggling, etc.)
  |
  +-- Need response diff analysis?
  |     |
  |     +-- YES --> Issue two resend_http calls and diff the recorded flows via the query tool
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
        +-- SOCKS5 traffic monitoring --> proxy_start on a SOCKS5-capable listen address (clients send SOCKS5 to it)
        +-- Raw TCP data --> TCP port forwarding via tcp_forwards
```

For the complete verification workflow, see `references/verify-vulnerability.md`.

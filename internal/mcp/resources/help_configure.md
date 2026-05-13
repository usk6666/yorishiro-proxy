# configure

Configure runtime proxy settings including TLS passthrough, intercept rules, and auto-transform. Supports incremental (merge) and full replacement (replace) operations.

## Parameters

### operation (string, optional)
How the configuration should be applied.
- `"merge"` (default): Apply incremental add/remove changes to existing config.
- `"replace"`: Replace entire configuration sections with new values.

### upstream_proxy (string, optional)
Upstream proxy URL. Set to a proxy URL to route traffic, set to `""` (empty string) to disable (direct connection). If omitted, the current setting is not changed.
- Supported schemes: `http://host:port`, `socks5://host:port`
- Authentication: `http://user:pass@host:port`, `socks5://user:pass@host:port`

### tls_passthrough (object, optional)
Controls which domains bypass TLS interception.

**Merge operation fields:**
- **add** (array of strings): Patterns to add (e.g. `["*.googleapis.com"]`).
- **remove** (array of strings): Patterns to remove.

**Replace operation fields:**
- **patterns** (array of strings): Full replacement of all passthrough patterns. Pass `[]` (with `operation: "replace"`) to clear all patterns.

**Field/operation alignment is enforced.** Supplying `patterns` while
`operation` is `merge` (default), or supplying `add` / `remove` while
`operation` is `replace`, returns a structured error and applies no
mutation. To clear all passthrough patterns, use
`{"operation":"replace","tls_passthrough":{"patterns":[]}}`.

## Usage Examples

### Add TLS passthrough patterns
```json
{
  "tls_passthrough": {
    "add": ["*.googleapis.com", "accounts.google.com"]
  }
}
```

### Replace all TLS passthrough patterns
```json
{
  "operation": "replace",
  "tls_passthrough": {
    "patterns": ["*.googleapis.com"]
  }
}
```

### intercept_rules (object, optional)
Configures intercept rules for matching requests/responses.

**Merge operation fields:**
- **add** (array of intercept rules): Rules to add.
- **remove** (array of strings): Rule IDs to remove.
- **enable** (array of strings): Rule IDs to enable.
- **disable** (array of strings): Rule IDs to disable.

**Replace operation fields:**
- **rules** (array of intercept rules): Full replacement of all intercept rules. Pass `[]` (with `operation: "replace"`) to clear all rules.

**Field/operation alignment is enforced.** Supplying `rules` while
`operation` is `merge` (default), or supplying `add` / `remove` /
`enable` / `disable` while `operation` is `replace`, returns a
structured error and applies no mutation. To clear all intercept
rules, use `{"operation":"replace","intercept_rules":{"rules":[]}}`.

Each intercept rule has:
- **id** (string): Unique rule identifier.
- **enabled** (boolean): Whether the rule is active.
- **direction** (string): `"request"`, `"response"`, or `"both"`.
- **conditions** (object): Matching criteria:
  - **host_pattern** (string): Regex for hostname matching (port excluded).
  - **path_pattern** (string): Regex for URL path matching.
  - **methods** (array of strings): HTTP method whitelist.
  - **header_match** (object): Header name to regex mapping (AND logic).
  - **upgrade_url_pattern** (string): Regex for WebSocket upgrade URL matching (WebSocket rules only).
  - **flow_id** (string): WebSocket flow ID to intercept (WebSocket rules only).

Note: WebSocket conditions (`upgrade_url_pattern`, `flow_id`) are exclusive to WebSocket intercept rules and must not be combined with HTTP conditions (`host_pattern`, `path_pattern`, `methods`, `header_match`).

## Usage Examples

### Add TLS passthrough patterns
```json
{
  "tls_passthrough": {
    "add": ["*.googleapis.com", "accounts.google.com"]
  }
}
```

### Replace all TLS passthrough patterns
```json
{
  "operation": "replace",
  "tls_passthrough": {
    "patterns": ["*.googleapis.com"]
  }
}
```

### Add intercept rules (merge)
```json
{
  "intercept_rules": {
    "add": [
      {
        "id": "target-host",
        "enabled": true,
        "direction": "request",
        "conditions": {
          "host_pattern": "httpbin\\.org"
        }
      },
      {
        "id": "admin-api",
        "enabled": true,
        "direction": "request",
        "conditions": {
          "host_pattern": "api\\.target\\.com",
          "path_pattern": "/api/admin.*",
          "methods": ["POST", "PUT", "DELETE"],
          "header_match": {"Content-Type": "application/json"}
        }
      }
    ]
  }
}
```

### Disable/enable intercept rules (merge)
```json
{
  "intercept_rules": {
    "disable": ["admin-api"],
    "enable": ["other-rule"]
  }
}
```

### Remove intercept rules (merge)
```json
{
  "intercept_rules": {
    "remove": ["admin-api"]
  }
}
```

### Add WebSocket intercept rules (merge)
```json
{
  "intercept_rules": {
    "add": [
      {
        "id": "ws-chat",
        "enabled": true,
        "direction": "both",
        "conditions": {
          "upgrade_url_pattern": "/ws/chat.*"
        }
      },
      {
        "id": "ws-specific-flow",
        "enabled": true,
        "direction": "both",
        "conditions": {
          "flow_id": "abc-123-def"
        }
      }
    ]
  }
}
```

### Replace all intercept rules
```json
{
  "operation": "replace",
  "intercept_rules": {
    "rules": [
      {
        "id": "new-rule",
        "enabled": true,
        "direction": "both",
        "conditions": {
          "path_pattern": "/api/.*"
        }
      }
    ]
  }
}
```

### auto_transform (object, optional)
Configures auto-transform rules for automatic request/response modification.

**Merge operation fields:**
- **add** (array of transform rules): Rules to add.
- **remove** (array of strings): Rule IDs to remove.
- **enable** (array of strings): Rule IDs to enable.
- **disable** (array of strings): Rule IDs to disable.

**Replace operation fields:**
- **rules** (array of transform rules): Full replacement of all auto-transform rules. Pass `[]` (with `operation: "replace"`) to clear all rules.

**Field/operation alignment is enforced.** Supplying `rules` while
`operation` is `merge` (default), or supplying `add` / `remove` /
`enable` / `disable` while `operation` is `replace`, returns a
structured error and applies no mutation. To clear all auto-transform
rules, use `{"operation":"replace","auto_transform":{"rules":[]}}`.

Each auto-transform rule has:
- **id** (string): Unique rule identifier.
- **enabled** (boolean): Whether the rule is active.
- **priority** (integer): Execution order (lower values applied first).
- **direction** (string): `"request"`, `"response"`, or `"both"`.
- **conditions** (object): Matching criteria (same as intercept rules):
  - **url_pattern** (string): Regex for URL path matching.
  - **methods** (array of strings): HTTP method whitelist.
  - **header_match** (object): Header name to regex mapping (AND logic).
- **action** (object): Transformation to apply:
  - **type** (string): `"add_header"`, `"set_header"`, `"remove_header"`, or `"replace_body"`.
  - **header** (string): Header name (for header actions).
  - **value** (string): Header value or replacement string.
  - **pattern** (string): Search regex (for replace_body).

### Add auto-transform rules (merge)
```json
{
  "auto_transform": {
    "add": [
      {
        "id": "add-auth",
        "enabled": true,
        "priority": 10,
        "direction": "request",
        "conditions": {
          "url_pattern": "/api/.*"
        },
        "action": {
          "type": "set_header",
          "header": "Authorization",
          "value": "Bearer <token>"
        }
      },
      {
        "id": "remove-csp",
        "enabled": true,
        "priority": 20,
        "direction": "response",
        "conditions": {},
        "action": {
          "type": "remove_header",
          "header": "Content-Security-Policy"
        }
      }
    ]
  }
}
```

### Replace body content (merge)
```json
{
  "auto_transform": {
    "add": [
      {
        "id": "replace-host",
        "enabled": true,
        "priority": 10,
        "direction": "request",
        "conditions": {},
        "action": {
          "type": "replace_body",
          "pattern": "production-host",
          "value": "staging-host"
        }
      }
    ]
  }
}
```

### Replace all auto-transform rules
```json
{
  "operation": "replace",
  "auto_transform": {
    "rules": [
      {
        "id": "only-rule",
        "enabled": true,
        "priority": 0,
        "direction": "both",
        "conditions": {},
        "action": {
          "type": "add_header",
          "header": "X-Proxy",
          "value": "yorishiro"
        }
      }
    ]
  }
}
```

### tls_fingerprint (string, optional)
Sets the TLS ClientHello fingerprint profile for upstream connections at runtime.
- Valid values: `"chrome"`, `"firefox"`, `"safari"`, `"edge"`, `"random"`, `"none"` (standard crypto/tls).
- If omitted, the current setting is not changed.

### Change TLS fingerprint profile
```json
{
  "tls_fingerprint": "firefox"
}
```

### Disable TLS fingerprinting (use standard TLS)
```json
{
  "tls_fingerprint": "none"
}
```

### socks5_auth (object, optional)
Configures SOCKS5 authentication at runtime.

- **method** (string, required): `"none"` or `"password"`.
- **username** (string): Username for password authentication. Required when method is `"password"`.
- **password** (string): Password for password authentication. Required when method is `"password"`.

### Enable SOCKS5 password authentication
```json
{
  "socks5_auth": {
    "method": "password",
    "username": "proxyuser",
    "password": "proxypass"
  }
}
```

### Disable SOCKS5 authentication
```json
{
  "socks5_auth": {
    "method": "none"
  }
}
```

### budget (object, optional)
Configures diagnostic session budget limits at runtime. Uses merge semantics by default — only provided fields are updated, others remain unchanged. In replace mode, omitted fields reset to 0.

For full-replace semantics, use the `security` tool's `set_budget` action instead.

- **max_total_requests** (integer): Maximum total requests for the session. `0` means no limit.
- **max_duration** (string): Maximum session duration as a Go duration string (e.g. `"30m"`, `"1h"`). `"0s"` means no limit.

### Set diagnostic budget
```json
{
  "budget": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  }
}
```

### intercept_queue (object, optional)
Configures the intercept queue behavior.

- **timeout_ms** (integer): Timeout in milliseconds for blocked requests (minimum 1000).
- **timeout_behavior** (string): Action when timeout is reached: `"auto_release"` (forward as-is, default) or `"auto_drop"` (discard).
- **protocol_overrides** (object, optional): Per-protocol hold-timeout / timeout-behavior overrides (USK-855). Valid keys are canonical envelope.Protocol strings: `http`, `ws`, `grpc`, `grpc-web`, `sse`, `raw`, `tls-handshake`. The literal `"http2"` is NOT valid — HTTP/1 and HTTP/2 both envelope as `"http"`. Each value is `{timeout_ms?, timeout_behavior?}`; pointer-optional sub-fields inherit the global per-field. On `"merge"`, each entry overwrites the keyed override; a JSON `null` value removes the key. On `"replace"`, the entire map atomically replaces the existing per-protocol override set; missing keys clear any prior override. Built-in defaults seed `ws=60000ms`, `sse=60000ms`, `grpc=60000ms` to provide a human-review window for AI-agent intercept loops (query intercept_queue → reason → intercept modify_and_forward typically takes 4–10s). The earlier 8s edge-idle safety margin is no longer required because USK-854's hold-window keepalive injection keeps the upstream alive during a hold, so the ~10s upstream edge-idle window (e.g. Fly.io edge) no longer races human-review latency (USK-863).

### max_connections (integer, optional)
Dynamically changes the maximum number of concurrent proxy connections. Range: 1-100000.

### max_concurrent_streams (integer, optional)
Dynamically changes the HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised to clients on the inbound (proxy-acting-as-server) Layer. Range: 1-65535. Default (when neither `configure` nor the config file sets it): `500` (USK-862).

**Next-connection semantics**: the new value affects only newly accepted H2 connections. Already-established H2 connections retain the cap captured at their stack-assembly time — the proxy does NOT reissue a mid-stream SETTINGS frame on existing connections (RFC 9113 §6.5.3 allows it but a runtime override surface that broadcasts to live conns is out of scope; restart listeners via `proxy_stop` + `proxy_start` if you need every connection to observe the change immediately).

Streams beyond this cap are rejected with `RST_STREAM(REFUSED_STREAM)` per RFC 9113 §5.1.2 — so re-tightening to a low value (e.g. 50) is the explicit way to reproduce the legacy 100-stream cap behaviour for testing.

### peek_timeout_ms (integer, optional)
Dynamically changes the protocol detection timeout in milliseconds. Range: 100-600000.

### request_timeout_ms (integer, optional)
Dynamically changes the HTTP request header read timeout in milliseconds. Range: 100-600000.

### client_cert (object, optional)
Global mTLS client certificate configuration for upstream connections.
- **cert_path** (string): Path to PEM-encoded client certificate. Set to `""` to disable.
- **key_path** (string): Path to PEM-encoded client private key. Set to `""` to disable.

### capture_scope (object, optional)
Recording-only observability filter (USK-776). Limits which flows are persisted to the flow store **without altering wire transmission**. Distinct from `target_scope` (transmission gate, configured via the `security` tool): use `capture_scope` to suppress noise from third-party CDNs / analytics during browser-driven testing without breaking page rendering.

Honours the top-level `operation` discriminator:
- `"merge"` (default): applies `add_includes` / `remove_includes` / `add_excludes` / `remove_excludes` deltas.
- `"replace"`: overwrites both rule lists with `includes` / `excludes`.

Each rule is AND-evaluated across `hostname` / `url_prefix` / `method`; at least one field must be non-empty. Excludes win over includes.

#### Add a capture include rule (merge)
```json
{
  "operation": "merge",
  "capture_scope": {
    "add_includes": [
      {"hostname": "api.target.com"}
    ]
  }
}
```

#### Drop noise from third-party CDNs (merge)
```json
{
  "operation": "merge",
  "capture_scope": {
    "add_excludes": [
      {"hostname": "*.cloudfront.net"},
      {"url_prefix": "/healthz"}
    ]
  }
}
```

#### Replace all capture rules
```json
{
  "operation": "replace",
  "capture_scope": {
    "includes": [
      {"hostname": "*.target.com", "url_prefix": "/api/"}
    ],
    "excludes": [
      {"url_prefix": "/api/internal/heartbeat"}
    ]
  }
}
```

### Combined update
```json
{
  "tls_passthrough": {
    "add": ["pinned.service.com"]
  },
  "intercept_rules": {
    "add": [
      {
        "id": "json-api",
        "enabled": true,
        "direction": "request",
        "conditions": {
          "header_match": {"Content-Type": "application/json"}
        }
      }
    ]
  },
  "auto_transform": {
    "add": [
      {
        "id": "add-auth",
        "enabled": true,
        "priority": 10,
        "direction": "request",
        "conditions": {},
        "action": {
          "type": "set_header",
          "header": "Authorization",
          "value": "Bearer test-token"
        }
      }
    ]
  }
}
```

### Set upstream proxy
```json
{
  "upstream_proxy": "http://proxy.corp:3128"
}
```

### Disable upstream proxy
```json
{
  "upstream_proxy": ""
}
```

### Configure intercept queue timeout
```json
{
  "intercept_queue": {
    "timeout_ms": 60000,
    "timeout_behavior": "auto_release"
  }
}
```

### Per-protocol hold-timeout overrides (USK-855)
```json
{
  "operation": "merge",
  "intercept_queue": {
    "protocol_overrides": {
      "ws":   {"timeout_ms": 2500},
      "grpc": {"timeout_ms": 30000, "timeout_behavior": "auto_drop"}
    }
  }
}
```

### Clear a per-protocol override (merge null)
```json
{
  "operation": "merge",
  "intercept_queue": {
    "protocol_overrides": {"ws": null}
  }
}
```

### Set connection limits
```json
{
  "max_connections": 256,
  "peek_timeout_ms": 10000,
  "request_timeout_ms": 30000
}
```

### Configure mTLS client certificate
```json
{
  "client_cert": {
    "cert_path": "/path/to/client.crt",
    "key_path": "/path/to/client.key"
  }
}
```

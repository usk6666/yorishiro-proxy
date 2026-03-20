# configure

Configure runtime proxy settings including capture scope, TLS passthrough, and intercept rules. Supports incremental (merge) and full replacement (replace) operations.

## Parameters

### operation (string, optional)
How the configuration should be applied.
- `"merge"` (default): Apply incremental add/remove changes to existing config.
- `"replace"`: Replace entire configuration sections with new values.

### upstream_proxy (string, optional)
Upstream proxy URL. Set to a proxy URL to route traffic, set to `""` (empty string) to disable (direct connection). If omitted, the current setting is not changed.
- Supported schemes: `http://host:port`, `socks5://host:port`
- Authentication: `http://user:pass@host:port`, `socks5://user:pass@host:port`

### capture_scope (object, optional)
Controls which requests are recorded. Only specified sections are modified.

**Merge operation fields:**
- **add_includes** (array of scope rules): Rules to add to the include list.
- **remove_includes** (array of scope rules): Rules to remove from the include list.
- **add_excludes** (array of scope rules): Rules to add to the exclude list.
- **remove_excludes** (array of scope rules): Rules to remove from the exclude list.

**Replace operation fields:**
- **includes** (array of scope rules): Full replacement of include rules.
- **excludes** (array of scope rules): Full replacement of exclude rules.

Each scope rule has:
- **hostname** (string): Hostname pattern (e.g. `"example.com"`, `"*.example.com"`).
- **url_prefix** (string): URL path prefix (e.g. `"/api/"`).
- **method** (string): HTTP method (e.g. `"GET"`, `"POST"`).

At least one field must be set per rule.

### tls_passthrough (object, optional)
Controls which domains bypass TLS interception.

**Merge operation fields:**
- **add** (array of strings): Patterns to add (e.g. `["*.googleapis.com"]`).
- **remove** (array of strings): Patterns to remove.

**Replace operation fields:**
- **patterns** (array of strings): Full replacement of all passthrough patterns.

## Usage Examples

### Add scope rules (merge)
```json
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com"}],
    "add_excludes": [{"hostname": "static.target.com"}]
  }
}
```

### Remove scope rules (merge)
```json
{
  "capture_scope": {
    "remove_includes": [{"hostname": "old.target.com"}]
  }
}
```

### Replace all scope rules
```json
{
  "operation": "replace",
  "capture_scope": {
    "includes": [{"hostname": "new-target.com"}],
    "excludes": []
  }
}
```

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
- **rules** (array of intercept rules): Full replacement of all intercept rules.

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

### Add scope rules (merge)
```json
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com"}],
    "add_excludes": [{"hostname": "static.target.com"}]
  }
}
```

### Remove scope rules (merge)
```json
{
  "capture_scope": {
    "remove_includes": [{"hostname": "old.target.com"}]
  }
}
```

### Replace all scope rules
```json
{
  "operation": "replace",
  "capture_scope": {
    "includes": [{"hostname": "new-target.com"}],
    "excludes": []
  }
}
```

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
- **rules** (array of transform rules): Full replacement of all auto-transform rules.

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

- **timeout_ms** (integer): Timeout in milliseconds for blocked requests.
- **timeout_behavior** (string): Action when timeout is reached: `"auto_release"` (forward as-is, default) or `"auto_drop"` (discard).

### max_connections (integer, optional)
Dynamically changes the maximum number of concurrent proxy connections. Range: 1-100000.

### peek_timeout_ms (integer, optional)
Dynamically changes the protocol detection timeout in milliseconds. Range: 100-600000.

### request_timeout_ms (integer, optional)
Dynamically changes the HTTP request header read timeout in milliseconds. Range: 100-600000.

### client_cert (object, optional)
Global mTLS client certificate configuration for upstream connections.
- **cert_path** (string): Path to PEM-encoded client certificate. Set to `""` to disable.
- **key_path** (string): Path to PEM-encoded client private key. Set to `""` to disable.

### Combined update
```json
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com", "url_prefix": "/v2/"}]
  },
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

# proxy_start

Start the proxy server with optional configuration. The proxy listens on the specified address and begins intercepting HTTP/HTTPS traffic.

## Parameters

### listen_addr (string, optional)
TCP address to listen on. Must be a loopback address for security.
- Default: `"127.0.0.1:8080"`
- Format: `"host:port"` (e.g. `"127.0.0.1:9090"`, `"[::1]:8080"`)
- Only loopback addresses (127.0.0.1, ::1, localhost) are allowed

### capture_scope (object, optional)
Controls which requests are recorded to the session store. If omitted, all requests are captured.

- **includes** (array of scope rules): Only matching requests are captured. If empty, all requests match.
- **excludes** (array of scope rules): Matching requests are excluded. Takes precedence over includes.

Each scope rule has:
- **hostname** (string): Hostname pattern. Exact match or wildcard prefix (e.g. `"example.com"`, `"*.example.com"`).
- **url_prefix** (string): URL path prefix match (e.g. `"/api/"`).
- **method** (string): HTTP method match (e.g. `"GET"`, `"POST"`).

At least one field must be set per rule.

### tls_passthrough (array of strings, optional)
Domain patterns that bypass TLS interception (no MITM). Useful for certificate-pinned services.
- Exact match: `"pinned-service.com"`
- Wildcard: `"*.googleapis.com"`

### intercept_rules (array of intercept rules, optional)
Rules for intercepting requests/responses. If omitted, no intercept rules are active.

Each intercept rule has:
- **id** (string, required): Unique rule identifier.
- **enabled** (boolean, required): Whether the rule is active.
- **direction** (string, required): `"request"`, `"response"`, or `"both"`.
- **conditions** (object, required): Matching criteria (all conditions are AND-ed):
  - **host_pattern** (string, optional): Regex pattern for hostname matching (port excluded).
  - **path_pattern** (string, optional): Regex pattern for URL path matching.
  - **methods** (array of strings, optional): HTTP method whitelist (case-insensitive).
  - **header_match** (object, optional): Maps header names to regex patterns (AND logic).

Multiple rules use OR logic: a request/response is intercepted if any enabled rule matches.

## Usage Examples

### Start with defaults
```json
{}
```

### Start on custom port
```json
{
  "listen_addr": "127.0.0.1:9090"
}
```

### Start with capture scope
```json
{
  "listen_addr": "127.0.0.1:8080",
  "capture_scope": {
    "includes": [
      {"hostname": "api.target.com"},
      {"hostname": "*.target.com", "url_prefix": "/api/"}
    ],
    "excludes": [
      {"hostname": "static.target.com"}
    ]
  },
  "tls_passthrough": ["*.googleapis.com", "accounts.google.com"]
}
```

### Start with intercept rules
```json
{
  "intercept_rules": [
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
```

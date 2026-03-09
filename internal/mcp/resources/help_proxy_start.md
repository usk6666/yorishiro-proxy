# proxy_start

Start the proxy server with optional configuration. The proxy listens on the specified address and begins intercepting HTTP/HTTPS/SOCKS5 traffic.

## Parameters

### listen_addr (string, optional)
TCP address to listen on. Must be a loopback address for security.
- Default: `"127.0.0.1:8080"`
- Format: `"host:port"` (e.g. `"127.0.0.1:9090"`, `"[::1]:8080"`)
- Only loopback addresses (127.0.0.1, ::1, localhost) are allowed

### capture_scope (object, optional)
Controls which requests are recorded to the flow store. If omitted, all requests are captured.

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

### tcp_forwards (object, optional)
Maps local listen ports to upstream TCP addresses for Raw TCP forwarding.
- Format: `{"port": "upstream_host:port"}` (e.g. `{"3306": "db.example.com:3306"}`)
- Connections arriving on a mapped port are forwarded to the specified upstream
- If omitted, Raw TCP forwarding is not configured

### protocols (array of strings, optional)
Specifies which protocols are enabled for detection.
- Valid values: `"HTTP/1.x"`, `"HTTPS"`, `"WebSocket"`, `"HTTP/2"`, `"gRPC"`, `"SOCKS5"`, `"TCP"`
- If omitted, all protocols are enabled (default behavior)
- Restricting protocols can improve performance and reduce noise

### tls_fingerprint (string, optional)
TLS ClientHello fingerprint profile for upstream connections.
- `"chrome"` (default): Mimic Chrome browser TLS fingerprint.
- `"firefox"`: Mimic Firefox browser TLS fingerprint.
- `"safari"`: Mimic Safari browser TLS fingerprint.
- `"edge"`: Mimic Edge browser TLS fingerprint.
- `"random"`: Select a random browser fingerprint per connection.
- `"none"`: Use standard Go crypto/tls (no fingerprint mimicry).

This helps evade JA3/JA4-based bot detection during vulnerability assessments.

### socks5_auth (string, optional)
SOCKS5 authentication method.
- `"none"` (default): SOCKS5 clients connect without authentication.
- `"password"`: Require username/password authentication (RFC 1929).
- When set to `"password"`, `socks5_username` and `socks5_password` are required.

### socks5_username (string, optional)
Username for SOCKS5 password authentication.
- Required when `socks5_auth` is `"password"`.
- Ignored when `socks5_auth` is `"none"`.

### socks5_password (string, optional)
Password for SOCKS5 password authentication.
- Required when `socks5_auth` is `"password"`.
- Ignored when `socks5_auth` is `"none"`.

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

### Start with TCP forwards
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "3306": "db.example.com:3306",
    "6379": "redis.example.com:6379"
  }
}
```

### Start with specific protocols
```json
{
  "listen_addr": "127.0.0.1:8080",
  "protocols": ["HTTP/1.x", "HTTPS", "gRPC"]
}
```

### Start with SOCKS5 password authentication
```json
{
  "listen_addr": "127.0.0.1:8080",
  "socks5_auth": "password",
  "socks5_username": "proxyuser",
  "socks5_password": "proxypass"
}
```

### Start with SOCKS5 via proxychains
```json
{
  "listen_addr": "127.0.0.1:1080",
  "protocols": ["SOCKS5"]
}
```
Then configure proxychains (`/etc/proxychains.conf`):
```
socks5 127.0.0.1 1080
```

### Start with TLS fingerprint
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tls_fingerprint": "firefox"
}
```

### Start with standard TLS (no fingerprint)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tls_fingerprint": "none"
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

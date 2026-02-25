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

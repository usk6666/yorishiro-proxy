# proxy_start

Start the proxy server with optional configuration. The proxy listens on the specified address and begins intercepting HTTP/HTTPS/SOCKS5 traffic.

## Parameters

### name (string, optional)
Listener name for multi-listener support. Allows running multiple simultaneous listeners with different names.
- Default: `"default"`

### listen_addr (string, optional)
TCP address to listen on. Must be a loopback address for security.
- Default: `"127.0.0.1:8080"`
- Format: `"host:port"` (e.g. `"127.0.0.1:9090"`, `"[::1]:8080"`)
- Only loopback addresses (127.0.0.1, ::1, localhost) are allowed

### upstream_proxy (string, optional)
Upstream proxy URL to route all outgoing traffic through.
- Supported schemes: `http://host:port` (HTTP CONNECT proxy), `socks5://host:port` (SOCKS5 proxy)
- Authentication: `http://user:pass@host:port`, `socks5://user:pass@host:port`
- If omitted, traffic is sent directly to the target
- Takes precedence over HTTP_PROXY/HTTPS_PROXY environment variables

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
Maps local listen ports to upstream forwarding configurations for TCP forwarding with protocol detection.

Each entry maps a local port number (string key) to either:
- A **string** value `"upstream_host:port"` (legacy format, treated as raw TCP forwarding)
- A **ForwardConfig object** with the following fields:
  - **target** (string, required): Upstream address in `"host:port"` format (e.g. `"api.example.com:50051"`)
  - **protocol** (string, optional): Expected protocol for L7 parsing. Default: `"auto"` (peek-based detection).
    Valid values: `"auto"`, `"raw"`, `"http"`, `"http2"`, `"grpc"`, `"websocket"`, `"sse"`
  - **tls** (boolean, optional): Enable client-side TLS MITM termination on the forwarded listen port. Default: `false`.
    When true, the proxy presents a dynamically-issued certificate to the local client and terminates TLS before applying L7 parsing.
  - **upstream_tls** (boolean, optional): Enable upstream-dial TLS encryption to `target`. Default: `false`.
    When true, the proxy wraps the upstream-direction connection in TLS (using the global TLS fingerprint, SNI derived from `target`, and the configured verification / client-cert settings).
  - **upstream_insecure_skip_verify** (boolean, optional): Per-entry override: skip upstream TLS certificate verification for this forward. Default: inherits global `insecure_skip_verify`.
    Useful for MITM-debugging local upstreams whose self-signed certs lack SAN entries for the dialled host/IP (e.g. `moul/grpcbin`). Scoped per `tcp_forwards` entry and independent of the CONNECT MITM `tls_passthrough` path.

`tls` and `upstream_tls` are **independent** and are never inferred from `target`'s scheme or port:

| tls   | upstream_tls | Client wire | Upstream wire | Typical use case                              |
|-------|--------------|-------------|---------------|-----------------------------------------------|
| false | false        | plaintext   | plaintext     | Raw L4/L7 forwarding (default)                |
| true  | false        | TLS         | plaintext     | TLS termination only (downstream offload)     |
| false | true         | plaintext   | TLS           | Plaintext client → TLS-only upstream          |
| true  | true         | TLS         | TLS           | Full MITM: terminate then re-encrypt upstream |

- If omitted, TCP forwarding is not configured
- Both legacy string format and structured ForwardConfig can be mixed in the same object

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

### client_cert (string, optional)
Path to a PEM-encoded client certificate for mTLS with upstream servers (global).
- Must be used together with `client_key`
- If omitted, no client certificate is presented

### client_key (string, optional)
Path to a PEM-encoded client private key for mTLS with upstream servers (global).
- Must be used together with `client_cert`
- If omitted, no client certificate is presented

### max_connections (integer, optional)
Maximum number of concurrent proxy connections.
- Default: `128`
- Range: 1-100000

### max_concurrent_streams (integer, optional)
HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` advertised to clients on the inbound (proxy-acting-as-server) Layer.
- Default: `500` (USK-862 bumped 100 → 500 to cover high-multiplexing pages such as 200-parallel image fetches)
- Range: 1-65535
- Omit to inherit the boot-time value set via the `-max-concurrent-streams` CLI flag or `YP_MAX_CONCURRENT_STREAMS` env var; the H2 Layer default of 500 applies when none is set.
- Streams beyond this cap are rejected with `RST_STREAM(REFUSED_STREAM)` per RFC 9113 §5.1.2.
- Applies only to the inbound (client-facing) Layer; the outbound (upstream) Layer continues to honour the peer's advertised limit.

### peek_timeout_ms (integer, optional)
Timeout in milliseconds for protocol detection on new connections.
- Default: `30000` (30 seconds)
- Range: 100-600000

### request_timeout_ms (integer, optional)
Timeout in milliseconds for reading HTTP request headers.
- Default: `60000` (60 seconds)
- Range: 100-600000

### auto_transform (array of transform rules, optional)
Auto-transform rules for automatic request/response modification at startup. Same format as the `configure` tool's auto_transform rules.
- If omitted, no auto-transform rules are active

### capture_scope (object, optional)
Recording-only observability filter. Limits which flows are persisted to the flow store **without altering wire transmission** — out-of-scope traffic is still proxied normally, it is just not stored.

Use `capture_scope` to suppress noise from third-party CDNs / analytics / fonts during browser-driven sessions, keeping the flow store and AI-agent context window focused on the assets under test. Distinct from `target_scope` (transmission gate, configured via the `security` tool): blocking with `target_scope` would break page rendering whenever a tested page also fetches from out-of-scope hosts.

Each rule is AND-evaluated across `hostname` / `url_prefix` / `method`; at least one field per rule must be non-empty. `excludes` are evaluated before `includes`. Empty `includes` means "all flows are eligible". `*.example.com` wildcard matches subdomains but NOT the apex `example.com`.

Per-protocol matching of `url_prefix` / `method`:

- **HTTP/1.x and HTTP/2 envelopes** — method and path are matched directly against the request line / `:path`.
- **gRPC envelopes** — the request-side `GRPCStart` envelope carries the HTTP/2 `:path` value (`/Service/Method`) and an implicit `:method = POST`, so `url_prefix` and `method` rules match against gRPC streams. Example: `{"url_prefix": "/hello.HelloService/"}` in `excludes` will skip every RPC under that service while still recording other RPCs on the same connection. A malformed `:path` that leaves Service or Method empty does not synthesize a partial path, so `/Service/` cannot spuriously prefix-match.
- **WebSocket frame envelopes and SSE event envelopes** — individual frames / events carry no method/path, so `url_prefix` and `method` rules do not match against them. The initial HTTP upgrade envelope IS subject to those rules, and the recording decision is cached per-stream and applied to subsequent frames — set the rule on the upgrade request to capture an entire WS / SSE stream.
- **Raw TCP envelopes** — no method/path; `url_prefix` and `method` rules never match. Use `hostname` (resolved from the CONNECT/SOCKS5 target or TLS SNI) to scope raw TCP recording.

Blocked flows (target_scope deny / rate_limit / safety_filter blocks) are recorded by their respective recorder paths; capture_scope governs only the normal Pipeline-Record code path.

Example:
```json
{
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

### Start with TLS passthrough
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tls_passthrough": ["*.googleapis.com", "accounts.google.com"]
}
```

### Start with TCP forwards (legacy string format)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "3306": "db.example.com:3306",
    "6379": "redis.example.com:6379"
  }
}
```

### Start with TCP forwards (structured ForwardConfig)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "50051": {
      "target": "api.example.com:50051",
      "protocol": "grpc"
    },
    "8443": {
      "target": "secure.example.com:443",
      "protocol": "http2",
      "tls": true
    },
    "3306": "db.example.com:3306"
  }
}
```

### Start with TCP forward to TLS-only upstream (HTTP → HTTPS bridge)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "8081": {
      "target": "api.example.com:443",
      "protocol": "http",
      "upstream_tls": true
    }
  }
}
```

### Start with TCP forward — full MITM (TLS terminate + re-encrypt upstream)
```json
{
  "listen_addr": "127.0.0.1:8080",
  "tcp_forwards": {
    "8443": {
      "target": "api.example.com:443",
      "protocol": "http",
      "tls": true,
      "upstream_tls": true
    }
  }
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
  "listen_addr": "127.0.0.1:1080"
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

### Start with upstream proxy
```json
{
  "listen_addr": "127.0.0.1:8080",
  "upstream_proxy": "http://upstream:3128"
}
```

### Start with named listener
```json
{
  "name": "api-proxy",
  "listen_addr": "127.0.0.1:9090"
}
```

### Start with mTLS client certificate
```json
{
  "listen_addr": "127.0.0.1:8080",
  "client_cert": "/path/to/client.crt",
  "client_key": "/path/to/client.key"
}
```

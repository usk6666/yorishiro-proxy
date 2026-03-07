# Vulnerability Assessment Workflow Examples

Common workflows for using yorishiro-proxy as an AI-driven vulnerability assessment tool.

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
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<original-flow-id>",
    "override_headers": {"Authorization": "Bearer <other-user-token>"}
  }
}
```

### Test without authentication (remove auth header)
```json
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<original-flow-id>",
    "override_headers": {"Authorization": ""}
  }
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
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>",
    "override_url": "https://target.example.com/api/admin/users"
  }
}
```

### Resend with modified body
```json
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>",
    "override_body": "{\"role\": \"admin\", \"user_id\": 1}"
  }
}
```

## HTTP Request Smuggling Analysis

### Resend raw bytes to preserve header formatting
```json
// resend
{
  "action": "resend_raw",
  "params": {
    "flow_id": "<flow-id>",
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

## SOCKS5 / proxychains Workflow

### 1. Start proxy with SOCKS5 support
```json
// proxy_start
{
  "listen_addr": "127.0.0.1:1080",
  "capture_scope": {
    "includes": [{"hostname": "target.example.com"}]
  }
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

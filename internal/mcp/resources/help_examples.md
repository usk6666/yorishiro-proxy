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

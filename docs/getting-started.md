# Getting Started

This guide walks you through installing yorishiro-proxy, connecting it to Claude Code as an MCP server, and capturing your first HTTP traffic. By the end, you will have a working proxy setup ready for vulnerability assessment workflows.

## Prerequisites

- **Go 1.25+** -- required for building from source
- **Claude Code** -- yorishiro-proxy operates as an MCP server for Claude Code
- **playwright-cli** (optional) -- for automated browser-based traffic capture

## Installation

### Build from source

Clone the repository and build:

```bash
git clone https://github.com/usk6666/yorishiro-proxy.git
cd yorishiro-proxy
make build
```

This produces the binary at `bin/yorishiro-proxy`.

### Install with `go install`

```bash
go install github.com/usk6666/yorishiro-proxy/cmd/yorishiro-proxy@latest
```

The binary is placed in `$GOPATH/bin/yorishiro-proxy` (or `$HOME/go/bin/yorishiro-proxy` if `GOPATH` is not set).

Verify the installation:

```bash
yorishiro-proxy -h
```

## MCP Server Setup

yorishiro-proxy runs as an MCP server communicating over stdin/stdout. To connect it to Claude Code, create a `.mcp.json` file in your project root (or home directory).

### Manual configuration

Create `.mcp.json` with the following content:

```json
{
  "mcpServers": {
    "yorishiro-proxy": {
      "command": "/path/to/bin/yorishiro-proxy",
      "args": ["-insecure", "-log-file", "/tmp/yorishiro-proxy.log"]
    }
  }
}
```

Replace `/path/to/bin/yorishiro-proxy` with the actual path to the binary. For example:

- If built from source: `"/home/user/yorishiro-proxy/bin/yorishiro-proxy"`
- If installed with `go install`: `"/home/user/go/bin/yorishiro-proxy"`

### Configuration options

Common CLI flags to include in `args`:

| Flag | Description |
|------|-------------|
| `-insecure` | Skip upstream TLS certificate verification (useful for testing) |
| `-log-file /tmp/yorishiro-proxy.log` | Write logs to a file instead of stderr (keeps MCP stdio clean) |
| `-log-level debug` | Set log verbosity (`debug`, `info`, `warn`, `error`) |
| `-db <name-or-path>` | SQLite database path or project name (e.g., `-db pentest-2026` creates `~/.yorishiro-proxy/pentest-2026.db`) |
| `-ca-ephemeral` | Use an ephemeral in-memory CA (no persistent certificate files) |

All flags also accept environment variables with the `YP_` prefix (e.g., `YP_INSECURE=true`, `YP_LOG_LEVEL=debug`). Priority: CLI flag > environment variable > config file > default value.

> **Note:** A future `yorishiro-proxy setup` command will automate this configuration. For now, manual `.mcp.json` setup is required.

### Verify the connection

After creating `.mcp.json`, restart Claude Code. You should see five MCP tools become available:

- `proxy_start` -- start the proxy listener
- `proxy_stop` -- stop the proxy listener
- `configure` -- change runtime settings
- `query` -- retrieve sessions, status, and configuration
- `execute` -- resend requests, run macros, start fuzz jobs

## CA Certificate Installation

yorishiro-proxy performs HTTPS interception (MITM) by dynamically generating server certificates signed by its own CA. On first startup, the CA certificate is automatically generated and saved to `~/.yorishiro-proxy/ca/ca.crt`.

To intercept HTTPS traffic, you must install this CA certificate in your operating system or browser trust store.

### Check the CA certificate path

Use the `query` tool to confirm the CA certificate location:

```json
// query
{"resource": "ca_cert"}
```

The response includes `cert_path` (file path) and `fingerprint` (SHA-256 hash) fields.

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.yorishiro-proxy/ca/ca.crt
```

### Linux

```bash
sudo cp ~/.yorishiro-proxy/ca/ca.crt \
  /usr/local/share/ca-certificates/yorishiro-proxy.crt
sudo update-ca-certificates
```

### Windows

```cmd
certutil -addstore "Root" %USERPROFILE%\.yorishiro-proxy\ca\ca.crt
```

Run the command prompt as Administrator.

### Alternative: Skip CA installation with playwright-cli

If you are using playwright-cli for browser automation, you can skip CA certificate installation by enabling `ignoreHTTPSErrors` in the playwright configuration (see the playwright-cli section below).

## First Capture (Manual Browser)

This section demonstrates the basic workflow: start the proxy, route browser traffic through it, and inspect captured sessions.

### Step 1: Start the proxy

Ask Claude Code to start the proxy, or use the `proxy_start` tool directly:

```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080"
}
```

The proxy is now listening on `127.0.0.1:8080`.

### Step 2: Configure your browser

Set your browser or system HTTP proxy to `http://127.0.0.1:8080`. You can also set environment variables for command-line tools:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

### Step 3: Generate traffic

Browse to any website or make HTTP requests through the proxy. For a quick test:

```bash
curl -x http://127.0.0.1:8080 http://httpbin.org/get
```

For HTTPS (requires CA certificate installed, or use `-k` to skip verification):

```bash
curl -x http://127.0.0.1:8080 -k https://httpbin.org/get
```

### Step 4: List captured sessions

```json
// query
{"resource": "sessions"}
```

This returns all captured sessions with their IDs, methods, URLs, status codes, and timestamps.

### Step 5: Filter sessions

To find specific requests:

```json
// query
{
  "resource": "sessions",
  "filter": {"url_pattern": "httpbin.org", "method": "GET"},
  "limit": 10
}
```

## First Capture (playwright-cli)

If you have playwright-cli installed, you can capture browser traffic programmatically.

### Step 1: Configure playwright-cli

Create `.playwright/cli.config.json` in your project root:

```json
{
  "browser": {
    "browserName": "chromium",
    "launchOptions": {
      "channel": "chromium",
      "proxy": {
        "server": "http://127.0.0.1:8080"
      }
    },
    "contextOptions": {
      "ignoreHTTPSErrors": true
    }
  }
}
```

The `ignoreHTTPSErrors: true` option bypasses SSL certificate errors, so you do not need to install the CA certificate when using playwright-cli.

### Step 2: Start the proxy

```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080"
}
```

### Step 3: Open a page with playwright-cli

Use playwright-cli to open a browser that routes through the proxy:

```
playwright-cli open https://httpbin.org/get
```

All browser traffic flows through yorishiro-proxy and is recorded as sessions.

### Step 4: View captured sessions

```json
// query
{"resource": "sessions", "limit": 20}
```

## Inspecting Request Details

Once you have captured sessions, you can drill into individual requests and responses.

### View full session details

```json
// query
{"resource": "session", "id": "<session-id>"}
```

This returns the complete request and response, including headers, body, status code, and timing information.

### View session messages

For streaming protocols (WebSocket, gRPC, HTTP/2), sessions contain multiple messages. List them with:

```json
// query
{
  "resource": "messages",
  "id": "<session-id>",
  "limit": 50
}
```

Filter by direction to see only sent or received messages:

```json
// query
{
  "resource": "messages",
  "id": "<session-id>",
  "filter": {"direction": "send"}
}
```

## Resending and Modifying Requests

The `resend` action lets you replay a captured request with modifications -- useful for testing authorization, parameter tampering, and other vulnerability patterns.

### Resend a request as-is

```json
// execute
{
  "action": "resend",
  "params": {
    "session_id": "<session-id>"
  }
}
```

### Resend with modified headers

```json
// execute
{
  "action": "resend",
  "params": {
    "session_id": "<session-id>",
    "override_headers": {"Authorization": "Bearer <different-token>"}
  }
}
```

### Resend with a modified body

```json
// execute
{
  "action": "resend",
  "params": {
    "session_id": "<session-id>",
    "body_patches": [
      {"json_path": "$.user.role", "value": "admin"}
    ]
  }
}
```

### Preview changes before sending (dry-run)

```json
// execute
{
  "action": "resend",
  "params": {
    "session_id": "<session-id>",
    "override_method": "PUT",
    "override_headers": {"X-Custom": "test"},
    "dry_run": true
  }
}
```

The dry-run returns the modified request without sending it, so you can verify the changes.

## Next Steps

With the basic setup complete, explore these advanced features:

### Scope management

Control which traffic is captured using capture scope rules:

```json
// configure
{
  "capture_scope": {
    "add_includes": [{"hostname": "api.target.com"}],
    "add_excludes": [{"url_prefix": "/health"}]
  }
}
```

### Intercept mode

Hold requests for manual inspection before forwarding:

```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080",
  "intercept_rules": [
    {
      "id": "api-requests",
      "enabled": true,
      "direction": "request",
      "conditions": {
        "host_pattern": "api\\.target\\.com",
        "methods": ["POST", "PUT", "DELETE"]
      }
    }
  ]
}
```

Intercepted requests appear in the intercept queue. Release, modify, or drop them:

```json
// query
{"resource": "intercept_queue"}

// execute
{"action": "release", "params": {"intercept_id": "<id>"}}
```

### Macros

Automate multi-step workflows (e.g., login then access protected resource):

```json
// execute
{
  "action": "define_macro",
  "params": {
    "name": "auth-flow",
    "description": "Login and extract session cookie",
    "steps": [
      {
        "id": "login",
        "session_id": "<login-session-id>",
        "extract": [
          {
            "name": "session_cookie",
            "from": "response",
            "source": "header",
            "header_name": "Set-Cookie",
            "regex": "PHPSESSID=([^;]+)",
            "group": 1
          }
        ]
      },
      {
        "id": "access",
        "session_id": "<protected-session-id>",
        "override_headers": {"Cookie": "PHPSESSID={{session_cookie}}"}
      }
    ]
  }
}
```

### Fuzzer

Automate payload injection for parameter testing:

```json
// execute
{
  "action": "fuzz",
  "params": {
    "session_id": "<session-id>",
    "attack_type": "sequential",
    "positions": [
      {
        "id": "pos-0",
        "location": "body_json",
        "json_path": "$.password",
        "payload_set": "passwords"
      }
    ],
    "payload_sets": {
      "passwords": {
        "type": "wordlist",
        "values": ["admin", "password", "123456", "root"]
      }
    },
    "tag": "password-test"
  }
}
```

Monitor fuzz job progress:

```json
// query
{"resource": "fuzz_jobs"}

// query
{"resource": "fuzz_results", "fuzz_id": "<fuzz-id>", "limit": 100}
```

### Session export and import

Export captured sessions for sharing or archival:

```json
// execute
{
  "action": "export_sessions",
  "params": {
    "format": "jsonl",
    "output_path": "/tmp/sessions.jsonl"
  }
}
```

Import sessions into another instance:

```json
// execute
{
  "action": "import_sessions",
  "params": {
    "input_path": "/tmp/sessions.jsonl",
    "on_conflict": "skip"
  }
}
```

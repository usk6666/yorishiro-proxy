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
| `-tls-fingerprint <profile>` | TLS fingerprint profile: `chrome`, `firefox`, `safari`, `edge`, `random`, `none` (default: `chrome`) |
| `-mcp-http-addr <host:port>` | Enable Streamable HTTP transport and serve the WebUI (e.g., `-mcp-http-addr 127.0.0.1:3000`) |

All flags also accept environment variables with the `YP_` prefix (e.g., `YP_INSECURE=true`, `YP_LOG_LEVEL=debug`). Priority: CLI flag > environment variable > config file > default value.

> **Tip:** You can automate this configuration by running `yorishiro-proxy install` (or `yorishiro-proxy install mcp` for MCP config only).

### Verify the connection

After creating `.mcp.json`, restart Claude Code. You should see eleven MCP tools become available:

- `proxy_start` -- start the proxy listener
- `proxy_stop` -- stop the proxy listener
- `configure` -- change runtime settings (capture scope, intercept rules, TLS passthrough, etc.)
- `query` -- retrieve flows, status, configuration, and fuzz results
- `resend` -- resend captured requests with optional mutations
- `fuzz` -- start, pause, resume, and cancel fuzz campaigns
- `macro` -- define and run multi-step macro workflows
- `intercept` -- release, modify, or drop intercepted requests
- `manage` -- delete, export, and import flows
- `security` -- configure target scope rules
- `plugin` -- list, reload, enable, and disable Starlark plugins

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

This section demonstrates the basic workflow: start the proxy, route browser traffic through it, and inspect captured flows.

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

### Step 4: List captured flows

```json
// query
{"resource": "flows"}
```

This returns all captured flows with their IDs, methods, URLs, status codes, and timestamps.

### Step 5: Filter flows

To find specific requests:

```json
// query
{
  "resource": "flows",
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

All browser traffic flows through yorishiro-proxy and is recorded as flows.

### Step 4: View captured flows

```json
// query
{"resource": "flows", "limit": 20}
```

## Inspecting Request Details

Once you have captured flows, you can drill into individual requests and responses.

### View full flow details

```json
// query
{"resource": "flow", "id": "<flow-id>"}
```

This returns the complete request and response, including headers, body, status code, and timing information.

### View flow messages

For streaming protocols (WebSocket, gRPC, HTTP/2), flows contain multiple messages. List them with:

```json
// query
{
  "resource": "messages",
  "id": "<flow-id>",
  "limit": 50
}
```

Filter by direction to see only sent or received messages:

```json
// query
{
  "resource": "messages",
  "id": "<flow-id>",
  "filter": {"direction": "send"}
}
```

## Resending and Modifying Requests

The `resend` tool lets you replay a captured request with modifications -- useful for testing authorization, parameter tampering, and other vulnerability patterns.

### Resend a request as-is

```json
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>"
  }
}
```

### Resend with modified headers

```json
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>",
    "override_headers": {"Authorization": "Bearer <different-token>"}
  }
}
```

### Resend with a modified body

```json
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>",
    "body_patches": [
      {"json_path": "$.user.role", "value": "admin"}
    ]
  }
}
```

### Preview changes before sending (dry-run)

```json
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>",
    "override_method": "PUT",
    "override_headers": {"X-Custom": "test"},
    "dry_run": true
  }
}
```

The dry-run returns the modified request without sending it, so you can verify the changes.

## WebUI

yorishiro-proxy includes a built-in web interface that provides a visual complement to the MCP tool workflow. The WebUI lets you browse captured flows, resend requests, run fuzz campaigns, and manage intercept rules -- all from your browser.

### Accessing the WebUI

To enable the WebUI, start yorishiro-proxy with the `-mcp-http-addr` flag. This activates the Streamable HTTP transport and serves the WebUI on the same address.

Add `-mcp-http-addr` to your `.mcp.json` configuration:

```json
{
  "mcpServers": {
    "yorishiro-proxy": {
      "command": "/path/to/bin/yorishiro-proxy",
      "args": [
        "-insecure",
        "-log-file", "/tmp/yorishiro-proxy.log",
        "-mcp-http-addr", "127.0.0.1:3000"
      ]
    }
  }
}
```

After restarting Claude Code, check the log output (stderr or the file specified by `-log-file`) for a line like:

```
WebUI available url=http://127.0.0.1:3000/?token=<random-token>
```

Open this URL in your browser. The WebUI pages load without authentication, but the `?token=` query parameter is required for the frontend to communicate with the MCP API backend. Without the token, the dashboard will not be able to fetch or display data.

The token is auto-generated on each launch. To use a fixed token, add `-mcp-http-token <your-token>` to the `args` in `.mcp.json`, or set the `YP_MCP_HTTP_TOKEN` environment variable.

### Browsing flows

The **Flows** page is the default landing page. It displays all captured HTTP/HTTPS, WebSocket, gRPC, and Raw TCP flows in a sortable table.

- **Filter flows** by protocol, HTTP method, URL pattern, or status code using the filter controls at the top of the page.
- **Click a flow** to open its detail view, which shows the full request and response including headers, body, and timing information.
- **Export flows** to JSONL format using the Export button in the toolbar.

### Exporting as cURL or HAR

From the flow detail view, you can export individual flows in standard formats:

- **Copy as cURL** -- Copies a ready-to-run `curl` command to your clipboard, preserving the method, headers, and body of the original request.
- **Export HAR** -- Downloads the flow as an HTTP Archive (HAR 1.2) JSON file, suitable for importing into other tools such as browser DevTools or Burp Suite.

Both buttons are located in the toolbar at the top of the flow detail page.

### Resending requests with the Resender

The **Resend** page lets you replay captured requests with modifications through a visual editor.

1. Navigate to a flow detail page and click the **Resend** button, or go to the Resend page directly and enter a flow ID.
2. Modify the request as needed:
   - Change the HTTP method or URL.
   - Add, edit, or remove headers using the header editor.
   - Apply body patches (JSON path-based) or edit the body directly.
   - Use the raw HTTP editor to edit the entire request as plain text.
3. Click **Send** to execute the modified request. The response appears in the response panel below.
4. Use **Dry Run** to preview the modified request without sending it.

### Fuzzing with the Fuzzer

The **Fuzz** page provides an interface for running automated payload injection campaigns.

1. Select a base flow to use as a template.
2. Define **positions** -- locations in the request where payloads will be injected (URL parameters, headers, JSON body fields).
3. Configure **payload sets** with values to inject (wordlists, numeric ranges, etc.).
4. Choose the attack type: **sequential** (one position at a time) or **parallel** (all positions simultaneously).
5. Click **Start** to launch the fuzz job.
6. Monitor progress on the fuzz results page, which shows each request's status code, response size, and latency. Use the filter controls to find anomalous responses.

### Intercepting requests

The **Intercept** page lets you hold requests for manual inspection and modification before they are forwarded to the upstream server.

1. Configure intercept rules in the **Rules** panel on the left side. Rules match on host pattern, path pattern, HTTP methods, and header values.
2. Enable interception by toggling rules on. Matching requests appear in the intercept queue.
3. For each intercepted request, choose one of three actions:
   - **Release** -- forward the request as-is.
   - **Modify and Forward** -- edit headers or body before forwarding.
   - **Drop** -- discard the request and return a 502 response to the client.

### Managing macros

The **Macros** page lets you view and run multi-step workflows defined via the `macro` MCP tool. Each macro shows its steps, extraction rules, and execution history. Click **Run** to execute a macro and view the results of each step.

## SOCKS5 Proxy with proxychains

yorishiro-proxy includes a built-in SOCKS5 listener, making it compatible with tools like `proxychains` and `proxychains-ng` that route arbitrary TCP traffic through a SOCKS5 proxy.

### Step 1: Start the SOCKS5 listener

```json
// proxy_start
{
  "listen_addr": "127.0.0.1:1080",
  "protocol": "socks5"
}
```

To require authentication:

```json
// configure
{
  "socks5_auth": {
    "method": "password",
    "username": "user",
    "password": "pass"
  }
}
```

### Step 2: Configure proxychains

Edit `/etc/proxychains.conf` (or `~/.proxychains/proxychains.conf`):

```ini
[ProxyList]
socks5 127.0.0.1 1080
```

If authentication is enabled:

```ini
[ProxyList]
socks5 127.0.0.1 1080 user pass
```

### Step 3: Route traffic through proxychains

```bash
proxychains curl https://httpbin.org/get
proxychains nmap -sT -p 80,443 target.example.com
```

All TCP traffic from the proxied command flows through yorishiro-proxy. HTTPS traffic is intercepted (MITM) and recorded as flows with the `SOCKS5+HTTPS` protocol identifier. Plaintext HTTP traffic is recorded as `SOCKS5+HTTP`.

### Step 4: Query SOCKS5 flows

```json
// query
{
  "resource": "flows",
  "filter": {"protocol": "SOCKS5+HTTPS"}
}
```

You can also filter by SOCKS5 metadata in flow tags (`socks5_target`, `socks5_auth_method`).

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

// intercept
{"action": "release", "params": {"intercept_id": "<id>"}}
```

### TLS fingerprint evasion

When targeting sites protected by WAF services such as Cloudflare, JA3/JA4-based bot detection may block requests made with the default Go TLS stack. Use the `tls_fingerprint` parameter to mimic a real browser's TLS ClientHello:

```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080",
  "tls_fingerprint": "chrome"
}
```

To change the profile at runtime:

```json
// configure
{
  "tls_fingerprint": "firefox"
}
```

Valid profiles: `chrome`, `firefox`, `safari`, `edge`, `random`, `none`. The default is `chrome`.

### Macros

Automate multi-step workflows (e.g., login then access protected resource):

```json
// macro
{
  "action": "define_macro",
  "params": {
    "name": "auth-flow",
    "description": "Login and extract session cookie",
    "steps": [
      {
        "id": "login",
        "flow_id": "<login-flow-id>",
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
        "flow_id": "<protected-flow-id>",
        "override_headers": {"Cookie": "PHPSESSID={{session_cookie}}"}
      }
    ]
  }
}
```

### Fuzzer

Automate payload injection for parameter testing:

```json
// fuzz
{
  "action": "fuzz",
  "params": {
    "flow_id": "<flow-id>",
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

### Plugins

Extend proxy behavior with Starlark scripts that hook into the request/response pipeline. Plugins can inspect, modify, or block traffic at various stages.

#### Load plugins via config file

Create a JSON config file with plugin definitions and pass it with `-config`:

```json
{
  "plugins": [
    {
      "path": "examples/plugins/add_auth_header.star",
      "protocol": "http",
      "hooks": ["on_before_send_to_server"],
      "on_error": "skip"
    }
  ]
}
```

```json
// .mcp.json
{
  "mcpServers": {
    "yorishiro-proxy": {
      "command": "/path/to/bin/yorishiro-proxy",
      "args": ["-config", "config.json"]
    }
  }
}
```

#### Manage plugins at runtime

List loaded plugins:

```json
// plugin
{"action": "list"}
```

Disable or enable a plugin:

```json
// plugin
{"action": "disable", "params": {"name": "add_auth_header"}}

// plugin
{"action": "enable", "params": {"name": "add_auth_header"}}
```

Reload a plugin after editing the script:

```json
// plugin
{"action": "reload", "params": {"name": "add_auth_header"}}
```

#### Custom codec plugins

Define custom encodings in Starlark for use in fuzzer, resender, and macro encoding chains:

```python
# codecs/sql_escape.star
name = "sql_escape"

def encode(s):
    return s.replace("'", "''")

def decode(s):
    return s.replace("''", "'")
```

Load codec plugins via config:

```json
{
  "codec_plugins": [
    {"path": "codecs/sql_escape.star"},
    {"path": "codecs/"}
  ]
}
```

Once loaded, custom codecs work anywhere built-in codecs do (e.g., `"encoding": ["sql_escape", "url_encode_query"]`).

For details on writing plugins, hook reference, and protocol data maps, see the [Plugin Development Guide](plugins.md).

### Comparing flows

The `resend` tool includes a `compare` action that produces a structural diff between two flows. This is useful for identifying how a parameter change affects the server's response:

```json
// resend
{
  "action": "compare",
  "params": {
    "flow_id_a": "<original-flow-id>",
    "flow_id_b": "<modified-flow-id>"
  }
}
```

The result includes status code changes, added/removed/changed headers, body length delta, timing differences, and for JSON responses, key-level diffs. Use this as a triage tool after resend or fuzz to quickly spot anomalous responses.

### AI Safety: Rate limits and diagnostic budgets

When running automated testing, rate limits and diagnostic budgets prevent the AI agent from overwhelming the target or running indefinitely:

```json
// security -- set rate limits
{
  "action": "set_rate_limits",
  "params": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  }
}

// security -- set diagnostic budget
{
  "action": "set_budget",
  "params": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  }
}
```

Rate limits and budgets use the same two-layer architecture as target scope -- the Policy Layer (set via config file) defines upper bounds, and the Agent Layer (set via MCP tool) can only apply equal or stricter limits. When a budget is exhausted, the proxy automatically stops accepting new requests.

Check current usage:

```json
// security
{"action": "get_budget"}
```

### Flow export and import

Export captured flows for sharing or archival:

```json
// manage
{
  "action": "export_flows",
  "params": {
    "format": "jsonl",
    "output_path": "/tmp/flows.jsonl"
  }
}
```

Import flows into another instance:

```json
// manage
{
  "action": "import_flows",
  "params": {
    "input_path": "/tmp/flows.jsonl",
    "on_conflict": "skip"
  }
}
```

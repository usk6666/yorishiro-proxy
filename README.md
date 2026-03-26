<p align="center">
  <img src="docs/images/yorishiro-proxy_banner.png" alt="Yorishiro Proxy" width="600">
</p>

<p align="center">
  <strong>AI-First MITM Proxy Tool</strong><br>
  A network proxy for AI agents — intercept, record, and replay traffic through MCP.
</p>

<p align="center">
  <a href="https://github.com/usk6666/yorishiro-proxy/actions/workflows/ci.yml"><img src="https://github.com/usk6666/yorishiro-proxy/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://goreportcard.com/report/github.com/usk6666/yorishiro-proxy"><img src="https://goreportcard.com/badge/github.com/usk6666/yorishiro-proxy" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
</p>

<p align="center">
  <a href="README-ja.md">日本語</a>
</p>

> **Beta** — yorishiro-proxy is under active development. APIs, configuration formats, and protocol behavior may change between minor versions. Non-HTTP/HTTPS protocols (gRPC, WebSocket, Raw TCP, SOCKS5) are at an earlier stage of maturity and may have known limitations.

---

Yorishiro Proxy runs as an [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server, giving AI agents full control over proxy operations through eleven MCP tools. Designed for use with Claude Code and other MCP-compatible agents, it enables automated security testing workflows without manual UI interaction. An embedded Web UI is also available for visual inspection and interactive use.

<p align="center">
  <img src="docs/images/yorishiro-proxy_webui_flows.png" alt="Web UI - Flows" width="800">
</p>

## Features

- **Traffic Interception & Recording** -- MITM proxy with automatic CA certificate management
- **Resender** -- Replay requests with header/body/URL overrides, JSON patches, and raw HTTP editing
- **Fuzzer** -- Automated payload injection with sequential/parallel modes and async execution
- **Macro** -- Multi-step request sequences with variable extraction and template substitution
- **Intercept** -- Hold and inspect requests/responses in real time, then release, modify, or drop
- **Auto-Transform** -- Automatic request/response modification rules for matching traffic
- **Target Scope** -- Two-layer security boundary (Policy + Agent) to restrict reachable hosts
- **Multi-Protocol** -- HTTP/1.x, HTTPS (MITM), HTTP/2 (h2c/h2), gRPC, WebSocket, Raw TCP, SOCKS5
- **Multi-Listener** -- Multiple proxy listeners on different ports simultaneously
- **mTLS Client Certificates** -- Per-host client certificate support for mutual TLS authentication
- **TLS Verification Control** -- Per-host TLS verification and custom CA configuration
- **Flow Timing** -- Per-phase timing recording (DNS, connect, TLS handshake, request, response) on each flow
- **Flow Export/Import** -- JSONL, HAR 1.2, and cURL export formats
- **SOCKS5 Listener** -- SOCKS5 proxy with optional username/password authentication for proxychains integration
- **Upstream Proxy** -- Chain through HTTP or SOCKS5 proxies
- **Streamable HTTP MCP** -- Multi-agent shared access with Bearer token authentication
- **Comparer** -- Structural diff between two flows (status code, headers, body length, timing, JSON key-level diff)
- **AI Safety** -- SafetyFilter blocks destructive payloads (DROP TABLE, rm -rf, etc.) at the Input Filter before they reach the target; Output Filter masks PII (credit card numbers, email addresses, phone numbers, etc.) in responses before returning to AI agents while preserving raw data in the flow store; rate limiting (global/per-host RPS) and diagnostic budgets (request count/duration limits) with two-layer Policy+Agent architecture
- **Plugin System** -- Extend proxy behavior with [Starlark](https://github.com/google/starlark-go) scripts that hook into the request/response pipeline
- **Web UI** -- Embedded React/Vite dashboard for visual inspection and interactive testing

## Quick Start

### 1. Get the Binary

Download a prebuilt binary from the [GitHub Releases](https://github.com/usk6666/yorishiro-proxy/releases) page, or build from source:

```bash
git clone https://github.com/usk6666/yorishiro-proxy.git
cd yorishiro-proxy
make build    # outputs bin/yorishiro-proxy
```

### 2. Configure MCP

Add to your MCP client configuration (e.g., `.mcp.json` for Claude Code):

```json
{
  "mcpServers": {
    "yorishiro-proxy": {
      "command": "/path/to/bin/yorishiro-proxy",
      "args": []
    }
  }
}
```

The proxy starts as an MCP server on stdin/stdout. The CA certificate is automatically generated on first run and persisted to `~/.yorishiro-proxy/ca/`.

To also enable the Web UI:

```json
{
  "mcpServers": {
    "yorishiro-proxy": {
      "command": "/path/to/bin/yorishiro-proxy",
      "args": ["-mcp-http-addr", "127.0.0.1:3000"]
    }
  }
}
```

On startup, the log (stderr or the file specified by `-log-file`) prints the access URL including an authentication token:

```
WebUI available url=http://127.0.0.1:3000/?token=<random-token>
```

Open this URL in your browser. The token is auto-generated each launch; use `-mcp-http-token` to set a fixed value.

### 3. First Capture

Once the MCP server is running, the AI agent can start capturing traffic:

```
1. Start the proxy       -> proxy_start with listen_addr "127.0.0.1:8080"
2. Set HTTP_PROXY        -> point your target application at the proxy
3. Install the CA cert   -> query ca_cert to get the certificate path
4. Browse / send traffic -> captured flows appear in query flows
5. Inspect & replay      -> use resend to replay with modifications
```

## MCP Tools

All proxy operations are exposed through eleven MCP tools:

| Tool | Purpose |
|------|---------|
| `proxy_start` | Start a proxy listener with capture scope, TLS passthrough, intercept rules, auto-transform, TCP forwarding, and protocol settings |
| `proxy_stop` | Graceful shutdown of one or all listeners |
| `configure` | Runtime configuration changes (upstream proxy, capture scope, TLS passthrough, intercept rules, auto-transform, connection limits) |
| `query` | Unified information retrieval: flows, flow details, messages, proxy status, config, CA certificate, intercept queue, macros, fuzz jobs/results |
| `resend` | Replay recorded requests with mutations (method/URL/header/body overrides, JSON patches, raw byte patches, dry-run) and compare two flows structurally |
| `fuzz` | Execute fuzz testing campaigns with payload sets, positions, concurrency control, and stop conditions |
| `macro` | Define and execute multi-step macro workflows with variable extraction, guards, and hooks |
| `intercept` | Act on intercepted requests: release, modify and forward, or drop |
| `manage` | Manage flow data (delete/export/import) and CA certificate regeneration |
| `security` | Configure target scope rules, rate limits, diagnostic budgets, and SafetyFilter inspection (Policy Layer + Agent Layer) |
| `plugin` | List, reload, enable, and disable Starlark plugins at runtime |

## Web UI

When Streamable HTTP mode is enabled (`-mcp-http-addr`), the embedded Web UI is served at the same address.

| Page | Description |
|------|-------------|
| **Flows** | Flow list with filtering by protocol, method, status code, and URL pattern |
| **Dashboard** | Flow statistics overview with real-time traffic summary |
| **Intercept** | Real-time request/response interception with inline editing |
| **Resender** | Replay requests with overrides, JSON patches, raw HTTP editing, and dry-run preview |
| **Fuzz** | Create and manage fuzz campaigns with payload sets and result analysis |
| **Macros** | Multi-step request workflows with variable extraction |
| **Security** | Target scope configuration (Policy + Agent Layer) with URL testing |
| **Settings** | Proxy control, TLS passthrough, auto-transform rules, CA management, and more |

The Web UI communicates with the backend via Streamable HTTP MCP -- the same protocol used by AI agents.

## Supported Protocols

| Protocol | Detection | Notes |
|----------|-----------|-------|
| HTTP/1.x | Automatic | Forward proxy mode |
| HTTPS | CONNECT | MITM with dynamic certificate issuance |
| HTTP/2 | h2c / ALPN | Both cleartext and TLS, with per-stream flow display |
| gRPC | HTTP/2 content-type | Service/method extraction, streaming support, structured metadata display |
| WebSocket | HTTP Upgrade | Message-level recording with per-message display |
| Raw TCP | Fallback | Captures any unrecognized protocol, with TCP forwarding mappings |

## CLI Flags

| Flag | Env Variable | Default | Description |
|------|-------------|---------|-------------|
| `-db` | `YP_DB` | `~/.yorishiro-proxy/yorishiro.db` | SQLite database path or project name |
| `-ca-cert` / `-ca-key` | `YP_CA_CERT` / `YP_CA_KEY` | -- | CA certificate and private key paths |
| `-ca-ephemeral` | `YP_CA_EPHEMERAL` | `false` | Use ephemeral in-memory CA |
| `-insecure` | `YP_INSECURE` | `false` | Skip upstream TLS verification |
| `-tls-fingerprint <profile>` | `YP_TLS_FINGERPRINT` | `chrome` | TLS fingerprint profile: chrome, firefox, safari, edge, random, none |
| `-config` | `YP_CONFIG` | -- | JSON config file path for proxy defaults |
| `-log-level` | `YP_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `-log-format` | `YP_LOG_FORMAT` | `text` | Log format: text, json |
| `-log-file` | `YP_LOG_FILE` | stderr | Log output file |
| `-mcp-http-addr` | `YP_MCP_HTTP_ADDR` | -- | Streamable HTTP listen address (also serves the Web UI) |
| `-mcp-http-token` | `YP_MCP_HTTP_TOKEN` | auto-generated | HTTP Bearer auth token |

Priority: CLI flag > environment variable > config file > default value.

The `-db` flag accepts an absolute path, a relative path with extension, or a plain project name. A project name (e.g., `my-project`) resolves to `~/.yorishiro-proxy/my-project.db`, making it easy to maintain separate databases per engagement.

## CLI Client

yorishiro-proxy includes a built-in CLI client that connects to a running server via the Streamable HTTP MCP endpoint. This provides a lightweight interface for scripting, automation, and ad-hoc pentest workflows without requiring a full MCP client integration.

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `server` | Start the proxy server (default when no subcommand given) |
| `client` | Call MCP tools via CLI |
| `install` | Install and configure components (MCP, CA, Skills, Playwright) |
| `upgrade` | Check for and install updates from GitHub Releases |
| `version` | Print version information |

### Server

Start the proxy server. The server writes its address and authentication token to `~/.yorishiro-proxy/server.json` for automatic discovery by the CLI client.

```bash
# Start with default settings (random loopback port)
yorishiro-proxy server

# Start on a fixed port
yorishiro-proxy server -mcp-http-addr 127.0.0.1:3000

# Start with browser auto-open
yorishiro-proxy server -open-browser
```

### Client

The `client` subcommand calls MCP tools on a running server. Parameters are passed as `key=value` pairs.

```bash
# Query proxy status
yorishiro-proxy client query resource=status

# Start a proxy listener
yorishiro-proxy client proxy_start listen_addr=127.0.0.1:8080

# List recorded flows
yorishiro-proxy client query resource=flows limit=10

# Get a specific flow detail
yorishiro-proxy client query resource=flow flow_id=<id>

# Replay a request with modifications
yorishiro-proxy client resend action=resend flow_id=<id>

# Configure upstream proxy
yorishiro-proxy client configure upstream_proxy=http://proxy:8888

# Stop all proxy listeners
yorishiro-proxy client proxy_stop
```

**Connection flags:**

| Flag | Env Variable | Default | Description |
|------|-------------|---------|-------------|
| `-server-addr` | `YP_CLIENT_ADDR` | auto-detect from `server.json` | Server address (host:port) |
| `--token` | `YP_CLIENT_TOKEN` | auto-detect from `server.json` | Bearer token for authentication |
| `--format` | `YP_CLIENT_FORMAT` | `json` (TTY) / `raw` (pipe) | Output format: json, table, raw |
| `--raw` | -- | `false` | Compact JSON output without indentation |
| `-q`, `--quiet` | -- | `false` | Suppress output on success |

Connection priority: CLI flag > environment variable > `server.json` auto-detection.

**Output format:** JSON is the default for interactive use (agent-friendly). When stdout is piped, the format automatically switches to `raw` (compact JSON) for easy integration with `jq` and other tools. Use `--format table` for human-readable output.

### Agent Integration

For AI agent workflows, configure the server as an MCP server and use the CLI client for ad-hoc operations:

```bash
# Terminal 1: Start the server
yorishiro-proxy server

# Terminal 2: Use CLI client for quick operations
yorishiro-proxy client query resource=status
yorishiro-proxy client proxy_start listen_addr=127.0.0.1:8080
yorishiro-proxy client query resource=flows | jq '.[] | .url'
```

The CLI client is designed for temporary-use pentest scenarios where an AI agent needs to quickly invoke proxy tools without maintaining a persistent MCP session. For full agent integration, configure yorishiro-proxy as an MCP server in your agent's MCP configuration (see [Quick Start](#quick-start)).

### Migration Note

> **`-no-open-browser` to `-open-browser`:** The default behavior has changed. The browser no longer opens automatically on server start. Use `-open-browser` to opt in to automatic browser opening. The old `-no-open-browser` flag has been removed.

## Architecture

```
Layer 4 TCP Listener
  -> Protocol Detection (peek bytes)
    -> Protocol Handler (HTTP/S, HTTP/2, gRPC, WebSocket, Raw TCP)
      -> Flow Recording (Request/Response)
        -> MCP Tool (Intercept / Replay / Search)
```

- Accepts connections at Layer 4 (TCP) and routes to modular protocol handlers
- No external proxy libraries -- built on Go standard library
- MCP-first: all operations are exposed exclusively as MCP tools
- Embedded Web UI built with React/Vite, served via Streamable HTTP

## Documentation

Full documentation is available at **[usk6666.github.io/yorishiro-proxy-docs](https://usk6666.github.io/yorishiro-proxy-docs/)**.

## Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

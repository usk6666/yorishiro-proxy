# yorishiro-proxy

**Status**: Open Source (Apache License 2.0)

AI agent network proxy -- a MITM proxy tool for AI.
Runs as an MCP (Model Context Protocol) server and provides traffic interception, recording, and replay capabilities for vulnerability assessment.

Designed for use with Claude Code and other MCP-compatible AI agents: the agent controls the proxy entirely through ten MCP tools, enabling automated security testing workflows without manual UI interaction. An embedded Web UI is also available for visual inspection and interactive use.

## Features

- **Traffic Interception & Recording** -- MITM proxy that captures HTTP/HTTPS traffic with automatic CA certificate management
- **Resender** -- Replay recorded requests with modifications (headers, body, URL, JSON patches, raw HTTP editing, dry-run preview)
- **Fuzzer** -- Automated payload injection with sequential/parallel attack modes, overload detection, and async execution
- **Macro** -- Multi-step request sequences with variable extraction, KV store, template substitution, and hook integration
- **Intercept** -- Hold requests/responses for manual inspection, then release, modify, or drop
- **Auto-Transform** -- Automatic request/response modification rules applied to matching traffic
- **Target Scope** -- Two-layer security boundary (Policy + Agent) to restrict which hosts/paths the proxy can reach
- **Multi-Protocol** -- HTTP/1.x, HTTPS (MITM), HTTP/2 (h2c/h2), gRPC (with structured metadata display), WebSocket (with message-level display), Raw TCP
- **Multi-Listener** -- Multiple proxy listeners on different ports simultaneously
- **Flow Export/Import** -- JSONL format for offline analysis and sharing
- **HAR Export** -- Export captured flows in HAR 1.2 format for use with other tools
- **cURL Export** -- Generate cURL commands from any recorded flow for quick reproduction
- **Upstream Proxy** -- Chain through HTTP or SOCKS5 proxies
- **Streamable HTTP MCP** -- Multi-agent shared access with Bearer token authentication
- **Web UI** -- Embedded React/Vite dashboard for visual flow inspection and interactive testing

## Web UI

yorishiro-proxy includes an embedded Web UI built with React and Vite. When Streamable HTTP mode is enabled (via the `-mcp-http-addr` flag), the Web UI is served at the same address and provides a full-featured browser interface for proxy operations.

### Accessing the Web UI

Start the proxy with Streamable HTTP enabled:

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

Then open `http://127.0.0.1:3000` in your browser.

### Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Flow statistics overview with real-time traffic summary |
| **Flows** | Flow list with filtering by protocol, method, status code, and URL pattern |
| **Flow Detail** | Full request/response inspection with syntax highlighting, HTTP/2 stream info, gRPC metadata, and WebSocket message display |
| **Resender** | Replay requests with header/body/URL overrides, JSON patches, raw HTTP editing, and dry-run preview |
| **Fuzzer** | Create and manage fuzz campaigns with payload sets, positions, and result analysis |
| **Intercept** | Real-time request/response interception with inline editing and release/drop controls |
| **Macros** | Define and execute multi-step request workflows with variable extraction |
| **Security** | Configure target scope rules (Policy Layer and Agent Layer) with URL testing |
| **Settings** | Proxy control, capture scope, TLS passthrough, intercept rules, auto-transform rules, TCP forwarding mappings, CA certificate management, and connection settings |

The Web UI communicates with the proxy backend via Streamable HTTP MCP, the same protocol used by AI agents.

## Supported Protocols

| Protocol | Detection | Notes |
|----------|-----------|-------|
| HTTP/1.x | Automatic | Forward proxy mode |
| HTTPS | CONNECT | MITM with dynamic certificate issuance |
| HTTP/2 | h2c / ALPN | Both cleartext and TLS, with per-stream flow display |
| gRPC | HTTP/2 content-type | Service/method extraction, streaming support, structured metadata display |
| WebSocket | HTTP Upgrade | Message-level recording with per-message display |
| Raw TCP | Fallback | Captures any unrecognized protocol, with TCP forwarding mappings |

## Quick Start

### 1. Build

```bash
git clone https://github.com/usk6666/yorishiro-proxy.git
cd yorishiro-proxy
make build    # outputs bin/yorishiro-proxy
```

### 2. Configure MCP

Add the following to your `.mcp.json` (Claude Code) or equivalent MCP client configuration:

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

To enable the Web UI and Streamable HTTP MCP:

```json
{
  "mcpServers": {
    "yorishiro-proxy": {
      "command": "/path/to/bin/yorishiro-proxy",
      "args": ["-mcp-http-addr", "127.0.0.1:3000", "-db", "my-project", "-log-file", "/tmp/yorishiro-proxy.log"]
    }
  }
}
```

The proxy starts as an MCP server on stdin/stdout. No additional setup is required -- the CA certificate is automatically generated and persisted to `~/.yorishiro-proxy/ca/` on first run.

When `-mcp-http-addr` is specified, the Web UI is also accessible at that address (e.g., `http://127.0.0.1:3000`).

### 3. First Capture

Once the MCP server is running, the AI agent can start capturing traffic:

```
1. Start the proxy       -> proxy_start with listen_addr "127.0.0.1:8080"
2. Set HTTP_PROXY         -> point your target application at the proxy
3. Install the CA cert   -> query ca_cert to get the certificate path
4. Browse / send traffic -> captured flows appear in query flows
5. Inspect & replay      -> use resend to replay with modifications
```

## MCP Tools

All proxy operations are exposed through ten MCP tools:

| Tool | Purpose |
|------|---------|
| `proxy_start` | Start a proxy listener with capture scope, TLS passthrough, intercept rules, auto-transform, TCP forwarding, and protocol settings |
| `proxy_stop` | Graceful shutdown of one or all listeners |
| `configure` | Runtime configuration changes (upstream proxy, capture scope, TLS passthrough, intercept rules, auto-transform, connection limits) |
| `query` | Unified information retrieval: flows, flow details, messages, proxy status, config, CA certificate, intercept queue, macros, fuzz jobs/results |
| `resend` | Resend and replay recorded requests with mutations (method/URL/header/body overrides, JSON patches, raw byte patches, dry-run) |
| `fuzz` | Execute fuzz testing campaigns with payload sets, positions, concurrency control, and stop conditions |
| `macro` | Define and execute multi-step macro workflows with variable extraction, guards, and hooks |
| `intercept` | Act on intercepted requests: release, modify and forward, or drop |
| `manage` | Manage flow data (delete/export/import) and CA certificate regeneration |
| `security` | Configure target scope rules (Policy Layer + Agent Layer) to restrict proxy reach |

## CLI Flags

| Flag | Env Variable | Default | Description |
|------|-------------|---------|-------------|
| `-db` | `YP_DB` | `~/.yorishiro-proxy/yorishiro.db` | SQLite database path or project name |
| `-ca-cert` / `-ca-key` | `YP_CA_CERT` / `YP_CA_KEY` | (empty) | CA certificate and private key paths |
| `-ca-ephemeral` | `YP_CA_EPHEMERAL` | `false` | Use ephemeral in-memory CA |
| `-insecure` | `YP_INSECURE` | `false` | Skip upstream TLS verification |
| `-config` | `YP_CONFIG` | (empty) | JSON config file path for proxy defaults |
| `-log-level` | `YP_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `-log-format` | `YP_LOG_FORMAT` | `text` | Log format: text, json |
| `-log-file` | `YP_LOG_FILE` | (stderr) | Log output file |
| `-mcp-http-addr` | `YP_MCP_HTTP_ADDR` | (empty) | Streamable HTTP listen address (also serves the Web UI) |
| `-mcp-http-token` | `YP_MCP_HTTP_TOKEN` | (auto-generated) | HTTP Bearer auth token |

Priority: CLI flag > environment variable > config file > default value.

The `-db` flag accepts either an absolute path, a relative path with extension, or a plain project name. A project name (e.g., `my-project`) resolves to `~/.yorishiro-proxy/my-project.db`, making it easy to maintain separate databases per engagement.

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

- [Getting Started Guide](docs/getting-started.md) -- Detailed setup and usage walkthrough

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

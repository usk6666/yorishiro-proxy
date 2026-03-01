# yorishiro-proxy

**Status**: Proprietary / In Development

AI agent network proxy -- a MITM proxy tool for AI.
Runs as an MCP (Model Context Protocol) server and provides traffic interception, recording, and replay capabilities for vulnerability assessment.

Designed for use with Claude Code and other MCP-compatible AI agents: the agent controls the proxy entirely through five MCP tools, enabling automated security testing workflows without manual UI interaction.

## Features

- **Traffic Interception & Recording** -- MITM proxy that captures HTTP/HTTPS traffic with automatic CA certificate management
- **Resender** -- Replay recorded requests with modifications (headers, body, URL, JSON patches, dry-run preview)
- **Fuzzer** -- Automated payload injection with sequential/parallel attack modes, overload detection, and async execution
- **Macro** -- Multi-step request sequences with variable extraction, KV store, template substitution, and hook integration
- **Intercept** -- Hold requests/responses for manual inspection, then release, modify, or drop
- **Auto-Transform** -- Automatic request/response modification rules applied to matching traffic
- **Multi-Protocol** -- HTTP/1.x, HTTPS (MITM), HTTP/2 (h2c/h2), gRPC, WebSocket, Raw TCP
- **Multi-Listener** -- Multiple proxy listeners on different ports simultaneously
- **Session Export/Import** -- JSONL format for offline analysis and sharing
- **Upstream Proxy** -- Chain through HTTP or SOCKS5 proxies
- **Streamable HTTP MCP** -- Multi-agent shared access with Bearer token authentication

## Supported Protocols

| Protocol | Detection | Notes |
|----------|-----------|-------|
| HTTP/1.x | Automatic | Forward proxy mode |
| HTTPS | CONNECT | MITM with dynamic certificate issuance |
| HTTP/2 | h2c / ALPN | Both cleartext and TLS |
| gRPC | HTTP/2 content-type | Service/method extraction, streaming support |
| WebSocket | HTTP Upgrade | Message-level recording |
| Raw TCP | Fallback | Captures any unrecognized protocol |

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

Common flag combinations:

```json
{
  "mcpServers": {
    "yorishiro-proxy": {
      "command": "/path/to/bin/yorishiro-proxy",
      "args": ["-db", "my-project", "-log-file", "/tmp/yorishiro-proxy.log"]
    }
  }
}
```

The proxy starts as an MCP server on stdin/stdout. No additional setup is required -- the CA certificate is automatically generated and persisted to `~/.yorishiro-proxy/ca/` on first run.

### 3. First Capture

Once the MCP server is running, the AI agent can start capturing traffic:

```
1. Start the proxy       -> proxy_start with listen_addr "127.0.0.1:8080"
2. Set HTTP_PROXY         -> point your target application at the proxy
3. Install the CA cert   -> query ca_cert to get the certificate path
4. Browse / send traffic -> captured sessions appear in query sessions
5. Inspect & replay      -> use execute resend to replay with modifications
```

## MCP Tools

All proxy operations are exposed through five MCP tools:

| Tool | Purpose |
|------|---------|
| `proxy_start` | Start a proxy listener with capture scope, TLS passthrough, intercept rules, auto-transform, and protocol settings |
| `proxy_stop` | Graceful shutdown of one or all listeners |
| `configure` | Runtime configuration changes (incremental merge or full replace) |
| `query` | Unified information retrieval: sessions, session details, messages, proxy status, config, CA certificate, intercept queue, macros, fuzz jobs/results |
| `execute` | Unified action execution: resend, resend_raw, tcp_replay, fuzz, macro operations, intercept actions, session management, CA regeneration, export/import |

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
| `-mcp-http-addr` | `YP_MCP_HTTP_ADDR` | (empty) | Streamable HTTP listen address |
| `-mcp-http-token` | `YP_MCP_HTTP_TOKEN` | (auto-generated) | HTTP Bearer auth token |

Priority: CLI flag > environment variable > config file > default value.

The `-db` flag accepts either an absolute path, a relative path with extension, or a plain project name. A project name (e.g., `my-project`) resolves to `~/.yorishiro-proxy/my-project.db`, making it easy to maintain separate databases per engagement.

## Architecture

```
Layer 4 TCP Listener
  -> Protocol Detection (peek bytes)
    -> Protocol Handler (HTTP/S, HTTP/2, gRPC, WebSocket, Raw TCP)
      -> Session Recording (Request/Response)
        -> MCP Tool (Intercept / Replay / Search)
```

- Accepts connections at Layer 4 (TCP) and routes to modular protocol handlers
- No external proxy libraries -- built on Go standard library
- MCP-first: all operations are exposed exclusively as MCP tools

## Documentation

- [Getting Started Guide](docs/getting-started.md) -- Detailed setup and usage walkthrough

## License

Proprietary. This software is not open source and is not licensed for redistribution.

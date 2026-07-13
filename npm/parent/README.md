# @usk6666/yorishiro-proxy

AI-first MITM proxy tool operated as an [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server. Intercept, record, and replay traffic for AI agents.

## Install

```bash
npm i -g @usk6666/yorishiro-proxy
# or run without installing:
npx @usk6666/yorishiro-proxy install
```

The correct prebuilt binary for your platform is delivered automatically as an
optional dependency — there is no postinstall script and no network fetch at
install time.

## Usage

```bash
# Start the MCP server (default when no subcommand is given)
yorishiro-proxy

# Configure MCP integration for the current project
yorishiro-proxy install mcp

# Call MCP tools from the CLI
yorishiro-proxy client query resource=status

# Print version
yorishiro-proxy version
```

All arguments are forwarded to the underlying binary unchanged.

## Supported platforms

| os      | cpu   | package                                 |
| ------- | ----- | --------------------------------------- |
| linux   | x64   | `@usk6666/yorishiro-proxy-linux-x64`    |
| linux   | arm64 | `@usk6666/yorishiro-proxy-linux-arm64`  |
| darwin  | x64   | `@usk6666/yorishiro-proxy-darwin-x64`   |
| darwin  | arm64 | `@usk6666/yorishiro-proxy-darwin-arm64` |
| win32   | x64   | `@usk6666/yorishiro-proxy-win32-x64`    |

Prebuilt binaries are also available from
[GitHub Releases](https://github.com/usk6666/yorishiro-proxy/releases), and the
`yorishiro-proxy upgrade` self-update path continues to work independently of npm.

## License

Apache-2.0. See the [repository](https://github.com/usk6666/yorishiro-proxy) for details.

# getting-started

Your first yorishiro-proxy session, end to end: connect the MCP server, start a listener, trust the CA, capture traffic, inspect it, then replay and fuzz it.

Read this once. After that, `docs(topic="<tool name>")` gives you the full reference for any tool named below.

## What this is

yorishiro-proxy is a MITM proxy driven entirely through MCP tools. It terminates TLS with its own CA, records every message as a structured L7 view **and** the raw wire bytes, and lets you replay or fuzz anything it recorded.

Supported protocols: HTTP/1.x, HTTP/2, WebSocket, gRPC, gRPC-Web, SSE, and raw TCP. SOCKS5 and HTTP `CONNECT` are both accepted as client-side transports.

## 1. Install and register

```bash
npm i -g @usk6666/yorishiro-proxy     # or download from GitHub Releases
yorishiro-proxy install mcp           # writes .mcp.json for the current project
yorishiro-proxy install mcp --user-scope   # or register at the user level
```

`install mcp` writes a stdio MCP entry with log output redirected to a file — the recommended shape for MCP hosts. The CA certificate is generated on first run and persisted to `~/.yorishiro-proxy/ca/`.

To run the server by hand instead (HTTP MCP transport plus the Web UI):

```bash
yorishiro-proxy server -mcp-http-addr 127.0.0.1:3000 -open-browser
```

The connection info, including the auth token, is written to `~/.yorishiro-proxy/server.json`.

## 2. Start a listener

```json
// proxy_start
{"listen_addr": "127.0.0.1:8080"}
```

Two things to know before you call it a second time:

- **Every `proxy_start` call fully resets the session.** Fields you omit revert to defaults — `capture_scope`, `tls_passthrough`, `intercept_rules`, `auto_transform`, `tcp_forwards`, SOCKS5 auth, TLS fingerprint, timeouts. It is not an "apply these extra settings" call.
- For in-session changes (add one intercept rule, change one timeout) use `configure` with `operation: "merge"` or `"replace"` instead.

Full reference: call `docs(topic="proxy_start")` and `docs(topic="configure")`.

## 3. Trust the CA

Set `HTTP_PROXY=http://127.0.0.1:8080` and `HTTPS_PROXY=http://127.0.0.1:8080` in the application under test, or configure its proxy settings directly.

Then fetch the CA certificate and install it into that client's trust store:

```json
// query
{"resource": "ca_cert"}
```

The response carries `persisted`, `cert_path` and `install_hint`. When `persisted` is true, install the file at `cert_path`. The CA is reused across restarts, so this is a one-time step per client.

Without the CA installed, HTTPS targets will fail certificate validation — that is the expected symptom, not a bug.

## 4. Find traffic

Drive the application normally. Then list what was captured:

```json
// query
{"resource": "flows", "limit": 20}
```

Narrow it down with filters:

```json
// query
{"resource": "flows", "filter": {"host": "api.example.com", "method": "POST"}}
```

`filter.protocol` takes a canonical family — `http`, `ws`, `grpc`, `grpc-web`, `sse`, `raw`, `tls-handshake` — and expands across every wire spelling of that family. Use `filter.scheme: "https"` to select TLS flows regardless of HTTP version.

Inspect one flow in full:

```json
// query
{"resource": "flow", "id": "<flow-id>"}
```

If a response body is large, pass `include_bodies: false` for metadata only, or `body_max_bytes: 4096` for a per-side cap, so the result stays under the MCP token limit.

Full reference: call `docs(topic="query")`.

## 5. Replay

Each protocol has its own typed resend tool. For HTTP:

```json
// resend_http
{
  "flow_id": "<flow-id>",
  "headers": [
    {"name": "Host", "value": "api.example.com"},
    {"name": "Authorization", "value": "Bearer <other-user-token>"}
  ]
}
```

Any field you omit is inherited from the recorded send. `headers` is an **ordered array of `{name, value}`**, not a map — wire casing, order and duplicates are all significant — and supplying it replaces the inherited header list wholesale.

The siblings are `resend_ws`, `resend_grpc` and `resend_raw`. `resend_raw` sends recorded bytes verbatim, which is what you want for request-smuggling work where header formatting must survive untouched.

Full reference: call `docs(topic="resend_http")`, `docs(topic="resend_ws")`, `docs(topic="resend_grpc")`, `docs(topic="resend_raw")`.

## 6. Fuzz

```json
// fuzz_http
{
  "flow_id": "<flow-id>",
  "positions": [
    {
      "path": "headers[1].value",
      "payloads": ["alice", "bob", "admin", "../../../etc/passwd"]
    }
  ],
  "stop_on_5xx": true
}
```

`path` is a typed path into the recorded `HTTPMessage`: one of `method`, `scheme`, `authority`, `path`, `raw_query`, `body`, `headers[N].name`, `headers[N].value`. Index into the recorded header list you saw in `query resource=flow`.

Variants are the cartesian product of every position, capped at 1000 per call. Results come back via `query resource=fuzz_results`. The siblings are `fuzz_ws`, `fuzz_grpc` and `fuzz_raw`.

Full reference: call `docs(topic="fuzz_http")`.

## 7. Where to go next

| You want to | Call |
|---|---|
| Chain requests, carrying a token from one into the next | `docs(topic="macro")` |
| Write `§var§` variables anywhere | `docs(topic="template-syntax")` |
| Pause a request mid-flight and edit it | `docs(topic="intercept")` |
| Restrict which hosts may be proxied, or mask secrets in tool output | `docs(topic="security")` |
| Export, import or delete recorded flows; rotate the CA | `docs(topic="manage")` |
| Decode gRPC bodies with real field names | `docs(topic="grpc_schema")` |
| See loaded Starlark plugins and their hooks | `docs(topic="plugin_introspect")` |
| Read worked end-to-end assessment workflows | `docs(topic="examples")` |
| List every documentation topic | `docs()` |

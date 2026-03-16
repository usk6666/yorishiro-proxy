# Protocol e2e Test Coverage Matrix

Existing protocols and their e2e test coverage status against the checklist in CLAUDE.md.
Last updated: 2026-03-16 (USK-361)

## Legend

- YES: Covered by existing e2e tests
- PARTIAL: Some aspects covered, gaps remain
- NO: Not covered
- N/A: Not applicable for this protocol

## Matrix

| Checklist Item                          | HTTP/1.x       | HTTPS          | HTTP/2         | gRPC           | WebSocket      | Raw TCP        | SOCKS5         |
|-----------------------------------------|----------------|----------------|----------------|----------------|----------------|----------------|----------------|
| Proxy communication success             | YES            | YES            | YES            | YES            | YES            | YES            | YES            |
| Flow record completeness (Protocol/FlowType/State) | PARTIAL (no State) | PARTIAL (no State/FlowType) | YES | YES | PARTIAL (no FlowType/State) | PARTIAL (no State) | N/A (transport) |
| Raw bytes recording                     | NO             | NO             | YES            | NO             | NO             | NO             | N/A            |
| Variant recording (intercept)           | NO             | NO             | NO             | NO             | NO             | NO             | N/A            |
| Progressive recording (streaming)       | N/A            | N/A            | NO             | PARTIAL (State wait) | NO       | NO             | N/A            |
| Plugin hook firing                      | NO             | NO             | YES            | YES            | NO             | NO             | N/A            |
| Safety Filter / Output Filter           | YES            | YES            | NO             | NO             | NO             | NO             | N/A            |
| Error path                              | PARTIAL (timeout) | PARTIAL (timeout) | NO         | NO             | NO             | NO             | YES (auth)     |
| Derived protocol independent tests      | N/A            | N/A            | N/A            | YES (from H2)  | N/A            | N/A            | N/A            |
| MCP tool integration                    | YES            | YES            | YES            | NO             | YES            | NO             | YES            |
| WebUI display tests                     | NO             | NO             | NO             | NO             | NO             | NO             | NO             |

## Key files

- `internal/proxy/https_integration_test.go` — HTTPS proxy e2e
- `internal/proxy/h2c_integration_test.go` — H2C (cleartext HTTP/2) e2e
- `internal/proxy/h2_frame_engine_integration_test.go` — HTTP/2 frame engine with raw bytes, gRPC unary
- `internal/protocol/http2/grpc_streaming_integration_test.go` — gRPC streaming patterns
- `internal/proxy/websocket_integration_test.go` — WebSocket echo relay
- `internal/proxy/tcp_integration_test.go` — Raw TCP relay
- `internal/proxy/socks5_integration_test.go` — SOCKS5 auth and tunneling
- `internal/proxy/production_wiring_integration_test.go` — Safety Filter, production setup
- `internal/mcp/multiproto_integration_test.go` — MCP query for HTTP/2, WebSocket
- `internal/mcp/intercept_integration_test.go` — MCP intercept (HTTP)
- `internal/mcp/raw_intercept_integration_test.go` — MCP raw bytes intercept

## Notable gaps

1. **Raw bytes recording** — Only HTTP/2 has raw bytes e2e tests. HTTP/1.x, HTTPS, WebSocket, TCP lack raw bytes verification.
2. **Variant recording** — No protocol has intercept variant (original/modified) e2e tests at the proxy layer.
3. **Progressive recording** — gRPC streaming tests wait for State transition but no explicit progressive state assertions for other streaming protocols.
4. **Plugin hooks** — Only HTTP/2 and gRPC test plugin hook firing. HTTP/1.x, HTTPS, WebSocket, TCP do not.
5. **Safety Filter** — Only tested via production wiring for HTTP. Not tested for WebSocket, HTTP/2, gRPC, TCP.
6. **WebUI display** — No protocol has WebUI component tests (would require Playwright or similar).
7. **gRPC MCP integration** — gRPC flows are not queried via MCP tools in existing e2e tests.
8. **TCP MCP integration** — TCP flows are not queried via MCP tools.

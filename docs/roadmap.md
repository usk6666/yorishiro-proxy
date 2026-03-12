# Roadmap

This document tracks the milestone-based development plan for yorishiro-proxy.

## Milestone Summary

| Milestone | Theme | Status |
|-----------|-------|--------|
| M1--M10 | Core proxy, MCP tools, protocol support | Completed |
| M11--M15 | Fuzzer, Macro, Intercept, Auto-Transform, Target Scope | Completed |
| M16--M18 | Multi-listener, SOCKS5, Upstream proxy, Streamable HTTP | Completed |
| M19 | Cross-Protocol Analysis & AI Safety | Completed |
| M20 | Web UI & Developer Experience | Completed |
| M21 | Real-World Readiness | Completed |

## M21 -- Real-World Readiness

Focused on features required for real-world vulnerability assessment engagements: mutual TLS support for testing client-certificate-protected services, detailed timing data for performance analysis, and industry-standard export formats for interoperability with other tools.

### Issues

| Issue | Title | PR | Status |
|-------|-------|----|--------|
| USK-293 | mTLS client certificate support | [#307](https://github.com/usk6666/yorishiro-proxy/pull/307) | Completed |
| USK-299 | Flow per-phase timing recording | [#308](https://github.com/usk6666/yorishiro-proxy/pull/308) | Completed |
| USK-295 | HAR 1.2 export support | [#309](https://github.com/usk6666/yorishiro-proxy/pull/309) | Completed |
| USK-296 | M21 integration tests | [#312](https://github.com/usk6666/yorishiro-proxy/pull/312) | Completed |
| USK-297 | Roadmap and documentation updates | -- | In Progress |

### Dependency Graph

```
USK-293 (mTLS) ──┐
                  ├──→ USK-296 (Integration Tests) ──→ USK-297 (Docs)
USK-299 (Timing) ─┤
                  │
USK-295 (HAR) ───┘
```

### Parallel Implementation Strategy

USK-293, USK-299, and USK-295 were implemented in parallel as independent features with no code-level dependencies. USK-296 (integration tests) was implemented after all three features were merged to validate cross-feature interactions. USK-297 (docs) follows as the final issue.

### Key Changes

- **mTLS Client Certificates** (`internal/protocol/httputil/hosttls.go`): Per-host client certificate configuration via `proxy_start` and `configure` tools. Supports PEM-encoded certificate and key pairs.
- **Per-Phase Flow Timing** (`internal/protocol/httputil/timing.go`, `internal/flow/types.go`): Records DNS lookup, TCP connect, TLS handshake, request send, and response receive durations for each flow. Timing data is stored in the flow record and exposed via `query` tool.
- **HAR 1.2 Export** (`internal/flow/har.go`): Export flows in HAR 1.2 format via `manage export format=har`. Includes full request/response data, timing information, and TLS metadata. Compatible with browser DevTools and other HTTP analysis tools.
- **Integration Tests** (`internal/proxy/*_integration_test.go`): End-to-end tests covering mTLS authentication, timing recording accuracy, and HAR export correctness.

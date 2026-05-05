# yorishiro-proxy

A network proxy tool for AI agents — a MITM proxy for AI.
Operates as an MCP (Model Context Protocol) server, providing traffic interception, recording, and replay capabilities for vulnerability assessment.

**Status**: OSS (Apache License 2.0) · Under active development

## Architecture

Design: [RFC-001 Envelope + Layered Connection Model](docs/rfc/envelope.md). Implementation strategy: [`docs/rfc/envelope-implementation.md`](docs/rfc/envelope-implementation.md).

### Principle: L7-first, L4-capable

1. **The default operation interface is a structured L7 view** — Prioritize AI agent token efficiency by representing communication as structured data: method, URL, headers, body, etc.
2. **Raw bytes recording, viewing, and modification must be possible for all protocols** — As a diagnostic tool, protocol-level anomaly detection and reproduction must be supported (pure transport-layer protocols like SOCKS5 apply to the tunneled protocol)
3. **L7 parsing is an overlay on top of raw bytes; the wire-observed raw bytes snapshot itself must not be destroyed or modified** — Recorded raw bytes always reflect the original wire data; modifications must always be treated as separate derived data (e.g., modified variant)

### Pipeline

```
TCP Listener (Layer 4)
  → Protocol Detection (peek bytes / ALPN)
    → Connection Stack (TCP → TLS → HTTP/1 | HTTP/2 → WS | gRPC | gRPC-Web | SSE | Raw)
      → Pipeline Steps
          (HostScope → HTTPScope → Safety → PluginPre → Intercept → Transform → Macro → PluginPost → Record)
        → Flow Recording (L7 Message + L4 Envelope.Raw)
          → MCP Tool (Intercept / Replay / Search / Plugin Introspect)
```

Each connection is an explicit stack of `Layer`s (RFC-001 §3.3); each Layer yields one or more `Channel`s; the Pipeline runs on `Envelope`s drawn from those Channels. The data model is:

- **`Envelope`** — protocol-agnostic outer container with identity (StreamID/FlowID/Sequence/Direction), provenance (Protocol), wire fidelity (Raw bytes), and a typed `Message`.
- **`Message`** — protocol-specific payload (`HTTPMessage`, `WSMessage`, `GRPCStartMessage`/`GRPCDataMessage`/`GRPCEndMessage`, `SSEMessage`, `RawMessage`, `TLSHandshakeMessage`).

### L7/L4 Support Status by Protocol

| Protocol | L7 Structured View | L4 raw bytes | Notes |
|----------|-------------------|--------------|-------|
| HTTP/1.x | YES | YES | Custom parser; `net/http` not used in data path |
| HTTP/2 | YES | YES | Custom frame engine; event-granular Channel + per-stream BodyBuffer |
| gRPC | YES | YES (via HTTP/2) | Native LPM reassembly; GRPCStart/Data/End envelope events |
| gRPC-Web | YES | YES (via HTTP/1.x or HTTP/2) | Binary + base64 wire formats |
| WebSocket | YES | YES (per frame) | Per-message-deflate (RFC 7692) supported |
| SSE | YES | YES | Per-event envelopes; streaming-aware Pipeline |
| Raw TCP | N/A | YES (byte stream) | Smuggling-safe pass-through (`bytechunk` Layer) |
| SOCKS5 | N/A | N/A (excluded as transport layer itself) | Apply raw bytes/L7 to the protocol delegated after handshake/tunnel |
| TLS handshake | YES (observation) | N/A | `TLSHandshakeMessage` envelope; SNI / ALPN / JA3 / JA4 visible to plugins |

### Design Principles

- Accept connections at Layer 4 (TCP) and route to a per-connection `ConnectionStack` of `Layer`s
- No external proxy libraries — built on the standard library
- MCP-first: all operations are exposed as MCP tools

### MITM Implementation Principles

As a MITM proxy, yorishiro-proxy must faithfully represent wire-level reality. The following principles apply to all data path code (`internal/envelope/`, `internal/layer/`, `internal/connector/`, `internal/pipeline/`, `internal/pluginv2/`, `internal/flow/`).

1. **Do not normalize what the wire did not normalize** — Header name casing, header order, duplicate headers with different casing, and whitespace must be preserved exactly as observed on the wire. If the wire sends `Set-Cookie: a=1` and `set-cookie: b=2`, they are two distinct headers with different names. Do not merge, canonicalize, or reorder.
2. **Each protocol has its own canonical form; do not unify across protocols** — HTTP/1.x headers are case-insensitive but preserve wire casing. HTTP/2 headers are lowercase by spec (RFC 9113). These are different realities and must be handled by protocol-specific code paths, not forced into a shared normalized representation.
3. **Prefer lossless representations over convenient ones** — Use ordered arrays (`[]KeyValue`) over maps (`map[string][]string`) for headers. Use protocol-native types (`parser.RawHeaders` for HTTP/1.x, `hpack.HeaderField` for HTTP/2) over bridge types. Convenience helpers may be provided on top but must not be the storage format.
4. **`net/http` usage policy** — Data path code must not use `net/http` types for transport or data representation. Use internal types (`internal/layer/http1/parser` `RawRequest`/`RawResponse`, hpack types). `net/http` is permitted only in the control plane: MCP server (`internal/mcp/`), CLI (`cmd/`), and self-update (`internal/selfupdate/`).

## Package Layout

```
cmd/yorishiro-proxy/       # Entry point
  main.go                  # CLI root: server/client/version/install/upgrade subcommands
  client.go                # CLI client subcommand (MCP client via Streamable HTTP)
  client_params.go         # Flag → JSON parameter conversion engine
  client_format.go         # Result formatting (JSON / table output)
  serverjson.go            # server.json multi-instance entry management (used for client auto-discovery)
  install.go, upgrade.go,  # Subcommand handlers
  version.go, browser.go
internal/
  envelope/                # Protocol-agnostic Envelope + typed Message
                           #   envelope.go (Envelope, EnvelopeContext, TLSSnapshot, Direction, Protocol, KeyValue)
                           #   message.go (Message interface) + per-protocol files
                           #   http.go (HTTPMessage), ws.go (WSMessage),
                           #   grpc.go (GRPCStartMessage/GRPCDataMessage/GRPCEndMessage),
                           #   grpcweb.go, sse.go, raw.go
                           #   bodybuf/ (memory-then-spill BodyBuffer for HTTP/2 streams)
  layer/                   # Layer + Channel interfaces; per-protocol implementations
                           #   layer.go (Layer interface), channel.go (Channel interface),
                           #   errors.go (StreamError)
                           #   bytechunk/ (raw TCP), tlslayer/ (TLS handshake),
                           #   http1/ (with parser/), http2/ (event-granular),
                           #   httpaggregator/ (folds H2 events into HTTPMessage),
                           #   grpc/, grpcweb/, ws/, sse/
  pipeline/                # Pipeline Step chain (HostScope → HTTPScope → Safety → PluginPre →
                           #   Intercept → Transform → Macro → PluginPost → Record).
                           #   Steps dispatch via type-switch on env.Message.
                           #   WireEncoderRegistry (per-protocol on-Send re-encode).
  connector/               # TCP listener, ConnectionStack builder, per-connection plumbing
                           #   full_listener.go (the sole listener API),
                           #   coordinator.go (multi-listener orchestrator),
                           #   connection_stack.go, detect.go, alpn_routing.go,
                           #   connect_handler.go (CONNECT tunnel), socks5_handler.go,
                           #   h2_dispatch.go, h2_pool.go, h2c_handler.go,
                           #   transport/ (TLS / uTLS / mTLS dial; per-host TLS config)
  proxybuild/              # Live data-path stack assembly + multi-listener Manager
                           #   builder.go (BuildLiveStack), manager.go,
                           #   listener.go (lifecycle wrapper)
  pluginv2/                # RFC-001 §9.3 Starlark plugin engine
                           #   register_hook builtin, (protocol, event, phase) 3-axis identity,
                           #   17-entry hook surface, mutable Starlark dict messages,
                           #   ctx.transaction_state / ctx.stream_state, plugin_introspect
  rules/                   # Per-protocol rule engines (Intercept, Transform, Safety)
                           #   common/ (HoldQueue, pattern compiler, presets)
                           #   http/, ws/, grpc/, sse/, raw/
  safety/                  # SafetyFilter Engine (envelope-native; Input Filter + Output Filter)
                           #   engine.go, rule.go, preset.go (destructive-sql,
                           #   destructive-os-command), preset_pii.go (credit-card,
                           #   japan-my-number, email, japan-phone)
  job/                     # Job runner with EnvelopeSource interface
                           #   http_source.go, ws_source.go, grpc_source.go, raw_source.go,
                           #   fuzz_http_source.go, fuzz_raw_source.go,
                           #   macro_adapter.go (Macro adapter)
  macro/                   # Macro engine: template / guard / extract / encoder
  flow/                    # Stream/Flow Store (sqlite); HAR / JSONL / cURL export, import
  pushrecorder/            # Drains upstream HTTP/2 pushed streams via OnHTTP2UpstreamDialed
  cert/                    # Root CA + dynamic server cert issuance
  config/                  # Configuration loading + validation (incl. Plugins, body-spill, limits)
  fingerprint/             # TLS fingerprint detection (JA3 / JA4)
  encoding/                # Protobuf framing helper
  fuzzer/                  # Iterator / Position / RequestData primitives for typed-fuzz path
  mcp/                     # MCP server, tools, handlers
                           #   typed resend: resend_http / resend_ws / resend_grpc / resend_raw
                           #   typed fuzz:   fuzz_http   / fuzz_ws   / fuzz_grpc   / fuzz_raw
                           #   plugin_introspect, query (with Protocol filter), intercept,
                           #   macro, manage, configure, security, proxy_start / proxy_stop
  session/                 # RunSession (universal session loop, OnComplete hook)
  logging/                 # Structured logging (log/slog)
  payload/, setup/, testutil/, selfupdate/
```

## Build & Test

```bash
make build          # build-ui → vet → go build (always rebuilds UI)
make build-ui       # Build the React/Vite app in web/ and generate dist/
make ensure-ui      # Run build-ui only if dist/ does not exist (lightweight)
make test           # ensure-ui → go test -race -v ./... (unit tests only)
make test-e2e       # ensure-ui → go test -race -v -tags e2e ./... (all tests including e2e)
make test-cover     # ensure-ui → test with coverage report
make vet            # ensure-ui → go vet ./...
make fmt            # Format all files with gofmt -w .
make lint           # gofmt check + go vet + staticcheck + ineffassign
make bench          # ensure-ui → run benchmarks
make clean          # Delete build artifacts
```

> **e2e tests**: `*_integration_test.go` files have the `//go:build e2e` tag.
> They are skipped by `make test` and run by `make test-e2e`.
> Always include this tag when adding new integration tests.

> **Important**: Do not run `go test` / `go vet` / `go build` directly.
> `internal/mcp/webui/embed.go` embeds the Web UI with `//go:embed dist/*`,
> so a missing `dist/` will cause a compilation error. Always run via `make` targets.

### e2e Test Subsystem Verification Checklist

When adding new e2e tests (`*_integration_test.go`), verify not just communication success
but also subsystem integration. Confirm that the following checklist is satisfied.

- [ ] **Communication success**: Data is correctly transmitted/transformed (send request → receive response → validate content)
- [ ] **Stream recording**: Stream saved to Store with correct protocol name (`Protocol`), State, and Scheme
- [ ] **Flow recording**: Individual Flows (Send/Receive) correctly recorded with direction, sequence, headers, and body
- [ ] **State transitions**: Progressive recording works correctly (`State` transitions from `active` → `complete`)
- [ ] **Plugin hook firing**: The relevant `(protocol, event, phase)` hook is dispatched via `pluginv2.Engine` for the protocol
- [ ] **Error paths**: Flow is recorded with `State="error"` on connection failure or timeout
- [ ] **Raw bytes recording**: Wire-observed raw bytes (`Envelope.Raw`) are correctly recorded — L4-capable principle
- [ ] **Variant recording**: On intercept/transform modification, both original and modified variants are recorded
- [ ] **MCP tool integration**: Flows are correctly retrievable via the `query` tool (with `resource: "flows"` / `resource: "flow"` parameters; Protocol family filter accepts `http`/`ws`/`grpc`/`grpc-web`/`sse`/`raw`/`tls-handshake`)

> **Applicability**: Not all items are required for every test. Verify relevant items based on protocol characteristics and test purpose.
> Example: Raw TCP has no L7 structured view, so header validation under "message content" is not required.
> SOCKS5 is excluded from flow recording as a transport layer; validate at the tunneled protocol instead.
>
> **Reference patterns**: see `internal/connector/full_listener_integration_test.go` (the canonical end-to-end harness) and per-Layer harnesses such as `internal/layer/http1/mitm_integration_test.go`, `internal/layer/http2/http2_integration_test.go`, `internal/layer/grpc/grpc_integration_test.go`, `internal/layer/ws/ws_integration_test.go`, `internal/layer/sse/sse_integration_test.go`, `internal/layer/grpcweb/grpcweb_integration_test.go`, `internal/layer/bytechunk/smuggling_integration_test.go`.

## Coding Conventions

- Go standard style (`gofmt` / `goimports`)
- Wrap errors with `fmt.Errorf("context: %w", err)`
- Propagate `context.Context` as the first argument
- Package comments go in doc.go or the leading file
- Tests in `_test.go` files; table-driven tests recommended
- The pattern of using `t.Logf` to record unverified behavior is prohibited. Use `t.Skip("not yet implemented: <issue-id>")` for unimplemented features
- Do not expose `internal/` packages externally

### Log Level Guidelines

Level selection for `log/slog` follows these criteria:

| Level | Purpose | Examples |
|-------|---------|---------|
| `slog.Debug` | Detailed information for developers/diagnostics. Output only at `-log-level debug` | Protocol detection results, TLS SNI, rule match decisions, frame send/receive, handshake progress |
| `slog.Info` | Major events of normal operation. Output by default | Server start/stop, proxy start/stop, config load complete, plugin load |
| `slog.Warn` | Abnormal but recoverable state. Events that need operator attention | TLS certificate validation failure (insecure mode), deprecated feature usage, retry occurrence, signs of resource exhaustion |
| `slog.Error` | Processing failure. Unrecoverable or request-level fatal errors | DB write failure, listener start failure, CA certificate load failure |

#### Decision Criteria

- **Debug vs Info**: If an operator can confirm normal operation without the log, use Debug. Use Info for events that show "what happened" — start, stop, config change
- **Info vs Warn**: Use Info if it is part of the normal flow. Use Warn if unexpected but processing continues. Warn means "operator should check", and if it occurs frequently, demote to Info or Debug
- **Warn vs Error**: Use Warn if processing can continue. Use Error if returning an error to the caller or if a request fails

#### Decision Examples for Ambiguous Cases

| Case | Level | Reason |
|------|-------|--------|
| Client sends invalid request (4xx) | `Debug` | Client-side issue; not a proxy anomaly |
| Upstream server returns 5xx | `Debug` | Proxy relayed correctly; upstream issue. Traceable via flow recording |
| Request matches intercept rule | `Debug` | Normal operation detail. Useful for diagnostics but not needed by default |
| Safety Filter blocks a request | `Info` | Security event that should notify the operator |
| Starlark script in plugin throws runtime error | `Warn` | Plugin issue, but the proxy itself can continue |
| WebSocket connection closes normally | `Debug` | Normal operation detail |
| WebSocket connection disconnects abnormally | `Warn` | Unexpected but processing can continue |
| Flow DB save fails | `Error` | Data loss occurred. Unrecoverable |
| Config file not found; using default values | `Info` | Part of normal flow (designed to work with default values) |
| Connection timeout to CONNECT tunnel target | `Debug` | Network-dependent. Returns error response to client, but not a proxy anomaly |

## Dependency License Policy

### Allowed

MIT, BSD (2-clause, 3-clause), Apache-2.0, ISC, MPL-2.0

### Prohibited

All GPL variants (GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, AGPL-3.0)

### Approved Dependencies

- `github.com/modelcontextprotocol/go-sdk` — Official MCP Go SDK
- `modernc.org/sqlite` — Pure Go SQLite driver (BSD-3-Clause)
- `github.com/google/uuid` — UUID generation (Apache-2.0)
- `golang.org/x/sync` — Concurrency control utilities such as singleflight (BSD-3-Clause)
- `go.starlark.net` — Starlark script engine (BSD-3-Clause)

When adding new external dependencies, verify the license with the `/license-check` skill.

## Development Workflow

1. `/project status` — Check milestone progress and decide what to work on next
2. `/project plan <milestone>` — Create and organize Linear Issues from the roadmap
3. `/orchestrate` — Delegate multiple Issues to sub-agents for parallel implementation per milestone
4. `/implement <Issue ID>` — Implement, test, commit, and create PR for a single Issue
5. `/review-gate` — Run Code Review + Security Review in parallel for a PR. If issues found, auto-fix → re-review (up to 2 rounds)
6. `/project sync` — Update roadmap documents after implementation is complete

> **Note**: `/implement` assumes single-session, solo execution. Use `/orchestrate` for parallel implementation of multiple Issues.

### Config Checklist for New Feature Milestones

When splitting Issues for a new feature milestone with `/project plan`, treat the following as mandatory checks.
This prevents config support from being omitted as an implicit assumption.

- [ ] Does the config struct in `internal/config/` need a new field?
- [ ] Does config validation (`Validate()`) need to be added or updated?
- [ ] Does an init function (`cmd/yorishiro-proxy/main.go`) need to change?
- [ ] Is a config → runtime path integration test needed?
- [ ] If any of the above apply, explicitly create a config support Issue

### e2e Test Checklist for New Protocol Addition

When splitting Issues for a new protocol with `/project plan`, treat the following as mandatory checks.
This prevents gaps in e2e test coverage. Refer to the "e2e Test Subsystem Verification Checklist" for individual test verification details.

- [ ] e2e test for successful proxy communication (`internal/connector/*_integration_test.go` and/or `internal/layer/*/*_integration_test.go`)
- [ ] Stream/Flow recording completeness verification (protocol name, State transitions, Flow count per Stream)
- [ ] Raw bytes recording completeness verification (frame boundaries, binary data round-trip) — L4-capable principle
- [ ] Variant recording test (original/modified save on intercept modification)
- [ ] Progressive recording test (intermediate state verification for streaming protocols)
- [ ] Plugin hook firing verification (relevant `(protocol, event, phase)` hooks dispatched via `pluginv2.Engine`)
- [ ] Safety Filter / Output Filter application verification
- [ ] Error path e2e tests (connection failure, timeout, malformed data)
- [ ] Independent tests for derived protocols (e.g., HTTP/2 → gRPC) if they exist
- [ ] MCP tool integration tests (flow details returned correctly via query tool)
- [ ] WebUI display tests (including null guards for new protocol components)
- [ ] If any of the above apply, explicitly create a test Issue

> **Relationship to Subsystem Verification Checklist**: This checklist is a planning-level list for splitting Issues when adding new protocols.
> The Subsystem Verification Checklist is an implementation-level list for writing individual e2e test files. Refer to both.

## Agent Isolation Strategy (Worktree)

To prevent git conflicts during parallel work by sub-agents, apply the following rules.

### Principles

- **Lock the main worktree (the repository clone origin) to the main branch and prohibit direct work** — All branch switching and commits happen inside worktrees. The main branch cannot be pushed to directly due to branch protection
- **All sub-agents are launched with `isolation: "worktree"`** — During parallel execution, checking out the main worktree's HEAD conflicts with the code state read by other agents, so even read-only review agents are isolated in worktrees

### Classification in Task Tool

| Agent Type | Operation | isolation |
|-----------|-----------|-----------|
| implementer | Code implementation, commit, push | `"worktree"` |
| fixer | Fix review findings, commit, push | `"worktree"` |
| code-reviewer | Checkout target branch, read diff, post review | `"worktree"` |
| security-reviewer | Checkout target branch, read diff, post review | `"worktree"` |

### When Adding New Agents

1. All sub-agents must use `isolation: "worktree"` by default
2. Document the isolation setting in the calling skill (`.claude/skills/*/SKILL.md`)

### Worktree Cleanup

The Claude Code Task tool does not auto-delete worktrees when they have changes after completion.
**The calling skill is responsible for cleanup.**

#### Cleanup Timing

| Skill | Cleanup Timing |
|-------|---------------|
| `/orchestrate` | Phase 3-3 (after all batches and reviews complete) |
| `/review-gate` | Phase 6 (after review cycle completes) |
| `/code-review` | Step 7 (after reporting results) |

Each skill tracks the agent IDs of the sub-agents it launched and deletes **only those worktrees**.
Do not bulk-delete to avoid destroying active worktrees of other sessions.

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
git worktree prune
```

If stale worktrees accumulate, check with `git worktree list` and remove individually with `git worktree remove`.

## Branch Strategy

- `main` — Always maintains a passing build and test state
- Feature branches: `feat/<issue-id>-<short-desc>` (e.g., `feat/USK-12-http-handler`)
- Bug fixes: `fix/<issue-id>-<short-desc>`
- All PRs require CI to pass before merge

## Commit Conventions

Conventional Commits format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

type: `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `chore`

## Linear

- Team: Usk6666
- Project: yorishiro-proxy

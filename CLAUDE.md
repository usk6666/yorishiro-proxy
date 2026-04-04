# yorishiro-proxy

A network proxy tool for AI agents — a MITM proxy for AI.
Operates as an MCP (Model Context Protocol) server, providing traffic interception, recording, and replay capabilities for vulnerability assessment.

**Status**: OSS (Apache License 2.0) · Under active development

## Architecture Rewrite (M36-M44)

> **Active rewrite in progress.** The codebase is being restructured from handler-per-protocol to Codec + Pipeline + Session architecture.
> **Before working on any M36-M44 Issue, read [`docs/architecture-rewrite.md`](docs/architecture-rewrite.md)** — it contains all design decisions, implementation FAQ, and rationale that are not repeated in individual Issue descriptions.

## Architecture

### Principle: L7-first, L4-capable

1. **The default operation interface is a structured L7 view** — Prioritize AI agent token efficiency by representing communication as structured data: method, URL, headers, body, etc.
2. **Raw bytes recording, viewing, and modification must be possible for all protocols** — As a diagnostic tool, protocol-level anomaly detection and reproduction must be supported (pure transport-layer protocols like SOCKS5 apply to the tunneled protocol)
3. **L7 parsing is an overlay on top of raw bytes; the wire-observed raw bytes snapshot itself must not be destroyed or modified** — Recorded raw bytes always reflect the original wire data; modifications must always be treated as separate derived data (e.g., modified variant)

### Pipeline

```
TCP Listener (Layer 4)
  → Protocol Detection (peek bytes)
    → Protocol Handler (HTTP/S, HTTP/2, gRPC, WebSocket, Raw TCP)
      → Session Recording (L7 structured + L4 raw bytes)
        → MCP Tool (Intercept / Replay / Search)
```

### L7/L4 Support Status by Protocol

| Protocol | L7 Structured View | L4 raw bytes | Notes |
|----------|-------------------|--------------|-------|
| HTTP/1.x | YES | YES (parser built-in) | Independent engine in M32; net/http removed |
| HTTP/2 | YES | YES (frame codec) | Custom frame engine implemented in M26 |
| gRPC | YES | YES (via HTTP/2) | |
| gRPC-Web | YES | YES (via HTTP/1.x or HTTP/2) | M33; binary + base64 wire formats |
| WebSocket | YES | YES (per frame) | |
| Raw TCP | N/A | YES (byte stream) | |
| SOCKS5 | N/A | N/A (excluded as transport layer itself) | Apply raw bytes/L7 to protocol delegated after handshake/tunnel |

### Design Principles

- Accept connections at Layer 4 (TCP) and route to modular protocol handlers
- No external proxy libraries — built on standard library
- MCP-first: all operations are exposed as MCP tools

### MITM Implementation Principles

As a MITM proxy, yorishiro-proxy must faithfully represent wire-level reality. The following principles apply to all data path code (`internal/protocol/`, `internal/proxy/`, `internal/flow/`, `internal/plugin/`).

1. **Do not normalize what the wire did not normalize** — Header name casing, header order, duplicate headers with different casing, and whitespace must be preserved exactly as observed on the wire. If the wire sends `Set-Cookie: a=1` and `set-cookie: b=2`, they are two distinct headers with different names. Do not merge, canonicalize, or reorder.
2. **Each protocol has its own canonical form; do not unify across protocols** — HTTP/1.x headers are case-insensitive but preserve wire casing. HTTP/2 headers are lowercase by spec (RFC 9113). These are different realities and must be handled by protocol-specific code paths, not forced into a shared normalized representation.
3. **Prefer lossless representations over convenient ones** — Use ordered arrays (`[{name, value}, ...]`) over maps (`{name: [values]}`) for headers. Use protocol-native types (RawHeaders for HTTP/1.x, hpack.HeaderField for HTTP/2) over bridge types (gohttp.Header). Convenience helpers may be provided on top but must not be the storage format.
4. **`net/http` usage policy** — Data path code must not use `net/http` types for transport or data representation. Use internal types (RawRequest/RawResponse, hpack types). `net/http` is permitted only in the control plane: MCP server (`internal/mcp/`), CLI (`cmd/`), self-update (`internal/selfupdate/`), and status code constants (via `internal/protocol/httputil` shared package, see USK-522).

## Package Layout

```
cmd/yorishiro-proxy/       # Entry point
  main.go                  # CLI root: server/client/version/install/upgrade subcommands
  client.go                # CLI client subcommand (MCP client via Streamable HTTP)
  client_params.go         # Flag → JSON parameter conversion engine
  client_format.go         # Result formatting (JSON / table output)
  serverjson.go            # server.json multi-instance entry management (used for client auto-discovery)
internal/
  mcp/                     # MCP server, tool definitions, handlers
  proxy/
    listener.go            # TCP listener (Layer 4)
    handler.go             # ProtocolHandler interface
    peekconn.go            # Buffered net.Conn wrapper
  protocol/
    detect.go              # Protocol detection logic
    http/                  # HTTP/1.x, HTTPS MITM implementation
      handler.go           # HTTP forward proxy handler
      connect.go           # CONNECT tunnel, HTTPS MITM
      parser/              # HTTP/1.x parser (RawRequest, RawResponse, Anomaly)
    grpcweb/               # gRPC-Web frame parsing, handler, request builder
    httputil/              # HTTP common utilities (TLS transport, per-host TLS config, timing)
  safety/                  # SafetyFilter engine (Input Filter + Output Filter)
    engine.go              # Rule compilation, CheckInput, FilterOutput
    rule.go                # Rule/Target/Action type definitions, Preset structures
    preset.go              # Input Filter presets (destructive-sql, destructive-os-command)
    preset_pii.go          # Output Filter PII presets (credit-card, japan-my-number, email, japan-phone)
  plugin/                  # Starlark plugin engine and registry
  flow/                    # Request/response recording, flow management, HAR export
  cert/                    # TLS certificate generation, CA management
    ca.go                  # Root CA generation and loading
    issuer.go              # Dynamic server certificate issuance
  config/                  # Configuration loading
  logging/                 # Structured logging (log/slog)
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
- [ ] **Flow recording**: Saved to Store with correct protocol name (`Protocol`), FlowType (`unary` / `bidirectional` / `stream`), and State
- [ ] **Message content**: Request/response headers and body are correctly recorded via `store.GetMessages(ctx, flowID, opts)`
- [ ] **State transitions**: Progressive recording works correctly (`State` transitions from `active` → `complete`)
- [ ] **Plugin hook firing**: The relevant hook is called for the protocol (for plugin-enabled protocols)
- [ ] **Error paths**: Flow is recorded with `State="error"` on connection failure or timeout
- [ ] **Raw bytes recording**: Wire-observed raw bytes (`Message.RawBytes`) are correctly recorded (L4-capable principle, established in M26/M27)
- [ ] **Variant recording**: On intercept/transform modification, both original and modified variants are recorded (introduced in M27)
- [ ] **MCP tool integration**: Flows are correctly retrievable via the `query` tool (with `resource: "flows"` / `resource: "flow"` parameters)

> **Applicability**: Not all items are required for every test. Verify relevant items based on protocol characteristics and test purpose.
> Example: Raw TCP has no L7 structured view, so header validation under "message content" is not required.
> SOCKS5 is excluded from flow recording as a transport layer; validate at the tunneled protocol instead.

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

- [ ] e2e test for successful proxy communication (`internal/proxy/*_integration_test.go`)
- [ ] Flow recording completeness verification (protocol name, FlowType, State transitions, message count)
- [ ] Raw bytes recording completeness verification (frame boundaries, binary data round-trip) — L4-capable principle
- [ ] Variant recording test (original/modified save on intercept modification)
- [ ] Progressive recording test (intermediate state verification for streaming protocols)
- [ ] Plugin hook firing verification (if relevant hooks exist for the protocol)
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

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
          (HostScope → HTTPScope → Safety → PluginPre → Intercept → Transform → PluginPost → Record [→ UpgradeStep])
        → Flow Recording (L7 Message + L4 Envelope.Raw)
          → MCP Tool (Intercept / Replay / Search / Plugin Introspect)
```

Each connection is an explicit stack of `Layer`s (RFC-001 §3.3); each Layer yields one or more `Channel`s; the Pipeline runs on `Envelope`s drawn from those Channels. The data model is:

- **`Envelope`** — protocol-agnostic outer container with identity (StreamID/FlowID/Sequence/Direction), provenance (Protocol), wire fidelity (Raw bytes), and a typed `Message`.
- **`Message`** — protocol-specific payload (`HTTPMessage`, `WSMessage`, `GRPCStartMessage`/`GRPCDataMessage`/`GRPCEndMessage`, `SSEMessage`, `RawMessage`, `TLSHandshakeMessage`).

### L7/L4 Support Status by Protocol

| Protocol | L7 Structured View | L4 raw bytes | Notes |
|----------|-------------------|--------------|-------|
| HTTP/1.x | YES | YES | Custom parser; `net/http` not used in data path. Forward: supported (USK-911~917). |
| HTTP/2 | YES | YES | Custom frame engine; event-granular Channel + per-stream BodyBuffer. Forward: supported (USK-911~917). |
| gRPC | YES | YES (via HTTP/2) | Native LPM reassembly; GRPCStart/Data/End envelope events. Forward: supported (USK-911~917). |
| gRPC-Web | YES | YES (via HTTP/1.x or HTTP/2) | Binary + base64 wire formats |
| WebSocket | YES | YES (per frame) | Per-message-deflate (RFC 7692) supported. Forward: supported (USK-911~917). |
| SSE | YES | YES | Per-event envelopes; streaming-aware Pipeline; per-event Transform / Intercept (rules/sse) — USK-892. Engines mutate SSEMessage fields directly; session-side sseMessageMutated field-diff is the authoritative re-encode signal (env.Raw is NOT cleared). Forward: supported (USK-911~917). |
| Raw TCP | N/A | YES (byte stream) | Smuggling-safe pass-through (`bytechunk` Layer). Forward: supported (USK-911~917). |
| SOCKS5 | N/A | N/A (excluded as transport layer itself) | Apply raw bytes/L7 to the protocol delegated after handshake/tunnel |
| TLS handshake | YES (observation) | N/A | `TLSHandshakeMessage` envelope; SNI / ALPN / JA3 / JA4 visible to plugins |
| HTTP/3 / QUIC | NO | NO | Out of scope (USK-1016). No UDP listener; ALPN advertises only `h2` / `http/1.1`. Proxied Firefox does not use h3 (h3 cannot traverse a `CONNECT` proxy), so absence is a weak bot signal. See [RFC-001 §11](docs/rfc/envelope.md#11-acceptance-record-and-deferred-items). |

> **TCP forward L7 dispatch (USK-911~917)**: All L7-supported protocols above are also usable through TCP forward mode (`tcp_forwards`) with independent client-side (`tls`) and upstream-side (`upstream_tls`) TLS axes. See `internal/proxybuild/tcp_forward.go` for the dispatch matrix and [RFC-001 §3.4.2](docs/rfc/envelope.md#342-tcp-forward-l7-dispatch).

### Design Principles

- Accept connections at Layer 4 (TCP) and route to a per-connection `ConnectionStack` of `Layer`s
- No external proxy libraries — built on the standard library
- MCP-first: all operations are exposed as MCP tools

### MITM Implementation Principles

As a MITM proxy, yorishiro-proxy must faithfully represent wire-level reality. The following principles apply to all data path code (`internal/envelope/`, `internal/layer/`, `internal/connector/`, `internal/pipeline/`, `internal/pluginv2/`, `internal/flow/`).

1. **Do not normalize what the wire did not normalize** — Header name casing, header order, duplicate headers with different casing, and whitespace must be preserved exactly as observed on the wire. If the wire sends `Set-Cookie: a=1` and `set-cookie: b=2`, they are two distinct headers with different names. Do not merge, canonicalize, or reorder. Example beyond headers: the client's TLS ALPN offer list is forwarded to upstream in the client's wire order, byte-identical — the sniff-first MITM path (USK-997) peeks `peekClientHelloSNIAndALPN`, threads `ClientHelloPeek.ALPN` through `BuildConnectionStack`, and dials upstream with that exact slice (no sort, no dedup, no case fold). Upstream's selected protocol is then advertised back to the client as a single-element list (`mitmAdvertiseFromUpstreamPick`) so end-to-end ALPN is whatever the upstream actually chose, including RFC 7301 §3.2 violations (e.g. demo1.nextcloud.com returning `http/1.1` for a solo `h2` offer).
2. **Each protocol has its own canonical form; do not unify across protocols** — HTTP/1.x headers are case-insensitive but preserve wire casing. HTTP/2 headers are lowercase by spec (RFC 9113). These are different realities and must be handled by protocol-specific code paths, not forced into a shared normalized representation.
3. **Prefer lossless representations over convenient ones** — Use ordered arrays (`[]KeyValue`) over maps (`map[string][]string`) for headers. Use protocol-native types (`parser.RawHeaders` for HTTP/1.x, `hpack.HeaderField` for HTTP/2) over bridge types. Convenience helpers may be provided on top but must not be the storage format.
4. **`net/http` usage policy** — Data path code must not use `net/http` types for transport or data representation. Use internal types (`internal/layer/http1/parser` `RawRequest`/`RawResponse`, hpack types). `net/http` is permitted only in the control plane: MCP server (`internal/mcp/`), CLI (`cmd/`), and self-update (`internal/selfupdate/`).
5. **Attacker-controlled input must be handled gracefully** — Parsers must not panic on malformed input. Surface anomalies via `parser.Anomaly` (HTTP/1.x) or equivalent typed anomaly fields (`grpcweb.Anomaly*`, etc.) so they are recorded with the flow rather than crashing the proxy. Buffer limits (`MaxBodySize`, `MaxLineLength`, etc.) must be enforced at parse time — not assumed by the caller.
6. **Pre-implementation reality check on hypothetical bugs** — Before implementing a code/security review finding (especially CWE-prefixed ones), construct the concrete scenario that triggers the bug and confirm the preconditions exist in the current architecture. If the failure mode requires architecture not yet present (hot-reload, multi-tenant pool, runtime override injection), defer with a documented re-open trigger rather than designing for hypothetical future requirements.
7. **SafetyFilter Input vs Output: different purposes, different layers** — Input Filter (Send-direction, live wire, `internal/pipeline/safety_step.go` + `internal/rules/{http,ws,grpc}/safety.go`) blocks destructive payloads bound for the upstream server. Output Filter (MCP control plane, `internal/safety.Engine` invoked from `internal/mcp/safety_helper.go`) masks sensitive bytes when an MCP tool returns recorded data to the AI agent. The wire copy delivered to the DB / browser / next hop is **never modified** by Output Filter; masking happens only at the MCP transport boundary. Do not propose "Output Safety on the wire", "Receive-direction SafetyStep", or "unify the two engines" — these have been considered and rejected. See [RFC-001 §3.7](docs/rfc/envelope.md#37-safety-architecture-input-vs-output) for the full rationale and acceptance record (USK-702 / USK-894).

## Package Layout

```
cmd/yorishiro-proxy/       # Entry point
  main.go                  # CLI root: server/client/docs/version/install/upgrade subcommands
  client.go                # CLI client subcommand (MCP client via Streamable HTTP)
  client_params.go         # Flag → JSON parameter conversion engine
  client_format.go         # Result formatting (JSON / table output)
  docs.go                  # Offline `docs` subcommand (embedded help; no server needed)
  install.go, upgrade.go,  # Subcommand handlers
  version.go
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
                           #   Intercept → Transform → PluginPost → Record). UpgradeStep is
                           #   appended after Record by proxybuild for the WS/SSE layer-swap.
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
                           #   http/, ws/, grpc/, sse/ (USK-892: Intercept + Transform), raw/
  safety/                  # SafetyFilter Engine (envelope-native; Input Filter + Output Filter)
                           #   engine.go, rule.go, preset.go (destructive-sql,
                           #   destructive-os-command), preset_pii.go (credit-card,
                           #   japan-my-number, email, japan-phone)
  job/                     # EnvelopeSource impls (per-protocol resend/fuzz sources)
                           #   consumed by internal/mcp/{resend_*,fuzz_*}_helpers.go.
                           #   source.go (EnvelopeSource interface),
                           #   http_source.go, ws_source.go, grpc_source.go, raw_source.go,
                           #   fuzz_http_source.go, fuzz_raw_source.go,
                           #   byte_patch.go (raw-payload patching),
                           #   template.go (§var§ expansion for fuzz sources)
  macro/                   # Macro engine: template / guard / extract / encoder
  flow/                    # Stream/Flow Store (sqlite); HAR / JSONL export, import
  cert/                    # Root CA + dynamic server cert issuance
  config/                  # Configuration loading + validation (incl. Plugins, body-spill, limits)
  encoding/                # Protobuf framing helper
  fuzzer/                  # Iterator / Position / RequestData primitives for typed-fuzz path
  mcp/                     # MCP server, tools, handlers
                           #   typed resend: resend_http / resend_ws / resend_grpc / resend_raw
                           #   typed fuzz:   fuzz_http   / fuzz_ws   / fuzz_grpc   / fuzz_raw
                           #   plugin_introspect, query (with Protocol filter), intercept,
                           #   macro, manage, configure, security, proxy_start / proxy_stop,
                           #   docs (embedded help corpus; shared with the CLI docs subcommand)
  session/                 # RunSession (universal session loop, OnComplete hook)
  logging/                 # Structured logging (log/slog)
  payload/, setup/, testutil/, selfupdate/
```

## Build & Test

```bash
make build          # build-ui → vet → go build (always rebuilds UI)
make build-ui       # Build the React/Vite app in web/ and generate dist/
make ensure-ui      # Run build-ui only if dist/ does not exist (lightweight)
make test           # fast tier: ensure-ui → go test -race -v ./... (unit tests only)
make test-fast      # alias for `make test`; explicit naming for the fast tier (USK-728)
make test-e2e-smoke # smoke tier (merge gate): ensure-ui → go test -race -v -tags 'e2e e2e_smoke' ./...
make test-e2e       # full tier (nightly): ensure-ui → go test -race -v -tags e2e ./...
make test-cover     # ensure-ui → test with coverage report
make vet            # ensure-ui → go vet ./...
make fmt            # Format all files with gofmt -w .
make lint           # gofmt check + golangci-lint (govet/staticcheck/unused/ineffassign/gocyclo)
make bench          # ensure-ui → run benchmarks
make clean          # Delete build artifacts
```

> **Linting (USK-1043)**: `make lint` runs two things. First the Go toolchain's own
> `gofmt -l .` over the whole working tree, then `golangci-lint run`.
> The golangci-lint version is pinned in `.golangci-lint-version` (a single source of
> truth shared by the Makefile and the CI job, which passes it to
> `golangci-lint-action` via `version-file:`), and `make lint` hard-fails if the
> binary on your PATH is a different version — local and CI results cannot drift.
> Install the pinned version with golangci-lint's official `install.sh`; do **not**
> `go install` it, because its source declares a newer Go than this module's floor.
>
> `.golangci.yml` enables exactly five linters — `govet`, `staticcheck`, `unused`,
> `ineffassign`, `gocyclo` — with `linters.default: none`. golangci-lint's own
> default set stays off deliberately; enabling more is a separate, incremental change.
> `unused` is in that list to *restore* a check, not to add one: the standalone
> `staticcheck` binary reported U1000 by default, and golangci-lint splits `unused`
> out into its own linter, so omitting it would silently drop U1000 coverage.
> `gofmt` is deliberately **not** delegated to golangci-lint: `golangci-lint run`
> only loads the default build configuration, so it cannot see the `//go:build e2e`
> files or `tools/depsec`, and it vendors a gofmt fork that disagrees with the
> toolchain on composite-literal indentation. Keeping `gofmt -l .` costs nothing
> (it ships with Go) and keeps `make fmt` a guarantee that `make lint` passes.

> **e2e test tiers (USK-728)**: e2e tests are split into three tiers.
> - **fast** (`make test`/`make test-fast`): untagged unit tests only.
> - **smoke** (`make test-e2e-smoke`): merge-gate subset — files with `//go:build e2e` only. Run by CI on every PR.
> - **full** (`make test-e2e`): every e2e file — smoke ∪ exhaustive. Run nightly via `.github/workflows/nightly-e2e.yml`; also on dependency-update PRs (head branch `automated/security-updates`) as `ci.yml`'s `test-e2e-full` job (advisory until it is added to the branch ruleset's required checks), and on any push to `main` touching `go.mod` / `go.sum` (USK-1055).
>
> The `e2e_smoke` build tag is an **exclusion filter**: smoke files keep plain `//go:build e2e`; exhaustive files use `//go:build e2e && !e2e_smoke` so they drop out of the smoke tier but remain in the full tier under `-tags e2e` alone. This guarantees `smoke ⊂ full`.
>
> When adding a new integration test, default to `//go:build e2e && !e2e_smoke` (exhaustive). Promote to plain `//go:build e2e` only when the test is part of the per-PR merge gate.

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
- [ ] **MCP tool integration**: Flows are correctly retrievable via the `query` tool (with `resource: "flows"` / `resource: "flow"` parameters; Protocol family filter accepts `http`/`ws`/`grpc`/`grpc-web`/`sse`/`raw`/`tls-handshake`; `filter.wire_level` accepts `semantic`/`h2-frame`/`h1-chunk`/`grpc-lpm-frame`/`grpcweb-base64`/`all` with default `semantic` — overlay rows are excluded from `message_count` / `message_preview` unless explicitly opted in)

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

### Concurrency Checklist

When implementation involves goroutines, channels, or `io.Pipe`, verify the following before opening a PR. Iterating on these in review (rather than designing them upfront) historically causes multi-round review cycles.

- [ ] **Termination condition is explicit for every goroutine** — context cancel, channel close, EOF, or a named `Closed()`/`Err()` interface. No "this should usually finish" assumptions.
- [ ] **Channel close ownership is single-writer** — wrap with `sync.Once` if multiple paths can request teardown. Never close the same channel from two code paths.
- [ ] **Teardown is centralized** — concentrate close logic in one `abort()` / `Close()` method. Callers signal; they do not close primitives directly.
- [ ] **Read loops do not block on external backpressure** — decouple slow consumers (e.g., `io.Pipe` writes that wait on a reader) with buffered channels or explicit drop policies.
- [ ] **Body / channel `Close()` stops every associated goroutine** — sender, writer, drainer. A leaked goroutine here often holds a reference to wire data.
- [ ] **Cascade-close is conditional on error** — for proxy session goroutines (`clientToUpstream` etc.), defer the upstream `Close()` only on non-nil error. Closing on `io.EOF` aborts in-flight responses on HTTP/1.x.

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

**Scope**: this policy governs **distributed** dependencies — anything linked into the shipped binary or the published npm artifacts, i.e. what `/license-check`'s `go list -m -json all` can see. Build-time-only tools that run as separate executables (linters, formatters) are out of scope: golangci-lint, for instance, is GPL-3.0 but appears in no `go.mod`/`go.sum`, and its diagnostic output is not a derivative work — the same reason GCC's licence does not infect the programs it compiles. Two caveats: this holds only while such a tool is never vendored or redistributed in a release artifact, and `golangci-lint custom` would build a combined GPL-3.0 binary, which must not be shipped.

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

## Supply Chain Risk Policy

Dependency updates are gated on **release age** so a freshly compromised version is never pulled in on publish day. The weekly `.github/workflows/dependabot-security.yml` run is the only automated path that edits dependency manifests; `tools/depsec` decides *what* to apply and the workflow applies it.

### npm

- The age window, registry, and exclusions live in `web/.npmrc` (`minimum-release-age`, the Takumi Guard proxy registry, `minimum-release-age-exclude[]`). pnpm >= 10.16 enforces them natively at install time — do not reimplement any of it in the workflow or in `tools/depsec`.
- **`pnpm.overrides` is forbidden.** Forcing a transitive package to a version its parent never declared decouples the lockfile from what upstream actually tested, and the pin silently outlives the parent's own fix.
- **Refreshing a transitive package within the range its parent already declares is allowed**, and the workflow does it automatically with `pnpm update --no-save` (no `--latest`, and the manifest is left untouched so the reviewer sees only lockfile movement). This is an ordinary update, not an override: the parent's semver contract is the ceiling. Do not conflate the two — treating every transitive package as untouchable is what let 48 in-range fixes sit unapplied for 10 weeks (USK-1040).
- A transitive fix that falls **outside** the parent's declared range is the one case that needs manual review: bump the parent, or wait for the parent's release. Never reach for an override to shortcut it.

### Go

Go has no native minimum-release-age mechanism, so `tools/depsec` gates each fix explicitly on the module's publish time from the Go module proxy and applies only fixes at least 7 days old. Newer fixes are deferred to a later run. Note that the Dependabot API reports Go patched versions **without** the leading `v`; canonicalize with `goVersionTag` before touching the proxy or `go get` (USK-1039).

### Judging severity

Dependabot alerts are module-level and carry no reachability analysis. Before treating a Go alert as urgent, check whether the vulnerable package is actually linked: `go list -deps ./cmd/yorishiro-proxy`. For npm, check whether the package reaches the shipped bundle at all — most of `web/`'s alerts are build-time or dev-only tooling and never appear in `internal/mcp/webui/dist/`.

## Development Workflow

1. `/project status` — Check milestone progress and decide what to work on next
2. `/project plan <milestone>` — Create and organize Linear Issues from the roadmap
3. `/orchestrate` — Delegate multiple Issues to sub-agents for parallel implementation per milestone
4. `/implement <Issue ID>` — Implement, test, commit, and create PR for a single Issue
5. `/review-gate` — Run Code Review + Security Review in parallel for a PR. If issues found, auto-fix → re-review (up to 2 rounds)
6. `/project sync` — Update roadmap documents after implementation is complete
7. `/autopilot` — Unattended variant of `/orchestrate` for scheduled runs (Desktop local scheduled task). One Issue per run through to a review-gated PR; never merges. See `.claude/skills/autopilot/SETUP.md`

> **Note**: `/implement` assumes single-session, solo execution. Use `/orchestrate` for parallel implementation of multiple Issues, and `/autopilot` only from a scheduled (unattended) session.

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
- **Sub-agents that touch the working tree are launched with `isolation: "worktree"`** — During parallel execution, checking out the main worktree's HEAD conflicts with the code state read by other agents, so even read-only review agents that check out a branch are isolated in worktrees
- **An agent whose only job is to orchestrate other agents is NOT isolated** — A sub-agent's worktree is created under its own cwd, so isolating a parent makes every child nest at `agent-<parent>/.claude/worktrees/agent-<child>`. Since `.claude/worktrees/` is gitignored, `git worktree remove <parent>` leaves that subtree behind as an *unregistered* directory holding still-registered children — reclaimable only with `rm`, which is in the `ask` list and therefore stalls an unattended run. A delegated review-gate agent reads the PR through `gh` and delegates all code access to its own isolated sub-agents, so it needs no worktree of its own; leaving it un-isolated keeps every leaf worktree flat
- **Never `git checkout` the main worktree to a different branch when the user has parallel work in progress** — Run `git status` first; if the working tree has user-owned modifications, treat the main worktree as locked. Use `git worktree add -b <new-branch> .claude/worktrees/<short-name> <base>` to materialise side tasks in an isolated checkout instead. Do not reuse `.claude/worktrees/agent-*` paths (those are reserved for sub-agents) — pick a descriptive sibling.
- **Verify main-worktree branch after parallel-agent return** — Sub-agents launched with `isolation: "worktree"` occasionally write edits into the main clone instead of the worktree (Edit-tool race), leaving the main clone on a feature branch. After every parallel-agent return, run `git branch --show-current` and `git worktree list`; if the main clone is off-base, switch back with `git checkout <base> && git pull --rebase origin <base>` before launching downstream agents.

### Classification in Task Tool

| Agent Type | Operation | isolation |
|-----------|-----------|-----------|
| implementer | Code implementation, commit, push | `"worktree"` |
| fixer | Fix review findings, commit, push | `"worktree"` |
| code-reviewer | Checkout target branch, read diff, post review | `"worktree"` |
| security-reviewer | Checkout target branch, read diff, post review | `"worktree"` |
| review-gate (delegated) | Launch reviewers/fixers, aggregate verdict; touches no files itself | **none** — isolating it nests its children |

### When Adding New Agents

1. Sub-agents that read or write the working tree use `isolation: "worktree"` by default
2. Sub-agents that only launch and aggregate other sub-agents take **no** isolation
3. Document the isolation setting in the calling skill (`.claude/skills/*/SKILL.md`)

### Worktree Cleanup

The Claude Code Task tool does not auto-delete worktrees when they have changes after completion.
**The calling skill is responsible for cleanup.**

#### Cleanup Timing

| Skill | Cleanup Timing |
|-------|---------------|
| `/orchestrate` | Phase 3-3 (after all batches and reviews complete) |
| `/review-gate` | Phase 6 (after review cycle completes) |
| `/autopilot` | Phase 6-1 (end of every run, success or failure) |
| `/code-review` | Step 7 (after reporting results) |

Each skill tracks the agent IDs of the sub-agents it launched and deletes **only those worktrees**.
Do not bulk-delete to avoid destroying active worktrees of other sessions.

This is the canonical snippet. `$IDS` is a file holding one recorded agent ID per line — never a
glob of `agent-*`:

```bash
git worktree list --porcelain | awk '/^worktree /{print $2}' > "$IDS.wt"
: > "$IDS.targets"
while read -r id _rest; do
  [ -n "$id" ] || continue
  while read -r wt; do
    case "$wt" in *"agent-$id"*) printf '%s\n' "$wt" >> "$IDS.targets" ;; esac
  done < "$IDS.wt"
done < "$IDS"

sort -u "$IDS.targets" | awk '{print length, $0}' | sort -rn | cut -d' ' -f2- |
while read -r wt; do
  git worktree remove "$wt" --force --force 2>/dev/null || true
done
git worktree prune
```

Three things in it are load-bearing; all three were verified on 2026-09-17 after a nested
`/orchestrate` run left a 110 MB unregistered husk on disk:

1. **Never construct `.claude/worktrees/agent-<id>` from an ID.** A sub-agent launched by another
   sub-agent nests under its parent, so the top-level path does not exist and the remove silently
   no-ops behind `2>/dev/null || true`. Resolve real paths from `git worktree list` and remove
   deepest first, so a child is unregistered before its parent's directory disappears.
2. **`--force --force`, not `--force`.** A single `--force` fails with exit 128 on a *locked*
   worktree (`cannot remove a locked working tree`), which an agent that is still registered
   leaves behind. `git worktree unlock` first is the equivalent alternative.
3. **Never select the paths with `grep -F -f <id-file>`.** The `grep` on this machine is **ugrep**,
   and with an empty pattern file it matches *every* line — an empty ID list would then delete
   other sessions' worktrees. The `case` loop above selects nothing when the list is empty.

If stale worktrees accumulate, check with `git worktree list` and remove individually with
`git worktree remove <path> --force --force`. An *unregistered* leftover directory (present on
disk, absent from `git worktree list`) can only be removed with `rm` — ask the user rather than
running it from an unattended session.

## Permission Policy (`.claude/settings.json`)

The three permission lists were rewritten for auto mode, where a classifier judges
each un-listed tool call instead of every unknown command reaching the user as a
prompt. That inverts what each list is for, so keep new entries in the right one.

| List | Meaning under auto mode | Admission test |
|------|------------------------|----------------|
| `deny` | Hard boundary. The classifier cannot override it, so this is the only backstop left. | The action is never legitimate in this repo, **and** the rule matches the whole class rather than one literal string. |
| `ask` | Forces a prompt even when the classifier would allow. Reserved for irreversible loss. | Losing this cannot be undone from reflog, the remote, or a rebuild. |
| `allow` | Skips the classifier entirely. | Deterministic and hard to misuse — *not* merely "usually fine". |

Consequences worth remembering:

- **Anything context-dependent belongs in no list.** `find`, `curl`, `gh api`, and
  `git rebase` are safe or destructive depending on their arguments, which is
  exactly the judgement the classifier makes per call. Listing them in `ask`
  taxes the safe 99% to catch the 1%; listing them in `allow` waves the 1% through.
- **`deny` rules must match a class.** The old `Bash(dd if=/dev/zero of=/dev/sda)`
  was an exact-match rule that `of=/dev/sdb` walked straight past. Prefer
  `Bash(dd:*)`. For the same reason, a `--long-flag` deny needs its short form
  too (`git push --force` *and* `git push -f`).
- **Prefix rules cannot see past the first token run.** `Bash(git worktree remove --force:*)`
  never fires on `git worktree remove <path> --force`, and `git push origin +main:main`
  force-pushes without matching any `--force` rule. Where a rule cannot be expressed,
  rely on the classifier and branch protection rather than writing one that looks
  like it works.
- **`Read(...)` deny rules also feed `sandbox.filesystem.denyRead`**, so a broad glob
  can block the *test process* from reading a file it just generated. This is why the
  CA private key is denied as `Read(**/.yorishiro-proxy/ca/**)` — the real path — and
  not as `Read(**/*.key)`, which would collide with certs that `internal/cert` tests
  generate in temp dirs.
- **The `make` targets are listed one by one**, mirroring `.PHONY` in the Makefile,
  so that adding a target does not silently inherit an allow rule. Add the new target
  here when you add it to the Makefile.
- **Supply-chain commands stay in `ask`.** `go get` / `go install` are gated because
  Go has no native minimum-release-age mechanism (see "Supply Chain Risk Policy").
  pnpm is not gated here — `web/.npmrc` enforces the age window natively at install time.
- `gh pr merge` / `gh pr close` are deliberately absent from `allow`: merging is
  outward-facing and should get a look.

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

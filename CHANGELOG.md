# Changelog

All notable changes to yorishiro-proxy are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`max_concurrent_streams` is now configurable end-to-end** (#858, USK-862). The HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` value is exposed via the MCP `proxy_start` / `configure` tools, the CLI flag `-max-concurrent-streams`, and the env var `YP_MAX_CONCURRENT_STREAMS`, so operators can tune the per-connection stream budget without recompiling.
- **`query` body inclusion controls** (#862). The `messages` and `flow` resources now accept `include_bodies` and `body_max_bytes` parameters, letting callers opt in to body payloads with an explicit per-call size cap.
- **Per-protocol intercept hold/timeout overrides** (#850, USK-855). `intercept_queue.protocol_overrides` lets operators set distinct `hold_timeout` and `timeout_behavior` values per protocol, which is necessary because WS/SSE long-lived flows tolerate longer holds than short HTTP requests.
- **WS hold-window keepalive injection** (#852, USK-854). While a WebSocket flow is held in the intercept queue, the proxy now injects keepalive frames toward the client to prevent edge proxies from tearing down the connection during the hold.
- **Linux NSSDB CA registration** (#854, USK-857). `setup` now installs the proxy CA into the per-user NSSDB so Chromium and Firefox on Linux trust the MITM cert without manual intervention.
- **`proxy_start` listen-address collision detection + bind-failure rollback** (#856). `listen_addr` and `tcp_forwards` ports are checked for collisions before bind, and any partial bind is rolled back on failure so the listener set never lingers in a half-started state.
- **HTTP/2 extended CONNECT support in ServerRole** (#866). The H2 ServerRole now mirrors the upstream's `SETTINGS_ENABLE_CONNECT_PROTOCOL` value, enabling extended CONNECT (RFC 8441) for downstream clients when the upstream advertises it.
- **HTTPMessage anomalies persisted on Flow rows** (#846). Parser-detected anomalies are now stored on the Flow record and surfaced through the MCP `query` tool so diagnostic anomalies remain inspectable after the fact.

### Changed

- **HTTP/2 `SETTINGS_MAX_CONCURRENT_STREAMS` default raised 100 → 500** (#858, USK-862). The previous 100-stream cap throttled modern clients (browsers, gRPC clients) that routinely open large request fan-outs; 500 better matches real-world load while still bounding per-connection memory.
- **WS / SSE intercept hold-timeout default raised 8s → 60s** (#860). The 8-second default fired before operators could review held messages and caused premature disconnects on edges with short idle limits (e.g. Fly.io); 60s is a more realistic review window for long-lived flows.
- **HTTP/1 and WS layers now wire `StateReleaser.ReleaseStream` on terminal events** (#849). Per-stream plugin state is released deterministically when the stream ends, removing a slow leak in long-running proxies with many short flows.

### Removed

- **Breaking change**: the `install skills` CLI subcommand and the `--skills-dir` flag are deleted (USK-951). USK-949 / #28 (merged 2026-05-21) already moved the nine vulnerability-verification playbooks (`audit-auth`, `capture-traffic`, `fuzz-endpoint`, `replay-with-mods`, `stateful-fuzz-loop`, `verify-csrf`, `verify-idor`, `verify-sqli`, `verify-xss`) to MCP Prompts as the single host-portable distribution channel; this commit removes the `[DEPRECATED]` shim and the embedded `internal/setup/skilldata/` tree that backed it. `yorishiro-proxy install skills` now returns an `unknown install target "skills"` error, `yorishiro-proxy install` (no target) no longer touches `.claude/skills/yorishiro/`, and the post-`upgrade` "to update skills, run …" tip is removed because MCP Prompts ship in the binary and travel with self-update. Migration: invoke the playbooks via `prompts/list` / `prompts/get` against the yorishiro-proxy MCP server — the content is identical.
- **Breaking change**: the broken technology-detection feature is deleted (#841, USK-843). The `query` tool's `technologies` resource and `technology` filter, plus the entire `internal/fingerprint/` package, are removed. The feature shipped without a working detection backend and had no clear use case beyond what the existing `query` filters already cover; idiomatic alternatives (response-header matching via `query` filters, or a Starlark plugin) are sufficient. Migration: clients invoking `query { resource: "technologies" }` or passing `filter: { technology: ... }` will receive a schema error and should drop those parameters.
- **Breaking change**: the `proxy_start.protocols` MCP input parameter and the `query("config").enabled_protocols` output field are deleted (#865, USK-870). The half-implemented protocol allow-list never had a use case not already covered by `target_scope` (host), `intercept_rules` (request pattern), `tls_passthrough` (MITM target), and `capture_scope` (recording target), and the WS/SSE/gRPC overlay enforcement built in USK-732 (listener peek-time gate) and USK-808 (MITM ALPN filter) is reverted in the same PR. Clients submitting `proxy_start { protocols: [...] }` now receive a schema unknown-field error from the MCP go-sdk — the field is not silently ignored. The WebUI Settings → Proxy panel no longer shows a protocol-selection toggle. Migration: drop the field from MCP calls and rely on the scope/passthrough/capture knobs for the same effect.

### Fixed

- **Security**: `security set_target_scope` is now enforced on proxy-relayed traffic — CONNECT tunnels, plain-HTTP forward proxy, and SOCKS5 tunnels (USK-879). Pre-fix, when no `target_scope_policy` was configured at boot, the MCP control plane and the live data path held separate `TargetScope` instances, so agent-layer rule mutations reached only MCP-tool-initiated requests (`resend_*` / `fuzz_*` / `test_target`) while client traffic through CONNECT / plain HTTP / SOCKS5 completely bypassed the scope evaluator. AI agents that scoped themselves down via `set_target_scope` could still reach denied hosts through the same proxy. The fix guarantees `InitTargetScope` always returns a non-nil instance so the MCP control plane and the connector handler gates / pipeline `HostScopeStep` / `HTTPScopeStep` share one pointer.
- Client-side MITM handshake rejection (e.g. Chromium pinning a proxy CA so the proxy's MITM cert is refused with an `unknown_certificate` / `bad_certificate` TLS alert) is now recorded with `failure_reason="client_tls_error"` instead of being misclassified as `upstream_tls_error` (#853, USK-858). Existing `upstream_tls_error` records for genuine upstream-side TLS failures are unaffected. MCP query consumers can therefore distinguish browser→proxy failures (CA install / pinning issues) from proxy→upstream failures (cert expiry / chain trust) without parsing `tags["error"]`.
- Macro template variables that remain unresolved after substitution are now detected and surfaced as a warning (#838) instead of being silently sent to the upstream as the literal `{{var}}` string.
- `request_timeout_ms` now applies to plain HTTP read deadlines and to the inner read deadline of CONNECT tunnels (#840), so the timeout is honored on the paths it was previously ignored on.
- CONNECT and SOCKS5 target hostnames are now propagated onto the passthrough audit envelope (#839), preserving the original target hostname for audit trails when the proxy is operating in pure tunnel mode.
- HAR export protocol predicates are now aligned with the canonical `Envelope.Protocol` values (#848), fixing exports that previously dropped or mislabeled flows due to the predicate using stale protocol names.
- `resend_http` now auto-splits a `?` inside the `path` parameter into `path` + `raw_query` (#855), and rejects the call with a clear error when both `path` carries `?` and `raw_query` is also supplied — preventing the previous silent ambiguity.
- The intercept-release EOF tag is now only attached on successful downstream relay (#857), so retries and partial failures are no longer misclassified as clean stream termination.
- HTTP/2 connection-specific headers (RFC 7540 §8.1.2.2: `Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`) are stripped on the H2 send path (#836), preventing wire-spec violations when an HTTP/1 → HTTP/2 hop forwards messages that originally carried hop-by-hop headers.
- Upstream EOF that arrives after a long intercept hold is now surfaced as a Stream tag (#844, USK-851), making the cause of post-hold connection loss visible instead of opaque.
- WebSocket per-message-deflate with context-takeover now correctly handles multi-frame messages and serializes the `deflateState` between frames (#864, USK-867). Previously, re-emitting `Close()` on the flate writer set BFINAL=1 and desynchronised the peer's persistent inflater on message 2+.
- The negotiated `Sec-WebSocket-Extensions` value from the WS handshake is now propagated to the post-Upgrade `ws.Layer` (#845), so per-message-deflate parameters agreed during handshake actually take effect on subsequent frames.
- Post-swap WebSocket frames now reuse the handshake StreamID (#843), keeping the upgrade and the data-frame phase under the same Stream identity for recording and intercept purposes.
- `query` filter `scheme=ws` / `scheme=wss` is now hard-rejected (#861, USK-848). `scheme` describes the handshake transport (`http`/`https`), so the `ws`/`wss` values were structurally meaningless; rejecting them prevents silently-empty result sets.
- The `livewire_pluginv2` integration test now correctly threads the `holdTracker` (#859), removing a flaky-test source rather than a runtime bug.
- The `manage` export/import path resolution is now documented as relative to the server's CWD (#863, USK-868) in the tool description, jsonschema, and CLI help — clarifying behavior that previously confused remote MCP clients.

### Docs

- The applicability scopes (Agent vs Policy Layer) of `target_scope`, `rate_limit`, and `budget` in the `security` MCP tool are now spelled out in the help text and security documentation (#837, USK-842), removing prior ambiguity about which knob applies at which layer.

## [0.15.0] - 2026-05-05

This release ships the [RFC-001 Envelope + Layered Connection Model](docs/rfc/envelope.md) rewrite (milestones N1–N9). The data path is rebuilt around an `Envelope` + typed `Message` + `Layer` + `Channel` model that fixes the HTTP bias of the previous `Exchange`/`Codec` abstractions and unlocks structurally-honest support for HTTP/2 multiplexing, gRPC, gRPC-Web, WebSocket, SSE, and raw-byte smuggling diagnostics.

This release contains breaking changes for plugin authors and MCP clients. There is **no compatibility shim**.

### Added

- **Envelope + typed Message data model** (RFC-001 §3.1, §3.2). `Envelope` carries identity (`StreamID`, `FlowID`, `Sequence`, `Direction`), provenance (`Protocol`), wire-fidelity raw bytes (`Raw`), and a typed `Message`. Message implementations: `HTTPMessage`, `WSMessage`, `GRPCStartMessage`/`GRPCDataMessage`/`GRPCEndMessage`, `SSEMessage`, `RawMessage`, `TLSHandshakeMessage`.
- **Layer + Channel architecture** (RFC-001 §3.3). Connections are explicit stacks of `Layer`s — `bytechunk` (raw TCP), `tlslayer`, `http1` (with parser), `http2` (event-granular), `httpaggregator` (folds H2 events into HTTPMessage), `grpc`, `grpcweb`, `ws`, `sse`. Each `Layer` yields one or more `Channel`s; the Pipeline runs on Channels.
- **Per-protocol typed MCP tools**: `resend_http`, `resend_ws`, `resend_grpc`, `resend_raw`; `fuzz_http`, `fuzz_ws`, `fuzz_grpc`, `fuzz_raw`. Each owns a typed schema for its protocol's `Message` type. Per-variant `SafetyFilter` gating.
- **`plugin_introspect` MCP tool**. Read-only listing of loaded Starlark plugins and their `(protocol, event, phase)` hook registrations.
- **`pluginv2` Starlark engine** (RFC-001 §9.3). Three-axis `(protocol, event, phase)` hook identity registered via the `register_hook(...)` builtin. 17-entry hook surface table covering `http`, `ws`, `grpc`, `grpc-web`, `sse`, `raw`, `connection`, `tls`, `socks5`. Snake-case dict messages with ordered headers and `msg["raw"]` byte-injection. `ctx.transaction_state` / `ctx.stream_state` Layer-managed scopes. `action.RESPOND(...)` / `action.RESPOND_GRPC(...)` callable builtins. Two-phase Pipeline integration (`PluginStepPre` before Intercept; `PluginStepPost` after Macro).
- **Per-protocol rule engines** under `internal/rules/{http,ws,grpc,sse,raw,common}/`. Intercept / Transform / Safety dispatch via type-switch on `env.Message`.
- **Event-granular HTTP/2 Layer** (RFC-001 §9.1). Per-stream `BodyBuffer` (10 MiB memory-then-spill); WINDOW_UPDATE fires at frame arrival, decoupled from Pipeline latency. Handles arbitrary-length Pipeline holds without stalling unrelated streams.
- **Native gRPC layer** with LPM reassembly. `GRPCDataMessage.EndStream` mirrors the wire `END_STREAM` flag for accurate request-side termination.
- **`query` Protocol family filter** accepting canonical Envelope.Protocol values: `http`, `ws`, `grpc`, `grpc-web`, `sse`, `raw`, `tls-handshake`.
- **`proxybuild` package** (live data-path stack assembly + multi-listener `Manager`).
- **`pushrecorder` package** drains upstream HTTP/2 push channels.
- **`internal/connector/transport/`** — `TLSTransport`, `HostTLSRegistry`, `H1Transport`, `ConnPool` rehomed from the deleted `internal/protocol/httputil`.
- **`internal/connector/budget.go`** — diagnostic `BudgetManager` rehomed from the deleted `internal/proxy/budget.go`.
- **WebUI `/plugins` route** — per-protocol Flow Detail panels and read-only Plugins management view.
- **`docs/rfc/envelope.md`** (RFC-001 specification, Accepted 2026-04-12), `docs/rfc/envelope-ja.md` (Japanese translation), `docs/rfc/envelope-implementation.md` (implementation strategy + 12 frictions), `docs/rfc/plugin-migration.md` (legacy → typed plugin migration guide).

### Changed

- **Architecture**: `Codec` interface → `Layer` + `Channel` interfaces; `Exchange` struct → `Envelope` + typed `Message` interface; unified Pipeline Steps → typed Steps that dispatch per protocol.
- **Pipeline canonical 8-step chain**: `HostScope → HTTPScope → Safety → PluginPre → Intercept → Transform → PluginPost → Record` (proxybuild appends `UpgradeStep` after `Record` for the WS/SSE layer-swap path). Resend / Macro fan-out / synthesized Send paths bypass `PluginStepPre` and `InterceptStep` and traverse only `Transform → PluginPost → Record → Layer encode`.
- **Connector `FullListener` is the sole listener API**. `Listener`, `MinimalListener`, `Connector` (multi-listener orchestrator), `Detector`, `CodecFactory`, `TunnelHandler`, `DialUpstream` — removed. Multi-listener orchestration lives in `proxybuild.Manager`.
- **Job `EnvelopeSource`** replaces the previous `ExchangeSource` interface. Per-protocol resend sources (`http_source.go`, `ws_source.go`, `grpc_source.go`, `raw_source.go`) and per-protocol fuzz sources (`fuzz_http_source.go`, `fuzz_raw_source.go`).
- **`SafetyFilter`** is envelope-native and operates on `[]envelope.KeyValue` rather than the deleted `[]exchange.KeyValue`. Re-checked at `HoldQueue` release on user-modified envelopes (USK-702).
- **HTTPMessage** is the canonical L7 type for both HTTP/1.x and HTTP/2; the wire-shape difference (case-preserving vs lowercase per RFC 9113) is handled inside the respective Layer.

### Removed

- **Legacy MCP tools** (no replacement is a compatibility shim): `resend` (collapsed into typed siblings), `fuzz` (collapsed into typed siblings), `compare` (no in-proxy replacement; perform structural diff on the client side from `query` results), `plugin` (the read-only `list` action moved to `plugin_introspect`; `reload`/`enable`/`disable` are removed by design — plugins load once at proxy boot from `config.plugins`).
- **Legacy `internal/plugin/` Starlark engine** and the 8-hook surface (`on_receive_from_client`, `on_before_send_to_server`, `on_receive_from_server`, `on_before_send_to_client`, `on_connect`, `on_disconnect`, `on_tls_handshake`, `on_socks5_connect`). Configuration files that still carry the legacy `protocol:` or `hooks:` YAML keys under `plugins:` are rejected at startup with a pointer to `docs/rfc/plugin-migration.md`. Migrate scripts to `register_hook()` per the [direct migration table](docs/rfc/plugin-migration.md#direct-migration-table).
- **Legacy data-path packages** (called out for plugin and integration authors who held references via reflection or grep): `internal/exchange/`, `internal/codec/`, `internal/protocol/`, `internal/proxy/`. The replacements live in `internal/envelope/`, `internal/layer/`, `internal/connector/`, `internal/proxybuild/`. Helpers from `internal/protocol/httputil/` rehomed to `internal/connector/transport/`. `internal/proxy/budget.go` rehomed to `internal/connector/budget.go`.
- **Legacy fuzzer engine**: `internal/fuzzer/{control,engine,hooks,monitor,payload,runner}.go` and corresponding tests. The position-application primitives (`Iterator`, `FuzzCase`, `Position`, `RequestData`, `ApplyPosition`) survive — they are consumed by the typed `fuzz_*` MCP tools via `internal/job/fuzz_*_source.go`.
- **WebUI Settings → Plugins panel** (consumed the legacy `plugin` MCP tool's `reload` / `enable` / `disable` actions). Replaced by the read-only `/plugins` route.

### Migration Notes

- **Plugin authors** — see `docs/rfc/plugin-migration.md` for the full migration guide. Direct mapping table for the 8 legacy hooks → `(protocol, event, phase)` calls is in [Direct Migration Table](docs/rfc/plugin-migration.md#direct-migration-table). The Starlark sandbox modules (`state`, `crypto`, `store`, `proxy`, `action`, `config`) are byte-identical; only the registration call and message dict shape change.
- **MCP clients** — replace `resend` calls with the typed sibling that matches the recorded flow's protocol. Replace `fuzz` calls likewise. The `compare` action has no in-proxy replacement — perform diff on the client side from `query` results. The `plugin` actions `reload`/`enable`/`disable` have no replacement — edit `config.plugins` and restart the proxy to change the loaded set.
- **Storage** — Pluginv2 uses the same `plugin_kv` table name as the legacy engine. Existing installs are not auto-dropped; if you want a clean slate, run `sqlite3 <db> 'DROP TABLE IF EXISTS plugin_kv;'` before upgrade.

## [0.14.x and earlier]

Pre-RFC-001 history is preserved as git tags `v0.3.0` through `v0.14.1` and in their corresponding GitHub Releases. The pre-rewrite architecture used the now-deleted `internal/exchange/` (`Exchange` struct), `internal/codec/` (`Codec` interface), `internal/protocol/` (per-protocol handlers), and `internal/proxy/` (listener / manager). Detailed per-tag changelogs were not maintained at the time; consult `git log` for fine-grained history of those releases.

[0.15.0]: https://github.com/usk6666/yorishiro-proxy/compare/v0.14.1...v0.15.0

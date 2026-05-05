# Changelog

All notable changes to yorishiro-proxy are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- **Pipeline canonical 8-step chain**: `HostScope → HTTPScope → Safety → PluginPre → Intercept → Transform → Macro → PluginPost → Record`. Resend / Macro fan-out / synthesized Send paths bypass `PluginStepPre` and `InterceptStep` and traverse only `Transform → Macro → PluginPost → Record → Layer encode`.
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

[Unreleased]: https://github.com/usk6666/yorishiro-proxy/compare/v0.14.1...HEAD

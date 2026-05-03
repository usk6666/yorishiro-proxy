# Plugin Migration: Legacy Hooks → RFC-001 `register_hook`

**Status:** Final (RFC-001 N9, USK-695, 2026-05-03) · Companion to [`envelope.md` §9.3](envelope.md#93-starlark-plugin-api-shape--resolved)
**Audience:** authors of existing `internal/plugin/` Starlark scripts; consumers of the legacy `resend` / `fuzz` / `plugin` MCP tools

This document maps the legacy 8-hook surface to the RFC-001 §9.3 three-axis hook identity `(protocol, event, phase)`.

The legacy surface is **removed in RFC-001** with no compatibility shim. Configuration files that still carry the legacy `protocol:` or `hooks:` YAML keys will be rejected at load time with the message:

> `field hooks/protocol removed in RFC-001; use register_hook() in your script. See docs/rfc/plugin-migration.md`

## What changed and why

Legacy plugins declared their hook subscriptions in `config.yaml`:

```yaml
plugins:
  - path: scripts/sign.star
    protocol: http
    hooks: [on_before_send_to_server, on_before_send_to_client]
```

The 8 legacy hook names conflated **direction** (request / response) and **Pipeline timing** (pre-intercept / post-Transform) into a single string. RFC-001 §9.3 separates these into three orthogonal axes:

- **Protocol** — `http`, `ws`, `grpc`, `grpc-web`, `sse`, `raw`, `tls`, `connection`, `socks5`
- **Event** — protocol-specific wire event (`on_request`, `on_message`, `on_chunk`, …)
- **Phase** — `pre_pipeline` (default; before Intercept) or `post_pipeline` (after Transform/Macro, before wire encode)

Hook registration moves from YAML into the script itself via the predeclared `register_hook()` builtin:

```python
def sign(env):
    # mutate env, return None for CONTINUE
    return None

register_hook("http", "on_request", sign, phase="post_pipeline")
register_hook("http", "on_response", sign, phase="post_pipeline")
```

This puts the hook surface under the operator's version control alongside the script logic, and makes the plugin self-describing — adding, removing, or rephasing a hook is one Starlark call instead of two coordinated edits across YAML and `.star`.

## Direct migration table

The legacy timing semantics map to RFC-001 phases as follows:

| Legacy hook                | RFC-001 `register_hook` call                                        |
|----------------------------|---------------------------------------------------------------------|
| `on_receive_from_client`   | `register_hook("http", "on_request", fn)` — defaults to `pre_pipeline` |
| `on_before_send_to_server` | `register_hook("http", "on_request", fn, phase="post_pipeline")`     |
| `on_receive_from_server`   | `register_hook("http", "on_response", fn)` — defaults to `pre_pipeline` |
| `on_before_send_to_client` | `register_hook("http", "on_response", fn, phase="post_pipeline")`    |
| `on_connect`               | `register_hook("connection", "on_connect", fn)` — no phase            |
| `on_disconnect`            | `register_hook("connection", "on_disconnect", fn)` — no phase         |
| `on_tls_handshake`         | `register_hook("tls", "on_handshake", fn)` — no phase                 |
| `on_socks5_connect`        | `register_hook("socks5", "on_connect", fn)` — no phase                |

**Lifecycle / observation hooks (the bottom four rows) accept no `phase=` argument.** Passing one is a load-time error — these hooks do not run through the Pipeline Step chain.

## New events available in RFC-001

RFC-001 adds first-class events for non-HTTP protocols that legacy lumped under `on_*_from_*`:

| Protocol  | Events                                              |
|-----------|-----------------------------------------------------|
| `ws`      | `on_upgrade`, `on_message`, `on_close`              |
| `grpc`    | `on_start`, `on_data`, `on_end`                     |
| `grpc-web`| `on_start`, `on_data`, `on_end`                     |
| `sse`     | `on_event`                                          |
| `raw`     | `on_chunk`                                          |

See [RFC-001 §9.3](envelope.md#93-starlark-plugin-api-shape--resolved) for the full surface table including action permissions per event.

## Before / after example

**Legacy script** (`auth.star` + `config.yaml`):

```yaml
# config.yaml
plugins:
  - path: scripts/auth.star
    protocol: http
    hooks: [on_before_send_to_server]
    vars:
      api_key: secret
```

```python
# scripts/auth.star
def on_before_send_to_server(req):
    req["headers"]["X-Auth"] = config["api_key"]
    return req
```

**RFC-001 equivalent** (`auth.star` + `config.yaml`):

```yaml
# config.yaml
plugins:
  - path: scripts/auth.star
    vars:
      api_key: secret
```

```python
# scripts/auth.star
def stamp_auth(env):
    # Headers are an ordered list of (name, value) 2-tuples; mutation API
    # is delivered in USK-669. Until then, stamp via env["headers"].append
    # once that lands.
    env["headers"].append(("X-Auth", config["api_key"]))
    return None  # CONTINUE

register_hook("http", "on_request", stamp_auth, phase="post_pipeline")
```

## Things that stay the same

- The Starlark sandbox modules — `state`, `crypto`, `store`, `proxy`, `action`, `config` — are byte-identical to the legacy versions. Plugins that only use these modules need no changes beyond the registration call.
- Hook function signatures still take a single dict argument and return either `None` (CONTINUE), a result dict, or raise. The exact dict shape is being redesigned in USK-669 (snake-case keys, ordered headers list, `msg["raw"]` byte injection).
- `state.set` / `state.get` / etc. are unchanged. Per-plugin state survives plugin reloads.
- `proxy.shutdown(reason)` is unchanged.

## Resend / fuzz / macro-variant semantics

Per RFC §9.3 Decision item 1: when a request is replayed via `resend_*` or fanned out via Macro, **only `phase="post_pipeline"` hooks fire**. `pre_pipeline` hooks run only on fresh wire receive. This means signing plugins (re-sign on each resend) can register once with `phase="post_pipeline"` and behave consistently across normal traffic, resend, and fuzz — no special-case routing.

## MCP Tool Migration

In parallel with the plugin hook surface change, RFC-001 N7/N8 introduced typed per-protocol MCP tools that replace the legacy multi-protocol `resend` and async `fuzz` tools. The legacy tools were retained side-by-side through N7/N8 so clients could migrate gradually; **N9 removes them with no compatibility shim** (per [RFC §9.3 P-8](envelope.md#93-starlark-plugin-api-shape--resolved), open questions Q7/Q24, and the "no shims" rule in [`envelope-implementation.md` §5](envelope-implementation.md)). Removal happens in two PRs:

- **USK-693** — delete the `resend` and `fuzz` MCP tool registrations and their support files in `internal/mcp/`.
- **USK-694** — delete `internal/fuzzer/` (async engine consumed only by the legacy `fuzz` tool).

### Migration table

| Legacy tool | New typed tools | Migration notes |
|---|---|---|
| `resend` (one tool with `action: "resend" \| "resend_raw" \| "tcp_replay" \| "compare"`) | `resend_http` / `resend_ws` / `resend_grpc` / `resend_raw` | Pick the tool that matches the recorded flow's protocol. Each owns its own typed schema (`HTTPMessage` / `WSMessage` / `GRPCStartMessage`+`GRPCDataMessage`+`GRPCEndMessage` / `RawMessage`) with ordered headers — the legacy untyped `map[string]any` surface is gone. The `tcp_replay` action is covered by `resend_raw` with `use_tls=false`. The `compare` action has no in-proxy replacement — diff at the client side from `query` results. |
| `resend_raw_h2` (informal name; the legacy `resend` tool's `resend_raw` action when the recorded flow is HTTP/2; helpers in `internal/mcp/resend_raw_h2.go`) | `resend_http` (re-encode through MITM frontend, preserves L7 view) **or** `resend_raw` (TLS-direct raw bytes, preserves smuggling/anomaly fidelity) | Use `resend_http` when the test cares about HTTP/2 semantics (HPACK, flow control, h2c upgrade) and you want the proxy frontend to re-frame from `HTTPMessage`. Use `resend_raw` when the test cares about literal byte sequences (request smuggling, malformed frames, pre-recorded `Flow.RawBytes`); requires `target_addr` with explicit port and `use_tls=true` for HTTPS targets. |
| `fuzz` (asynchronous, with concurrency / rate-limit / overload monitor / per-payload safety gating) | `fuzz_http` / `fuzz_ws` / `fuzz_grpc` / `fuzz_raw` (synchronous, typed, position-path-driven) | Each typed fuzzer caps variants at 1000, positions at 32, per-payload decoded size at 1 MiB, and gates `checkSafetyInput` **per variant** (closing the legacy `fuzz_tool.go` per-payload gating gap). Each variant runs the same `[PluginStepPost, RecordStep]` pipeline as its `resend_*` sibling. **If you need concurrency, drive the typed fuzzers from multiple MCP client connections** — the proxy no longer schedules concurrent variants. The legacy rate-limit / overload monitor have no replacement; pace from the client side or bound the payload count via `positions[]`. |

### Why per-protocol typed schemas

The legacy `resend` tool dispatched on an untyped `map[string]any` after reading the recorded flow's protocol field. Three classes of bug were structurally hard to prevent under that surface:

1. **Schema drift across protocols** — a header patch shaped for HTTP/1.x silently misbehaved against HTTP/2 because the field semantics differ (`:authority` vs `Host`, ordered list vs map).
2. **Missing safety gates per variant** — `fuzz_tool.go` ran `checkSafetyInput` against the base flow only, not per generated variant; a payload mutation could bypass `destructive-sql` / `destructive-os-command` presets. The typed `fuzz_*` tools gate per variant.
3. **Plugin hook surface ambiguity** — the resend path's "PluginStepPre + InterceptStep bypass" (RFC §9.3 D1) required runtime branching inside one tool. The typed tools each construct `[PluginStepPost, RecordStep]` directly.

The N9 typed surface fixes all three at the schema level.

## Status of related work

| Component | Issue | Status |
|-----------|-------|--------|
| Foundation: registry, `register_hook`, surface table | USK-665 | DONE |
| Message → snake-case Starlark dict + ordered headers + `msg["raw"]` | USK-669 | DONE |
| `ctx.transaction_state` / `ctx.stream_state` lifecycle | USK-670 | DONE |
| `PluginStepPre` / `PluginStepPost` Pipeline integration with resend bypass | USK-671 | DONE |
| `plugin_introspect` MCP tool | USK-676 | DONE |
| End-to-end plugin pipeline E2E suite | USK-681 | DONE |
| Legacy MCP tool retire-plan (this document's "MCP Tool Migration" section + "Appendix: N9 Removal Inventory") | USK-689 | DONE |
| Delete legacy `resend` / `fuzz` / `compare` MCP tool registrations and support files | USK-693 | DONE |
| Delete `internal/fuzzer/` async engine (partial; iterator/position kept for typed-fuzz path) | USK-694 | DONE |
| Delete `internal/plugin/` legacy engine; finalize this document | USK-695 | DONE (this PR) |

## Release Notes Snippet

This snippet is intended for inclusion in the N9 release notes (USK-698). Operators upgrading to RFC-001 N9 should be aware of the following:

- **Legacy `internal/plugin/` Starlark engine is removed.** Configuration files that still carry the legacy `protocol:` or `hooks:` YAML keys under `plugins:` are rejected at startup with a pointer to this document. Migrate scripts to `register_hook()` per the [direct migration table](#direct-migration-table) above. There is no compatibility shim.
- **Legacy MCP tools `plugin`, `resend`, `fuzz`, and `compare` are removed.** Use the typed siblings: `plugin_introspect` (replaces `plugin list`); `resend_http` / `resend_ws` / `resend_grpc` / `resend_raw` (replace `resend`); `fuzz_http` / `fuzz_ws` / `fuzz_grpc` / `fuzz_raw` (replace `fuzz`). The `plugin` actions `reload`/`enable`/`disable` have no replacement by design (RFC §9.3 D2): plugins are loaded once at proxy boot from `config.plugins`. To change the loaded set, edit the config and restart the proxy.
- **Storage table policy.** New installs use the `plugin_kv` table created and managed by `pluginv2.Engine`. Existing installs from before USK-687 may have a `plugin_kv` table populated by the legacy engine; that table is **not** dropped on upgrade. Both engines used the same table name, so legacy data may still be visible to new pluginv2 plugins reading the same `(plugin, key)`. To start fresh, drop the table manually before upgrading: `sqlite3 <db> 'DROP TABLE IF EXISTS plugin_kv;'`. The proxy will recreate it on next start.
- **WebUI Plugins panel** (`/plugins` route) now reads exclusively from `plugin_introspect`. The Settings → Plugins panel, which exposed the legacy `reload`/`enable`/`disable` actions, is removed.

## Appendix: N9 Removal Inventory

The following files and lines are scheduled for deletion in N9 issues **USK-693** (`resend` / `fuzz` MCP tools and their support files) and **USK-694** (`internal/fuzzer/` async engine). This appendix exists so reviewers and downstream documentation can confirm the surface that disappears at N9 close. It is generated against the code state on `rewrite/rfc-001` at the time USK-689 lands; line numbers will drift as `internal/mcp/server.go` is edited by other N9 work.

### USK-693 — legacy MCP tool surface

| Path | Action | Notes |
|---|---|---|
| `internal/mcp/resend_tool.go` | delete file | Defines `registerResend()` (the legacy multi-protocol `resend` MCP tool with `action: "resend" \| "resend_raw" \| "tcp_replay" \| "compare"`). |
| `internal/mcp/resend_tool_test.go` | delete file | Unit / table tests for `resend_tool.go`. |
| `internal/mcp/resend_action_test.go` | delete file | Per-action behavior tests for the legacy `resend` tool. |
| `internal/mcp/resend_target_scope_unit_test.go` | delete file | `TargetScope` CWE-918 regression for the legacy tool (typed tools have their own equivalents). |
| `internal/mcp/resend_multiproto.go` | delete file | Multi-protocol dispatch helper for the legacy `resend` tool. |
| `internal/mcp/resend_multiproto_test.go` | delete file | Tests for `resend_multiproto.go`. |
| `internal/mcp/resend_raw_h2.go` | delete file | HTTP/2 direct-resend helpers (`buildAndSendRawH2`, `h2Handshake`, `remapH2StreamIDs`, `applyServerMaxFrameSize`, `classifyH2ResponseFrame`, `readH2ResponseFrames`, `shouldDropH2ControlFrame`, `appendRawCapped`, `inferFlowUseTLS`, `isHTTP2Protocol`, `upgradeTLSH2`, `putStreamID`, `h2WaitForServerSettings`) used **only** by the legacy `resend` tool's `resend_raw` action. The new `resend_raw` (USK-675) goes via `bytechunk.New` Layer + `tlslayer.Client` and needs none of these helpers. |
| `internal/mcp/resend_raw_h2_test.go` | delete file | Tests for `resend_raw_h2.go`. |
| `internal/mcp/fuzz_tool.go` | delete file | Defines `registerFuzz()` (legacy async fuzzer; consumes `internal/fuzzer/` for concurrency / rate-limit / overload monitor). |
| `internal/mcp/fuzz_tool_test.go` | delete file | Unit tests for `fuzz_tool.go`. |
| `internal/mcp/legacy_options_test.go` | delete file | Schema validation tests for legacy tool option shapes. |
| `internal/mcp/server.go` line `s.registerResend()` (currently L366) | remove line | Legacy `resend` registration. |
| `internal/mcp/server.go` line `s.registerFuzz()` (currently L372) | remove line | Legacy `fuzz` registration. |

> **Naming note (vs USK-689 issue text):** the original retire-plan issue listed `s.registerResendRaw()` as "legacy direct H2". That was a transcription slip — `s.registerResendRaw()` (currently `internal/mcp/server.go:370`) is the **new typed** `resend_raw` MCP tool from USK-675 and is **kept**. The legacy direct-H2 path is the `resend_raw` *action* of the legacy `resend` tool, whose helpers live in `resend_raw_h2.go` (a helper file with no `register*` line of its own, called from `resend_tool.go`'s `resend_raw` action handler). No MCP tool is literally named `resend_raw_h2`. Likewise `s.registerFuzzRaw()` (currently L376) is the new typed `fuzz_raw` from USK-680 and is kept.

### USK-694 — legacy fuzzer engine (partial deletion)

The async legacy engine layered on top of `internal/fuzzer/` is removed, but
the position-application primitives (`Iterator`, `FuzzCase`, `Position`,
`RequestData`, `ApplyPosition`) survive — they are consumed by the typed
fuzz MCP tools via `internal/job/fuzz_http_source.go` (USK-677..USK-680:
`fuzz_http` / `fuzz_ws` / `fuzz_grpc` / `fuzz_raw`).

| Path | Action | Notes |
|---|---|---|
| `internal/fuzzer/control.go` + `_test.go` | delete file | Async concurrency limiter for the legacy engine. |
| `internal/fuzzer/engine.go` + `_test.go` | delete file | Top-level async fuzzer engine consumed only by the legacy `fuzz` MCP tool. |
| `internal/fuzzer/hooks.go` + `_test.go` | delete file | Legacy `HookCallbacks` / `HookState` plumbing for the async engine. |
| `internal/fuzzer/monitor.go` + `_test.go` | delete file | `OverloadMonitor` (token-bucket rate limiter / backpressure) for the legacy engine. |
| `internal/fuzzer/payload.go` + `_test.go` | delete file | Legacy `PayloadSet` / `ResolvePayloads` / `DefaultWordlistBaseDir` resolver. The typed tools resolve payloads in `internal/job/`. |
| `internal/fuzzer/runner.go` + `_test.go` | delete file | Per-case async runner (`HTTPDoer`, `FlowRecorder`, `FlowFetcher`) for the legacy engine. |
| `internal/fuzzer/safety_input_test.go` | delete file | Safety-input coverage for the deleted engine path. |
| `internal/fuzzer/iterator.go` + `_test.go` | **keep** | `Iterator` / `NewIterator` / `FuzzCase` — consumed by `internal/job/fuzz_http_source.go` for the typed fuzz path. |
| `internal/fuzzer/position.go` + `_test.go` | **keep** | `Position` / `RequestData` / `ApplyPosition` — consumed by `internal/job/fuzz_http_source.go` for the typed fuzz path. |
| `internal/fuzzer/doc.go` | add file | Package doc-comment narrowing the package's stated scope to position-application primitives only. |

### USK-695 — `internal/plugin/` deletion

The legacy `internal/plugin/` Starlark engine package is deleted in full (35 files: `engine.go`, `hook.go`, `registry.go`, `config.go`, `errors.go`, `convert.go`, `proxy.go`, `store.go`, `state.go`, `txctx.go`, `crypto.go`, `action.go`, `conninfo.go`, `httpconv.go`, `h2conv.go`, `rawconv.go`, `codec.go`, `doc.go`, and corresponding `*_test.go` files). The legacy 8-hook surface is gone.

Plus the following surface scrubs in keeper packages:

| Path | Action | Notes |
|---|---|---|
| `internal/mcp/plugin_tool.go` + `plugin_tool_test.go` | delete | Defined the legacy `plugin` MCP tool with actions `list`/`reload`/`enable`/`disable`. The `list` action is replaced by `plugin_introspect` (USK-676); the others have no replacement by design (RFC §9.3 D2). |
| `internal/mcp/server.go` `s.registerPlugin()` line | remove | Legacy `plugin` registration. `s.registerPluginIntrospect()` (the typed introspect tool) remains. |
| `internal/mcp/components.go::PluginEngine` | shrink | Drops `engine *plugin.Engine` field, retains `pluginv2 *pluginv2.Engine` only. `NewPluginEngine` signature changes from `(engine, pluginv2Engine)` to `(pluginv2Engine)`. |
| `internal/mcp/legacy_options_test.go` | scrub | Drops `pluginEngine` field on `legacyDeps` and the `WithPluginEngine` Option. Other Options (`WithFuzzStore`, `WithIssuer`, `WithDetector`, `WithSafetyEngine`, `WithPluginv2Engine`) are kept. |
| `internal/mcp/proxy_start_tool.go` | scrub | Drops `PluginEngine: s.pluginEngine.engine` from `proxy.TCPForwardParams`. |
| `internal/mcp/plugin_introspect.go` | scrub | Description string drops the back-reference to the legacy `plugin` tool. |
| `cmd/yorishiro-proxy/main.go` | scrub | Drops the `*plugin.Engine` import / field on `protocolResult` / dead-coded stub block (introduced as a stub by USK-687) / call to `mcp.NewPluginEngine(proto.pluginEngine, …)`. |
| `internal/connector/listener.go` | scrub | Drops `pluginEngine *plugin.Engine` field on `Listener` and `Connector`, `SetPluginEngine` / `PluginEngine()` accessors, and the legacy `dispatchOnConnect` / `dispatchOnDisconnect` methods. The pluginv2 path (`SetPluginV2Engine` / `dispatchV2OnConnect` / `dispatchV2OnDisconnect`) is the only lifecycle path. |
| `internal/connector/full_listener.go` | scrub | Drops `PluginEngine` config field and `dispatchOnConnect` / `dispatchOnDisconnect` methods. pluginv2 lifecycle hooks fan out via `proxybuild.Listener.wrapHandler`. |
| `internal/connector/coordinator.go` | scrub | Drops `PluginEngine` config field. |
| `internal/connector/socks5.go` | scrub | Drops `PluginEngine` field on `SOCKS5Negotiator` and the `dispatchOnSOCKS5Connect` method. pluginv2 `socks5.on_connect` fires from `connector/socks5_handler.go`. |
| `internal/connector/tunnel.go` | scrub | Drops `PluginEngine` field on `TunnelHandler`, `pluginHookDispatcher` type alias, and `dispatchOnTLSHandshake` method. pluginv2 `tls.on_handshake` fires from `connector/stack_builder.go`. |
| `internal/connector/socks5_test.go` + `tunnel_test.go` | trim | Delete the legacy hook tests. |
| `internal/proxy/{manager,listener,tcp_forward}.go` | scrub | Drops `PluginEngine` config and the legacy lifecycle dispatch methods. The package itself is deleted in USK-697. |
| `internal/proxy/listener_lifecycle_test.go` | delete | Whole-file delete (legacy lifecycle hook test). |
| `internal/protocol/{grpc,grpcweb,http,http2,socks5,tcp,ws}/handler.go` and supporting files | scrub | Drops `pluginEngine` fields, `SetPluginEngine` accessors, `dispatchOn*` methods, and call sites that fired the legacy 8 hooks during request/response processing. The packages themselves are deleted in USK-697. |
| `internal/protocol/http/plugin_hooks.go` + `plugin_hooks_test.go` | delete | Whole-file delete (legacy plugin hook helpers). |
| `internal/protocol/http2/plugin_hooks.go` + `plugin_hooks_test.go` | delete | Whole-file delete. |
| `internal/protocol/http2/grpc_subsystem.go` | scrub | Drops `applyGRPCPluginHook` / `applyGRPCResponsePluginHookH2`; safety filter and auto-transform pipeline retained. |
| `internal/protocol/http2/grpc_subsystem_test.go` | delete | Whole-file delete (covered legacy plugin path only). |
| `internal/protocol/{grpc,grpcweb,http,http2,socks5,tcp,ws}/*_test.go` legacy-plugin tests | delete | 10 files: `grpc/plugin_test.go`, `grpcweb/plugin_test.go`, `http/connect_lifecycle_test.go`, `http/plugin_hooks_test.go`, `http2/plugin_hooks_test.go`, `socks5/plugin_hook_test.go`, `tcp/handler_plugin_test.go`, `ws/handler_plugin_test.go`. Pluginv2 e2e parity (USK-691 livewire suite) covers the same scenarios. |
| `internal/protocol/http2/trailer_test.go::TestTrailers_PluginHook_*` | trim | Delete the legacy plugin hook trailer test only (other trailer tests retained). |
| `web/src/pages/Settings/PluginPanel.tsx` | delete | WebUI panel that consumed the legacy `plugin` MCP tool's `reload`/`enable`/`disable` actions. |
| `web/src/pages/Settings/SettingsPage.tsx` | scrub | Drops the `Plugins` tab entry and the `case "plugins"` switch arm. |
| `web/src/lib/mcp/client.ts`, `hooks.ts`, `types.ts` | scrub | Drops `client.plugin()` method, `usePlugin` hook + `UsePluginResult` interface, and the `PluginAction` / `PluginInfo` / `PluginToolParams` / `PluginListResult` / `PluginToggleResult` / `PluginReloadResult` type interfaces. The `PluginIntrospectResult` interface and `client.pluginIntrospect()` / `usePluginIntrospect()` (read-only, used by `/plugins` route) remain. |

### Coexistence note

Through N7/N8 + N9 batches 1-9 (USK-686..USK-694), both legacy and pluginv2 surfaces compiled and tested in parallel. After USK-695 ships (this PR), the legacy surface is gone. USK-696 collapses the connector Listener API, USK-697 deletes the now-orphan `internal/protocol/` and `internal/proxy/` trees, and USK-698 finalizes README/CHANGELOG with the user-facing snippet above.

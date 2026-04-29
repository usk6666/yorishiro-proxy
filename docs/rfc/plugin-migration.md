# Plugin Migration: Legacy Hooks → RFC-001 `register_hook`

**Status:** Draft (USK-665, 2026-04-29) · Companion to [`envelope.md` §9.3](envelope.md#93-starlark-plugin-api-shape--resolved)
**Audience:** authors of existing `internal/plugin/` Starlark scripts

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

## Status of related work

| Component | Issue | Status |
|-----------|-------|--------|
| Foundation: registry, `register_hook`, surface table | USK-665 | this PR |
| Message → snake-case Starlark dict + ordered headers + `msg["raw"]` | USK-669 | blocked by USK-665 |
| `ctx.transaction_state` / `ctx.stream_state` lifecycle | USK-670 | blocked by USK-665 |
| `PluginStepPre` / `PluginStepPost` Pipeline integration with resend bypass | USK-671 | blocked by USK-665 |
| `plugin_introspect` MCP tool | USK-676 | blocked by USK-665 |
| End-to-end plugin pipeline E2E suite | USK-681 | blocked by USK-665 |
| Legacy `internal/plugin/` deletion | N9 | gated on the above |

This document will be expanded as the downstream issues land. Final form ships with the N9 release notes.

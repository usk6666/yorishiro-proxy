---
description: "Scaffold, implement, and test Starlark plugins. From protocol/hook selection to running sample tests"
user-invokable: true
---

# /implement-plugin

A workflow skill for creating Starlark plugins. Interactively select protocols and hooks to generate a working scaffold.

## Arguments

- `/implement-plugin` — Create a plugin in interactive mode
- `/implement-plugin <description>` — Auto-generate a plugin from a description (e.g., `/implement-plugin Add X-Request-ID header to HTTP requests`)

## Steps

### Phase 1: Requirements Clarification

If no description argument is given, interactively confirm:

1. **Purpose**: What should the plugin do?
2. **Protocol**: Target protocol (http, https, h2, grpc, websocket, tcp, socks5)
3. **Hook**: Hook points to use
4. **Action**: CONTINUE (modify) / DROP (discard) / RESPOND (immediate response)

If a description argument is given, auto-determine from its content.

### Phase 2: Context Collection

Read the following to understand the plugin API:

1. `docs/plugins.md` — Plugin development guide (hook reference, data map, actions)
2. `examples/plugins/` — Existing sample plugins
3. `internal/plugin/engine.go` — Engine API (action constants, dispatch mechanism)
4. `internal/plugin/hook.go` — List of hook constants

### Phase 3: Plugin Generation

Create a plugin file in `examples/plugins/`:

- Filename: `<snake_case_name>.star`
- Include a comment at the top describing the purpose and configuration example
- Use protocol-specific data map keys correctly
- Use `action.CONTINUE` / `action.DROP` / `action.RESPOND` appropriately

#### Template Structure

```python
# <Plugin Name>
#
# Purpose: <description of purpose>
#
# Config:
#   protocol: "<protocol>"
#   hooks: [<hook list>]
#   on_error: "skip"

def <hook_name>(data):
    # Protocol: data["protocol"] == "<protocol>"
    # Available keys: <protocol-specific keys>

    return {"action": action.CONTINUE}
```

#### Protocol Data Map Quick Reference

| Protocol | Keys |
|----------|------|
| http/https | protocol, method, url, headers, body, status_code, conn_info |
| h2 | Same as above (protocol="h2") |
| grpc | protocol, method, url, headers, body, conn_info (observe-only) |
| websocket | protocol, opcode, payload, is_text, direction, conn_info |
| tcp | protocol, data, direction, conn_info, forward_target |
| socks5 | protocol, target_host, target_port, target, auth_method, auth_user, client_addr (observe-only, CONTINUE only) |

#### Action Constraints

| Action | Usable Hooks | Protocol Restrictions |
|--------|-------------|----------------------|
| CONTINUE | All hooks | None |
| DROP | on_receive_from_client | None |
| RESPOND | on_receive_from_client | HTTP/HTTPS/H2 only |

### Phase 4: Verification

1. Visually verify Starlark syntax (confirm compliance with `go.starlark.net` syntax rules)
2. Referring to existing test patterns, verify the plugin can be correctly loaded by the Engine:

```bash
make build
go test -v ./internal/plugin/ -run TestLoad
```

### Phase 5: Present Configuration Example

Present the PluginConfig for the generated plugin:

```json
{
  "path": "examples/plugins/<name>.star",
  "protocol": "<protocol>",
  "hooks": ["<hook1>", "<hook2>"],
  "on_error": "skip"
}
```

Also provide guidance on managing via the MCP plugin tool:

```json
// plugin tool: list
{"action": "list"}

// plugin tool: reload after editing
{"action": "reload", "params": {"name": "<name>"}}

// plugin tool: disable temporarily
{"action": "disable", "params": {"name": "<name>"}}
```

## Notes

- gRPC is observe-only. DROP/RESPOND cannot be used (CONTINUE only)
- SOCKS5 is observe-only. Only the `on_socks5_connect` hook, CONTINUE only. See sample: `examples/plugins/socks5_logger.star`
- WebSocket control frames (Close, Ping, Pong) skip plugin dispatch
- Plugin-modified TCP chunk size is limited to 1MB (original data used if exceeded)
- Lifecycle hooks (on_connect, on_tls_handshake, on_disconnect) have a 5-second timeout
- Starlark is a subset of Python. `import`, `class`, file I/O, and network access are not available
- `print()` outputs to the proxy log (for debugging)
- **Module-level variables are frozen after loading** — Mutable objects like lists or dicts placed at module level cannot be modified inside hook functions (runtime error). With `on_error: "skip"`, this is silently skipped, so be careful. Use only immutable values (strings, ints, tuples) at module level

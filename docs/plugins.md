# Plugin Development Guide

yorishiro-proxy supports user-defined plugins written in [Starlark](https://github.com/google/starlark-go), a Python-like language designed for configuration and extension. Plugins hook into the proxy pipeline to inspect, modify, or block traffic.

## Overview

Plugins are Starlark scripts (`.star` files) that define hook functions. When the proxy processes traffic, it calls the registered hooks in order, passing protocol-specific data as a dictionary. Each hook returns an action that controls how the proxy proceeds.

Key design principles:

- **Fail-open**: If a plugin errors at runtime, the default behavior (`on_error: "skip"`) skips that plugin and continues processing. Traffic is never silently blocked by a broken plugin unless `on_error: "abort"` is explicitly configured.
- **Sandboxed execution**: Starlark scripts run with a step limit (default: 1,000,000 steps) to prevent infinite loops. Scripts cannot access the filesystem, network, or other system resources.
- **Registration order**: Plugins are called in the order they are registered. A plugin's modifications are visible to subsequent plugins in the chain.

## Configuration

Plugins are configured via `PluginConfig` structs, typically loaded from a configuration file:

```json
{
  "plugins": [
    {
      "path": "examples/plugins/add_auth_header.star",
      "protocol": "http",
      "hooks": ["on_before_send_to_server"],
      "on_error": "skip",
      "max_steps": 1000000
    }
  ]
}
```

### PluginConfig Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | string | Yes | Filesystem path to the `.star` script |
| `protocol` | string | Yes | Protocol this plugin applies to: `http`, `https`, `h2`, `grpc`, `websocket`, `tcp` |
| `hooks` | string[] | Yes | List of hook function names to register |
| `on_error` | string | No | Error behavior: `"skip"` (default) or `"abort"` |
| `max_steps` | uint64 | No | Maximum Starlark execution steps per hook call (default: 1,000,000) |

## Writing Plugins

### Basic Structure

A plugin is a `.star` file that defines one or more hook functions. Each function receives a `data` dictionary and returns a result dictionary.

```python
def on_receive_from_client(data):
    # Inspect or modify the data
    url = data.get("url", "")
    print("Request to: %s" % url)

    # Return an action
    return {"action": action.CONTINUE, "data": data}
```

### The `action` Module

Every plugin has access to the predeclared `action` module with three constants:

| Constant | Description |
|----------|-------------|
| `action.CONTINUE` | Continue processing with the (optionally modified) data |
| `action.DROP` | Silently drop the connection (only in `on_receive_from_client`) |
| `action.RESPOND` | Send a custom response to the client (only in `on_receive_from_client`, HTTP/HTTPS only) |

### Return Format

Hook functions must return one of:

- `None` (or no explicit return) -- treated as `action.CONTINUE` with no modifications
- A dictionary with the following keys:

```python
# Continue with modified data
{"action": action.CONTINUE, "data": modified_data}

# Continue without modifications
{"action": action.CONTINUE}

# Drop the connection
{"action": action.DROP}

# Respond directly (HTTP/HTTPS only)
{
    "action": action.RESPOND,
    "response": {
        "status_code": 200,
        "headers": {"Content-Type": "application/json"},
        "body": '{"ok": true}',
    },
}
```

### Starlark Basics

Starlark is a subset of Python. Key differences from Python:

- No `import` statement (use the predeclared `action` module)
- No classes, only functions and basic data types
- Dictionaries, lists, tuples, strings, ints, floats, booleans, `None`
- `print()` outputs to the proxy log
- No file I/O, network access, or system calls

### Module-Level Freeze Constraint

**Important:** All module-level variables are **frozen** (immutable) after the script is loaded. Attempting to mutate a frozen value inside a hook function causes a runtime error.

```python
# BAD: _counter is frozen after load — mutating it raises an error.
_counter = [0]

def on_before_send_to_server(data):
    _counter[0] = _counter[0] + 1  # Runtime error: frozen list
    return {"action": action.CONTINUE}
```

With `on_error: "skip"` (the default), frozen-mutation errors are silently skipped, making them hard to diagnose. Use `on_error: "abort"` during development to surface these errors immediately.

Module-level **constants** (strings, ints, tuples) are safe because they are inherently immutable:

```python
# OK: immutable constants.
AUTH_TOKEN = "Bearer ..."
BLOCKED_PATHS = ("/admin", "/internal")
```

## Hook Reference

### Data Hooks

These hooks are called during request/response processing:

| Hook | When Called | Can DROP/RESPOND |
|------|------------|------------------|
| `on_receive_from_client` | After TargetScope evaluation, before Intercept | Yes |
| `on_before_send_to_server` | After Transform, before Recording | No (CONTINUE only) |
| `on_receive_from_server` | After receiving the server response, before Transform | No (CONTINUE only) |
| `on_before_send_to_client` | After Transform, before Recording | No (CONTINUE only) |

### Lifecycle Hooks

These hooks are called during connection lifecycle events:

| Hook | When Called | Can DROP/RESPOND |
|------|------------|------------------|
| `on_connect` | When a new TCP connection is accepted | No (CONTINUE only) |
| `on_tls_handshake` | After a TLS handshake completes | No (CONTINUE only) |
| `on_disconnect` | When a connection is closed | No (CONTINUE only) |
| `on_socks5_connect` | After a SOCKS5 CONNECT tunnel is established | No (CONTINUE only) |

## Protocol Data Map Reference

### HTTP / HTTPS

Hooks receive the following data keys for HTTP/1.x and HTTPS (MITM) traffic:

| Key | Type | Direction | Description |
|-----|------|-----------|-------------|
| `protocol` | string | Both | `"HTTP/1.x"` or `"HTTPS"` |
| `method` | string | Request | HTTP method (GET, POST, etc.) |
| `url` | string | Request | Full request URL |
| `headers` | dict | Both | HTTP headers as key-value pairs |
| `body` | string | Both | Request or response body |
| `status_code` | int | Response | HTTP response status code |
| `conn_info` | dict | Both | Connection metadata (see below) |

### HTTP/2

Same keys as HTTP/HTTPS, with:

| Key | Value |
|-----|-------|
| `protocol` | `"h2"` |

All other fields are identical to HTTP/HTTPS.

### gRPC

gRPC plugins operate in **observe-only** mode. Only `action.CONTINUE` is allowed.

| Key | Type | Direction | Description |
|-----|------|-----------|-------------|
| `protocol` | string | Both | `"grpc"` |
| `method` | string | Request | gRPC method path (e.g., `/package.Service/Method`) |
| `url` | string | Request | Same as method for gRPC |
| `headers` | dict | Both | gRPC metadata/headers |
| `body` | string | Both | Serialized protobuf message |
| `conn_info` | dict | Both | Connection metadata |

### WebSocket

| Key | Type | Direction | Description |
|-----|------|-----------|-------------|
| `protocol` | string | Both | `"websocket"` |
| `opcode` | int | Both | WebSocket frame opcode (1=text, 2=binary) |
| `payload` | string | Both | Message payload |
| `is_text` | bool | Both | `True` if the message is a text frame |
| `direction` | string | Both | `"client_to_server"` or `"server_to_client"` |
| `conn_info` | dict | Both | Connection metadata |

### TCP (Raw)

| Key | Type | Direction | Description |
|-----|------|-----------|-------------|
| `protocol` | string | Both | `"tcp"` |
| `data` | string | Both | Raw TCP data |
| `direction` | string | Both | `"client_to_server"` or `"server_to_client"` |
| `conn_info` | dict | Both | Connection metadata |
| `forward_target` | string | Both | Target address for TCP forwarding |

### SOCKS5

The `on_socks5_connect` hook is called when a SOCKS5 CONNECT tunnel is successfully established. It receives the following data:

| Key | Type | Description |
|-----|------|-------------|
| `event` | string | Always `"socks5_connect"` |
| `target_host` | string | Destination hostname (e.g., `"example.com"`) |
| `target_port` | int | Destination port (e.g., `443`) |
| `target` | string | Full destination address (e.g., `"example.com:443"`) |
| `auth_method` | string | Authentication method used: `"none"` or `"username_password"` |
| `auth_user` | string | Authenticated username (empty if `auth_method` is `"none"`) |
| `client_addr` | string | Remote address of the client |

Only `action.CONTINUE` is allowed; DROP and RESPOND are not supported.

Flows that pass through a SOCKS5 tunnel are recorded with protocol identifiers like `SOCKS5+HTTPS` or `SOCKS5+HTTP`, and include `socks5_target` and `socks5_auth_method` in their tags.

### Connection Info (`conn_info`)

The `conn_info` dictionary is available in all protocols:

| Key | Type | Description |
|-----|------|-------------|
| `client_addr` | string | Remote address of the client (e.g., `"192.168.1.100:54321"`) |
| `server_addr` | string | Resolved address of the upstream server |
| `tls_version` | string | Negotiated TLS version (e.g., `"TLS 1.3"`) |
| `tls_cipher` | string | Negotiated TLS cipher suite name |
| `tls_alpn` | string | Negotiated ALPN protocol |

## Actions

### CONTINUE

Continue processing with the (optionally modified) data. Valid in all hooks. If the returned dictionary contains a `"data"` key, its values are merged into the data map for subsequent plugins.

### DROP

Silently drop the connection. Only valid in `on_receive_from_client`. The proxy closes the client connection without sending a response.

### RESPOND (HTTP/HTTPS only)

Send a custom response directly to the client without forwarding to the upstream server. Only valid in `on_receive_from_client` for HTTP and HTTPS protocols.

The `response` dictionary must contain:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `status_code` | int | Yes | HTTP status code |
| `headers` | dict | No | Response headers |
| `body` | string | No | Response body |

## Fail-Open Behavior

By default (`on_error: "skip"`), if a plugin hook raises a runtime error:

1. The error is logged
2. The plugin is skipped
3. Processing continues with the next plugin in the chain

This ensures that a buggy plugin does not block traffic. To change this behavior, set `on_error: "abort"` in the plugin configuration. With `"abort"`, a runtime error stops the hook chain and returns an error to the caller.

## Example Plugins

### add_auth_header.star

Injects an Authorization header into every outgoing HTTP request:

```python
AUTH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiJ9.example"

def on_before_send_to_server(data):
    headers = data.get("headers", {})
    headers["Authorization"] = AUTH_TOKEN
    data["headers"] = headers
    return {"action": action.CONTINUE, "data": data}
```

**Config**: `protocol: "http"`, `hooks: ["on_before_send_to_server"]`

### grpc_logger.star

Logs all gRPC method calls for monitoring:

```python
def on_receive_from_client(data):
    method = data.get("url", "unknown")
    print("gRPC call: method=%s" % method)
    return {"action": action.CONTINUE}
```

**Config**: `protocol: "grpc"`, `hooks: ["on_receive_from_client"]`

### ws_filter.star

Drops WebSocket messages containing a blocked pattern:

```python
BLOCKED_PATTERN = "FORBIDDEN_COMMAND"

def on_receive_from_client(data):
    payload = data.get("payload", "")
    is_text = data.get("is_text", False)
    if is_text and BLOCKED_PATTERN in payload:
        return {"action": action.DROP}
    return {"action": action.CONTINUE}
```

**Config**: `protocol: "websocket"`, `hooks: ["on_receive_from_client"]`

### http_mock.star

Returns a mock response for requests to a specific path:

```python
MOCK_PATH = "/api/v1/health"

def on_receive_from_client(data):
    url = data.get("url", "")
    if MOCK_PATH in url:
        return {
            "action": action.RESPOND,
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": '{"status":"ok","mocked":true}',
            },
        }
    return {"action": action.CONTINUE}
```

**Config**: `protocol: "http"`, `hooks: ["on_receive_from_client"]`

### socks5_logger.star

Logs SOCKS5 tunnel establishment details:

```python
def on_socks5_connect(data):
    target = data.get("target", "unknown")
    auth_method = data.get("auth_method", "unknown")
    auth_user = data.get("auth_user", "")
    client_addr = data.get("client_addr", "unknown")

    if auth_user:
        print("SOCKS5 CONNECT: target=%s auth=%s user=%s client=%s" % (
            target, auth_method, auth_user, client_addr))
    else:
        print("SOCKS5 CONNECT: target=%s auth=%s client=%s" % (
            target, auth_method, client_addr))

    return {"action": action.CONTINUE}
```

**Config**: `protocol: "socks5"`, `hooks: ["on_socks5_connect"]`

## Custom Codec Plugins

In addition to protocol hook plugins, yorishiro-proxy supports **codec plugins** — Starlark scripts that define custom encode/decode transformations. These are registered alongside the 14 built-in codecs and can be used seamlessly in fuzzer, resender, and macro template encoding chains.

### How Codec Plugins Differ from Hook Plugins

| Aspect | Hook Plugins | Codec Plugins |
|--------|-------------|---------------|
| Purpose | Inspect/modify/block traffic | Define string transformations |
| Configuration | `plugins` section | `codec_plugins` section |
| Starlark API | Hook functions + action module | `name` variable + `encode`/`decode` functions |
| State | Stateless per hook call | Stateless (pure functions) |
| Execution limit | Configurable `max_steps` | Default 1,000,000 steps |

### Codec Plugin File Format

A codec plugin is a `.star` file that defines:

- `name` (string, required): The name used to reference this codec in encoding chains
- `encode(s)` (function, required): Takes a string, returns the encoded string
- `decode(s)` (function, optional): Takes a string, returns the decoded string. If not defined, decode operations return an error.

```python
# codecs/sql_escape.star
name = "sql_escape"

def encode(s):
    return s.replace("'", "''")

def decode(s):
    return s.replace("''", "'")
```

Encode-only codec (irreversible transformation):

```python
# codecs/rot13.star
name = "rot13"

_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_lower = "abcdefghijklmnopqrstuvwxyz"

def encode(s):
    result = []
    for c in s.elems():
        i = _upper.find(c)
        if i >= 0:
            result.append(_upper[(i + 13) % 26])
        else:
            i = _lower.find(c)
            if i >= 0:
                result.append(_lower[(i + 13) % 26])
            else:
                result.append(c)
    return "".join(result)
```

### Configuration

Codec plugins are configured in the `codec_plugins` section of the config file. Each entry specifies a `path` to a `.star` file or a directory containing `.star` files.

```json
{
  "codec_plugins": [
    {"path": "codecs/sql_escape.star"},
    {"path": "codecs/"}
  ]
}
```

- **File path**: Loads the specified `.star` file
- **Directory path**: Loads all `*.star` files in the directory (non-recursive)
- Paths are relative to the working directory

### Name Collision

If a codec plugin defines a `name` that conflicts with a built-in codec (e.g., `base64`, `url_encode_query`) or another already-loaded codec plugin, the proxy returns an error at startup. Choose unique names for custom codecs.

### Error Handling

| Error Type | Behavior |
|-----------|----------|
| Syntax error in `.star` file | Warning logged, codec skipped |
| Missing `name` variable | Warning logged, codec skipped |
| Missing `encode` function | Warning logged, codec skipped |
| `encode`/`decode` runtime error | Error propagated to the encoding chain caller |
| Infinite loop (exceeds step limit) | Execution halted, error returned |
| Name conflict with existing codec | Startup error |

### Using Custom Codecs

Once loaded, custom codecs are available everywhere built-in codecs are used:

**Fuzzer encoding chain:**

```json
{
  "action": "fuzz",
  "params": {
    "flow_id": "...",
    "targets": [{"location": "query", "name": "q"}],
    "payloads": {
      "type": "values",
      "values": ["admin'--", "' OR 1=1--"],
      "encoding": ["sql_escape", "url_encode_query"]
    }
  }
}
```

**Macro template:**

```
{{payload | sql_escape | url_encode_query}}
```

**Starlark `codec` module** (in hook plugins):

```python
# The codec module automatically includes custom codecs
encoded = codec.sql_escape("admin'--")   # "admin''--"
decoded = codec.sql_escape_decode("admin''--")  # "admin'--"

# Chain encoding also works
result = codec.encode("admin'--", ["sql_escape", "url_encode_query"])
```

## MCP Plugin Tool

The `plugin` MCP tool provides runtime management of loaded plugins.

### Actions

#### list

Returns all registered plugins with their metadata.

```json
{"action": "list"}
```

Response:

```json
{
  "plugins": [
    {
      "name": "add_auth_header",
      "path": "/path/to/add_auth_header.star",
      "protocol": "http",
      "hooks": ["on_before_send_to_server"],
      "enabled": true
    }
  ],
  "count": 1
}
```

#### reload

Reloads a plugin from disk. If `name` is empty, all plugins are reloaded.

```json
{"action": "reload", "params": {"name": "add_auth_header"}}
```

```json
{"action": "reload"}
```

The enabled/disabled state is preserved across reloads.

#### enable

Enables a previously disabled plugin.

```json
{"action": "enable", "params": {"name": "add_auth_header"}}
```

#### disable

Disables a plugin. Disabled plugins' hooks are skipped during dispatch.

```json
{"action": "disable", "params": {"name": "ws_filter"}}
```

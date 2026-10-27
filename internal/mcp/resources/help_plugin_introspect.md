# plugin_introspect

Return the list of loaded `pluginv2` plugins together with their `(protocol, event, phase)` `register_hook` registrations, the `PluginConfig.Vars` map after applying `redact_keys`, and how many of each plugin's hook outcomes **failed open** (were refused or could not be evaluated and were treated as `CONTINUE`).

Returns an empty list when the `pluginv2` engine is not configured.

Use it to self-verify a plugin setup: after sending traffic, a non-zero `fail_open_count` means a hook did not do what it returned — for example a "blocking" hook whose `action.RESPOND` was refused let the request through to the upstream.

## Parameters

`plugin_introspect` takes no parameters today. Pass an empty object.

## Result fields

- `plugins[]` — one entry per loaded plugin:
  - `name` (string): plugin's stable identifier (`PluginConfig.Name`, or the script basename). Not guaranteed unique — two scripts named `p.star` both report `"p"`; use `path` to tell them apart.
  - `path` (string): filesystem location of the plugin script
  - `enabled` (boolean): whether the engine considers the plugin live. All successfully loaded plugins are reported as enabled today.
  - `registrations[]` — each `register_hook` call the plugin made, in script order:
    - `protocol` (string): one of `"http"`, `"ws"`, `"grpc"`, `"grpc-web"`, `"sse"`, `"raw"`, `"tls"`, `"connection"`, `"socks5"`
    - `event` (string): e.g. `"on_request"`, `"on_response"`, `"on_upgrade"`, `"on_message"`, `"on_close"`, `"on_start"`, `"on_data"`, `"on_end"`, `"on_event"`, `"on_chunk"`, `"on_handshake"`, `"on_connect"`, `"on_disconnect"`
    - `phase` (string): `"pre_pipeline"`, `"post_pipeline"`, or `"none"` for lifecycle / observation-only events
  - `vars` (object): `PluginConfig.Vars` with `RedactKeys` applied. Keys named in `RedactKeys` carry the literal string `"<redacted>"`; large values are truncated by the engine.
  - `fail_open_count` (integer, always present): number of this plugin's hook outcomes that the engine refused or could not evaluate since the proxy process started. Every counted outcome was treated as `CONTINUE`: the message was forwarded as if the hook had not acted (for a refused RESPOND / DROP / size-cap hit, the hook's `msg` edits were discarded too). `0` when none.
  - `fail_open_by_kind` (object, omitted when `fail_open_count` is 0): `fail_open_count` broken down per `kind`.
  - `last_fail_open` (object, omitted when `fail_open_count` is 0): the most recent fail-open outcome:
    - `kind` (string): see the table below
    - `action` (string): the refused action (`"DROP"` / `"RESPOND"`) for `action_not_allowed` / `respond_*`; omitted otherwise
    - `protocol`, `event`, `phase` (string): the hook that produced it
    - `reason` (string): the engine's error text, passed through the SafetyFilter Output Filter and truncated to 256 bytes (an error text over 1 KiB also loses its last 128 bytes after masking, so a value cut in half is not shown). For `hook_error` it is the plugin's own error message.
    - `at` (string): RFC 3339 timestamp

### Fail-open kinds

| `kind` | Cause |
|--------|-------|
| `action_not_allowed` | The hook returned DROP / RESPOND for an event that does not accept it (e.g. DROP from `grpc.on_data`, RESPOND from `ws.on_message`, DROP from `ws.on_close`, DROP from `http.on_response`, RESPOND from `connection.on_connect`). |
| `respond_shape_mismatch` | `action.RESPOND` from a `grpc` / `grpc-web` hook, or `action.RESPOND_GRPC` from an `http` / `ws.on_upgrade` hook. Use the builtin matching the hook's protocol. |
| `respond_on_informational` | RESPOND on a 1xx response other than 101 (`http.on_response`). RESPOND on the final response instead. |
| `hook_error` | The hook raised a Starlark runtime error (`fail()`, an exception, the step budget). In-place `msg` edits made before the error are kept. |
| `hook_timeout` | The hook was still running when its deadline expired (lifecycle hooks such as `connection.on_connect`, `socks5.on_connect` and `tls.on_handshake` get 5 s), so it was cancelled and the connection / message went through. A hook cancelled because the connection was being torn down is not counted. |
| `invalid_return` | The hook returned a value that is not an action: a bare `"RESPOND"` string, another unrecognized string, or a value of another type. In-place `msg` edits are kept. |
| `invalid_mutation` | The hook's `msg` edits could not be turned back into a message (e.g. an out-of-range field value); all edits of that call were discarded. |
| `chunk_too_large` | A `raw.on_chunk` hook produced more than 1 MiB. |
| `body_too_large` | The message body exceeded the 1 MiB plugin view cap, so the hook was **not run** for that message. |
| `unsupported_message` | The message type has no plugin view, so the hook was not run. |
| `dispatch_error` | Any other dispatch error that made the engine skip the hook. |

Each hook call counts at most once (the first cause). Counters are per loaded plugin and last for the process lifetime; they are not reset.

Read `fail_open_by_kind`, not just the total: `body_too_large` and `unsupported_message` rise on ordinary traffic (e.g. any body over 1 MiB) even for an observe-only plugin. The kinds that mean a blocking decision was lost are `action_not_allowed`, `respond_shape_mismatch`, `respond_on_informational`, `hook_error`, `hook_timeout` and `invalid_return`.

## Examples

### List all loaded plugins
```json
{}
```

Response:
```json
{
  "plugins": [
    {
      "name": "auth-signer",
      "path": "/etc/yorishiro/plugins/auth.star",
      "enabled": true,
      "registrations": [
        {"protocol": "http", "event": "on_request", "phase": "post_pipeline"},
        {"protocol": "grpc", "event": "on_start", "phase": "post_pipeline"}
      ],
      "vars": {
        "issuer": "internal-ca",
        "secret": "<redacted>"
      },
      "fail_open_count": 0
    },
    {
      "name": "block-admin",
      "path": "/etc/yorishiro/plugins/block_admin.star",
      "enabled": true,
      "registrations": [
        {"protocol": "grpc", "event": "on_start", "phase": "pre_pipeline"},
        {"protocol": "ws", "event": "on_close", "phase": "none"}
      ],
      "fail_open_count": 3,
      "fail_open_by_kind": {"respond_shape_mismatch": 3},
      "last_fail_open": {
        "kind": "respond_shape_mismatch",
        "action": "RESPOND",
        "protocol": "grpc",
        "event": "on_start",
        "phase": "pre_pipeline",
        "reason": "pluginv2: hook returned disallowed action for this event: HTTP-shaped action.RESPOND cannot be rendered on (grpc, on_start); use action.RESPOND_GRPC",
        "at": "2026-10-27T09:12:44Z"
      }
    }
  ]
}
```

When no plugins are loaded or the engine is not configured:
```json
{
  "plugins": []
}
```

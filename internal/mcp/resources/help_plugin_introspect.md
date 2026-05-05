# plugin_introspect

Return the list of loaded `pluginv2` plugins together with their `(protocol, event, phase)` `register_hook` registrations and the `PluginConfig.Vars` map after applying `redact_keys`.

Returns an empty list when the `pluginv2` engine is not configured.

## Parameters

`plugin_introspect` takes no parameters today. Pass an empty object.

## Result fields

- `plugins[]` — one entry per loaded plugin:
  - `name` (string): plugin's stable identifier
  - `path` (string): filesystem location of the plugin script
  - `enabled` (boolean): whether the engine considers the plugin live. All successfully loaded plugins are reported as enabled today.
  - `registrations[]` — each `register_hook` call the plugin made, in script order:
    - `protocol` (string): e.g. `"http"`, `"ws"`, `"grpc"`, `"sse"`, `"raw"`, `"tls-handshake"`
    - `event` (string): e.g. `"on_request"`, `"on_response"`, `"on_send"`, `"on_receive"`, `"on_open"`, `"on_close"`, `"on_start"`, `"on_data"`, `"on_end"`, `"on_handshake"`
    - `phase` (string): e.g. `"pre"`, `"post"`, `"observe"`
  - `vars` (object): `PluginConfig.Vars` with `RedactKeys` applied. Keys named in `RedactKeys` carry the literal string `"<redacted>"`; large values are truncated by the engine.

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
        {"protocol": "http", "event": "on_request", "phase": "post"},
        {"protocol": "grpc", "event": "on_start", "phase": "post"}
      ],
      "vars": {
        "issuer": "internal-ca",
        "secret": "<redacted>"
      }
    },
    {
      "name": "log-headers",
      "path": "/etc/yorishiro/plugins/log.star",
      "enabled": true,
      "registrations": [
        {"protocol": "http", "event": "on_request", "phase": "observe"},
        {"protocol": "http", "event": "on_response", "phase": "observe"}
      ]
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

# resend_raw

Resend a recorded raw byte payload via a freshly dialled TCP (or TLS) upstream connection. Schema fields mirror `envelope.RawMessage` so AI agents address arbitrary TCP / TLS-passthrough payloads by raw byte content (with optional offset-based patches) instead of a typed L7 shape.

This is the smuggling-and-anomaly-test surface — the wire bytes ARE the message, and the proxy is forbidden from normalising them anywhere on the path.

`resend_raw` is the typed N7/N8 successor to the legacy raw resend tools.

## Pipeline placement (RFC-001 §9.3)

The resend traverses `PluginStepPost -> RecordStep`. `PluginStepPre` and `InterceptStep` are bypassed.

## Wire fidelity invariant

Wire bytes (`override_bytes`, `patches[].data`, recovered `Flow.RawBytes`) reach the wire VERBATIM. CR/LF guards or any other content-level normalization are NEVER applied to payloads. Schema-level CR/LF guards apply ONLY to `target_addr` / `sni` (where a CR/LF would smuggle a second TCP-layer connection through any intermediate that reads them line-oriented).

## Mode: replay-only

`flow_id` is REQUIRED. Unlike `resend_http` / `resend_ws` / `resend_grpc` which support a from-scratch path, raw resend always recovers the original wire bytes from a recorded `RawMessage` Flow. Ad-hoc byte injection without a recorded flow belongs to **`fuzz_raw`**.

## Parameters

### flow_id (string, REQUIRED)
Recorded raw stream id. resend_raw has no from-scratch path.

### target_addr (string, REQUIRED)
Upstream `host:port`. Explicit port is REQUIRED — there is no port defaulting because raw is protocol-agnostic. CR/LF rejected.

### use_tls (boolean, optional)
Set `true` to upgrade the dialed connection to TLS via `tlslayer.Client`.

### sni (string, optional)
SNI server name. Defaults to the host portion of `target_addr` when `use_tls=true`. CR/LF rejected.

### override_bytes (string, optional)
Replacement payload interpreted per `override_bytes_encoding`. Mutually exclusive with `patches`.

### override_bytes_encoding (string, optional)
`"text"` (default) or `"base64"`. base64 is required for binary smuggling payloads with control bytes.

### override_bytes_set (boolean, optional)
Set `true` to replace with empty bytes. Otherwise an empty `override_bytes` string is treated as no override.

### patches (array, optional)
Offset-based byte patches applied to the recovered bytes. Mutually exclusive with `override_bytes`. Each entry has:
- **offset** (integer, REQUIRED): zero-based byte offset in the recovered payload.
- **data** (string, REQUIRED): replacement bytes interpreted per `data_encoding`.
- **data_encoding** (string, optional): `"text"` (default) or `"base64"`.

### insecure_skip_verify (boolean, optional)
Skip TLS server certificate verification when `use_tls=true`.

### tls_fingerprint (string, optional)
Informational v1; per-call selection deferred.

### timeout_ms (integer, optional)
Per-call timeout covering dial+handshake+send+receive. Default `30000`.

### tag (string, optional)
Tag stored on the new flow's `Tags` map.

## Result fields

- `stream_id` — new Stream record holding send Flow + every received chunk Flow
- `response_bytes` — concatenated payload across all received bytechunk envelopes (always base64; raw bytes are binary by definition)
- `response_size` — total received byte count
- `response_chunks` — envelope count for callers who want segmentation shape without per-chunk schema
- `truncated` — `true` when the receive loop hit the per-call response cap before upstream closed
- `duration_ms` / `tag`

## Examples

### Replay recorded raw bytes verbatim
```json
{
  "flow_id": "raw-abc-123",
  "target_addr": "target.example.com:443",
  "use_tls": true
}
```

### Replay with full payload override (smuggling test)
```json
{
  "flow_id": "raw-abc-123",
  "target_addr": "target.example.com:443",
  "use_tls": true,
  "override_bytes": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IHRhcmdldA0KQ29udGVudC1MZW5ndGg6IDANCg0K",
  "override_bytes_encoding": "base64"
}
```

### Replay with offset-based patch (modify a single byte at offset 16)
```json
{
  "flow_id": "raw-abc-123",
  "target_addr": "target.example.com:443",
  "use_tls": true,
  "patches": [
    {"offset": 16, "data": "QQ==", "data_encoding": "base64"}
  ]
}
```

### Replay over plain TCP without TLS
```json
{
  "flow_id": "raw-abc-123",
  "target_addr": "127.0.0.1:8080"
}
```

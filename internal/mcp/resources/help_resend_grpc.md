# resend_grpc

Resend a gRPC RPC via a freshly dialled HTTP/2 upstream connection. Schema fields mirror `envelope.GRPCStartMessage` / `envelope.GRPCDataMessage` / `envelope.GRPCEndMessage` so AI agents address gRPC RPCs by structured event (Start headers, Data LPMs, optional End trailers) instead of round-tripping an opaque `message_sequence` index.

`resend_grpc` is the typed N7/N8 successor to the legacy multi-protocol `resend` tool. It restricts itself to native gRPC flows; non-gRPC `flow_id`s are rejected with an explicit pointer to `resend_http` / `resend_ws` / `resend_raw`.

## Pipeline placement (RFC-001 §9.3)

Each envelope (Start, every Data, optional End) traverses `PluginStepPost -> RecordStep`. `PluginStepPre` and `InterceptStep` are bypassed. `End` is observation-only — the surface table marks `("grpc","on_end") = PhaseSupportNone`.

## Upstream connection

A fresh TCP (+ TLS for `grpcs` / `scheme=https`) dial -> HTTP/2 Layer in `ClientRole` (no `net/http`) -> `http2.Layer.OpenStream` -> `grpclayer.Wrap` (`RoleClient`). The gRPC Layer's Send path translates GRPCStart/Data/End envelopes into the underlying H2 HEADERS / DATA / TRAILERS frames.

## End semantics

- When `trailer_metadata` is omitted (the common case): the trailing `GRPCDataMessage` carries `EndStream=true`. The request-side stream terminates via `END_STREAM` on the last DATA frame. This matches the standard gRPC client convention.
- When `trailer_metadata` is supplied: the trailing `GRPCDataMessage` keeps `EndStream=false` and a `GRPCEndMessage` envelope is sent afterwards. The Layer emits the trailer HEADERS frame with `END_STREAM` — a non-standard but diagnostic-useful Send-direction trailer (recorded as Direction=Send under `AnomalyUnexpectedGRPCWebRequestTrailer`).

## Two operating modes

### Mode A: replay a recorded flow (`flow_id` set)

The original RPC's send-direction GRPCStart Flow supplies `service` / `method` / `metadata` / `encoding`; the receive-direction GRPCStart Flow supplies the negotiated upstream encoding hint for `accept_encoding` defaulting. User-supplied fields override on a per-field basis.

### Mode B: from-scratch (`flow_id` empty)

`target_addr`, `service`, and `method` are REQUIRED. No encoding state is inherited.

## Parameters

### flow_id (string, optional)
Recorded gRPC stream id. When set, omitted Start fields and the encoding hint are inherited.

### target_addr (string, conditional)
Upstream `host:port`. REQUIRED when `flow_id` is empty. When supplied with `flow_id`, redirects the dial target while preserving the recovered `:authority`.

### scheme (string, optional)
`"http"` or `"https"`. Defaults to `"https"`. `"http"` selects plaintext h2c.

### service (string, conditional)
gRPC service name (e.g. `"pkg.Greeter"`). Required when `flow_id` is empty.

### method (string, conditional)
gRPC method name (e.g. `"SayHello"`). Required when `flow_id` is empty.

### metadata (array of `{name, value}`, optional)
Ordered metadata list. Preserves wire case, order, and duplicates per RFC-001 §3.1 wire-fidelity.

### encoding (string, optional)
`grpc-encoding` for outgoing messages. One of `"identity"` or `"gzip"`.

### accept_encoding (array of strings, optional)
`grpc-accept-encoding` list (e.g. `["gzip","identity"]`).

### messages (array, optional)
Request-side LPM (length-prefixed message) list. At least one element required. Each element has:
- **payload** (string, REQUIRED): LPM payload interpreted per `body_encoding`.
- **body_encoding** (string, optional): `"text"` (default), `"base64"`, `"proto-schemaless-json"`, or `"proto-json"`.
- **compressed** (boolean, optional): Set the LPM compression flag. Requires `encoding` to be set (recovered from flow or user-supplied).

An RPC with zero DATA frames is not well-formed and is rejected.

#### body_encoding values

- `"text"` (default): the payload is the raw proto bytes as UTF-8 (may contain control characters and is rarely human-readable).
- `"base64"`: the payload is base64-encoded raw proto bytes. Useful when copying `body` from `query messages` for a gRPC flow that came back as `body_encoding="base64"`.
- `"proto-schemaless-json"` (USK-922): the payload is a JSON object produced by `query.decode_bodies=true` (or hand-written following the same key format). The proxy re-encodes it to proto wire bytes via `internal/encoding/protobuf.Encode` before LPM-framing. JSON keys follow the format `"<fieldNumber hex>:<ordinal hex>:<wireType>"` — for example `"0001:0000:String"`, `"0002:0001:Varint"`, `"0003:0002:embedded message"`, `"0004:0003:repeated"`, `"0005:0004:bytes"`, `"0006:0005:64-bit"`, `"0007:0006:32-bit"`. Embedded messages are nested JSON objects; repeated is a JSON array of integers; bytes is a colon-separated hex string. The size cap (16 MiB) is enforced AFTER encoding, not on the JSON input.
- `"proto-json"` (USK-923): the payload is a JSON object with the original `.proto` field names. Requires a schema previously registered for this `(service, method)` via the `grpc_schema` tool — see `yorishiro://help/grpc_schema`. Re-encoded via `protoreflect.DynamicMessage` + `protojson.UnmarshalOptions{DiscardUnknown:true}`; JSON keys not in the schema are silently dropped, type mismatches still hard-error. **Lossy:** wire fields not in the schema are dropped on encode — when the resend includes a `flow_id` and the source flow's wire bytes carried unknowns, the response surfaces a non-fatal `warnings[]` entry suggesting `proto-schemaless-json` / `base64` for lossless round-trip.

> **Heuristic ambiguity caveat (schemaless)**: the schemaless decoder picks `String` / `embedded message` / `repeated` / `bytes` by inspection of the wire bytes — there is no `.proto` schema. The same wire payload may decode as `embedded message` in one envelope and `bytes` in another (visually similar wire encodings). For predictable round-tripping, keep the `body_encoding="base64"` form of the bytes that came out of `query` and only switch to `proto-schemaless-json` when you intend to mutate the JSON. Or register a `.proto` schema via the `grpc_schema` tool and use `proto-json` for unambiguous, real-field-name JSON.

### trailer_metadata (array of `{name, value}`, optional)
Optional Send-direction trailer HEADERS. When supplied, the request terminates via a trailer frame instead of `END_STREAM` on the last DATA.

### timeout_ms (integer, optional)
Per-call timeout covering dial+handshake+send+receive. Default `30000`.

### tls_fingerprint (string, optional)
Informational v1; per-call selection deferred.

### tag (string, optional)
Tag stored on the new flow's `Tags` map.

## Result fields

- `stream_id` — new Stream record holding send Flows (Start + Data*) and receive Flows (Start + Data* + End)
- `start_metadata` — ordered `[{name, value}]` from the response GRPCStart
- `messages[]` — decoded response Data LPMs (`payload`, `payload_encoding`, `compressed`). The gRPC Layer always decompresses for inspection convenience; original wire bytes preserved on `Flow.RawBytes`.
- `end` — optional. Contains `status` (gRPC code; 0 = OK), `message`, and `trailers` (excluding `grpc-status`, `grpc-message`, `grpc-status-details-bin`). May be `null` when the upstream terminated without a trailer HEADERS frame — diagnostic callers should treat that as "abnormal termination observed; no trailer received".
- `duration_ms` / `tag`

## Examples

### Replay a recorded RPC with a different request body
```json
{
  "flow_id": "grpc-abc-123",
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ]
}
```

### From-scratch unary RPC
```json
{
  "target_addr": "grpc.target.com:443",
  "scheme": "https",
  "service": "pkg.Greeter",
  "method": "SayHello",
  "metadata": [
    {"name": "authorization", "value": "Bearer ..."},
    {"name": "x-request-id", "value": "abc-123"}
  ],
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ]
}
```

### Plaintext h2c with custom request trailer (diagnostic)
```json
{
  "target_addr": "127.0.0.1:50051",
  "scheme": "http",
  "service": "pkg.Greeter",
  "method": "SayHello",
  "messages": [
    {"payload": "CgVhbGljZQ==", "body_encoding": "base64"}
  ],
  "trailer_metadata": [
    {"name": "x-trailer-test", "value": "diagnostic"}
  ]
}
```

### Replay with gzip-encoded request message
```json
{
  "flow_id": "grpc-abc-123",
  "encoding": "gzip",
  "accept_encoding": ["gzip", "identity"],
  "messages": [
    {"payload": "H4sI...", "body_encoding": "base64", "compressed": true}
  ]
}
```

### Replay with a schemaless-proto JSON payload (USK-922)
Feeding the same JSON shape that `query.decode_bodies=true` returns under `*_body_decoded`. The proxy re-encodes via `internal/encoding/protobuf.Encode` before LPM-framing.
```json
{
  "flow_id": "grpc-abc-123",
  "messages": [
    {
      "payload": "{\"0001:0000:String\":\"hi from resend\"}",
      "body_encoding": "proto-schemaless-json"
    }
  ]
}
```

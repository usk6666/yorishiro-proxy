# grpc_schema

Manage .proto schemas for schema-aware gRPC decode (query) and encode (resend_grpc).

Once a schema is registered, the `query` tool decodes matching gRPC Data envelopes as protojson with the real `.proto` field names (`body_decoded_encoding="proto-json"`), and the `resend_grpc` tool accepts `body_encoding="proto-json"` for the messages array. Schemaless fallback always applies when no schema matches the flow's `(grpc_service, grpc_method)`.

## Parameters

### action (string, required)
One of: `register`, `list`, `unregister`, `clear`.

### params (object)
Action-specific parameters.

## Actions

### register
Upsert a service from either a precompiled protobuf `FileDescriptorSet` (recommended) or a list of `.proto` files compiled by a host `protoc` binary. Last-write-wins: re-registering a service replaces every method's input/output binding.

Two source modes are available:

#### Descriptor-set source (`source="descriptor_set"`, recommended)

Generate the descriptor set on the operator machine with:

```
protoc --include_imports --descriptor_set_out=schema.desc <protos>
```

The `--include_imports` flag is required — without it, transitive imports stay unresolved and `register` rejects the payload with an explicit error.

Then read `schema.desc` and pass the base64-encoded bytes:

**Parameters:**
- **source** (string, optional): `"descriptor_set"` or omitted (the default).
- **descriptor_set_b64** (string, required): Base64-encoded FileDescriptorSet payload. Max 16 MiB after base64 decode.
- **service_filter** (array of strings, optional): Fully-qualified service names to register. Empty means register every service the descriptor declares. Names not found in the descriptor produce an error.
- **source_label** (string, optional): Free-form label preserved in `list` output (filename hint, version tag, etc.).

This is the recommended path because it does not require `protoc` on the proxy host.

#### File source (`source="file"`)

The proxy invokes a host `protoc` binary to compile a list of absolute `.proto` paths into a FileDescriptorSet on the operator's behalf.

**Parameters:**
- **source** (string, required for this mode): `"file"`.
- **proto_paths** (array of strings, required): Absolute paths to the `.proto` files to compile. Each path must be canonical (no `..`, no double-slashes) and resolve under the proxy's working directory or one of `import_paths`. Symlinks are followed; the resolved target must also fall under the allowed roots.
- **import_paths** (array of strings, optional): Absolute `-I` roots for protoc. Defaults to the parent directory of each proto path.
- **service_filter**, **source_label**: Same semantics as the descriptor-set source. When `source_label` is omitted, it defaults to a comma-joined list of proto-file basenames.

`protoc` is invoked with `--include_imports` and a 30-second timeout. The environment is reduced to `PATH` only. By default the binary is resolved against `PATH` as `protoc`; configure an explicit path via `ProxyConfig.GRPCSchema.ProtocBinary` (config file) or the `YP_PROTOC_BINARY` environment variable. If `protoc` is missing, the call returns an install hint.

**Recommended default**: prefer `source="descriptor_set"`. The file path is provided for environments where invoking `protoc` server-side is acceptable; the descriptor-set path keeps the proxy free of an out-of-process compiler dependency.

Returns: `registered[]` — list of `{ service, methods: [{name, input, output}], source_label, registered_at }`.

### list
Return every currently registered schema, ordered alphabetically by service name.

Returns: `schemas[]` — same entry shape as `register`'s `registered[]`.

### unregister
Remove a single service from the registry. Methods owned by that service stop matching the schema-aware path; the schemaless fallback resumes.

**Parameters:**
- **service** (string, required): Fully-qualified service name to remove.

Returns: `{ service, unregistered }`.

### clear
Remove every registered schema.

Returns: `{ cleared }` — number of rows deleted from persistent storage.

## Usage Examples

### Register a descriptor set
```json
{
  "action": "register",
  "params": {
    "source": "descriptor_set",
    "descriptor_set_b64": "Cg<...base64 bytes...>",
    "service_filter": ["pkg.Greeter"],
    "source_label": "greeter@v1.2.0"
  }
}
```

### Register from .proto files (host protoc)
```json
{
  "action": "register",
  "params": {
    "source": "file",
    "proto_paths": ["/srv/protos/greeter.proto"],
    "import_paths": ["/srv/protos"],
    "service_filter": ["pkg.Greeter"]
  }
}
```

### List
```json
{ "action": "list" }
```

### Unregister a service
```json
{
  "action": "unregister",
  "params": { "service": "pkg.Greeter" }
}
```

### Clear all
```json
{ "action": "clear" }
```

## Decode path (query)

When `query` is invoked with `decode_bodies=true` (the default) and the flow's metadata carries `grpc_service` + `grpc_method`, the proxy:

1. Looks up the (service, method) pair in the registered schemas.
2. **Hit:** decodes the body via `protoreflect.DynamicMessage` + `protojson`, returns `body_decoded_encoding="proto-json"` with real field names. The `protojson` marshaller uses `UseProtoNames=true` and `EmitUnpopulated=false` so the output matches the `.proto` definition.
3. **Hit, parse failure:** falls back to the schemaless path AND surfaces `body_decode_anomaly{Type:"proto_schema_mismatch"}` so the caller can correlate the failure.
4. **Miss:** falls back to the existing schemaless decode (`body_decoded_encoding="proto-schemaless-json"`) — unchanged from USK-922.

Output Filter (PII masking, RFC-001 §3.7) applies identically to the protojson output.

## Encode path (resend_grpc)

The `resend_grpc` tool gains a new `body_encoding="proto-json"` value:

```json
{
  "flow_id": "<recorded gRPC stream>",
  "messages": [
    {
      "body_encoding": "proto-json",
      "payload": "{\"f_string\":\"hello\",\"f_int32\":42}"
    }
  ]
}
```

The payload JSON is parsed against the registered schema's input descriptor for `(service, method)`, encoded to proto wire bytes via `proto.Marshal`, then LPM-framed by the gRPC Layer.

`protojson.UnmarshalOptions{DiscardUnknown:true}` is applied — JSON keys not in the schema are silently dropped (so AI-typoed field names produce a message with the field absent rather than a hard error). Type mismatches (string for int32, etc.) still fail.

**No schema registered:** `body_encoding="proto-json"` returns a hard error pointing at the `grpc_schema register` command.

## Lossy round-trip

`protojson.Marshal` drops fields not in the schema. A decode → user edit → encode round-trip via `proto-json` therefore **loses any wire field not present in the registered `.proto`** — both unknown fields and protocol-level extensions.

The resend tool inspects the source flow's bytes (when `flow_id` is supplied) against the registered schema and emits a non-fatal `warnings[]` entry if the source carried fields outside the schema:

```
"warnings": [
  "source flow message 0 carries fields not in the registered schema; proto-json round-trip will drop those bytes — consider body_encoding=base64 or proto-schemaless-json for lossless preservation"
]
```

For lossless round-trips, use `body_encoding="proto-schemaless-json"` (synthetic-key JSON via `internal/encoding/protobuf`) or `body_encoding="base64"`.

## Caveats and limits

- **Last-write-wins.** Re-registering a service replaces its previous binding. The `list` output shows the most recent registration for each service.
- **Persistence.** Registrations survive process restart via the `grpc_schemas` SQLite table.
- **`source="file"` requires a host `protoc`.** The recommended path is still `source="descriptor_set"`: run `protoc --include_imports --descriptor_set_out=…` on the operator machine and pass the base64-encoded bytes. Use the file path only when invoking `protoc` server-side is acceptable in your environment. The proxy resolves the binary from `YP_PROTOC_BINARY` → `ProxyConfig.GRPCSchema.ProtocBinary` → `PATH:protoc`.
- **Reflection-based discovery is not supported.** Server-reflection auto-discovery is deferred to a follow-up Issue.
- **Case-sensitive lookup.** Protobuf service/method identifiers are case-sensitive per spec. The lookup against `Flow.Metadata["grpc_service"]` / `["grpc_method"]` is exact-match.
- **Output Filter still applies.** PII patterns (credit cards, etc.) configured in the safety engine mask the protojson output before it leaves the MCP boundary.

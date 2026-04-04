# Architecture Rewrite: Codec + Pipeline + Session (M36-M44)

This document captures the design decisions and implementation guidance for the yorishiro-proxy architecture rewrite. **All agents working on M36-M44 must read this document before implementation.**

## 1. Why: The Problem

The current architecture has two structural issues:

### 1.1 Pipeline Duplication

Each protocol handler (HTTP/1.x, HTTP/2, WebSocket, TCP) independently reimplements the same cross-cutting pipeline:

```
TargetScope → Safety → Plugin → Intercept → Transform → Record
```

HTTP/1.x handler has ~14 pipeline steps hand-written across handler.go, request_steps.go, plugin_hooks.go, recording.go. HTTP/2 handler reimplements the same ~14 steps independently. Adding or modifying a pipeline step requires changes in every handler.

### 1.2 Responsibility Confusion in internal/protocol/

`internal/protocol/` contains three fundamentally different kinds of things at the same level:

| Kind | Who | Has Handle(ctx, conn)? |
|------|-----|----------------------|
| Connection handlers | http, http2, socks5, tcp | Yes (registered in Detector) |
| Sub-protocol handlers | ws, grpc, grpcweb | No (called from parent handler's if-branch) |
| Shared utilities | httputil, detect.go | N/A |

gRPC doesn't receive a `net.Conn` — HTTP/2 handler calls it when Content-Type matches. WebSocket is called by HTTP/1.x handler on Upgrade header. These are not "protocols" in the same sense, but they live at the same directory level.

## 2. What: The New Architecture

```
connector/       Accept connections, detect transport, route
                 (Listener, Protocol Detection, TLS MITM, SOCKS5)
                        |
                        v
session/         RunSession(client Codec, dial, pipeline)
                 Two goroutines: client->upstream, upstream->client
                 Same loop for ALL protocols
                        |
                        v
codec/           Wire bytes <-> Exchange conversion
                 Protocol-specific. Handles Upgrade internally
                        |
                        v
pipeline/        Step[] operating on Exchange
                 Protocol-agnostic. No protocol knowledge
                        |
                        v
job/             Execution unit for resend/fuzz
                 Manages Macro hooks (pre-send, post-receive)
                 Uses same RunSession internally
```

### 2.1 Component Relationships

```
                    +-----------+
                    | Connector |
                    +-----+-----+
                          | creates Codec pair, calls RunSession
                          v
            +-------------+-------------+
            |         RunSession         |
            |  (single universal loop)   |
            +--+----------------------+--+
               |                      |
   client.Next()                upstream.Next()
               |                      |
         +-----v-----+        +------v------+
         | Client     |        | Upstream    |
         | Codec      |        | Codec       |
         +-----+------+        +------+------+
               |                      |
               +----> Pipeline <------+
                    (Step chain)

            +-------------+
            |     Job      |  (resend/fuzz only)
            | pre-send macro -> RunSession -> post-receive macro
            +-------------+
```

### 2.2 Data Flow

```
Wire bytes
  -> Codec.Next()
    -> Exchange (protocol-agnostic message)
      -> Pipeline.Run(exchange)
        -> Each Step: Scope -> RateLimit -> Safety -> Plugin(recv)
           -> Intercept -> Transform -> Plugin(send) -> Record
      -> Modified Exchange (or Drop/Respond)
    -> Codec.Send(exchange)
  -> Wire bytes
```

## 3. Key Design Decisions

### 3.1 Everything is a Stream

There is no `RunStreamSession` vs `RunSession` distinction. **All protocols use the same RunSession**, which always runs two goroutines (client->upstream, upstream->client).

- HTTP/1.x unary: goroutine 2 blocks on `upstream.Next()` until goroutine 1 sends the request
- WebSocket / gRPC streaming: both goroutines run freely
- SSE: goroutine 1 sends 1 request then blocks, goroutine 2 streams events
- TCP: both goroutines stream chunks

**Rationale:** Unary HTTP is "a stream with 1 Send and 1 Receive". Removing the distinction eliminates a branching point and makes the session loop trivially simple.

### 3.2 Direction is Send/Receive (not Request/Response)

```go
const (
    Send    Direction = iota  // client -> server
    Receive                    // server -> client
)
```

**Rationale:** Request/Response is HTTP-centric vocabulary. WebSocket frames and TCP chunks don't have "requests". Send/Receive is protocol-agnostic.

### 3.3 Codec Handles Upgrade Internally

When an HTTP/1.x Codec detects `Upgrade: websocket`, it internally switches to a WebSocket parser. Session loop doesn't know this happened — it just keeps calling `Next()` and getting Exchanges.

**Rationale:** If Session handles Upgrade, protocol knowledge leaks into Session. Each Codec knows its own wire format and can detect upgrades by reading headers — the most accurate and autonomous approach.

Application protocol detection:
- **WebSocket**: HTTP/1.x Codec detects `Upgrade: websocket` header + 101 response
- **gRPC**: HTTP/2 Codec detects `Content-Type: application/grpc`
- **gRPC-Web**: HTTP/1.x or HTTP/2 Codec detects `Content-Type: application/grpc-web`
- **SSE**: HTTP/1.x Codec detects response `Content-Type: text/event-stream`

### 3.4 gRPC Always Uses Codec Switch

A proto-less MITM proxy cannot distinguish unary vs streaming gRPC at the start of a stream. The Codec always switches to gRPC message-level parsing. Unary is just "a stream with 1 message".

**Rationale:** Avoids a detection branch that would require schema knowledge the proxy doesn't have.

### 3.5 Exchange is a View, Opaque is Source of Truth

Exchange.Headers (`[]KeyValue`) is a read-friendly view for Pipeline Steps. The real protocol-specific data lives in Exchange.Opaque (e.g., `*RawRequest` for HTTP/1.x, `*h2Request` for HTTP/2).

When Codec.Send() is called:
1. Extract protocol-specific type from Exchange.Opaque
2. Detect diff between original headers and Exchange.Headers
3. Apply diff to protocol-specific type (preserving order, casing)
4. Serialize protocol-specific type to wire

**Rationale:** Wire fidelity. If Pipeline changes a header, only that header changes. Everything else (order, casing, whitespace) is preserved exactly as observed on the wire.

### 3.6 Macro is NOT a Pipeline Step

Macro is a **Job-level hook** for resend/fuzz operations. It does not apply to normal proxy traffic.

```
Normal proxy:  Connector -> RunSession(client Codec, dial, pipeline)
               No macros. No Job.

Resend/Fuzz:   Job(ExchangeSource, dial, pipeline, macro hooks).Run()
               pre-send macro -> template expand -> RunSession -> post-receive macro
```

**Rationale:**
- Macros are specified per-Job, not globally
- RunInterval (once, every_n, on_error, on_status) is job-level state
- Post-receive runs after Pipeline completes
- Macros are inherently stateful (KV Store)

Macro internal requests use `Pipeline.Without(InterceptStep)` — all other Steps (Scope, Safety, Transform, Record) still apply.

### 3.7 Large Body Passthrough

When body exceeds a threshold (e.g., 2MB), Exchange.Body is set to `nil` (passthrough mode). Codec streams the body directly without loading it into memory. Pipeline Steps check for nil Body and process headers only.

**Rationale:** MITM proxy's primary purpose is API inspection, not video streaming. Safety/Transform on chunked large bodies would explode Pipeline complexity for minimal value.

### 3.8 CONNECT/TLS MITM is Connection Routing

CONNECT tunnel and TLS MITM are extracted from HTTP/1.x handler into `internal/connector/tunnel.go`. This eliminates the unnatural dependency where "HTTP/1.x is the parent of HTTP/2".

```
Protocol Detection -> CONNECT detected -> TunnelHandler
  -> 200 response -> TLS handshake -> ALPN
    -> h2 -> HTTP/2 Codec pair -> RunSession
    -> h1 -> HTTP/1.x Codec pair -> RunSession

SOCKS5 -> handshake -> TunnelHandler (same path)
```

### 3.9 Upstream Connection is Lazy

In a forward proxy, the upstream destination isn't known until the first request is parsed. RunSession creates the upstream Codec on the first Send Exchange using a `DialFunc`.

```go
type DialFunc func(ctx context.Context, ex *exchange.Exchange) (codec.Codec, error)
```

This same DialFunc is used by both normal proxy sessions and resend/fuzz Jobs.

### 3.10 OutputFilter is NOT a Pipeline Step

OutputFilter (PII masking on responses) is a **presentation layer** concern, not a data path concern. The current implementation stores raw data in Flow Store and masks only when returning to AI agents via MCP tools.

This is preserved: OutputFilter applies at the MCP query/resend/fuzz result return layer, not in the Pipeline. RecordStep records raw unmasked data.

Pipeline Steps are:
```
Scope -> RateLimit -> Safety(InputOnly) -> Plugin(recv) -> Intercept -> Transform -> Plugin(send) -> Record
```

## 4. Implementation FAQ

### 4.1 Header Type Bridge: exchange.KeyValue vs parser.RawHeaders

**Decision: Modify existing subsystems to accept `[]exchange.KeyValue` directly.**

Both `exchange.KeyValue{Name, Value string}` and `parser.RawHeader{Name, Value string}` are structurally identical but Go treats them as different types. Since this is a scrap-and-build rewrite, change the existing subsystems (safety, intercept, transform, plugin) to accept `[]exchange.KeyValue`. No adapters, no conversion overhead.

### 4.2 Dependency Injection into Steps

**Decision: Struct + constructor (option A).**

```go
func NewScopeStep(scope *TargetScope) *ScopeStep
func NewSafetyStep(engine *safety.Engine) *SafetyStep
```

Most Go-idiomatic. Each Step is a struct holding its dependencies.

### 4.3 PluginStep: Single Type with Phase Parameter

**Decision: Same type, phase parameter (option A/C).**

```go
type PluginStep struct {
    engine *plugin.Engine
    phase  HookPhase  // PhaseReceive or PhaseSend
}
```

Pipeline has two PluginStep instances with different phases. `Pipeline.Without()` excludes both by matching the same type, which is correct behavior for Macro internal sessions.

### 4.4 Variant Recording Snapshot

**Decision: Pipeline.Run() takes snapshot at start, passes via context.**

Pipeline.Run() calls `Exchange.Clone()` before any Step runs and stores it in context. RecordStep retrieves the snapshot and compares with the current Exchange to detect changes.

```go
func (p *Pipeline) Run(ctx context.Context, ex *exchange.Exchange) (...) {
    snapshot := ex.Clone()
    ctx = withSnapshot(ctx, snapshot)
    for _, step := range p.steps {
        // ...
    }
}
```

This keeps variant logic centralized without adding fields to Exchange.

### 4.5 Flow Lifecycle

| Responsibility | Owner |
|---------------|-------|
| FlowID generation | Codec (knows protocol message boundaries) |
| ConnID injection | Connector (via context) |
| Flow State transitions (active -> complete) | RecordStep |
| Flow creation (SaveFlow) | RecordStep on first Send Exchange |
| Message append (AppendMessage) | RecordStep on each Exchange |
| Flow completion (UpdateFlow) | RecordStep on EOF or final Receive |

### 4.6 Send-Only Steps

**Decision: Step internally checks Direction and returns Continue for irrelevant directions.**

```go
func (s *ScopeStep) Process(ctx context.Context, ex *exchange.Exchange) Result {
    if ex.Direction != exchange.Send { return Result{} }
    // ...
}
```

No need for direction-specific Pipeline configurations. Simple and uniform.

### 4.7 Exchange Mutability

**Decision: In-place mutation is allowed.**

Steps may modify Exchange fields directly. Clone() is only needed for variant snapshot (done by Pipeline.Run()). When a Step modifies the Exchange, it returns `Result{Exchange: nil}` (the original, now modified, Exchange continues through the pipeline).

When a Step needs to replace the Exchange entirely (e.g., SafetyStep masking body), it creates a new Exchange and returns `Result{Exchange: newEx}`.

### 4.8 Passthrough Mode (Body=nil)

When Exchange.Body is nil:
- **SafetyStep**: Check headers/URL only, skip body check
- **TransformStep**: Apply header-only rules, skip body rules
- **InterceptStep**: Match on headers/URL only. If intercepted, body is not available for modification (raw mode only)
- **RecordStep**: Record headers only, Message.Body = nil

### 4.9 OutputFilter is NOT Recorded as Variant

OutputFilter masking is a presentation-layer operation. RecordStep stores raw unmasked data. Masking applies when MCP tools return data to the AI agent, consistent with current behavior.

### 4.10 Import Direction During Migration

**Decision: M37 imports existing packages (internal/proxy/intercept/, internal/proxy/rules/, etc.) directly. M44 moves or deletes them.**

Focus M37 on Step implementation, not package reorganization. The pipeline/ package will temporarily depend on proxy/ packages. This is cleaned up in M44 when legacy code is deleted.

## 5. Package Layout (Target State)

```
internal/
  exchange/              Exchange type, Direction, Protocol, KeyValue
  codec/                 Codec interface
    http1/               HTTP/1.x Codec (reuses parser/)
      parser/            HTTP/1.x parser (moved from protocol/http/parser/)
    http2/               HTTP/2 Codec
      frame/             Frame codec (moved from protocol/http2/frame/)
      hpack/             HPACK (moved from protocol/http2/hpack/)
    grpc/                gRPC Codec (length-prefixed messages)
    grpcweb/             gRPC-Web Codec
    ws/                  WebSocket Codec
    sse/                 SSE Codec
    tcp/                 TCP Codec (passthrough)
  pipeline/              Pipeline + Step implementations
  session/               RunSession (single universal loop)
  connector/             Listener, detect, tunnel, socks5, dial
  job/                   resend/fuzz Job + ExchangeSource
  encoding/              Payload encode/decode (renamed from codec/)
  macro/                 Macro Engine (mostly unchanged)
  flow/                  Flow Store (mostly unchanged)
  cert/                  CA + Issuer (unchanged)
  safety/                Safety rules/engine (unchanged, API updated for KeyValue)
  plugin/                Starlark engine (hook interface updated for Exchange)
  config/                Config (unchanged)
  mcp/                   MCP server + tools (dependency targets change)
```

## 6. Milestone Dependency Graph

```
M36: Foundation Types
  |
M37: Pipeline Steps
  |
M38: HTTP/1.x Codec + TCP Codec    <- first E2E: plain HTTP works
  |
M39: Connector                      <- HTTPS MITM + SOCKS5 work
  |
  +-> M40: HTTP/2 Codec             <- HTTP/2 works
  |     |
  |    M41: Application Codecs      <- WS, gRPC, gRPC-Web, SSE (parallel)
  |
  +-> M42: Job + Macro Integration  <- resend/fuzz work
        |
M43: MCP + WebUI Reconnection       <- all features on new architecture
  |
M44: Legacy Removal + Documentation <- old code deleted
```

## 7. What to Reuse vs Rewrite

### Reuse (move to new package)
- `internal/protocol/http/parser/` -> `internal/codec/http1/parser/`
- `internal/protocol/http2/frame/` -> `internal/codec/http2/frame/`
- `internal/protocol/http2/hpack/` -> `internal/codec/http2/hpack/`
- `internal/protocol/grpc/frame.go` -> `internal/codec/grpc/frame.go`
- `internal/protocol/grpcweb/frame.go` -> `internal/codec/grpcweb/frame.go`
- `internal/protocol/ws/frame.go`, `deflate.go` -> `internal/codec/ws/`
- `internal/protocol/http/sse_parser.go` -> `internal/codec/sse/`
- `internal/safety/` (API updated for KeyValue)
- `internal/macro/` (SendFunc changed to use RunSession)
- `internal/flow/` (unchanged)
- `internal/cert/` (unchanged)

### Rewrite
- All handler code (`internal/protocol/*/handler.go`) -> replaced by Codecs
- `internal/proxy/listener.go`, `manager.go` -> `internal/connector/`
- `internal/protocol/http/connect.go` -> `internal/connector/tunnel.go`
- `internal/protocol/socks5/` -> `internal/connector/socks5.go`
- `internal/proxy/handler_base.go` -> eliminated (Steps replace it)
- `internal/mcp/server.go` deps struct -> simplified
- `cmd/yorishiro-proxy/main.go` init flow -> rewired

### Unchanged (interface-compatible)
- `internal/plugin/` (hook dispatch interface changes but engine core is stable)
- `internal/config/`
- `internal/logging/`
- `internal/fingerprint/`
- `web/` (WebUI, may need minor API adjustments)

# RFC-001: Envelope + Layered Connection Model

**Status:** Accepted
**Authors:** usk6666, Claude
**Created:** 2026-04-11
**Accepted:** 2026-04-12
**Supersedes:** `docs/architecture-rewrite.md` (M36–M44)
**Companion docs:**
- `docs/rfc/envelope-ja.md` — Japanese translation
- `docs/rfc/envelope-implementation.md` — Implementation strategy, file copy table, pseudo-code friction list, design rationale cross-references

## TL;DR

Replace the single HTTP-biased `Exchange` struct and the flat `Codec` abstraction with:

1. **`Envelope` + typed `Message` interface** — a minimal protocol-agnostic outer struct that carries identity, raw bytes, and a typed payload. Each protocol defines its own `Message` implementation (HTTPMessage, WSMessage, GRPCMessage, RawMessage, SSEMessage, TLSHandshakeMessage).
2. **`Layer` + `Channel` stack** — connections are an explicit stack of layers (TCP → TLS → HTTP/1 or HTTP/2 → WebSocket/gRPC/SSE). Each layer yields one or more `Channel`s. Pipeline runs on `Channel`s, not connections.
3. **Pipeline stays protocol-agnostic by type** — Steps are either `Envelope-only` (work on identity/raw/context) or `Message-typed` (type-switch on `env.Message`). Rule engines for Intercept/Transform/Safety split per protocol.

This eliminates the HTTP bias in the data model, unlocks HTTP request-smuggling diagnostics (raw-over-TLS), makes HTTP/2 multiplexing and gRPC/WebSocket wrapping structurally honest, and preserves ~70% of the existing M36–M39 implementation as-is.

---

## 1. Motivation

### 1.1 The HTTP Bias in `Exchange`

The current `exchange.Exchange` struct (defined in `internal/exchange/exchange.go`) contains these L7 fields:

```go
Method   string       // HTTP verb
URL      *url.URL     // HTTP target
Status   int          // HTTP status code
Headers  []KeyValue   // HTTP-style header KV
Trailers []KeyValue   // HTTP/gRPC trailers
Body     []byte       // unstructured byte blob
```

These fields are natural for HTTP but conceptually wrong for every other protocol:

| Field | WebSocket | gRPC message | TCP | SSE |
|-------|-----------|--------------|-----|-----|
| `Method` | no such concept | `/service/method` is a path, not a verb | none | none |
| `URL` | only at initial Upgrade | `service+method` is closer | none | URL + event name |
| `Status` | close codes, not 4xx/5xx | `grpc-status` (different from HTTP status) | none | none |
| `Headers` | no frame-level headers (only `Opcode`) | trailers belong to HTTP/2 layer, not the gRPC message | none | event fields |
| `Body` | typed (text vs binary) | length-prefixed single message | raw chunk | structured event |

Every non-HTTP protocol either leaves most fields empty or smuggles its data into `Metadata map[string]any`. This is a **type-system lie**: the `Exchange` struct claims to be protocol-agnostic while actually being "HTTP with optional fields".

### 1.2 The HTTP Bias in Pipeline Steps

The Step implementations in `internal/pipeline/` inherit the bias:

- `ScopeStep.Process` matches on `ex.URL` — non-HTTP protocols never match.
- `InterceptStep.MatchRequestRules(ex.Method, ex.URL, ex.Headers)` — HTTP signature.
- `TransformStep` delegates to `rules.Pipeline.TransformRequest(Method, URL, Headers, Body)` — HTTP signature.
- `SafetyStep` checks header+body — no-op for header-less protocols.

The result: **Pipeline "runs" on all protocols, but effectively does nothing for non-HTTP.** The L4-capable principle exists in the README but not in the code.

### 1.3 Layer Conflation in `Codec`

The current `Codec` interface assumes "1 connection = 1 Codec = 1 protocol". This breaks for:

- **HTTP request smuggling diagnosis** — The user needs to write arbitrary bytes over a TLS-terminated connection *without* an HTTP parser in between. There is currently no way to acquire a TLS-wrapped channel without the HTTP/1.x Codec being forced on top.
- **HTTP/2 multiplexing** — The current design says "multiplexing is absorbed inside the Codec". This requires one Codec instance to internally manage N concurrent streams while exposing a single `Next()/Send()` surface, which is a structural mismatch.
- **WebSocket Upgrade** — The current plan is "Codec internally switches parsers". The byte stream below is the same, but the abstraction hides the transition and makes buffered-reader hand-off implicit.
- **gRPC over HTTP/2** — gRPC is naturally "a wrapper over one HTTP/2 stream". Making it a sibling `Codec` to HTTP/2 is a category error.
- **TLS metadata observation** — SNI / ALPN / peer cert / fingerprint are TLS-layer concerns, currently buried in `Connector` and `DialOpts` with no first-class surface.

### 1.4 What an MITM Diagnostic Tool Actually Needs

Re-deriving from first principles, the truly shared essence of MITM observation is minimal:

1. **Identity** — stream/flow/sequence/direction, so messages can be located in time.
2. **Wire fidelity** — raw bytes preserved exactly as observed.
3. **Provenance** — which protocol layer produced this message.
4. **Recording hook** — a uniform way to persist everything.
5. **Mutation trace** — before/after snapshot for variant recording.

**That is all that is universally shared.** Everything else (Method, URL, Status, Headers, Opcode, grpc-status, CloseCode, SSE event fields) is protocol-specific and should live in a protocol-specific type.

---

## 2. Non-Goals

This RFC does **not** attempt to solve:

1. **HTTP/2 flow-control × Pipeline latency** — the question of what happens when an Intercept step blocks a Pipeline for minutes while HTTP/2 connection-level WINDOW fills up. Tracked as Open Question #1 (§9.1).
2. **gRPC message granularity** — whether headers/messages/trailers are separate Envelopes or one per RPC. Tracked as Open Question #2 (§9.2).
3. **Upstream HTTP/2 connection pooling** — coalesced-connection handling, idle timeout, max streams per connection. Deferred to a dedicated design doc once §9.1 lands.
4. **MCP tool API redesign** — the RFC notes that protocol-split `resend_*` tools become natural, but the tool surface redesign is a separate deliverable.

These are important but orthogonal to the data model and layer structure.

---

## 3. Core Concepts

### 3.1 Envelope

The outer container. Protocol-agnostic. Holds identity, raw bytes, provenance, cross-layer context, and a typed Message.

```go
package envelope

type Envelope struct {
    // --- Identity (shared across all protocols) ---
    StreamID  string     // connection/RPC-level grouping
    FlowID    string     // individual message unique id
    Sequence  int        // order within the stream (0-origin)
    Direction Direction  // Send (client→server) | Receive (server→client)

    // --- Provenance ---
    Protocol Protocol    // which layer produced this envelope

    // --- Wire fidelity (read-only view for Pipeline; authoritative bytes) ---
    Raw []byte

    // --- Protocol-specific structured view ---
    Message Message      // interface; typed by Protocol

    // --- Connection-scoped context accessible to any Step ---
    Context EnvelopeContext

    // --- Layer-internal state; Pipeline must not type-assert ---
    Opaque any
}

type EnvelopeContext struct {
    ConnID     string        // unique per client TCP connection
    ClientAddr net.Addr      // original client address
    TargetHost string        // CONNECT destination or SOCKS5 target
    TLS        *TLSSnapshot  // non-nil if a TLS layer is in the stack
    ReceivedAt time.Time     // wall-clock at Next() time
}

type TLSSnapshot struct {
    SNI               string
    ALPN              string
    PeerCertificate   *x509.Certificate
    ClientFingerprint string // JA3 or JA4 hash of the client's ClientHello
    Version           uint16
    CipherSuite       uint16
}
```

**Design rule:** Any field on `Envelope` (not on `Message`) must be meaningful for *every* protocol, including raw TCP. If a field is HTTP-shaped, it belongs on `HTTPMessage`, not `Envelope`.

### 3.2 Message

A protocol-specific payload type. Implements a minimal interface so that `Envelope.Clone()` and generic Step code can work uniformly.

```go
type Message interface {
    // Protocol returns the protocol identifier. Must match Envelope.Protocol.
    Protocol() Protocol

    // CloneMessage returns a deep copy for variant snapshotting.
    CloneMessage() Message
}
```

#### 3.2.1 HTTPMessage

Represents one HTTP request or response. Used by HTTP/1.x and HTTP/2 layers alike.

```go
type HTTPMessage struct {
    // Request-side fields (valid when Envelope.Direction == Send)
    Method    string
    Scheme    string   // "http" | "https"
    Authority string   // Host header or :authority
    Path      string
    RawQuery  string

    // Response-side fields (valid when Envelope.Direction == Receive)
    Status       int
    StatusReason string  // "OK", "Not Found" (for HTTP/1.x wire fidelity)

    // Both directions
    Headers    []KeyValue  // order-preserved, case-preserved
    Trailers   []KeyValue
    Body       []byte
    BodyStream io.Reader   // non-nil in passthrough mode (Body == nil)
}
```

**Note:** HTTP/2 and HTTP/1.x share this type. The layer below is responsible for translating to/from wire-specific representation. `HTTPMessage` is the *natural* form for both.

#### 3.2.2 WSMessage

Represents one WebSocket frame. Frame-level, not message-level — control frames (Ping/Pong/Close) are surfaced as their own Envelopes.

```go
type WSOpcode uint8

const (
    WSContinuation WSOpcode = 0x0
    WSText         WSOpcode = 0x1
    WSBinary       WSOpcode = 0x2
    WSClose        WSOpcode = 0x8
    WSPing         WSOpcode = 0x9
    WSPong         WSOpcode = 0xA
)

type WSMessage struct {
    Opcode  WSOpcode
    Fin     bool
    Masked  bool
    Mask    [4]byte
    Payload []byte

    // Close frame only
    CloseCode   uint16
    CloseReason string

    // Per-message-deflate (RFC 7692)
    Compressed bool
}
```

#### 3.2.3 GRPCMessage

Represents one length-prefixed gRPC message on an HTTP/2 stream. Metadata and trailers are *not* on `GRPCMessage` — they belong to the HTTP/2 layer's `HTTPMessage`. gRPC is modeled as "wrapping one HTTP/2 stream" where HEADERS frames become `HTTPMessage` envelopes and DATA frames become `GRPCMessage` envelopes on the same Channel.

```go
type GRPCMessage struct {
    // Derived from HTTP/2 stream's :path; denormalized here for convenience
    Service string
    Method  string

    // The 5-byte gRPC frame header
    Compressed bool
    Length     uint32

    // The message body (raw protobuf or compressed blob)
    Payload []byte
}
```

**Open Question #2 (see §9.2):** whether a gRPC RPC surfaces as one Envelope-per-frame (HEADERS + DATA* + HEADERS-trailer) or aggregated. This RFC documents the frame-per-envelope default; alternative is tracked in §9.2.

#### 3.2.4 RawMessage

For TCP, raw-mode TLS passthrough, and any byte-chunk channel.

```go
type RawMessage struct {
    Bytes []byte  // exactly the bytes received in one Read() call (or Write())
}
```

#### 3.2.5 SSEMessage

Server-Sent Events (RFC 8895).

```go
type SSEMessage struct {
    Event string
    Data  string
    ID    string
    Retry time.Duration
}
```

#### 3.2.6 TLSHandshakeMessage

Emitted exactly once per TLS connection, immediately after handshake completes. Allows Pipeline Steps to observe TLS metadata as first-class events (for fingerprint-based scope rules, for example).

```go
type TLSHandshakeMessage struct {
    Side              TLSSide  // Client | Server
    SNI               string
    ALPN              string
    NegotiatedVersion uint16
    NegotiatedCipher  uint16
    PeerCertificate   *x509.Certificate
    ClientHelloRaw    []byte   // for JA3/JA4 computation
    Fingerprint       string
}
```

### 3.3 Layer and Channel

A **Layer** is a connection-level component that consumes a lower layer and produces one or more **Channel**s upward. A **Channel** is the Pipeline's input/output surface — one Channel drives one `session.RunSession` invocation.

```go
package layer

// Layer consumes a lower layer and yields Channels upward.
// Byte-stream layers (TCP, TLS) implement a simpler interface; see §3.3.1.
type Layer interface {
    // Channels yields Channels as they become available. For single-channel
    // layers (HTTP/1.x, WS, gRPC wrapper), exactly one Channel is yielded
    // then the receive-side is closed. For multi-channel layers (HTTP/2),
    // one Channel is yielded per stream.
    Channels() <-chan Channel

    // Close tears down the layer. Does NOT close lower layers unless the
    // layer owns them. Ownership is established at construction time.
    Close() error
}

// Channel is the unit the Pipeline operates on.
type Channel interface {
    // StreamID returns the stable identifier for this channel's lifetime.
    StreamID() string

    // Next reads the next Envelope from the channel. Returns io.EOF on
    // normal termination, other errors on abnormal termination.
    Next(ctx context.Context) (*envelope.Envelope, error)

    // Send writes an Envelope back out through the channel.
    Send(ctx context.Context, env *envelope.Envelope) error

    // Close closes just this channel. Underlying layer lifecycle is separate.
    Close() error
}
```

#### 3.3.1 Byte-Stream Layers (TCP, TLS)

TCP and TLS do not participate in the Pipeline directly. They transform a `net.Conn` into another `net.Conn`:

```go
package tcp  // package-level — no Layer type needed
// TCP is a no-op: callers pass a net.Conn directly to whichever layer consumes it.

package tlslayer
// Server performs a server-side TLS handshake on plain.
// Returns a net.Conn that is also a *tls.Conn (or uTLS).
func Server(ctx context.Context, plain net.Conn, cfg *tls.Config) (net.Conn, *TLSSnapshot, error)

// Client performs a client-side TLS handshake toward an upstream.
func Client(ctx context.Context, plain net.Conn, opts ClientOpts) (net.Conn, *TLSSnapshot, error)
```

To *observe* or *expose* a byte-stream layer to the Pipeline, wrap it in a `ByteChunkLayer`:

```go
package bytechunk

// New wraps conn in a single-channel Layer that yields RawMessage envelopes
// for each Read(). Used for raw TCP passthrough and for TLS-terminate-only
// diagnostic mode (HTTP request smuggling).
func New(conn net.Conn, streamID string) layer.Layer
```

This is essentially today's `internal/codec/tcp/` repackaged as a Layer.

#### 3.3.2 Message-Stream Layers

HTTP/1.x, HTTP/2, WebSocket, gRPC, SSE all implement `Layer`. Each one takes whatever its input is:

```go
package http1layer
// New wraps a net.Conn in an HTTP/1.x layer. Yields exactly one Channel
// that produces HTTPMessage envelopes for each request-response pair in
// keep-alive order.
func New(conn net.Conn, role Role) layer.Layer

// DetachStream tears down the HTTP/1 layer after an Upgrade response and
// returns the buffered reader, writer, and underlying closer so that the
// next layer (WebSocket) can be constructed on top of the same wire.
// The caller takes ownership of these resources; the Layer becomes unusable.
func (l *Layer) DetachStream() (io.Reader, io.Writer, io.Closer, error)
```

```go
package http2layer
// New wraps a net.Conn in an HTTP/2 layer. Yields one Channel per HTTP/2
// stream. The returned Layer manages HPACK state, connection-level flow
// control, SETTINGS negotiation, and stream lifecycle.
func New(conn net.Conn, role Role) layer.Layer
```

```go
package wslayer
// New wraps an already-upgraded bidirectional byte stream in a WebSocket
// layer. The reader may be a bufio.Reader holding pre-upgrade buffered
// bytes from HTTP/1 layer detachment.
func New(reader io.Reader, writer io.Writer, closer io.Closer, role Role) layer.Layer
```

```go
package grpclayer
// Wrap takes an HTTP/2 stream Channel and wraps it so that DATA frames are
// surfaced as GRPCMessage envelopes. HEADERS-derived HTTPMessage envelopes
// from the underlying stream pass through unchanged. Requires the first
// HTTPMessage envelope to be peeked already (for content-type detection).
func Wrap(stream layer.Channel, firstHTTP *envelope.Envelope, role Role) layer.Channel
```

### 3.4 ConnectionStack

A per-connection runtime object representing the layer stack. Held by the Connector while the connection is alive; owned by Session for the duration of `RunSession`.

```go
package connector

type ConnectionStack struct {
    ConnID string
    Client struct {
        Layers  []layer.Layer  // bottom-up
        Topmost layer.Layer
    }
    Upstream struct {
        Layers  []layer.Layer
        Topmost layer.Layer
    }
}

// Push adds a new top layer and makes it the current topmost.
func (s *ConnectionStack) PushClient(l layer.Layer)
func (s *ConnectionStack) PushUpstream(l layer.Layer)

// Replace atomically swaps the topmost layer (used for Upgrade transitions).
func (s *ConnectionStack) ReplaceClientTop(l layer.Layer) (old layer.Layer)
func (s *ConnectionStack) ReplaceUpstreamTop(l layer.Layer) (old layer.Layer)
```

The stack is mutable — WebSocket Upgrade is expressed as `ReplaceClientTop(wsLayer)`. Session observes the current topmost channel at the start of each iteration; when a replacement happens, the existing goroutines must be signaled to tear down and restart on the new channel (see §4.3).

### 3.5 Pipeline Step Categorization

Pipeline interface is unchanged:

```go
package pipeline

type Step interface {
    Process(ctx context.Context, env *envelope.Envelope) Result
}

type Pipeline struct { steps []Step }
func (p *Pipeline) Run(ctx, *Envelope) (*Envelope, Action, *Envelope)  // unchanged
```

What changes is that Steps are now *explicitly categorized* into two kinds:

#### 3.5.1 Envelope-Only Steps (protocol-agnostic)

These Steps only access fields on `Envelope` and `Envelope.Context`. They never type-assert on `env.Message`. They work identically for every protocol.

Examples:
- **RecordStep** — persists the envelope (Raw + Message serialized as opaque blob + identity).
- **RateLimitStep** — counts envelopes per `Context.ConnID` or `Context.TargetHost`.
- **HostScopeStep** — validates `Context.TargetHost` against a scope policy. Separate from path-based scoping, which is HTTP-specific.

#### 3.5.2 Message-Typed Steps (protocol-aware)

These Steps type-switch on `env.Message` and dispatch to protocol-specific engines.

```go
type InterceptStep struct {
    http  *httprules.InterceptEngine
    ws    *wsrules.InterceptEngine
    grpc  *grpcrules.InterceptEngine
    raw   *rawrules.InterceptEngine  // byte-pattern matching
}

func (s *InterceptStep) Process(ctx context.Context, env *envelope.Envelope) Result {
    switch m := env.Message.(type) {
    case *HTTPMessage:
        return s.http.Process(ctx, env, m)
    case *WSMessage:
        return s.ws.Process(ctx, env, m)
    case *GRPCMessage:
        return s.grpc.Process(ctx, env, m)
    case *RawMessage:
        return s.raw.Process(ctx, env, m)
    default:
        return Result{} // unknown Message: pass through
    }
}
```

Each branch has its own rule engine with its own match DSL, its own intercept UI surface, and its own edit operations. This is **not duplication** — it is an acknowledgement that "intercept an HTTP request" and "intercept a WebSocket frame" are genuinely different operations.

Shared concerns (blocking-queue coordination, timeout handling, rule compilation utilities) are factored into helper packages that the per-protocol engines call.

### 3.6 Rule Engine Split

Today's `internal/safety/`, `internal/proxy/intercept/`, `internal/proxy/rules/` (transform) are structured around HTTP. They are split per protocol:

```
internal/rules/
  http/       HTTP-specific match DSL, edit operations, UI surface
  ws/         WebSocket frame match + edit
  grpc/       gRPC service/method/message match + edit
  raw/        Byte-pattern match (regex, binary pattern, offset-based)
  common/     Shared: rule compilation utilities, blocking queue primitives
```

Each `internal/rules/<proto>/` exposes `InterceptEngine`, `TransformEngine`, `SafetyEngine` — protocol-typed. The Pipeline Step (e.g., `InterceptStep`) owns one engine per protocol and dispatches.

---

## 4. Canonical Scenarios

This section shows how the four canonical scenarios work end-to-end under this RFC. These are the scenarios that motivated the design; they must all be expressible naturally.

### 4.1 HTTPS MITM, plain HTTP/1.1

```
Client TCP conn
  → tlslayer.Server(cfg) yields *tls.Conn
    → http1layer.New(tlsConn, ServerRole)
      → single Channel producing HTTPMessage envelopes

Upstream:
  DialUpstream(target) returns *tls.Conn
    → http1layer.New(upstreamTLS, ClientRole)
      → single Channel consuming HTTPMessage envelopes

Session.RunSession(clientChan, dialFunc, pipeline)
  iterates HTTPMessage envelopes through Pipeline
```

Unchanged from current model except for type names. This is the baseline.

### 4.2 HTTP Request Smuggling Diagnosis

```
Client TCP conn
  → tlslayer.Server(cfg) yields *tls.Conn
    → bytechunk.New(tlsConn)
      → single Channel producing RawMessage envelopes

Upstream:
  DialUpstreamRaw(target) returns *tls.Conn (no Codec attached)
    → bytechunk.New(upstreamTLS)
      → single Channel consuming RawMessage envelopes

Pipeline:
  - RecordStep records Raw bytes + RawMessage
  - HostScopeStep validates Context.TargetHost
  - No Intercept/Transform/Safety — those operate on HTTP, not raw bytes
```

**Configuration mechanism:** the per-host passthrough mode is set in config. The Connector inspects the CONNECT target against the passthrough list *before* building the client stack. Hosts in the passthrough list get a `bytechunk` top layer; all others get `http1` or `http2` based on negotiated ALPN.

Intentionally malformed bytes (dual Content-Length / Transfer-Encoding, obfuscated chunk sizes) flow through uninterpreted. The upstream's parser sees the exact client bytes. Front-end vs back-end parser divergence is observable.

### 4.3 WebSocket Upgrade

```
Initial stack:
  Client:   [TCP → TLS → HTTP/1.x]
  Upstream: [TCP → TLS → HTTP/1.x]

HTTPMessage (request) arrives with Upgrade: websocket header.
Pipeline forwards it; HTTPMessage (response) arrives with Status: 101.

Session detects the successful upgrade and:
  1. Calls http1Client.DetachStream() → (bufReader, writer, closer)
  2. Calls http1Upstream.DetachStream() → (bufReader, writer, closer)
  3. Constructs wslayer.New(...) on each side using the detached streams
  4. Stack.ReplaceClientTop(wsClient)
     Stack.ReplaceUpstreamTop(wsUpstream)
  5. Cancels the current RunSession, waits for both goroutines to exit
  6. Starts a new RunSession on the new topmost channels
```

The bufio.Reader held by the HTTP/1.x layer is passed to the WebSocket layer as-is, so any bytes the HTTP/1.x layer read past the `\r\n\r\n` of the 101 response are available to the WS frame parser.

Step 5 (cancel-and-restart) is the ugly part. An alternative is to make `RunSession` loop-observable — but cancel-and-restart is simpler and correct. Revisit if perf matters.

### 4.4 HTTP/2 Multiplexing + gRPC Detection

```
Initial stack:
  Client:   [TCP → TLS(ALPN=h2) → HTTP/2]
  Upstream: [TCP → TLS(ALPN=h2) → HTTP/2]  (pooled)

HTTP/2 layer's Channels() yields one Channel per new client stream:
  for clientStreamChan := range clientH2.Channels():
    go handleStream(clientStreamChan)

handleStream(clientStreamChan):
  Peek first envelope (HTTPMessage from HEADERS)
  if isGRPC(firstHTTPMessage):
    // Wrap with gRPC layer
    grpcChan := grpclayer.Wrap(clientStreamChan, firstHTTPMessage, ServerRole)
    upstreamStreamChan := upstreamH2.OpenStream(ctx)
    upstreamGRPCChan := grpclayer.Wrap(upstreamStreamChan, firstHTTPMessage, ClientRole)
    Session.RunSession(grpcChan, staticDial(upstreamGRPCChan), pipeline)
  else:
    upstreamStreamChan := upstreamH2.OpenStream(ctx)
    Session.RunSession(clientStreamChan, staticDial(upstreamStreamChan), pipeline)
```

HTTP/2 layer internally handles:
- HPACK encoder/decoder state (per connection)
- SETTINGS and WINDOW_UPDATE frames
- Per-stream and per-connection flow control
- Write serialization across streams (single write goroutine + queue)

Upstream `http2.Layer.OpenStream()` is the API for Session/Job to request a new outbound stream on an existing upstream connection. Connection pool key is `(target_host, tls_config_hash)`; pool management is out of scope for this RFC (§2).

---

## 5. Variant Snapshot (unchanged)

Pipeline.Run takes `env.Clone()` at entry and stores it in context. RecordStep reads the snapshot and compares Envelope fields *and* Message fields (via `CloneMessage`) to detect modifications. Snapshots work uniformly because every Message implementation provides `CloneMessage`.

```go
// internal/pipeline/snapshot.go (updated)
func withSnapshot(ctx context.Context, env *envelope.Envelope) context.Context {
    snap := &envelope.Envelope{
        StreamID: env.StreamID, FlowID: env.FlowID, Sequence: env.Sequence,
        Direction: env.Direction, Protocol: env.Protocol,
        Raw:     cloneBytes(env.Raw),
        Message: env.Message.CloneMessage(),
        Context: env.Context,
        // Opaque not cloned — Layer responsibility
    }
    return context.WithValue(ctx, snapshotKey, snap)
}
```

---

## 6. Migration from Current Code

Mapping current files/packages to RFC-001 structure:

| Current | RFC-001 Target | Reuse % |
|---------|----------------|---------|
| `internal/exchange/exchange.go` (Exchange struct) | `internal/envelope/envelope.go` (Envelope struct, reduced fields) + `internal/envelope/message.go` (Message interface + HTTPMessage/WSMessage/...) | 60% |
| `internal/pipeline/pipeline.go` (Pipeline.Run, snapshot) | `internal/pipeline/pipeline.go` (unchanged) | 95% |
| `internal/pipeline/scope_step.go`, `intercept_step.go`, `transform_step.go`, `safety_step.go` | Rewritten to type-switch on `env.Message` and dispatch to per-protocol engines | 40% |
| `internal/pipeline/record_step.go`, `ratelimit_step.go` | Promoted to Envelope-Only Steps; minor adjustments | 80% |
| `internal/codec/http1/parser/` | Moved to `internal/layer/http1/parser/`, byte-level parser logic unchanged | 100% |
| `internal/codec/http1/codec.go` | Rewritten as `internal/layer/http1/layer.go` (Layer interface) + `channel.go` (Channel interface). The raw-first patching and `opaqueHTTP1` diff logic moves into the new Channel's `Send` path. | 50% |
| `internal/codec/tcp/tcp.go` | Rewritten as `internal/layer/bytechunk/layer.go` | 90% |
| `internal/codec/codec.go` (Codec interface) | **Deleted.** Replaced by `internal/layer/layer.go` (Layer + Channel interfaces). | 0% |
| `internal/connector/dial.go` (DialUpstream) | Mostly unchanged; add `DialUpstreamRaw` for raw mode and expose stack-construction helpers. TLS/uTLS/mTLS handshake code preserved. | 90% |
| `internal/connector/listener.go`, `detect.go`, `tunnel.go`, `socks5.go` (via USK-561) | Mostly unchanged structurally; updated to build `ConnectionStack` instead of picking a single Codec | 70% |
| `internal/session/session.go` | Renamed Codec → Channel; add support for `Stack.ReplaceClientTop`-driven session restart | 70% |
| `internal/job/job.go` | `ExchangeSource` renamed `EnvelopeSource`. Sources for L7 resend build `HTTPMessage` envelopes; sources for L4 resend build `RawMessage` envelopes and call `DialUpstreamRaw`. | 60% |
| `internal/safety/`, `internal/proxy/intercept/`, `internal/proxy/rules/` | Split into `internal/rules/http/`, `internal/rules/ws/`, `internal/rules/grpc/`, `internal/rules/raw/`. Existing rule compilation code mostly reused. | 55% |
| `internal/flow/` (Store) | Message interface serialization added; otherwise unchanged | 85% |
| `internal/mcp/` (resend_tool.go, etc.) | `resend` action split into `resend_http`, `resend_ws`, `resend_grpc`, `resend_raw`. Each takes a protocol-typed schema. | 30% |
| `internal/plugin/` (Starlark hooks) | Hook signatures updated for `HTTPMessage`/`WSMessage`/etc. Existing hook infrastructure preserved. | 60% |

**Weighted reuse estimate: ~70%.** The deletions (Codec interface, HTTP-biased Step signatures, unified rule engines) are precisely the sources of the design friction discussed in this RFC.

---

## 7. Proposed Milestones

Replaces M36–M44. All current M36–M44 Linear issues should be moved to **Cancelled** and re-created under the new milestones.

```
N1: Foundation Types
    Envelope, Message interface, HTTPMessage, RawMessage
    Layer and Channel interfaces
    ConnectionStack type
    Pipeline.Run snapshot updated for Message.CloneMessage
    Deliverable: interfaces compile; no runtime yet

N2: TCP + TLS + ByteChunk + raw smuggling E2E
    tlslayer package (server/client handshake with uTLS/mTLS preserved)
    bytechunk layer
    Minimal Connector: listener, CONNECT negotiator, ConnectionStack builder
    Pipeline: RecordStep + HostScopeStep only
    Deliverable: "curl → yorishiro → target" with raw-passthrough mode works,
                 request-smuggling payload observable on the wire

N3: HTTP/1.x Layer + normal HTTPS MITM E2E
    http1 layer (reuses existing parser package)
    HTTP-typed Pipeline Steps: InterceptStep, TransformStep, SafetyStep,
                               ScopeStep dispatching to http rules engine
    internal/rules/http/ (intercept/transform/safety for HTTP)
    Deliverable: normal HTTPS MITM with L7 intercept/transform works end-to-end

N4: Connector Completion
    Protocol detection (peek + ALPN)
    SOCKS5 negotiator (per-host mode selection applies)
    ConnectionStack built declaratively from config (per-host policy)
    Deliverable: full connector surface, feature parity with current proxy

N5: Job + Macro Integration
    EnvelopeSource interface
    L7 resend: HTTPMessage source + http1 Channel upstream
    L4 resend: RawMessage source + DialUpstreamRaw + bytechunk upstream
    Macro hook invocation around Job.Run
    Deliverable: resend_http, resend_raw both work; smuggling payload fuzz works

N6: HTTP/2 Layer
    http2 layer (frame codec, HPACK, per-stream channels)
    Upstream connection pool (basic: per-target, LRU eviction)
    Deliverable: HTTPS + h2 normal traffic works

N7: Application Layers
    grpclayer (wraps http2 stream channels)
    wslayer (from HTTP/1 Upgrade; HTTP/2 CONNECT+:protocol for RFC 8441 deferred)
    ssehlayer (from HTTP/1 response)
    Corresponding rule engines in internal/rules/{ws,grpc}/
    Deliverable: WS/gRPC/SSE flows recordable and intercept-able

N8: MCP + WebUI Reconnection
    resend action split: resend_http, resend_ws, resend_grpc, resend_raw
    Query tool: filters by Protocol (Message type)
    WebUI: per-protocol flow detail views
    Deliverable: full MCP tool surface on new architecture

N9: Legacy Removal + Documentation
    Delete internal/protocol/, internal/codec/, internal/proxy/
    Update CLAUDE.md, README.md, docs/
    Final migration of any stragglers
    Deliverable: single architecture, docs consistent
```

**Milestone dependency:** N1 → N2 → N3 → (N4 || N5) → N6 → N7 → N8 → N9. N4 and N5 can proceed in parallel after N3 lands.

---

## 8. Relationship to Existing Work (M36–M39)

**What is preserved:**
- `internal/codec/http1/parser/` (byte-level HTTP/1.x parser) — 100%
- `internal/connector/dial.go` TLS/uTLS/mTLS/upstream-proxy/ALPN-cache logic — 90%
- `internal/pipeline/pipeline.go` Run loop and snapshot mechanism — 95%
- The raw-first patching algorithm in `http1/codec.go` (moves into http1 Layer's Channel.Send)
- `internal/cert/` CA + Issuer — unchanged
- `internal/flow/` Stream/Flow store — mostly unchanged (Message serialization added)
- All safety/intercept/transform rule *compilation* logic — split but internals preserved
- `internal/macro/` engine — unchanged except for send-function signature

**What is replaced:**
- `Codec` interface → `Layer` + `Channel` interfaces
- `Exchange` struct → `Envelope` struct + `Message` interface
- Unified Pipeline Steps → typed Step implementations that dispatch to per-protocol engines
- `MakeDialFunc` returning a single Codec → stack-building helpers returning a `ConnectionStack`

**What is deleted:**
- The "multiplexing is absorbed by HTTP/2 Codec" design — HTTP/2 Layer naturally yields N Channels
- The "single unified rule engine" assumption — protocols have their own engines
- The implicit assumption that every connection produces one Pipeline session — WebSocket Upgrade replaces the stack, HTTP/2 produces N sessions

---

## 9. Open Questions

### 9.1 HTTP/2 Flow Control × Long-Blocking Pipeline Steps — RESOLVED

**Resolved:** 2026-04-15

**Problem:** HTTP/2 has per-stream and per-connection flow control (WINDOW_UPDATE frames). If a Pipeline Step blocks for minutes (e.g., `InterceptStep` waiting for AI agent action), the stream's WINDOW fills and the downstream side stalls. If *many* concurrent streams on the same connection all block simultaneously, connection-level WINDOW fills and the entire HTTP/2 connection stalls, impacting unrelated streams.

**Resolution: Complete-message aggregation model.**

The original problem formulation assumed a frame-per-envelope streaming model where the HTTP/2 Layer yields individual DATA frames as separate Envelopes. Analysis revealed this model is incompatible with the Pipeline's actual requirements: SafetyFilter, TransformEngine, PluginHooks, and InterceptStep all operate on **complete HTTP messages** (headers + body), not individual frames. The HTTP/1.x Layer already aggregates the full request/response body before returning from `Channel.Next()`.

**Decision:** HTTP/2 `Channel.Next()` aggregates all frames (HEADERS + DATA* + END_STREAM) into a single Envelope containing a complete `HTTPMessage`, identical to HTTP/1.x behavior.

**Why this resolves the flow control concern:**

1. **During body assembly (Layer-internal):** The Layer sends WINDOW_UPDATE immediately as DATA frames arrive, because it must receive all frames to assemble the complete message. Connection-level and stream-level windows are replenished during assembly.
2. **After assembly:** `Channel.Next()` returns the complete message. No more DATA frames will arrive for this stream (END_STREAM was received). The in-memory cost is fixed (= body size), not growing.
3. **During InterceptStep block:** The Pipeline holds a single complete message in memory. No buffer is growing because the stream's data transfer is already finished. Other streams are unaffected — the frame reader goroutine handles them independently, and the connection-level window was replenished during assembly.

**Memory protection during assembly:** Same `passthroughThreshold` (10 MiB) as HTTP/1.x. Bodies exceeding the threshold switch to passthrough mode (`BodyStream io.Reader`). The worst-case memory for concurrent assembly is `passthroughThreshold × MAX_CONCURRENT_STREAMS` (default: 10 MiB × 100 = 1 GiB), which is bounded and acceptable.

**Body size limitations (passthrough mode):** When `Body` is nil (passthrough), SafetyFilter and TransformEngine skip body inspection — same behavior as HTTP/1.x today. A dedicated disk-backed body mechanism is planned as a separate cross-cutting improvement to remove this limitation for both protocols.

**Rejected alternatives:**
- **Frame-per-envelope streaming + per-stream buffer cap + RST_STREAM** (original proposal): Incompatible with Pipeline Steps that require complete messages. Would require every Step to handle partial data, adding significant complexity.
- **Pipeline-driven back-pressure (Option 2):** A single intercepted stream stalls the connection-level window, blocking all other streams on the same connection.
- **Async Intercept (Option 3):** Breaks the "intercept blocks forwarding" contract that the MCP tool surface depends on.

### 9.2 gRPC Message Envelope Granularity

**Problem:** A gRPC RPC consists of (request HEADERS) + (request DATA*) + (response HEADERS) + (response DATA*) + (trailers HEADERS). How are these surfaced to the Pipeline?

**Options:**
1. **Frame-per-envelope.** HEADERS → HTTPMessage envelope (on the gRPC Channel). Each DATA frame → GRPCMessage envelope. Trailers → HTTPMessage envelope with `Trailers` populated. Pipeline sees a mix of types on the same Channel.
2. **Aggregated-per-message.** One envelope per gRPC message, carrying both metadata and payload. Streaming RPCs yield multiple envelopes; unary is one. Simpler Pipeline, but delays the metadata until the full first message is assembled.
3. **Aggregated-per-RPC.** One envelope per RPC, with internal streaming representation. Works only for unary — streaming doesn't fit.

**Proposal (tentative):** Option 1. It matches wire reality, is naturally composable with the HTTPMessage type we already have, and doesn't require a new aggregation state machine. Pipeline Steps that care about "the full message" can accumulate across envelopes if needed, keyed by `Envelope.StreamID`.

**Decision required before N7 starts.**

### 9.3 Starlark Plugin API Shape

**Problem:** Current `internal/plugin/` exposes `request.method`, `request.url`, etc. as Starlark values. With typed Messages, plugins must see a protocol-shaped object.

**Proposal:** Plugin hooks are registered with a Protocol filter, e.g., `register_hook("http", "on_request", ...)`. The handler receives a Starlark dict shaped like HTTPMessage, WSMessage, etc. Protocol-mismatched hooks never fire.

**Decision required before N8 starts.**

---

## 10. Alternatives Considered

### 10.1 Keep Exchange, Put Everything in Metadata map[string]any

**Rejected because:** type-unsafe, requires every Step and plugin to string-key into a map, loses IDE completion, and encodes the HTTP bias at the type level even if the fields are technically absent.

### 10.2 Sum Type with Fixed Fields (`HTTP *HTTPMessage; WS *WSMessage; ...`)

```go
type Envelope struct {
    // identity + raw...
    HTTP *HTTPMessage
    WS   *WSMessage
    GRPC *GRPCMessage
    Raw  *RawMessage
}
```

**Considered but rejected** in favor of the `Message` interface because:
- Adding a new protocol requires touching `Envelope` struct
- Pipeline Steps still do `if env.HTTP != nil {}` chains which are equivalent to type-switches but less idiomatic in Go
- `CloneMessage()` as an interface method is cleaner than cloning each field

The interface approach is more Go-idiomatic and extensible. The tradeoff (interface method call overhead) is negligible for this workload.

### 10.3 Per-Protocol Pipelines (No Shared Pipeline Type)

```go
type HTTPPipeline struct { steps []HTTPStep }
type WSPipeline struct { steps []WSStep }
// ... one per protocol
```

**Rejected because:**
- Shared Steps (Record, RateLimit, HostScope) have to be instantiated per protocol
- Pipeline.Without() logic has to be duplicated
- Snapshot mechanism duplicated
- The generic-pipeline-with-typed-dispatch approach gives 95% of the type safety at 30% of the complexity

### 10.4 Pipeline Replaced by Hook System

Instead of a Step chain, expose well-defined lifecycle hooks (`on_http_request`, `on_ws_frame`, `on_tcp_chunk`, ...) and let subscribers register.

**Rejected because:**
- Order management becomes distributed (every hook needs priority)
- Variant-snapshot placement is ambiguous (once per hook? once total?)
- `Pipeline.Without()` for macro becomes awkward
- The linearity of Pipeline matches how MITM processing actually works (Scope → Safety → Intercept → Transform → Record)

The Pipeline concept is sound; the problem is `Exchange`, not `Pipeline`.

### 10.5 Radically Shrink Envelope (Identity + Raw Only)

```go
type Envelope struct {
    StreamID, FlowID string
    Sequence int
    Direction Direction
    Protocol Protocol
    Raw []byte
    // no Message at all
}
```

Then each protocol has a completely separate Channel type that exposes its own message object.

**Rejected because:**
- The Pipeline Step interface would need to be generic or duplicated per protocol
- Shared Steps (Record) can't observe Message fields even for reporting
- The common case (one Envelope type flowing through one Pipeline) is traded away for an extreme that isn't actually needed

The current proposal (Envelope + Message interface) is the smallest *useful* shared type.

---

## 11. Acceptance Record and Deferred Items

This RFC is **accepted** as of 2026-04-12. Implementation proceeds on N1.

**Completed at acceptance time:**
- [x] Japanese translation exists (`envelope-ja.md`)
- [x] Implementation strategy documented (`envelope-implementation.md`)
- [x] N1–N9 milestones created in Linear
- [x] M36–M44 milestones and incomplete issues moved to Cancelled

**Deferred to implementation phase (per-milestone gating):**
- [x] Open Question #1 (HTTP/2 flow control vs Pipeline latency) — **resolved 2026-04-15: complete-message aggregation model (§9.1)**
- [ ] Open Question #2 (gRPC envelope granularity) — **resolved before N7 starts**
- [ ] Open Question #3 (Starlark plugin API shape) — **resolved before N8 starts**
- [ ] Envelope + Message Go interfaces compiled and validated — **part of N1**
- [ ] Pseudocode-level InterceptStep implementation proving dispatch pattern — **part of N3**
- [ ] Migration reuse % validated against actual file sizes — **part of each N milestone retrospective**

---

## Appendix A: Naming Decisions

- `Envelope` over `Message` — the outer container is an envelope wrapping a typed message. The payload type is called `Message` and is the inner interface.
- `Layer` over `Stage` — matches the networking literature.
- `Channel` over `Stream` or `Codec` — "Codec" carried the conflation we're trying to remove; "Stream" collides with existing `flow.Stream` terminology.
- `ConnectionStack` over `LayerStack` — emphasizes the per-connection lifetime.
- `HTTPMessage` over `HTTPExchange` — "Exchange" is vestigial from the old model.

## Appendix B: Glossary

| Term | Meaning |
|------|---------|
| Envelope | Protocol-agnostic outer container with identity, raw bytes, typed Message |
| Message | Protocol-specific structured payload (interface + implementations) |
| Layer | Connection-level component that yields Channels |
| Channel | Pipeline input/output unit; one Channel drives one RunSession |
| ConnectionStack | Mutable layer stack per client connection, owned by the Connector |
| Byte-stream layer | TCP, TLS — transforms `net.Conn` to `net.Conn` |
| Message-stream layer | HTTP/1, HTTP/2, WS, gRPC, SSE — produces Channels |
| Envelope-only Step | Pipeline Step that uses only `Envelope` fields (protocol-agnostic) |
| Message-typed Step | Pipeline Step that type-switches on `env.Message` |
| Variant snapshot | Clone of Envelope taken at Pipeline.Run entry, used to detect modifications |

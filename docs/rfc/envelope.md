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

#### 3.2.3 gRPC Messages

A gRPC RPC is surfaced as a **stream of three event types** on a single Channel. Each event type is its own Message implementation. Metadata and trailers have their own types; HTTPMessage is **not** reused for gRPC. See §9.2 for the resolution and rationale.

```go
// GRPCStartMessage carries the gRPC metadata (HEADERS frame) for both
// request-side and response-side openings. One per direction per RPC.
type GRPCStartMessage struct {
    // Derived from :path on the request side; mirrored on the response side.
    Service string
    Method  string

    // gRPC metadata — custom and reserved. HTTP/2 pseudo-headers (:method,
    // :path, :status, etc.) are NOT included here; they belong to the
    // transport layer and are observable via Envelope.Context if needed.
    Metadata []KeyValue

    // Parsed gRPC-specific metadata for convenience. Wire copies also
    // remain in Metadata (wire fidelity).
    Timeout        time.Duration // grpc-timeout parsed (0 = unset)
    ContentType    string        // application/grpc[+proto|+json|...]
    Encoding       string        // grpc-encoding (identity, gzip, deflate, ...)
    AcceptEncoding []string      // grpc-accept-encoding
}

// GRPCDataMessage carries one length-prefixed gRPC message (LPM), reassembled
// from the underlying H2 DATA event stream (LPM boundaries are independent of
// DATA frame boundaries).
type GRPCDataMessage struct {
    // Denormalized from the associated GRPCStartMessage. Read-only.
    Service string
    Method  string

    // Wire-level fields (from the 5-byte LPM prefix).
    Compressed bool   // first byte of the 5-byte prefix
    WireLength uint32 // uint32 length field of the 5-byte prefix

    // Always decompressed bytes, regardless of Compressed flag, for inspection
    // convenience. On Send, the Layer re-compresses per Compressed + the
    // negotiated grpc-encoding. To inject malformed compressed bytes, write
    // Envelope.Raw directly.
    Payload []byte

    // EndStream mirrors the H2 DATA frame's END_STREAM flag. gRPC clients
    // do not emit trailer headers, so the request side has no analog of
    // GRPCEndMessage; the wire-level terminator is END_STREAM=1 on the
    // last DATA frame. Layers attach the bit to the trailing LPM produced
    // from each frame (or to the previously-queued LPM when the
    // terminating frame carries empty payload). Termination mid-LPM, or
    // with no LPM ever emitted on the direction, is a protocol violation
    // surfaced via *layer.StreamError, not via this field.
    EndStream bool
}

// GRPCEndMessage carries the trailer HEADERS frame (with END_STREAM) that
// terminates a gRPC RPC. Always Direction=Receive.
type GRPCEndMessage struct {
    // grpc-status parsed (codes.OK, codes.Canceled, ...)
    Status uint32
    // grpc-message parsed (percent-decoded)
    Message string
    // grpc-status-details-bin parsed bytes (raw protobuf Status message;
    // decoding schema-dependent; left as bytes).
    StatusDetails []byte

    // Remaining trailer metadata (after removing grpc-status, grpc-message,
    // grpc-status-details-bin).
    Trailers []KeyValue
}
```

**Envelope.Raw for gRPC envelopes** contains the wire bytes specific to that event:
- `GRPCStartMessage`: the encoded HPACK block of the HEADERS frame (not the HTTP/2 frame wrapper).
- `GRPCDataMessage`: the 5-byte LPM prefix + compressed payload, exactly as observed on the wire.
- `GRPCEndMessage`: the encoded HPACK block of the trailer HEADERS frame.

HTTP/2 frame-level bytes (frame headers, SETTINGS, WINDOW_UPDATE, etc.) are owned by the HTTP/2 Layer and are not exposed on gRPC envelopes. To observe them, attach to the HTTP/2 Layer's event stream directly (see §3.3.2).

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
//
// Each per-stream Channel is EVENT-GRANULAR: Next() yields H2HeadersEvent,
// H2DataEvent (for each DATA frame, or each BodyBuffer drain chunk), and
// H2TrailersEvent. Pipeline consumers that want an aggregated HTTPMessage
// must wrap with HTTPAggregatorLayer (see below); gRPC consumers wrap with
// GRPCLayer. See §9.1 revised resolution for the rationale.
//
// Flow control: the Layer appends DATA bytes to a per-stream BodyBuffer and
// sends WINDOW_UPDATE at append time, independent of whether the Pipeline
// has consumed the event yet. Per-stream soft cap triggers stream-level
// stall + disk spill; hard cap triggers RST_STREAM. Connection-level WINDOW
// is decoupled from Pipeline latency.
func New(conn net.Conn, role Role) layer.Layer
```

```go
package httpaggregator
// Wrap consumes an HTTP/2 (or HTTP/1.x event-granular) stream Channel and
// produces one HTTPMessage envelope per request/response. Used for plain
// HTTP/2 traffic that the user wants to treat as request-response pairs
// (intercept/transform on full message) rather than as an event stream.
//
// Aggregation reuses the N6.5 BodyBuffer: small bodies land in HTTPMessage.Body,
// large bodies land in HTTPMessage.BodyBuffer with the same materialize semantics.
//
// For gRPC streams (content-type: application/grpc), the caller must use
// GRPCLayer.Wrap instead; HTTPAggregatorLayer cannot represent streaming.
func Wrap(stream layer.Channel, role Role) layer.Channel
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
// Wrap takes an event-granular HTTP/2 stream Channel and surfaces its events
// as gRPC envelopes. The mapping is:
//   H2HeadersEvent  → GRPCStartMessage envelope
//   H2DataEvent*    → GRPCDataMessage envelope (one per LPM; LPM reassembly
//                     happens inside the wrapper, independent of DATA frame
//                     boundaries)
//   H2TrailersEvent → GRPCEndMessage envelope
//
// Requires the caller to have peeked the first H2HeadersEvent for content-type
// detection before calling Wrap. The peeked event is consumed by Wrap and
// re-emitted as the first envelope on the wrapped Channel.
func Wrap(stream layer.Channel, firstHeaders *envelope.Envelope, role Role) layer.Channel
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
  Client:   [TCP → TLS(ALPN=h2) → HTTP/2]  (event-granular)
  Upstream: [TCP → TLS(ALPN=h2) → HTTP/2]  (event-granular, pooled)

HTTP/2 layer's Channels() yields one event-granular Channel per new stream:
  for clientStreamChan := range clientH2.Channels():
    go handleStream(clientStreamChan)

handleStream(clientStreamChan):
  // Peek the first event on the raw H2 Channel (H2HeadersEvent).
  firstHeaders := clientStreamChan.Next(ctx)

  upstreamStreamChan := upstreamH2.OpenStream(ctx)

  if isGRPC(firstHeaders):
    // Wrap each side with GRPCLayer: GRPCStart + GRPCData* + GRPCEnd
    clientGRPC   := grpclayer.Wrap(clientStreamChan, firstHeaders, ServerRole)
    upstreamGRPC := grpclayer.Wrap(upstreamStreamChan, firstHeaders, ClientRole)
    Session.RunSession(clientGRPC, staticDial(upstreamGRPC), pipeline)
  else:
    // Plain HTTP/2: wrap with HTTPAggregatorLayer for one HTTPMessage per
    // request/response (same user-visible ergonomics as HTTP/1.x).
    clientHTTP   := httpaggregator.Wrap(clientStreamChan, ServerRole, firstHeaders)
    upstreamHTTP := httpaggregator.Wrap(upstreamStreamChan, ClientRole, nil)
    Session.RunSession(clientHTTP, staticDial(upstreamHTTP), pipeline)
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
| `internal/layer/http2/` (HTTP/2 Layer built in N6/N6.5/N6.6 with in-layer aggregation) | **Split** into `internal/layer/http2/` (event-granular Channel: H2HeadersEvent/H2DataEvent/H2TrailersEvent, BodyBuffer-driven flow control) + `internal/layer/httpaggregator/` (wrapper that produces HTTPMessage for plain HTTP/2). Aggregation algorithm + BodyBuffer integration preserved verbatim — only API boundary moves. Tracked as N6.7 aftermath. | 85% |
| `internal/rules/grpc/` (new) | gRPC-typed engines: InterceptEngine/TransformEngine/SafetyEngine operating on GRPCStartMessage / GRPCDataMessage / GRPCEndMessage. LPM reassembly handled at Layer; engines see logical events. | 0% (new) |
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

N6: HTTP/2 Layer  [DONE as of N6 / N6.5 / N6.6]
    http2 layer (frame codec, HPACK, per-stream channels)
    Upstream connection pool (basic: per-target, LRU eviction)
    Deliverable: HTTPS + h2 normal traffic works

N6.7: HTTP/2 Layer Split (aftermath)  [BLOCKS N7]
    Split current HTTP/2 Layer (in-layer aggregation) into:
      - internal/layer/http2/ — event-granular Channel (H2HeadersEvent /
        H2DataEvent / H2TrailersEvent); BodyBuffer-driven flow control
      - internal/layer/httpaggregator/ — wrapper producing HTTPMessage
    BodyBuffer and aggregation algorithm preserved verbatim; only API moves.
    Rationale: §9.1 revised resolution (2026-04-23) + §9.2 resolution.
    Deliverable: plain HTTP/2 traffic unchanged end-to-end; event-granular
                 Channel available for GRPCLayer (N7).

N7: Application Layers
    grpclayer: consumes event-granular HTTP/2 Channel, emits
               GRPCStartMessage / GRPCDataMessage / GRPCEndMessage envelopes
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

**Milestone dependency:** N1 → N2 → N3 → (N4 || N5) → N6 → N6.7 → N7 → N8 → N9. N4 and N5 can proceed in parallel after N3 lands. N6.7 is an aftermath of the §9.1/§9.2 resolution (2026-04-23) and blocks N7.

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
**Revised:** 2026-04-23 (supersedes the 2026-04-15 in-layer aggregation model; see OQ#2 resolution for motivation)

**Problem:** HTTP/2 has per-stream and per-connection flow control (WINDOW_UPDATE frames). If a Pipeline Step blocks for minutes (e.g., `InterceptStep` waiting for AI agent action), the stream's WINDOW fills and the downstream side stalls. If *many* concurrent streams on the same connection all block simultaneously, connection-level WINDOW fills and the entire HTTP/2 connection stalls, impacting unrelated streams.

**Resolution: Event-granular HTTP/2 Layer with bounded per-stream buffers; aggregation is an upper-layer wrapper.**

The initial resolution (2026-04-15) folded aggregation inside the HTTP/2 Layer so `Channel.Next()` returned one complete `HTTPMessage` per stream. Work on OQ#2 (gRPC granularity) revealed this model cannot coexist with streaming gRPC — long-lived bidi streams never "complete", so there is nothing to aggregate. The underlying design mistake was letting Pipeline latency propagate into the transport layer. The revision below fixes that by decoupling the two concerns.

**Decision:**

1. **HTTP/2 Layer is always event-granular.** Its Channels yield three event types on each stream: `H2HeadersEvent` (from HEADERS frame), `H2DataEvent` (from DATA frame *or* from a BodyBuffer chunk — see below), and `H2TrailersEvent` (from trailer HEADERS frame with END_STREAM).
2. **Per-stream buffer drives flow control.** Each stream owns a `BodyBuffer` (reusing the N6.5 memory-then-spill primitive). DATA frames are appended to the buffer as they arrive; the Layer sends WINDOW_UPDATE **at append time**, not at Pipeline-consume time. Connection-level WINDOW is therefore decoupled from Pipeline latency entirely — no Pipeline hold, however long, can affect other streams on the same connection.
3. **Back-pressure is stream-scoped, not connection-scoped.** If a stream's BodyBuffer grows past a per-stream soft cap while the Pipeline holds it, the Layer stops replenishing *that stream's* WINDOW (stream-level stall), then spills to disk, then RST_STREAMs if a hard cap is breached. Other streams are never affected.
4. **Aggregation is a wrapper Layer, not a property of HTTP/2 Layer.** For plain HTTP/2 traffic the `HTTPAggregatorLayer` consumes H2 events and produces one `HTTPMessage` per request/response (preserving the N6.5 user-visible behavior for HTTP/1.x parity). For gRPC, `GRPCLayer` consumes the same events and produces `GRPCStartMessage` / `GRPCDataMessage` / `GRPCEndMessage` without ever aggregating.

**Why this resolves the flow control concern:**

- Transport-layer ACKing is now independent of application-layer processing speed. WINDOW_UPDATE fires as soon as the byte reaches the per-stream buffer, which happens within microseconds of the frame reader goroutine pulling it off the socket. Pipeline blocking an individual stream cannot backpressure the connection.
- Worst-case memory per connection is `perStreamSoftCap × MAX_CONCURRENT_STREAMS`. Once the soft cap is reached for a stream, that stream spills to disk; the soft cap itself is tunable. The disk-spill path is already proven in N6.5.
- Plain HTTP users see the same "one HTTPMessage per exchange" ergonomics as before, via HTTPAggregatorLayer. Streaming-protocol users (gRPC, future SSE) see events as they arrive.

**Rejected alternatives:**
- **In-layer aggregation (the 2026-04-15 resolution):** Cannot support streaming gRPC; forces passthrough-mode body skipping for any bidi stream.
- **Frame-per-envelope streaming without buffering (original pre-2026-04-15 proposal):** Pipeline holds cause connection-level WINDOW stall. Fixed here by decoupling buffer drain from Pipeline drain.
- **Pipeline-driven back-pressure:** Same connection-level stall problem.
- **Async Intercept:** Breaks the "intercept blocks forwarding" contract that the MCP tool surface depends on.

**Migration note:** The HTTP/2 Layer built in N6 / N6.5 / N6.6 implements in-layer aggregation. Splitting it into `HTTP2Layer` (event-granular) + `HTTPAggregatorLayer` (wrapper) is tracked as an N6-series aftermath Issue (see N6.7). The aggregation algorithm and BodyBuffer integration survive verbatim — only the API boundary moves.

### 9.2 gRPC Message Envelope Granularity — RESOLVED

**Resolved:** 2026-04-23

**Problem:** A gRPC RPC is a stream of events: (request HEADERS) + (request DATA*) + (response HEADERS) + (response DATA*) + (trailers HEADERS). Even unary is conceptually "start + 1 message + end". How should these be surfaced to the Pipeline?

**Resolution: Event-per-envelope with dedicated gRPC Message types.**

Each logically distinct gRPC event becomes its own Envelope with its own Message type. Unlike the original tentative proposal, HTTPMessage is **not** reused for headers/trailers — gRPC has its own semantics (grpc-status, grpc-timeout, grpc-encoding) that do not survive the HTTPMessage type-system contract ("any field on HTTPMessage must be meaningful as HTTP"). The new message types are:

| Wire event | Envelope.Message type | When it fires |
|------------|----------------------|---------------|
| Request HEADERS | `GRPCStartMessage` | Direction=Send, Sequence=0 |
| Each length-prefixed request message | `GRPCDataMessage` | Direction=Send, one per LPM |
| Response HEADERS | `GRPCStartMessage` | Direction=Receive, Sequence=0 |
| Each length-prefixed response message | `GRPCDataMessage` | Direction=Receive, one per LPM |
| Trailer HEADERS (with END_STREAM) | `GRPCEndMessage` | Direction=Receive, last |

All five events share a single `Envelope.StreamID` (the HTTP/2 stream ID); `Sequence` orders them within the stream. Pipeline Steps operating on the "full RPC" aggregate across envelopes keyed by StreamID.

**Granularity is the length-prefixed gRPC message (LPM), not the HTTP/2 DATA frame.** A single gRPC message may span multiple DATA frames; a DATA frame may contain multiple gRPC messages. The gRPC Layer reassembles LPM boundaries from the raw byte stream surfaced by the H2 Layer (`H2DataEvent`). `Envelope.Raw` on a `GRPCDataMessage` envelope is exactly the 5-byte prefix + payload wire bytes (compressed form, if compression is in use).

**Compression handling:**
- `GRPCDataMessage.Compressed` reflects the wire-level flag (first byte of 5-byte prefix).
- `GRPCDataMessage.Payload` is **always decompressed** bytes for inspection convenience.
- `GRPCDataMessage.WireLength` is the wire-level length (compressed bytes length).
- `Envelope.Raw` carries the exact wire bytes (5-byte prefix + compressed payload).
- On Send: if `Compressed=true`, the gRPC Layer re-compresses `Payload` using the negotiated `grpc-encoding` before writing. If a user wants to inject deliberately malformed compressed bytes, they write `Envelope.Raw` directly via a low-level bypass (same pattern as raw TCP layer).

**Why this resolves the question:**

- Matches wire reality (wire is an event stream, type system reflects it).
- gRPC streaming is first-class: bidi streams produce events as they arrive, Pipeline can intercept/transform any single message without waiting for stream completion.
- No `HTTPMessage`-shaped lies: every field on every Message type is meaningful for that protocol at that event.
- Pipeline flow-control concerns delegated to the revised §9.1 resolution (transport-layer buffers are decoupled from Pipeline).
- MCP `resend_grpc` tool maps naturally to "replay this stream of events, with optional per-event edits".

**Rejected alternatives:**
- **Frame-per-envelope reusing HTTPMessage for headers/trailers (original tentative proposal):** Creates "HTTPMessage with only Trailers populated" instances, violating the §3.1 design rule that every field must be meaningful for its type. gRPC semantics (status code, timeout, encoding negotiation) have no natural home on HTTPMessage.
- **Aggregated-per-message with metadata bundled into first message:** Delays headers observation until the first LPM is fully received, which interacts badly with server-streaming (headers may be observable long before first message arrives).
- **Aggregated-per-RPC:** Works only for unary; cannot represent streaming.

**Sub-decisions recorded here:**
- Metadata on `GRPCDataMessage` (Service, Method) is **read-only denormalization** from the associated `GRPCStartMessage`. To change service/method, intercept the Start envelope.
- grpc-web is out of scope for this resolution; it has its own layer (`GRPCWebLayer`) that wraps either HTTP/1 or HTTP/2 aggregated `HTTPMessage` (base64 or binary framing). See Friction 4-C in `envelope-implementation.md`.
- HTTP/2 CONNECT + `:protocol` extended CONNECT (RFC 8441) for WebSocket-over-H2 remains deferred per N7's milestone scope.
- **Request-side termination (USK-663, 2026-04-27):** `GRPCDataMessage` carries an `EndStream bool` mirroring the H2 DATA frame's END_STREAM flag. gRPC clients emit no trailer headers, so the only request-side terminator on the wire is the END_STREAM bit on the last DATA frame. When a DATA frame's payload completes one or more LPMs and carries END_STREAM=1, the trailing LPM owns the bit. When a terminating frame carries empty payload (the canonical gRPC-Go `Stream.CloseSend` shape `DATA(payload=msg)` then `DATA(payload=, END_STREAM=1)`), the wrapper synthesizes a pure end-marker envelope — `GRPCDataMessage{Payload: nil, WireLength: 0, Compressed: false, EndStream: true}` — so the wire-frame boundary is observable in Pipeline and on Send the wrapper emits an empty H2 DATA payload with END_STREAM=1. Mid-LPM termination (reassembler holds partial bytes when END_STREAM arrives) cannot be faithfully forwarded and surfaces as `*layer.StreamError{ErrorProtocol}`. EndStream is a wire-affecting field for variant-recording purposes (Pipeline Steps that toggle it produce variant rows).

### 9.3 Starlark Plugin API Shape — RESOLVED

**Resolved:** 2026-04-29

**Problem:** Legacy `internal/plugin/` exposed `request.method`, `request.url`, etc. as Starlark values with HTTP-only field names and 8 hook names that conflated direction and Pipeline timing (`on_receive_from_client` / `on_before_send_to_server`, etc.). With typed Messages from RFC §3.2, plugins must see a protocol-shaped object, and the hook surface must be uniform across protocols. In addition, plugins need to fire at two distinct Pipeline-relative timings — before user-visible Intercept editing (annotation, fingerprinting) and after all mutations have settled (signing, last-mile mutation). The legacy 4-name pattern conflated these axes; RFC-001 separates them.

**Resolution: Three-axis Hook identity `(protocol, event, phase)` with mutable Starlark dict messages.**

A Hook is uniquely identified by three axes registered together:

```python
register_hook(protocol, event, fn, phase="pre_pipeline")
```

- **`protocol`** — string namespace matching either an RFC §3.2 Message type or one of four pseudo-protocols for connection-lifecycle and transport hooks: `"http"`, `"ws"`, `"grpc"`, `"grpc-web"`, `"sse"`, `"raw"`, `"connection"`, `"tls"`, `"socks5"`.
- **`event`** — string name of the wire event within that protocol. The valid `(protocol, event)` pairs are enumerated in the table below; load-time validation rejects unknown pairs.
- **`phase`** — `"pre_pipeline"` (default) or `"post_pipeline"`. Determines firing point relative to the Pipeline Step chain. Lifecycle and observation-only hooks (those marked "no phase" below) ignore this argument.

**Hook surface (the complete enumeration):**

| `(protocol, event)` | Phase support | Action surface |
|---|---|---|
| `("http", "on_request")` | pre / post | DROP, RESPOND, CONTINUE+mutate |
| `("http", "on_response")` | pre / post | CONTINUE+mutate, RESPOND-replace |
| `("ws", "on_upgrade")` | pre / post | DROP, RESPOND, CONTINUE+mutate |
| `("ws", "on_message")` | pre / post | CONTINUE+mutate |
| `("ws", "on_close")` | no phase | observe only |
| `("grpc", "on_start")` | pre / post | DROP, RESPOND-with-status, CONTINUE+mutate |
| `("grpc", "on_data")` | pre / post | CONTINUE+mutate |
| `("grpc", "on_end")` | no phase | observe only |
| `("grpc-web", "on_start")` | pre / post | DROP, RESPOND-with-status, CONTINUE+mutate |
| `("grpc-web", "on_data")` | pre / post | CONTINUE+mutate |
| `("grpc-web", "on_end")` | no phase | observe only |
| `("sse", "on_event")` | pre / post | CONTINUE+mutate |
| `("raw", "on_chunk")` | pre / post | CONTINUE+mutate |
| `("tls", "on_handshake")` | no phase | observe only |
| `("connection", "on_connect")` | no phase | DROP, CONTINUE |
| `("connection", "on_disconnect")` | no phase | observe only |
| `("socks5", "on_connect")` | no phase | DROP, CONTINUE |

Any other `(protocol, event)` combination is a load-time error.

**Decision:**

1. **Two-phase Pipeline integration (decoupled from Intercept timing).** The Pipeline contains two plugin Steps: `PluginStepPre` and `PluginStepPost`. The execution order is `Scope → RateLimit → Safety → PluginStepPre → Intercept → Transform → Macro → PluginStepPost → Record → (Layer encode)`. `pre_pipeline` plugins fire after Safety (so Safety blocks before plugin sees) and before Intercept (so plugin annotations are visible to user/AI in the intercept UI). `post_pipeline` plugins fire after all mutations are settled, before Record and wire encode. Resend, Macro fan-out (fuzz), and synthesized Send paths bypass `PluginStepPre` and traverse only `Transform → Macro → PluginStepPost → Record → Layer encode`; consequently, `post_pipeline` plugins receive every wire-bound variant exactly once, while `pre_pipeline` plugins fire only on fresh wire receive.

2. **Mutable dict with WireEncoder regeneration.** Plugins receive `msg` as a snake_case Starlark dict (e.g., `msg["method"]`, `msg["headers"]`). Field key names are derived mechanically from the corresponding Go Message struct field names (PascalCase → snake_case) so future field additions require no manual mapping table. On hook return, the Layer reads back fields and applies them to `Envelope.Message`; if any Message field changed, `Envelope.Raw` is regenerated via the per-protocol WireEncoder (USK-661 grpc-web pattern, USK-N3 http1 pattern). Audit trail is provided by the existing Variant Snapshot mechanism (§5) — plugin mutations that diverge from the snapshot produce a variant row identical in shape to TransformStep mutations.

3. **Headers as ordered list of pairs with case-insensitive read accessor.** `msg["headers"]` is a list of `(name, value)` 2-tuples preserving wire case, order, and duplicates. Mutation operations are `append`, `replace_at(index, pair)`, `delete_first(name)`, etc. — operations that preserve order. A read-only convenience method `headers.get_first(name)` does case-insensitive lookup but does **not** alter the list. The Layer never re-canonicalizes; any plugin attempt to invoke a re-sort or dedup operation raises a Starlark error explicitly (`fail("ordered list operations only")`) rather than silently re-ordering. This satisfies the §1.4 wire-fidelity invariant under plugin mutation.

4. **Both Message and Raw editable; Raw wins if both touched.** A plugin may write `msg["raw"] = b"..."` to inject byte-level content directly. If the plugin modified `msg["raw"]` (compared to its snapshot), the Layer takes the wire-faithful path and writes the bytes verbatim, ignoring any Message-field mutations. This preserves smuggling-test capability (the original motivation for §1.4) under the plugin API. If only Message fields changed, the Layer regenerates Raw via WireEncoder. If neither changed, the original Raw passes through zero-copy.

5. **Action surface depends on event semantics, not direction.** DROP/RESPOND are valid only at transaction-start events (`http.on_request`, `http.on_response`, `ws.on_upgrade`, `grpc.on_start`, `grpc-web.on_start`, `connection.on_connect`, `socks5.on_connect`). Mid-stream events (`on_data`, `on_message`, `on_event`, `on_chunk`) accept only CONTINUE + mutation; "drop a frame" is not wire-realizable for stateful streams without breaking the stream, so plugins that want to terminate must use the protocol's native termination action (e.g., `ctx.rst_stream(code)` for gRPC/HTTP/2, `ctx.close(code, reason)` for WebSocket). Lifecycle observation events accept no actions other than CONTINUE.

6. **Per-stream / per-transaction state via `ctx.stream_state` and `ctx.transaction_state`.** The Layer provides two scoped dict-like objects on the `ctx` argument. `ctx.transaction_state` is bound to a single HTTP request/response pair (or one WS upgrade). `ctx.stream_state` is bound to an HTTP/2 StreamID (used by gRPC, WebSocket-over-H2, future server push); the Layer auto-releases it when the stream ends. Plugins do not manage their own dicts keyed by ID — that pattern leaks if the plugin forgets to clean up.

7. **Strict load-time validation; runtime mismatch silently skips with Debug log.** `register_hook("htttp", "on_request", ...)` (typo) raises a Starlark module-load error against the enumeration above. At runtime, when an envelope of a different `Envelope.Message` type than registered reaches the plugin Step, the plugin is skipped and a single Debug log line is emitted. An MCP introspection tool (`plugin_introspect`) returns the registered `(protocol, event, phase)` tuples per plugin so AI agents can self-verify their hook setup.

8. **No backwards compatibility.** The legacy 8-hook surface (`on_receive_from_client`, etc.) is removed entirely. User scripts must be rewritten against the new shape; a one-page migration table (legacy hook → `(protocol, event, phase)`) ships with N9 release notes. Per RFC-001 implementation discipline rule #5 ("no shims"), no compat alias is introduced.

**Why this resolves the question:**

- Wire fidelity: header mutation preserves case/order/duplicates by construction; Raw byte injection remains available for smuggling diagnostics.
- L7/L4 duality at the plugin API: Both Message-level and Raw-level editing are first-class. Smuggling-class plugins write `msg["raw"]`; ergonomic transform plugins write fields.
- Protocol-uniform: every Hook identity is `(protocol, event[, phase])`. Adding a future protocol (e.g., HTTP/3, MQTT) requires only enumerating its `(protocol, event)` pairs and the Pipeline-Step plumbing — no plugin-API changes.
- AI-agent friendly: `plugin_introspect` tool exposes the registration table; snake_case dict serializes naturally to JSON for MCP transport.
- Two-phase covers both observation and last-mile mutation use cases (annotation/fingerprinting at `pre_pipeline`; HMAC/signing/Content-Length recomputation at `post_pipeline`); resend/fuzz fire only `post_pipeline` because pre is "fresh wire receive".

**Rejected alternatives:**

- **Single-phase plugin Step (one `PluginStep` between Safety and Intercept, the legacy position):** Cannot express "sign after final mutations are settled". Forces signing plugins to live in TransformStep, but TransformStep is declarative-rule-driven and cannot host arbitrary Starlark.
- **Direction-prefixed hook names (`on_request_received` / `on_request_sending`, mirroring legacy):** Conflates phase with hook identity. Adding a future "between Intercept and Transform" phase would require new hook names.
- **Read-only dict + explicit `ctx.modify(field, value)` API:** Verbose for the common case; creates two ways to do the same thing (because Raw-byte injection still needs `msg["raw"] = ...` shape).
- **Method-call API on Message (`msg.method()`, `msg.set_method(...)`):** Starlark has no struct/class system; the dict shape is idiomatic.
- **Compatibility shim for legacy 8 hooks:** Violates RFC-001 implementation discipline rule #5; reintroduces HTTP bias via the back door.
- **Per-protocol hook registration functions (`register_http_hook(...)`, `register_ws_hook(...)`):** Equivalent to the chosen design but multiplies the loadable name surface and breaks the `(protocol, event, phase)` introspection symmetry.

**Sub-decisions recorded here:**

- **Snake-case key derivation is mechanical.** A `convertMessageToDict` helper performs PascalCase → snake_case conversion on Message field names. No manual alias table; future fields appear under their derived name automatically.
- **`phase` default is `pre_pipeline` and is documented as such.** Plugin authors writing observation/annotation plugins (the majority case) need not pass `phase=` at all. Signing/finalization plugins must explicitly opt in via `phase="post_pipeline"`.
- **`PluginStepPost` runs once per Macro variant.** A fuzz run that generates 1000 variants invokes `post_pipeline` plugins 1000 times, each receiving the variant-specific final state. Plugin authors must keep `post_pipeline` work O(1) per envelope.
- **Resend is `PluginStepPost`-only.** The Resend MCP tools (`resend_http`, `resend_ws`, `resend_grpc`, `resend_raw`) construct an Envelope from stored Flow data and inject directly into the Pipeline at `Transform`'s entry. `pre_pipeline` plugins do not fire because the data is not fresh-wire receive. This is the correct semantics for signing plugins (re-sign on each resend) and for forensic plugins (already saw the original wire receive).
- **`("http", "on_response")` accepts RESPOND-replace** but not RESPOND-with-status (a response already has its status; replacement supersedes the upstream response). DROP is excluded because dropping a response yields a hung client; plugins that want to terminate a response should mutate it to a synthetic 502 instead.
- **`tls.on_handshake` is observation-only.** The TLS handshake is opaque to higher layers in MITM operation; the proxy already terminates client TLS and re-handshakes upstream. Plugins observe ClientHello, ServerHello, and JA3/JA4 fingerprints but cannot modify them — modification would require re-implementing the TLS state machine in Starlark.
- **`socks5.on_connect` is the SOCKS5 tunnel-established event** (post-handshake, pre-data). The handshake itself (SOCKS5 method negotiation, auth) is not exposed because the per-method bytes have no useful Starlark abstraction; if needed in the future, a separate `socks5.on_handshake` event can be added under the same `(protocol, event)` enumeration without API change.
- **`connection.on_connect` accepts DROP** for IP-allowlist plugins. DROP closes the accepted TCP connection before any further Layer is built. This is the only place a plugin can reject a connection without protocol participation.
- **Plugin-introduced state lifetime.** `ctx.transaction_state` is GC'd when the parent Pipeline session ends (one HTTP request/response pair, or one WS upgrade transaction). `ctx.stream_state` is GC'd when the H2 stream reaches `complete`/`error`/`reset`. Lifetime is enforced by the Layer; plugins cannot extend it.

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
- [x] Open Question #1 (HTTP/2 flow control vs Pipeline latency) — **resolved 2026-04-15; revised 2026-04-23: event-granular HTTP/2 Layer + HTTPAggregatorLayer wrapper (§9.1)**
- [x] Open Question #2 (gRPC envelope granularity) — **resolved 2026-04-23: event-per-envelope with dedicated GRPCStart/Data/End types (§9.2)**
- [x] Open Question #3 (Starlark plugin API shape) — **resolved 2026-04-29: three-axis Hook identity `(protocol, event, phase)` with two-phase Pipeline integration and mutable Starlark dict messages (§9.3)**
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

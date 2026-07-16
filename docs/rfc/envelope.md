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

    // USK-920: the request-side pseudo-headers (:authority, :scheme,
    // :path) are projected as derived L7 fields so RecordStep can build
    // Flow.URL the same way it does for HTTPMessage. Empty on the
    // response side (response HEADERS only carry :status). The pseudo-
    // header wire bytes remain in Envelope.Raw — these fields are an
    // overlay, not a replacement.
    Authority string
    Scheme    string
    Path      string

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

**Wire-level recording overlays.** In addition to the semantic gRPC envelopes above, the data path records two wire-level views per RPC (controlled by `internal/session/grpc_lpm_record.go` and `internal/session/grpc_h2_data_frame_record.go`):

- `wire_level=grpc-lpm-frame` — one envelope per fully reassembled LPM (5-byte prefix + payload, BEFORE decompression). Captures LPM length-prefix smuggling, compressed-flag anomalies, and multi-LPM-in-one-DATA-frame packing.
- `wire_level=h2-frame` — one envelope per H2 DATA event consumed by the gRPC Layer, BEFORE LPM reassembly. Captures per-DATA-frame boundaries that LPM reassembly hides (tiny-DATA-frame covert channels, zero-payload DATA frames between LPMs, `SETTINGS_MAX_FRAME_SIZE` boundary anomalies). Native gRPC is the third producer of this wire_level value alongside `httpaggregator` (USK-897) and the WS/SSE-over-h2 detach paths (USK-889).

The two overlays produce independent per-direction sequence counters; the schemaV14 UNIQUE constraint on `(stream_id, sequence, direction, variant, wire_level)` keeps the three views (semantic + LPM + h2-frame) from colliding under the same StreamID.

**MCP default exposure (USK-921).** The MCP `query` tool (`messages` / `flow` / `flows` resources) hard-defaults `filter.wire_level` to `semantic` at the control-plane boundary so the L7 view never returns overlay rows by default — they would otherwise inflate `message_count` and `message_preview` by 2-4x on gRPC / WS / SSE / gRPC-Web flows. AI agents opt in to overlay rows via `filter.wire_level={h2-frame | h1-chunk | grpc-lpm-frame | grpcweb-base64 | all}`. The wire-level data persists losslessly in the flow store regardless of the MCP cosmetic default (L4-capable promise: §3.2 wire-level recording always holds; the default filter is a cosmetic projection at the MCP transport boundary, never a wire-data modification).

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
//
// The same constructor serves both transport modes:
//   - HTTP/1.1 Upgrade (RFC 6455): (reader, writer, closer) is the triple
//     returned by http1.Layer.DetachStream(). Wire framing is full WS.
//   - HTTP/2 extended CONNECT (RFC 8441) — "h2 mode": (reader, writer,
//     closer) is the per-stream byte triple returned by
//     http2.Layer.DetachStream(streamID). The Layer MUST be constructed
//     in h2 mode (selected via Option / Role pair documented at
//     implementation time) so that the framing rules below are honoured.
//
// h2-mode semantics (normative):
//   - **Masking.** Per RFC 8441 §5.3, client→server WS frames over an
//     HTTP/2 stream MUST NOT have the MASK bit set, regardless of Role.
//     The Layer MUST emit unmasked frames in both directions in h2 mode
//     and MUST surface a *layer.StreamError on receive if a peer sets
//     MASK=1 (RFC 8441 §5.3 violation).
//   - **Termination.** Stream end is signaled by HTTP/2 END_STREAM, NOT
//     by a WS Close frame. The Layer in h2 mode MUST NOT generate a WS
//     Close frame on stream termination, and MUST tolerate (record but
//     not double-close) an inbound WS Close frame from the peer.
//   - **No `Connection`/`Upgrade` headers.** Those HTTP/1.1 hop-by-hop
//     headers are absent from extended CONNECT; the Layer relies solely
//     on the per-stream byte stream surfaced by http2.Layer.DetachStream.
func New(reader io.Reader, writer io.Writer, closer io.Closer, role Role) layer.Layer
```

For the HTTP/2 extended CONNECT path, http2.Layer exposes a per-stream variant of `DetachStream` that yields a `(reader, writer, closer)` triple bound to a single stream — distinct from http1's connection-level variant:

```go
// DetachStream tears down http2.Layer's framing for one stream and returns
// a per-stream byte reader / writer / closer triple, leaving the rest of
// the HTTP/2 connection (sibling streams, HPACK state, connection-level
// flow control) untouched. The returned reader emits the stream's DATA
// payload bytes in arrival order (END_STREAM surfaces as io.EOF on the
// reader); the returned writer accepts opaque bytes and frames them as
// DATA on the same stream id. closer terminates the per-stream framing
// without closing the connection.
//
// Used in conjunction with ws.New (h2 mode) to swap a single stream into
// WebSocket framing under RFC 8441 extended CONNECT, with all sibling
// streams continuing as standard HTTP/2.
//
// Bytes that arrived on the stream between the trigger envelope (the
// 2xx response to the extended CONNECT) and the DetachStream call are
// surfaced on the returned reader in arrival order — the per-stream
// BodyBuffer (§9.1 revised resolution) is the source of truth, so DATA
// frames the server sent immediately after the 2xx are not lost. Callers
// MUST drain the reader before generating new outbound DATA on the
// per-stream writer to preserve causal order on the wire.
//
// Distinct from http1.Layer.DetachStream(): the http2 variant takes a
// stream id argument and returns io.ReadCloser / io.WriteCloser, because
// the underlying HTTP/2 connection survives detachment and the per-stream
// framing layer needs its own Close hook.
func (l *Layer) DetachStream(streamID string) (io.ReadCloser, io.WriteCloser, func() error, error)
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

#### 3.3.3 MITM ALPN Transparency (Sniff-First)

A subtle wire-faithfulness requirement applies to the TLS MITM path: when the proxy
terminates the client's TLS in order to inspect L7 traffic, the ALPN extension on
both wires must reflect the upstream's authoritative pick — not a guess the proxy
made up speculatively. RFC 7301 servers like `demo1.nextcloud.com` (USK-995) violate
§3.2 by returning `http/1.1` even for a solo `h2` ALPN offer; the proxy must propagate
that wrong pick transparently rather than impose its own opinion, otherwise it injects
a protocol mismatch the wire never had.

The sniff-first MITM flow (USK-997, `internal/connector/connect_handler.go runTLSMITM` →
`stack_builder.go buildSniffFirstStack`):

1. CONNECT/SOCKS5 200 → peek the inner ClientHello via `peekClientHelloSNIAndALPN`
   (non-consuming, bounded by `clientHelloPeekTimeout`/`clientHelloPeekSize`).
2. Forward the client's ALPN list to upstream **verbatim** (`dialUpstreamWithALPN`
   receives `peeked.ALPN` directly — no sort, no dedup, no case fold; MITM
   Principle #1).
3. Observe upstream's negotiated pick on the resulting `TLSSnapshot.ALPN`.
4. Advertise that pick as a single-element ALPN list to the MITM client
   (`mitmAdvertiseFromUpstreamPick` returns `[upstreamPick]`, or `nil` when
   upstream did not negotiate ALPN so the proxy omits the extension entirely).
5. The client necessarily picks the same single value → end-to-end single-ALPN
   holds by construction; the legacy speculate-then-redial dance is reachable
   only on peek failure (timeout, non-TLS, ECH, ClientHello > 4 KiB).

The pre-sniff widening helpers (`clientALPNOffersForUpstream`,
`canonicalRedialALPNOffer`, `clientALPNMatchesUpstream`, `defaultALPNOffer`)
remain as fallback-only safety nets when the peek did not return an ALPN
list. Their USK-793 / USK-884 history is orthogonal to the sniff-first
flow, which never widens past upstream's authoritative pick.

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

#### 3.4.1 Per-Stream Sub-Stack Overlay (HTTP/2 Extended CONNECT)

`ReplaceClientTop` / `ReplaceUpstreamTop` swap the *connection-level* topmost layer. That is the right primitive for HTTP/1.1 → WebSocket Upgrade (where the whole connection becomes WS) but it is **structurally wrong** for the HTTP/2 extended CONNECT case (RFC 8441), because an HTTP/2 connection multiplexes many concurrent streams. Replacing the connection-level topmost layer would tear down framing for *every* sibling stream when only the extended-CONNECT stream needs WebSocket semantics.

To localize the swap to a single stream without disturbing siblings, `ConnectionStack` carries a per-stream **sub-stack overlay** keyed by stream id. The overlay is empty by default; the connection-level chain is unchanged when no entry is registered. When an extended CONNECT swap occurs (USK-765), the orchestrator constructs a `ws.Layer` pair in h2 mode (see §3.3.2) over the per-stream byte triple returned by `http2.Layer.DetachStream(streamID)` and registers it on the overlay for that stream id only.

```go
package connector

type ConnectionStack struct {
    ConnID string
    Client struct {
        Layers  []layer.Layer
        Topmost layer.Layer
    }
    Upstream struct {
        Layers  []layer.Layer
        Topmost layer.Layer
    }

    // streamSubStacks holds per-stream Layer overlays installed by
    // protocol upgrades that affect a single h2 stream (e.g. RFC 8441
    // extended CONNECT → WebSocket-over-h2). Empty by default; the
    // connection-level Topmost is the source of truth when no entry
    // is registered for a stream id.
    //
    // Map key is envelope.StreamID (the same string returned by
    // layer.Channel.StreamID()). Values are stream-scoped Layer pairs
    // that own the per-stream byte triple obtained via
    // http2.Layer.DetachStream(streamID).
    streamSubStacks map[string]*sideSubStack
}

type sideSubStack struct {
    Client   layer.Layer // ws.Layer in h2 mode (RoleServer)
    Upstream layer.Layer // ws.Layer in h2 mode (RoleClient)
}

// RegisterStreamSubStack installs a per-stream Layer pair on `streamID`.
// The connection-level Layers are unchanged. Sibling streams are
// unaffected and continue to be processed by the connection-level h2
// Layer.
//
// Single-writer invariant: registration MUST happen exactly once per
// stream id, on the same goroutine that observed the trigger envelope
// (the extended CONNECT response), under the existing ConnectionStack
// mutex. Re-registration on the same id is a programming error and
// returns an error without mutating state.
func (s *ConnectionStack) RegisterStreamSubStack(streamID string, client, upstream layer.Layer) error

// ClientTopmostForStream returns the per-stream client Layer if a
// sub-stack is registered for streamID; otherwise it falls back to
// ClientTopmost(). Pipeline / Session per-stream channel iteration
// MUST consult this method (or the symmetric upstream variant) rather
// than ClientTopmost() directly.
func (s *ConnectionStack) ClientTopmostForStream(streamID string) layer.Layer

// UpstreamTopmostForStream is the upstream-side counterpart of
// ClientTopmostForStream.
func (s *ConnectionStack) UpstreamTopmostForStream(streamID string) layer.Layer
```

**Normative invariants:**

- **Multiplex isolation (MUST).** Registering a sub-stack on stream N MUST NOT affect any other stream on the same h2 connection. Sibling streams continue to be processed by the connection-level HTTP/2 Layer with no observable change.
- **Per-stream lookup is the source of truth (MUST).** Pipeline Steps and Session loops that operate on a specific stream MUST resolve the topmost via `*ForStream(streamID)`. The plain `ClientTopmost()` / `UpstreamTopmost()` accessors remain valid only for the connection-level fallback (e.g. building the initial channel iterator) — they MUST NOT be used to fetch the framing layer for a stream that may have been swapped. Whether the per-stream lookup is achieved via `*ForStream` calls on `ConnectionStack` or by carrying a sub-stack reference inside the per-stream `layer.Channel` is an implementation detail of the connector / session glue — pick one and keep it consistent within a single milestone.
- **Sub-stack lifetime tracks the stream (MUST).** When the underlying h2 stream reaches `complete` / `error` / `reset`, the sub-stack entry is removed and its Layer pair Closed. The connection-level Layers remain alive for sibling streams.
- **Goroutine safety (MUST).** All `streamSubStacks` mutations and reads happen under the existing `ConnectionStack` mutex. The map itself is never exposed; callers interact only via the `RegisterStreamSubStack` / `*ForStream` API surface.
- **Recognized `:protocol` values.** Only `:protocol = "websocket"` triggers a sub-stack swap in this milestone. Other `:protocol` values are a forward-compat extension point and MUST currently produce no swap: the stream falls back to the connection-level h2 Layer with the unrecognized value recorded as a stream-level anomaly. The policy for additional `:protocol` registrations is deferred to a follow-up.

**Why this design (option #2 over #1 / #3):**

- **#1 — per-stream `ConnectionStack` (full refactor)** would push every connection-level concern (HPACK state, connection-level flow control, write serialization) into per-stream copies. Rejected: structurally invalid for h2.
- **#3 — `bytechunk` fallback** would record the extended-CONNECT stream as raw bytes only, abandoning structured WS observation for any h2-mode wss endpoint. Rejected: violates the §1.4 L7-first principle whenever the stream is in fact a recognizable WS conversation.
- **#2 — sub-stack overlay (this design)** localizes the swap to the single affected stream, leaves connection-level h2 Layer intact for siblings, and keeps WS framing observable in L7. The cost is one extra map and the `*ForStream` indirection; both are O(1) on the hot path.

**Out of scope for this section (deferred):**

- Default-Chrome `wss://` end-to-end ergonomics depend on USK-763 (deferred); the overlay design is independent of that work.
- HTTP/3 / QUIC extended CONNECT is a separate milestone; the overlay is described against the HTTP/2 framing surface only. The proxy's overall HTTP/3 out-of-scope policy (no UDP listener; ALPN advertises only `h2` / `http/1.1`) is recorded as a first-class deferred item in §11 (USK-1016).
- gRPC / SSE behavior under extended CONNECT is unchanged: those layers do not participate in extended-CONNECT-driven swaps.

#### 3.4.2 TCP Forward L7 Dispatch

In addition to the CONNECT / SOCKS5 / transparent paths, `yorishiro-proxy` accepts pre-configured **TCP forward** listeners (`tcp_forwards` in `proxy_start`). Each entry maps a local port to an upstream `host:port` and selects the connection-stack assembly explicitly rather than via peek-based detection.

Implementation: `internal/proxybuild/tcp_forward.go`. Configuration: `internal/config.ForwardConfig` with three independent axes —

- **`Protocol`** — one of `auto` (peek), `raw`, `http`, `http2`, `grpc`, `websocket`, `sse`. Selects which Layer stack the forward dispatches into; `auto` peeks the first bytes and falls back to `raw` when no L7 signature is detected. Inner L7 dispatch (WebSocket Upgrade, SSE response sniff, gRPC content-type) is derived from the chosen protocol Layer and reuses the same Pipeline.
- **`TLS`** — when `true`, the proxy terminates client TLS on the forward listener (the per-entry `tls.Config` honors SNI and dispatches by negotiated ALPN), then applies L7 parsing on the cleartext stream. Recorded Stream `Scheme="https"`.
- **`UpstreamTLS`** — when `true`, the proxy dials the upstream over TLS (global TLS fingerprint, SNI derived from `Target`, configured verification / mTLS material). Wire-level ALPN propagation follows the rule in `dialForwardUpstream`: explicit `Protocol="http2"` → offer `[h2]`; `Protocol="http"` → `[http/1.1]`; `Protocol="auto"` → propagate the client-negotiated ALPN if any, else `[http/1.1]`.

`TLS` and `UpstreamTLS` are independent (4 combinations) and are never inferred from `Target`'s scheme or port. The TLS × UpstreamTLS matrix:

| TLS   | UpstreamTLS | Client wire | Upstream wire | Use case                                      |
|-------|-------------|-------------|---------------|-----------------------------------------------|
| false | false       | plaintext   | plaintext     | Raw L4/L7 forwarding (default)                |
| true  | false       | TLS         | plaintext     | TLS termination only                          |
| false | true        | plaintext   | TLS           | Plaintext client → TLS-only upstream          |
| true  | true        | TLS         | TLS           | Full MITM: terminate then re-encrypt upstream |

All forwarded streams reuse the same `Pipeline` and `RecordStep`, so Flow / Stream recording (`flow.Stream.Scheme` reflects the client-side wire; per-Flow `Envelope.Raw` preserves wire bytes), plugin hooks, intercept / transform rules, and Safety Input Filter apply identically to forward traffic.

**gRPC-Web auto-classify (USK-934).** The `http` arm (and `auto` arm when it dispatches to HTTP/1.1) inspects the first request's `Content-Type` header per-exchange. When it matches `application/grpc-web[-text][+proto|…]`, the per-exchange client Channel is wrapped with `grpcweb.Wrap` (downstream) and the upstream Channel is wrapped via `connector.WrapH1UpstreamForDispatch` (upstream symmetry) — Stream `Protocol` is then re-tagged to `grpc-web` by `record_step.maybeRetagProtocol`. This mirrors the H2 sibling pattern (`connector.DispatchH2Stream`) so HTTP/1.1 keep-alive that mixes grpc-web POST and JSON POST on the same connection routes correctly per-exchange. See `internal/connector/h1_dispatch.go`.

#### 3.4.3 Upstream HTTP/2 Fingerprint Parity (USK-1007)

Anti-bot frontends (Cloudflare, Akamai) fingerprint a client's **HTTP/2 behaviour** — SETTINGS values + wire order, the connection-level WINDOW_UPDATE increment, and the request pseudo-header order — in addition to the TLS ClientHello. For the proxy's MITM identity to be coherent, its own *upstream* (ClientRole) H2 send-shape must match the browser it claims to be.

The shape is driven by the existing `tls_fingerprint` value (no separate `h2_fingerprint` config): `http2.WithH2Fingerprint(cfg.EffectiveTLSFingerprint())` is threaded through all four upstream ClientRole dial seams (`stack_builder.go` pool dial, `connect_inner_dispatch.go` h2c, `stack_builder_target_override.go` forward, `h2_redial.go` GOAWAY redial). Only `firefox` diverges:

- **SETTINGS** (`internal/layer/http2/fingerprint.go`, `firefoxSettingsFrame`): `HEADER_TABLE_SIZE=65536`, `ENABLE_PUSH=0`, `INITIAL_WINDOW_SIZE=131072`, `MAX_FRAME_SIZE=16384`, in that wire order; `MAX_CONCURRENT_STREAMS` dropped.
- **Connection WINDOW_UPDATE**: stream-0 increment `12517377` (12 MiB window) vs the default 16 MiB.
- **Request pseudo-header order** (`appendRequestPseudoHeaders`): Firefox `:method :path :authority :scheme` vs the default (Chrome-shaped) `:method :scheme :authority :path`.

Every other profile (chrome / edge / safari / random / none / unset) and every ServerRole Layer keep the pre-USK-1007 behaviour byte-for-byte. Pinned against a Firefox 120 capture (coherent with the uTLS `Firefox_120` ClientHello, USK-1014); Akamai H2 fingerprint `1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s`. `env.Raw` (the wire-observed snapshot) is never modified — this is an upstream send-shape only.

> **Known limitations.**
> - **PRIORITY frames / stream-dependency tree — unimplemented: USK-1018.** Firefox's HTTP/2 PRIORITY tree is not reproduced (RFC 9113 deprecated the scheme; high engine cost given lazy stream-id allocation). Acceptance is verifiable on SETTINGS + WINDOW_UPDATE + pseudo-order without it.
> - **safari / edge / random** get coherent TLS but Chrome-shaped H2 (only `firefox` has an H2 profile today; an independent `h2_fingerprint` axis is deferred to M48).
> - The offline recorded **modified-variant** re-encode (`httpaggregator.EncodeWireBytes`, used by `RecordStep` for the diagnostic `env.Raw` of a rule/plugin-mutated request) uses the default pseudo-header order regardless of fingerprint. The **live wire** is always correct (it is re-decomposed from the structured `HTTPMessage` through the fingerprint-aware native send path, not from the recorded bytes); wiring the per-connection fingerprint into the shared per-stack `WireEncoderRegistry` requires envelope-carried or per-connection registry plumbing, deferred.
> - **Firefox fingerprint ceiling = FF120 (uTLS v1.8.2) — USK-1014.** Both the upstream H2 send-shape above (`internal/layer/http2/fingerprint.go` `firefox*` constants) and the TLS ClientHello (`tls_fingerprint=firefox` → uTLS `HelloFirefox_Auto`) are pinned to **Firefox 120** (2023-11). This is a hard ceiling, **not bumpable by a dependency update**: uTLS v1.8.2 is the latest release and it ships *no* Firefox parrot newer than 120 (`HelloFirefox_Auto = HelloFirefox_120`; newest available parrot is `HelloFirefox_120`). The residual coherence tell is version skew: the proxy presents a **Firefox 120 JA3/JA4 + H2 fingerprint**, whereas an anti-detect browser like camoufox advertises a **Firefox ~150 UA / JS surface**. This is a minor tell — the FF120 JA3 is still a *genuine* Firefox JA3 (far closer to the claimed identity than Go's native `crypto/tls` ClientHello, which is trivially bot-flagged) — and the two send-shapes stay coherent with each other. The coherence is a **hand-maintained pin at two sites** that must move together: this §3.4.3 (H2 constants) and `internal/layer/http2/fingerprint.go`; the TLS side follows `HelloFirefox_Auto` automatically. The `TestFirefoxAutoProfilePinnedTo120` drift test (`internal/tlsfingerprint/firefox_version_drift_test.go`) breaks the build if a future uTLS bump re-aliases `HelloFirefox_Auto` to a newer parrot, signalling that this pin can advance. **Re-open trigger (MITM Principle #6):** a reproducible block against a real Cloudflare target that resolves when the ClientHello is hand-built for a FF150-class spec (uTLS `HelloCustom` + `ApplyPreset`). Until such a concrete failure exists, accepting the real FF120 fingerprint is the documented decision. HTTP/3 / QUIC coherence is a separate out-of-scope item — see §11 (USK-1016).

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

### 3.7 Safety Architecture: Input vs Output

SafetyFilter has **two filters with completely different purposes, layers, and protected targets**. Conflating them is the most common design mis-step, so the distinction is captured here as the authoritative source.

#### Input Filter (Send direction, live wire)

- **Purpose**: prevent AI agents from sending destructive vulnerability-assessment payloads (SQL injection, OS command injection, upstream data destruction) to the upstream server.
- **Layer**: live data path — `internal/pipeline/safety_step.go` dispatches to per-protocol `internal/rules/{http,ws,grpc}/safety.go` engines. Send-only by design (`safety_step.go` early-returns `Result{}` on `env.Direction != envelope.Send`).
- **Behaviour**: blocks at wire time. HTTPMessage violations emit `Action=Respond` with a synthetic 403; mid-stream WS/gRPC frames emit `Action=Drop`. `BlockedBy=safety_filter` is stamped on the recorded flow.
- **Protected target**: the **upstream server**.
- **Modify-and-forward recheck (USK-702)**: the Send-side modify_and_forward path in `InterceptStep.holdAndDispatch` re-runs the same `SafetyStep.Process` against the operator-supplied modified envelope, closing the bypass where an AI agent first issues a benign request and then rewrites the body to a destructive payload at hold time.

#### Output Filter (MCP control plane, on AI return)

- **Purpose**: prevent AI agents from receiving sensitive information as **input**. Two driving concerns:
  1. **LLM training-data leakage** — sensitive bytes that flow into an AI agent's context window may be retained by upstream LLM operators.
  2. **Enterprise LLM Input Security Policy compliance** — many organizations regulate which categories of data their AI tooling is permitted to ingest.
- **Layer**: MCP control plane — `internal/safety.Engine` exposes `FilterOutput` / `FilterOutputHeaders`, invoked by `internal/mcp/safety_helper.go` at the moment a query / resend / fuzz / replay tool serializes its response to the AI client.
- **Behaviour**: masks (redacts) matched bytes in the response payload. Block / log_only actions are also supported. The original wire-recorded bytes in flow.Store are never mutated — Output Filter operates on a copy at the MCP transport boundary.
- **Protected target**: the **AI agent**.

#### Key consequence: wire ≠ MCP plane

- The DB / browser / next-hop client receives the **raw wire bytes** as observed, including sensitive content. Output Filter does not touch the wire.
- Output Filter masks **only when the AI agent fetches the recorded flow via an MCP tool**.
- This separation is a deliberate role split, not an implementation accident:

| Question | Input Filter | Output Filter |
|----------|--------------|---------------|
| Where does it fire? | Live wire (Send only) | MCP transport boundary (on AI return) |
| What does it produce? | block / drop on the wire | mask / redact in the MCP response |
| Whom does it protect? | upstream server | AI agent |
| Default presets | `destructive-sql`, `destructive-os-command` | PII presets (credit-card, my-number, email, phone) |

#### Anti-patterns (do not propose)

The following ideas have come up repeatedly and are deliberately rejected:

- **"Apply Output Safety on the wire" / "block upstream-originated Receive payloads at SafetyStep"** — violates the wire-fidelity intent: recording is faithful, and the wire copy delivered to the next hop must reflect what was observed. Sensitive content reaching the DB or a browser is not in scope; SafetyFilter's protected target is the AI agent reading recorded flows, not arbitrary downstream consumers.
- **"Receive-direction SafetyStep" / "direction-aware Input filter"** — Receive-direction modify_and_forward (HTTP response, WS server frame, SSE event) only affects browser-side rendering or AI consumption; it cannot harm the upstream server. Browser-side XSS / prompt injection / token swap is out of SafetyFilter's threat model; if such protections are ever needed, they belong in a separate layer (for example, an MCP-side confirmation prompt), not in SafetyStep. The `Direction != Send` early return in `safety_step.go` is an intentional scope boundary.
- **"Unify `internal/safety` and `internal/rules/*/safety.go` into one engine"** — they sit at different layers (MCP plane vs live wire) and serve different threat models. Preset *definitions* can be shared (`internal/rules/common/preset.go`), but the engines and their invocation surfaces must remain separate. `internal/safety/doc.go` explicitly forbids importing `internal/safety` from data-path packages for this reason.

#### Acceptance record

- USK-702 (Done, 2026-05-04) — Input Filter modify_and_forward recheck wired into `InterceptStep.holdAndDispatch`. Send-only by design.
- USK-894 (Canceled, 2026-05-15) — Investigation concluded that Receive-direction modify_and_forward does not need a SafetyEngine recheck because it cannot harm the upstream server; browser-side effects are out of scope for SafetyFilter. This subsection codifies the rationale so the question does not need to be re-litigated.

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

### 4.5 HTTP/2 Extended CONNECT → WebSocket (RFC 8441)

```
Initial stack (per-connection, unchanged from §4.4):
  Client:   [TCP → TLS(ALPN=h2) → HTTP/2]  (event-granular)
  Upstream: [TCP → TLS(ALPN=h2) → HTTP/2]  (event-granular, pooled)

handleStream(clientStreamChan):
  firstHeaders := clientStreamChan.Next(ctx)

  // Recognize extended CONNECT: :method=CONNECT + :protocol=websocket
  // (HTTPMessage.Method=="CONNECT", HTTPMessage.ConnectProtocol=="websocket").
  // The h2 Layer surfaces :protocol via HTTPMessage.ConnectProtocol — the
  // ENABLE_CONNECT_PROTOCOL settings + parse path landed in USK-764.
  if isExtendedConnectWS(firstHeaders):
    upstreamStreamChan := upstreamH2.OpenStream(ctx)

    // Wait for the 200 response on the same stream that signals
    // server-side acceptance of the extended CONNECT.
    if !awaitExtendedConnectAccept(upstreamStreamChan):
      // Server rejected; stream falls back to standard h2 handling
      // (the response body, if any, flows through HTTPAggregatorLayer).
      // No swap occurs — return to the standard §4.4 path.
      return

    // Per-stream byte detachment: framing for THIS stream only is
    // peeled off the connection-level h2 Layer. DetachStream surfaces
    // any DATA bytes that arrived between the 2xx and this call on the
    // returned reader (BodyBuffer drain) — see §3.3.2 DetachStream doc.
    cR, cW, cClose, _ := clientH2.DetachStream(streamID)
    uR, uW, uClose, _ := upstreamH2.DetachStream(streamID)

    // Construct ws.Layer pair in h2 mode (no MASK; END_STREAM-driven
    // termination — see §3.3.2 ws-layer h2-mode contract).
    clientWS   := wslayer.New(cR, cW, cClose, RoleServer /* h2 mode */)
    upstreamWS := wslayer.New(uR, uW, uClose, RoleClient /* h2 mode */)

    // Register on the per-stream sub-stack overlay (§3.4.1). The
    // connection-level Layers stay live and continue serving sibling
    // streams — only THIS stream id swaps to WS framing.
    stack.RegisterStreamSubStack(streamID, clientWS, upstreamWS)

    // Pipeline / Session iterate the swapped stream via
    // ClientTopmostForStream(streamID) / UpstreamTopmostForStream(streamID).
    // Single-channel layers (wslayer) yield exactly one Channel on
    // Channels() then close, so reading once is sufficient.
    Session.RunSession(<-clientWS.Channels(), staticDial(<-upstreamWS.Channels()), pipeline)
  else:
    // (existing §4.4 fork: gRPC or plain HTTP/2)
```

The crucial difference from §4.3 (HTTP/1.1 → WS) is that the underlying connection is **not** consumed by the swap. `clientH2` and `upstreamH2` keep running for every other stream on the same h2 connection; only stream id N is detached and rewrapped.

The `:protocol=websocket` recognition relies on HTTPMessage.ConnectProtocol carrying the parsed `:protocol` pseudo-header value (USK-764 / PR #754). Other `:protocol` values currently produce no swap — see §3.4.1 *Recognized `:protocol` values*.

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
    wslayer (from HTTP/1 Upgrade; HTTP/2 CONNECT+:protocol for RFC 8441
             deferred from N7 — design landed in §3.4.1 / §4.5,
             implementation in USK-765)
    ssehlayer (from HTTP/1 response; HTTP/2 sub-stack overlay via USK-886)
    Corresponding rule engines in internal/rules/{ws,grpc,sse}/
    SSE per-event TransformEngine + InterceptEngine landed in USK-892;
    the original N7 scope-out (D-U3: SSE half-duplex pass-through) is
    closed. Engines mutate SSEMessage fields directly; the session-side
    sseMessageMutated field-diff (relaySSEEvent) is the authoritative
    re-encode signal — engines do NOT clear env.Raw.
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
- HTTP/2 CONNECT + `:protocol` extended CONNECT (RFC 8441) for WebSocket-over-H2 was deferred from N7's milestone scope; the design now lives in §3.4.1 (Per-Stream Sub-Stack Overlay) and §4.5, with implementation tracked under USK-765.
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
- [x] Envelope + Message Go interfaces compiled and validated — **completed in N1**
- [x] Pseudocode-level InterceptStep implementation proving dispatch pattern — **completed in N3**
- [x] Migration reuse % validated against actual file sizes — **closed at N9; weighted reuse % held within the ~70% estimate from §6 (e.g. http1 parser preserved verbatim, Pipeline.Run snapshot mechanism reused, TLS handshake / cert / macro / flow store packages reused)**

**Milestone completion record:**
- [x] N1 (Foundation Types) — DONE
- [x] N2 (TCP + TLS + ByteChunk + raw smuggling E2E) — DONE
- [x] N3 (HTTP/1.x Layer + normal HTTPS MITM E2E) — DONE
- [x] N4 (Connector Completion) — DONE
- [x] N5 (Job + Macro Integration) — DONE
- [x] N6 / N6.5 / N6.6 / N6.7 (HTTP/2 Layer + event-granular split + httpaggregator) — DONE
- [x] N7 (gRPC, gRPC-Web, WS, SSE Layers + per-protocol rule engines) — DONE
- [x] N8 (Plugin v2 — Starlark; MCP + WebUI Reconnection) — DONE
- [x] N9 (Legacy Removal + Documentation) — DONE (closed 2026-05-05)

**Post-N9 deferred design decisions:**
- [ ] `WireLevelTap` interface unification — **deferred 2026-05-15 (USK-900)**. The five frame-level record callback sibling Options (`http2.WithFrameRecordCallback`, `http1.WithChunkRecordCallback`, `grpc.WithLPMFrameRecordCallback`, `httpaggregator.WithH2FrameRecordCallback`, `grpc.WithH2DataFrameRecordCallback`) already share their session-side closure builder (`session/h2_frame_record.go` `wireLevelRecordCallback()`), so the main boilerplate cost is already absorbed. Layer-side Option contracts remain per-Layer ad-hoc by design: `http1.WithChunkRecordCallback` is constrained to `func([]byte)` by the parser-level `ChunkRecordSetter` hook (parser owns chunk-boundary detection, not the Layer), so a naive `WireLevelTap` seam would degenerate into "four uniform + one adaptor". Re-evaluate when a 6th sibling appears (e.g. a WebSocket per-frame record producer) or when the http1 parser hook is revisited for an unrelated reason — at that point the seam will be either fully uniform or clearly fragmented, and the decision becomes unambiguous.
- [ ] HTTP/3 / QUIC — **out of scope, deferred 2026-07-16 (USK-1016)**. The proxy is h3/QUIC-incapable: there is no UDP listener and the TLS layer advertises only `h2` / `http/1.1` in ALPN. This is a **weak** bot signal for the anti-detect use case (M47/M48): a Firefox routed through an explicit HTTP proxy does **not** use HTTP/3 anyway, because h3 runs over QUIC/UDP and cannot traverse a `CONNECT` proxy — the same reason a real Firefox behind a corporate proxy falls back to h2. So a proxied Firefox presenting no h3 is *expected*, coherent behaviour, not an anomaly. Actual h3/QUIC MITM (a UDP listener, QUIC transport termination, and `h3` ALPN) is a separate, much larger milestone and is explicitly out of scope here. **Alt-Svc note:** an upstream may still send an `Alt-Svc: h3=...` response header advertising its own h3 endpoint; a strict detector could flag that the advertised h3 service is never exercised by the proxied client. Stripping that header is **already achievable today** with a user-authored response `TransformRemoveHeader` rule (`HeaderName: "Alt-Svc"`, `Direction: response`) — no new code required. A dedicated opt-in `suppress_alt_svc` config knob is **deferred to M48**. **Re-open trigger:** a reproducible camoufox/Cloudflare detection that flips green when the upstream `Alt-Svc` header is stripped from the client-bound response (justifies the dedicated knob), or a decision to build real h3/QUIC MITM (justifies the UDP listener + `h3` ALPN work). Cross-referenced from §3.4.3.

### 11.1 Macro hook `__response_*` key matrix per protocol

The `pre_macro` / `post_macro` hooks on the typed fuzz tools (`fuzz_http` / `fuzz_ws` / `fuzz_grpc` / `fuzz_raw`) inject a per-protocol set of reserved keys into the per-iteration KV Store so `post_macro` templates can reference the response. Each protocol's surface differs because the wire reality differs — raw has no L7 status, WS has framed message events instead of headers, gRPC has trailers in addition to headers, and HTTP has the canonical status / headers / body triplet. This is consistent with the MITM principle "do not invent hypothetical surface" (CLAUDE.md §MITM Implementation Principles #6).

| Protocol | `__response_status` | `__response_body` | `__response_headers__<lower(name)>__` | `__response_chunks` | `__response_truncated` |
| -------- | ------------------- | ----------------- | -------------------------------------- | ------------------- | ----------------------- |
| http     | YES (3-digit status, base-10 decimal string) | YES (64 KiB cap) | YES (≤ 256 entries × 8 KiB) | n/a | n/a |
| ws       | TBD pending USK-984 acceptance | TBD pending USK-984 | n/a (WS has no headers post-handshake) | TBD pending USK-984 | TBD pending USK-984 |
| grpc     | TBD pending USK-985 acceptance | TBD pending USK-985 | TBD pending USK-985 (trailers as well) | TBD pending USK-985 | TBD pending USK-985 |
| raw      | **NO** (raw has no L7 status) | YES (64 KiB cap) | n/a (raw has no headers) | YES (receive-loop envelope count, decimal string) | YES (`"true"` / `"false"` — set when the receive loop hit the 16 MiB cap) |

Implementation references:
- HTTP: `internal/mcp/hooks.go:injectResponseVars` (status + body + headers).
- Raw: `internal/mcp/hooks.go:injectRawResponseVars` (body + chunks + truncated). USK-986.
- The shared `MacroConfig` validator (`internal/mcp/fuzz_macro_common.go:ValidateMacroConfig`) stays protocol-neutral; protocol-specific rejects (e.g. `fuzz_raw` rejecting `run_interval="on_status"`) live in the per-protocol input validator (`internal/mcp/fuzz_raw_helpers.go:validateFuzzRawMacroConfig`).

`run_interval` cross-protocol compatibility:
- `on_status`: HTTP yes, raw NO (rejected at validation — no status concept).
- `on_match`: regex against `__response_body` — applicable to every protocol that surfaces body bytes.
- `every_n`, `once`, `on_error`: protocol-neutral (per-iteration cadence is a loop knob, not a wire knob).

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

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

    // RFC §9.3 D4 "Raw wins" marker: Raw is caller-authored bytes the Layer
    // must write verbatim, ignoring Message. Set by the Pipeline on a plugin
    // msg["raw"] write; cleared by any later Step that changes the Message.
    // Layers consult Envelope.RawWins() (marker AND len(Raw) > 0). USK-1079.
    // Refused (never set) on h2 HTTPMessage / gRPC Start+End / gRPC-Web
    // Start, whose Raw cannot be written verbatim (§9.3 D4, USK-1237).
    RawAuthoritative bool

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
    ServerAddr net.Addr      // upstream leg only: the upstream socket's peer (USK-1116)
    UpstreamProxy string     // upstream leg only: proxy dialed through, "scheme://host:port", no userinfo
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

**Upstream peer (USK-1116).** `ServerAddr` and `UpstreamProxy` follow the per-Layer rule: they are stamped only on the upstream-facing Layer's template (`connector.WithUpstreamPeer` at every upstream Layer construction site, including h1 / h2 redial, which overwrite the values copied from the stale Layer), so they ride on Receive envelopes and stay empty on the client leg. `ServerAddr` is `upstreamConn.RemoteAddr()` — the socket the proxy actually talked to, which is the upstream proxy when one was used, never the dial-target hostname; on an h2 pool hit the pooled Layer's own socket is authoritative. `UpstreamProxy` is the proxy URL the dial resolved (per-listener override and rotation included), carried by a marker wrapper on the raw TCP conn from `dialTCP` and rendered as `scheme://host:port` with userinfo dropped so no credential reaches the flow store. RecordStep projects both onto `Stream.ConnInfo` from the first Receive envelope per stream, and stamps `ConnInfo.ClientAddr` (from the listener's per-connection ctx) and `Stream.ListenerName` (construction-time `WithListenerName`, i.e. configuration) at stream creation. A stream that never receives an upstream envelope keeps `server_addr` empty.

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
    Path      string   // wire form: request-target / :path up to the first '?', percent-encoding untouched (USK-1139)
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

**Wire-form path surfaces (USK-1139):** `Flow.URL` is stored with the wire path byte-exact (`internal/envelope/wirepath.go`). JSON output surfaces — JSONL export, HAR `request.url`, the MCP `query` tool — cannot carry bytes that are not valid UTF-8, so they show exactly those bytes `%XX`-escaped (`envelope.WireURLStringJSONSafe`); a JSONL import of such a row therefore stores the escaped text. Security gates (TargetScope `path_prefix`, Input SafetyFilter `url` / gRPC `service` / `method` targets, the MCP-plane resend / fuzz safety check) match either the wire path or its single-pass percent-decoded form and fail closed.

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

    // Layer-detected anomalies (USK-1321): WSDecompressedTooLarge.
    Anomalies []Anomaly
}
```

**Over-cap compressed messages (USK-1321).** The Layer decompresses a permessage-deflate message for the L7 view and keeps at most the decompression cap (`web_socket.max_frame_size`, default 16 MiB `config.MaxWebSocketFrameSize`; USK-1322) of it as `Payload`. A message that decompresses past the cap carries `Anomalies: [WSDecompressedTooLarge]` (recorded as Flow Metadata `ws_anomaly_decompressed_too_large` with `BodyTruncated=true`; `RawBytes` is the complete wire frame) and a Layer-private `Envelope.Opaque` snapshot of the received frame. Under context takeover the rest of the message is still inflated — output discarded except the trailing 32 KiB — so the LZ77 window stays in step with the peer (memory bounded at cap + 32 KiB). On Send the relaying Layer writes the received frame verbatim when the message is unchanged (fields + payload hash, Mask excluded) and, under context takeover, its send window equals the receiving leg's window before the message; it then adopts the receiving leg's window after the message. Otherwise — the message was modified by Transform / intercept / plugin, the snapshot was dropped by `Envelope.Clone` (intercept `modify_and_forward`), or the windows diverged because an earlier message was modified — Send fails with `StreamError{ErrorAborted}` and writes nothing: the record may be cut, the wire never. A plugin `msg["raw"]` (raw wins) is still honoured. Input Safety fails closed on such a Send-direction message when the WS engine has any payload / body rule, since the rule cannot see the bytes past the cap. Messages at or under the cap keep the re-compress path. Fragmented over-cap messages get the receive-side handling (anomaly on the FIN envelope, window kept); their end-to-end relay depends on the fragmented-message relay follow-up.

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
    //
    // USK-1053 added RawQuery (the query component, without the leading
    // "?" — the same split H2HeadersEvent and HTTPMessage use) and made
    // Path authoritative on Send only when parseGRPCPath could not
    // represent it; on any parseable :path the derived Service/Method
    // view still wins, which is what keeps the intercept / plugin
    // service+method override working.
    //
    // USK-1069 / USK-1110 applied the same overlay and precedence rule to
    // gRPC-Web, whose Layer runs over HTTP/1.x or HTTP/2: the per-transport
    // path source is the inner HTTPMessage's Path / RawQuery (the HTTP/1.x
    // request-target or the HTTP/2 :path, already split by the inner
    // Layer), projected by applyRequestOverlay. The query is forwarded on
    // RawQuery and rejoined by the inner HTTP Layer.
    Authority string
    Scheme    string
    Path      string
    RawQuery  string

    // USK-1252: request-side method overlay populated by the gRPC-Web
    // Layer — the client's HTTP/1.x request-line method / HTTP/2 :method,
    // verbatim (no case folding), so the opposite-side Send relays it
    // instead of forcing POST and RecordStep records Flow.Method. Empty on
    // the response side and on native gRPC (not populated yet); an empty
    // value is sent as POST. Carried across plugin rebuilds but not
    // exposed as a dict key.
    HTTPMethod string

    // USK-1219 / USK-1251: response-side overlay — the upstream's HTTP
    // status line / :status (and, on gRPC-Web over HTTP/1.x, the reason
    // phrase), populated by both the gRPC-Web and the native gRPC Layer,
    // so the opposite-side Send relays it (instead of 200) and RecordStep
    // records Flow.StatusCode. An Envoy / load-balancer 503 in front of a
    // gRPC service therefore reaches the client as 503. Zero on the
    // request side; a Start with zero (synthetic producers, unparseable
    // status) is sent as 200. HTTPStatusReason is always empty on native
    // gRPC (HTTP/2 has no reason phrase). Carried across plugin rebuilds
    // but not exposed as dict keys.
    HTTPStatus       int
    HTTPStatusReason string

    // gRPC metadata — custom and reserved, order and casing as observed.
    // Pseudo-headers (:method, :path, :status, ...) are NOT included here;
    // :authority / :scheme / :path are projected onto the overlay fields
    // above, as are the gRPC-Web request method and the response status
    // (native gRPC does not project :method yet). Their wire bytes stay in
    // Envelope.Raw.
    Metadata []KeyValue

    // Parsed gRPC-specific control headers (D7). These four are stripped
    // from Metadata, so the structured fields are the single editable
    // source. Both the gRPC-Web Layer (USK-1219) and the native gRPC Layer
    // (USK-1251) additionally record each observed entry's name, raw value
    // and position on their Opaque, and the opposite-side Send restores
    // them: verbatim while the field is unchanged (duplicates and
    // unparseable values such as "grpc-timeout: soon" survive), value
    // rewritten in place when it was edited, dropped when cleared,
    // synthesized lowercase at the front only when never observed. Nothing
    // the wire did not carry is added on that path — no default
    // content-type, and on native gRPC no "te: trailers" on a request
    // whose client sent none. An Envelope without that Opaque
    // (Envelope.Clone, e.g. intercept modify_and_forward, or a synthetic
    // producer such as resend_grpc / fuzz_grpc / RESPOND_GRPC) falls back
    // to the synthesized layout (content-type defaulted to
    // application/grpc first, "te: trailers" on native gRPC requests).
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

    // USK-1254: LPM framing anomalies (GRPCLPMTooLarge / GRPCLPMTruncated).
    // Set only on the grpc-lpm-frame overlay envelope that records an LPM
    // the Layer could not complete (Payload nil); never on a semantic
    // envelope, never forwarded, excluded from variant comparison.
    Anomalies []Anomaly
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

**Native gRPC responses that end on their HEADERS frame (USK-1251).** A Receive HEADERS frame carrying END_STREAM is both the Start and the End of the response side, so the native gRPC Layer emits a Start and a synthetic End (`Raw=nil`) for it. For a trailers-only response (grpc-status in the headers) the End is parsed from the frame, and its `Trailers` list the frame's other entries (content-type included — in this form the HEADERS frame *is* the trailer block). With no grpc-status at all (e.g. a load balancer's bare `HEADERS(:status 503, server: lb, END_STREAM)`) the End is a `Status=0` placeholder stamped `GRPCMissingStatus` (recorded as `grpc_anomaly_missing_status`). The opposite-side Send writes either back as the ONE `HEADERS ... END_STREAM` frame the wire carried — the Start's header list, nothing fabricated. An End edit is detected against the End as emitted (a snapshot on the Layer's Opaque, read from the Start's Envelope so an intercept `Clone()` of the End does not lose it): a status / message / details edit is written into the grpc-status / grpc-message / grpc-status-details-bin entries in place (cleared → dropped, never observed → appended), and a Start-side edit is relayed as edited. An End `Trailers` edit cannot be written in place, so that response falls back to HEADERS (no END_STREAM) + a TRAILERS frame rebuilt from the End. A placeholder End whose status was not edited never gets a fabricated grpc-status: in that fallback its TRAILERS frame carries only the edited trailers. When the Start was `Clone()`d (its HEADERS went out without END_STREAM), an untouched placeholder End ends the stream with an empty DATA frame (or a TRAILERS frame of just its edited trailers) rather than a fabricated grpc-status trailer. When no response HEADERS went out at all (a Step dropped the Receive Start), the End's Send fails with a StreamError and the session resets the client stream rather than answer with a proxy-built `:status 200` + `grpc-status: 0`. A dropped End leaves the deferred HEADERS unsent; teardown discards it, and the client sees RST_STREAM.

**Envelope.Raw for gRPC envelopes** contains the wire bytes specific to that event:
- `GRPCStartMessage`: the encoded HPACK block of the HEADERS frame (not the HTTP/2 frame wrapper).
- `GRPCDataMessage`: the 5-byte LPM prefix + compressed payload, exactly as observed on the wire.
- `GRPCEndMessage`: the encoded HPACK block of the trailer HEADERS frame.

HTTP/2 frame-level bytes (frame headers, SETTINGS, WINDOW_UPDATE, etc.) are owned by the HTTP/2 Layer and are not exposed on gRPC envelopes. To observe them, attach to the HTTP/2 Layer's event stream directly (see §3.3.2).

**Wire-level recording overlays.** In addition to the semantic gRPC envelopes above, the data path records two wire-level views per RPC (controlled by `internal/session/grpc_lpm_record.go` and `internal/session/grpc_h2_data_frame_record.go`):

- `wire_level=grpc-lpm-frame` — one envelope per fully reassembled LPM (5-byte prefix + payload, BEFORE decompression). Captures LPM length-prefix smuggling, compressed-flag anomalies, and multi-LPM-in-one-DATA-frame packing. The flag byte is kept verbatim in `Raw` on every LPM row (semantic and `grpc-lpm-frame`) and on forwarding — a non-RFC value such as `0x02` is not normalized to `0x01`; `GRPCDataMessage.Compressed` is only the convenience view (`flag != 0`).
  - **Partial-LPM anomaly rows (USK-1254).** An LPM the Layer cannot complete still gets one `grpc-lpm-frame` row, written just before the stream terminates with the same `*layer.StreamError` / RST_STREAM it always did (recording only; nothing is forwarded). Its `Raw` is the observed bytes, verbatim; its Message is a `GRPCDataMessage` with `Payload=nil`, `WireLength` = the declared length, and one anomaly: `GRPCLPMTooLarge` when the declared length exceeds the message-size cap (`Raw` = the 5 prefix bytes, even if split across DATA frames, + at most the declared length of the same DATA frame's remaining bytes; Detail `declared=N cap=M captured=K`), or `GRPCLPMTruncated` when END_STREAM arrives mid-LPM (`Raw` = the 1-4 prefix bytes seen, Detail `prefix_bytes=N`, or the prefix + payload received, Detail `declared=N observed=M`). RecordStep projects them to `grpc_anomaly_lpm_too_large` / `grpc_anomaly_lpm_truncated` and omits `grpc_compressed` / `grpc_wire_length` when the prefix itself was truncated. LPMs completed earlier in the same DATA event are recorded as ordinary rows before the anomaly row. Out of scope: a length prefix that is wrong but still parses into valid LPM boundaries (the bytes shift into the next LPM) is indistinguishable from a legitimate stream; invalid compressed-flag values (preserved verbatim in `Raw`, but not yet flagged as a typed anomaly) and gzip-decode failures on a complete LPM are not flagged.
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

**HTTP/1.x keep-alive rule (USK-1229).** HTTP/1.1 answers requests in order (RFC 9112 §9.3), so the client-facing HTTP/1.x Layer never parses another request on a connection after an exchange whose request was delivered but which did not write a complete final response (status ≥ 200, `101`, or a raw-authoritative response) — the upstream closed before or in the middle of its response, or the Pipeline dropped the request. The connection is closed instead, mirroring the upstream's FIN; no response is synthesized. On the upstream-facing side, a close after a request was written and before the response head completed is an aborted `StreamError`, and a body cut short (Content-Length shortfall, chunked body without its terminal chunk) is delivered exactly as received with the `TruncatedBody` anomaly, followed by an aborted `StreamError`.

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

`DetachStream` MUST be called on the `http2.Layer` that owns the stream — the Layer reported by the stream's Channel (`H2Layer()`, paired with `H2StreamID()`) — never on the stack's pooled upstream Layer: after an upstream GOAWAY the redial chain (USK-991) places later streams of the same CONNECT on different connections whose stream ids restart at 1, so the pooled Layer would detach an unrelated stream (USK-1164).

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

In addition to the CONNECT / SOCKS5 / transparent paths, `yorishiro-proxy` accepts pre-configured **TCP forward** listeners (`tcp_forwards` in `proxy_start`). Each entry maps a local port to an upstream `host:port` and selects the connection-stack assembly explicitly rather than via peek-based detection. A forward binds on its parent listener's **bound host** (USK-1125): a `0.0.0.0` parent yields `0.0.0.0:<port>` forwards, a `[::1]` parent yields `[::1]:<port>`; there is no per-forward bind override. `proxybuild.Manager` rejects a bind that overlaps another running listener or forward (equal non-zero port, and equal hosts or either host unspecified) with `ErrBindConflict` before calling `net.Listen`.

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

**Upstream HTTP/2 GOAWAY (USK-1165).** An `http2` / `grpc` forward connection (and `TLS=true` + negotiated `h2`) starts with one upstream connection, but it is not bound to it: when that connection goes stale (peer GOAWAY or shutdown), the next stream is opened on a freshly dialed upstream connection, exactly like the CONNECT path (USK-991). The same machinery applies — the redial chain shared by concurrent streams, one retry of an `OpenStream` refused before HEADERS (USK-993), and the pre-warm worker woken by GOAWAY on the current head, including the first connection (USK-992 / USK-994). The pre-warm does not replace a connection it opened itself that went away without carrying a stream (USK-1179), so an upstream that sends GOAWAY on every connection costs an idle client connection at most two upstream connections instead of one redial per RTT; reactive redials stay per-request. The redial re-runs the forward upstream dial (`dialForwardUpstream`: `UpstreamTLS`, the ALPN offer above, the `UpstreamInsecureSkipVerify` tri-state, upstream-proxy rotation, and the `(tls, on_handshake)` hook for the new handshake), not the CONNECT `RedialUpstreamH2`. Streams already open on a GOAWAY'd connection drain up to its `last_stream_id` (RFC 9113 §6.8); redialed connections are closed when the forward connection ends. Redials count in the same `h2_upstream` status counters as CONNECT. A stream whose `OpenStream` succeeded just before the GOAWAY but whose first HEADERS is sent after it is refused locally before any stream id is allocated (USK-1175; RFC 9113 §6.8 forbids opening it) and reaches the client as `RST_STREAM(REFUSED_STREAM)` with the flow recorded `failure_reason=refused`, so a retrying client lands on the redialed connection; the proxy does not re-send it itself.

**Upstream RST_STREAM code relay (USK-1269).** On every path (CONNECT and forward) where both legs are HTTP/2 — plain h2, gRPC, and gRPC-Web over h2 — the RST_STREAM error code the upstream resets a stream with reaches the client verbatim, any non-zero value including codes outside the five `layer.ErrorCode` categories and unknown extension codes (RFC 9113 §7), as a direct connection would show; it is no longer rewritten to `CANCEL`. The HTTP/2 Layer records the peer's code losslessly on `layer.StreamError.PeerWireCode` (set only by a received RST_STREAM, never by proxy-synthesized terminations), and the session closes the client stream with `CloseWithCode`, which also carries the REFUSED_STREAM propagation above: a peer code wins, else an upstream refusal yields `REFUSED_STREAM`, else `CANCEL`. Only `REFUSED_STREAM` is downgraded to `CANCEL` once response HEADERS (a 1xx included) reached the client (RFC 9113 §8.7). Proxy-local failures (e.g. a truncated gRPC LPM) still reset the client with `CANCEL`, and the recorded `failure_reason` keeps the lossy classification (`ENHANCE_YOUR_CALM` records as `aborted`). The client→upstream direction is unchanged.

**Server-speaks-first raw relays (USK-1216).** A `[bytechunk → bytechunk]` stack — the `raw` arm, the `auto` arm's raw fallback, and on the CONNECT / SOCKS5 side the raw-passthrough hosts, an unknown inner ALPN after TLS MITM and plaintext inner bytechunk — has its upstream connected before the session starts, so the session runs pre-dialed (`session.RunPreDialedStackSession`): both directions are read from the start, and a protocol whose server speaks first (SMTP / FTP / MySQL / IMAP / POP3 banners) reaches the client without the client sending anything. Lazy dialling on the first client envelope is an HTTP routing need, not a raw one. On these relays a clean EOF in one direction is passed on as a half-close (`bytechunk.Channel.CloseWrite`: FIN on TCP, `close_notify` on TLS), never a full close, so the peer reads EOF as on a direct TCP connection and the other direction keeps flowing. The first raw envelope in **either** direction creates the Stream row and makes the capture-scope decision (a raw envelope has no method / path, so the decision is direction-symmetric); a server-first stream therefore records the banner as its Receive sequence-0 Flow. Non-raw protocols keep "the first Send creates the Stream". Caveat: with `Protocol="auto"` the 5 s first-bytes peek runs before the raw fallback, so a server-first protocol's banner reaches a silent client only after that peek times out — use `Protocol="raw"` for such targets. Plaintext CONNECT / SOCKS5 to a server-first target is out of scope: the inner-protocol peek waits for client bytes.

**Target scope gate (USK-1161).** A forward's target is fixed, so it is checked against `TargetScope` before the target is contacted: at listener start (`startTCPForwardListener`; a denied target fails `proxy_start` via `ErrTCPForwardTargetBlocked`, advisory) and at every accept (`admitTCPForwardConn`, authoritative — the scope changes at runtime), in the per-connection goroutine before client TLS termination, before `dialForwardUpstream` and before arm dispatch, so one site covers every `Protocol` × `TLS` × `UpstreamTLS` combination. A denied plaintext `http` / `websocket` / `sse` client gets a canned `403`; every other arm is closed with no byte; no flow is recorded. An admitted connection is registered in `LiveConns` (`Via="tcp-forward"`) with the same predicate (`tcpForwardScopeCheck`), and every handler's `connCtx` derives from the registered context, so `Reconcile` closes it — including the h2 redial / pre-warm machinery, which runs under that context. The check's scheme is the **upstream (dial) leg's** (`UpstreamTLS ? "https" : "http"`), not the client leg's: the Policy Layer protects egress, and a client-leg scheme would let a `TLS=true` forward carry plaintext egress past an `http`-only deny. `HostScopeStep` keeps checking each envelope with the client leg's scheme (§3.5.1), so on mixed-axis entries a deny fires if either leg matches. Host is the literal `Target` host (no DNS resolution).

**Acceptance record — TargetScope host comparison form (USK-1250, absorbing USK-1132, 2026-10-20).** Every scope gate (CONNECT, SOCKS5, plain-HTTP forward, `tcp_forwards`, `HostScopeStep` / `HTTPScopeStep`, the MCP resend / fuzz / macro / hook helpers, `security test_target`) hands `CheckTarget` the host as the client spelled it, and the dialer reads several spellings as one destination. `connector.canonicalScopeHost` now folds, on both rule and target side and for comparison only: one trailing dot (`db.internal.` = `db.internal`, `a.internal.` matches `*.internal`, two or more dots are not folded), the IPv6 zone (dropped), IPv4-mapped IPv6 (unmapped, in both directions: a `::ffff:10.0.0.5` rule equals `10.0.0.5`), and legacy inet_aton IPv4 spellings (`2130706433`, `0x7f.0.0.1`, `0177.0.0.1`, `127.1`), which a libc resolver (`GODEBUG=netdns=cgo`) or an upstream proxy reads as the address while Go's pure resolver rejects only the all-digit ones and looks the hex ones (`0x7f.0.0.1`) up in DNS with the `resolv.conf` search list. The legacy parser mirrors glibc `inet_aton`, not WHATWG, on a hex part with no digits: a bare `0x` (`1.2.3.0x`, `0x.0.0.1`) is not an address, so it is not folded (and fails closed under the numeric rule below). A host whose last label is a number (WHATWG "ends in a number") but that is not a parseable IPv4 address fails closed in `CheckTarget` whenever any rule exists; open mode is unaffected. Dial targets, CONNECT replies, Host headers, recorded flows and stored rules stay verbatim (MITM Principle 1). The allow side widens to the same aliases. Each alias dials the host the allow names only under a libc resolver or an upstream proxy: Go's pure resolver (the Linux default) does not parse legacy IPv4 spellings as addresses but looks them up in DNS with the `resolv.conf` search list, so an allow for `10.0.0.5` also admits `10.5` or `0x0a.0.0.5`, which may resolve to a different host. The deny side is unaffected (a deny blocks every alias whichever way it resolves). The allow-side widening for legacy IPv4 spellings is withdrawn by USK-1273 (next records): as a dial host they now fail closed whenever any rule exists; the trailing-dot / `ndots` part of the caveat stays with the resolver follow-up (D2/D3). Not folded, with reasons: `::a.b.c.d` (IPv4-compatible) is routed as IPv6; NAT64 (`64:ff9b::/96`) is a different address at the proxy; percent-encoding is rejected by the absolute-form URL parser. Deferred: the per-host `RateLimiter` and `PassthroughList` still keyed on the literal host (an alias evaded a per-host limit, or was MITM'd instead of passed through) — closed by USK-1263 (record below); Kubernetes `ndots` search-list expansion of a dotless name, and resolution performed by an upstream proxy, are outside what a literal-host predicate can see (the numeric fail-closed rule narrows the latter).

**Acceptance record — empty and unspecified dial hosts fail closed (USK-1312, 2026-10-20).** Go's `net.Dial` reads an empty host (`:80`) and an unspecified address (`0.0.0.0:80`, `[::]:80`) as the local system, yet no hostname-bearing deny matched them: `matchTargetRule` skips an empty host, and `canonicalScopeHost` folds the unspecified spellings to `0.0.0.0` / `::`, which a `127.0.0.1` / `localhost` / `::1` deny never names. A deny meant to protect services on the proxy host (admin ports, the MCP endpoint) was therefore reachable through every dial leg. Decision (b): whenever any rule exists on either layer, `CheckTarget` / `CheckHost` (and so `CheckOpaqueTarget`, `CheckURL`) refuse a dial host that is empty or whose canonical form is an unspecified address — `0.0.0.0`, `::`, `[::]`, `::ffff:0.0.0.0`, `0:0::0`, `::%zone`, and the legacy `0` / `0.0` / `0x0` / `00` — before deny and allow evaluation, with the reason "empty or unspecified host … use an explicit address such as 127.0.0.1" (`connector.unspecifiedOrEmptyHost`, step 0 next to the numeric rule above, shared through `dialHostFailClosedLocked`). Open mode is unchanged; nothing is rewritten (comparison-only, MITM Principle 1). Option (a), folding the unspecified address into loopback for the deny side, was rejected: `[::]` also reaches an IPv4 `127.0.0.1`-only listener, so (a) would need a fixed loopback set, and `0.0.0.0` reaches wildcard-bound services that an operator may deny only by LAN IP — no rule-side folding can say what the dial reaches. (b) mirrors the numeric fail-closed rule and browser behaviour (Chrome's Private Network Access blocks `0.0.0.0`). Scope of the guard: **dial legs only**. A name leg with a known dial target (a Host / `:authority` value, `nameDenyLocked`) is not dialled, so an empty or `0.0.0.0` Host on an allowed dial target stays a legitimate Host-injection value; a deny rule that explicitly names `0.0.0.0` / `::` still matches names as before. `resend_http` / `fuzz_http` now scope-check the dial address even without `override_host`, because `net/url` reads an unbracketed `::` authority as host `:` while the dial goes to `[::]:80`. Cost: with any rule configured (even deny-only, e.g. `deny evil.example`), `http://0.0.0.0:3000/`, `CONNECT [::]:443` and a `tcp_forwards` target of `0.0.0.0:P` / `:P` are refused — use `127.0.0.1` / `[::1]`. Known gaps, documentation only: an allow rule naming `0.0.0.0` / `::` is now dead (no config-load warning); a LAN-IP-only deny still does not protect a wildcard-bound service reached through the loopback address.

**Acceptance record — non-canonical IPv4 dial hosts fail closed (USK-1273, 2026-10-25).** The USK-1250 fold assumed every legacy inet_aton spelling reaches the same destination, which holds only for a libc resolver or an upstream proxy. Probe (Go 1.26.1, pure-Go resolver, a wildcard DNS record answering `127.0.0.2`): under `allows:[127.0.0.1]`, `0x7f.0.0.1` and `0X7F.0.0.1` were admitted, sent to DNS and landed on `127.0.0.2` — an allow-list escape. The all-digit spellings (`2130706433`, `127.1`, `0177.0.0.1`, `127.0.0.01`) failed with "no such host" without a DNS query (Go's `isDomainName` wants a non-digit), but a libc resolver or an upstream proxy (`CONNECT 2130706433:443` is forwarded verbatim after the scope check) reads them as `127.0.0.1`, so whether the dial reaches the allowed host depends on a resolver the scope cannot see. Decision: whenever any rule exists on either layer, `CheckTarget` / `CheckHost` (and so `CheckOpaqueTarget`, `CheckURL`, every gate in the USK-1250 record and the `tcp_forwards` start and per-connection checks) refuse a dial host with no `:` that `canonicalScopeHost` reads as an IPv4 address in any spelling other than canonical dotted-quad decimal — integer, hex / `0X`, octal or leading-zero parts, short forms (`127.1`, `10.0.5`), any of those or a dotted-quad with a trailing dot (`127.0.0.1.`), and a bracketed IPv4 (`[127.0.0.1]`) — with the reason "non-canonical IPv4 spelling … use the dotted-decimal address such as 127.0.0.1" (`connector.legacyIPv4Spelling`, step 0 after the unspecified and numeric rules in `dialHostFailClosedLocked`, so `0` / `0x0` keep the unspecified reason). IPv6 literals, IPv4-mapped ones included (`::ffff:127.0.0.1`), are dialed as IP literals and are not affected. Open mode is unchanged; nothing is rewritten (comparison-only, MITM Principle 1). Scope of the guard: **dial legs only**, as for USK-1312 — `nameDenyLocked` does not call it, so `Host: 0x7f.0.0.1` on a connection dialing an IP-allowed `127.0.0.1` stays a legitimate Host-injection value, and a deny for `127.0.0.1` still blocks it through the fold, which is kept for name legs, for `numericHostUnparsable` and for rule-side comparison. Cost: with any rule configured (even deny-only, e.g. `deny evil.example`), `http://2130706433/`, `CONNECT 127.1:443` and a `tcp_forwards` target `0x7f.0.0.1:P` are refused — use the dotted-quad address. With this the "No configuration becomes more permissive than it was written to be" note at the end of §3.5.2's acceptance list holds again for IPv4 allows. Not changed: hex rule hostnames (`0x7f.0.0.1` in a rule) still load as names and fold to an IPv4 on the rule side.

**Acceptance record — per-host rate limit and TLS passthrough host comparison (USK-1263, 2026-10-26).** `RateLimiter.Check` / `Wait` keyed per-host buckets on `strings.ToLower(host)` and `PassthroughList.Contains` compared the lowercased literal, so `CONNECT localhost.:P`, `[::ffff:127.0.0.1]:P`, `[0:0::1]:P` or `[::1%25lo]:P` drew a fresh bucket for an already-limited host, and `CONNECT pinned.example.:443` was MITM'd although `pinned.example` is a passthrough pattern. Probe (pure-Go resolver, real loopback dial): `localhost.` reaches localhost; `::ffff:127.0.0.1`, `0:0::ffff:7f00:1` and `::ffff:127.0.0.1%lo` reach `127.0.0.1`; `0:0::1`, `::1%lo` reach `::1`; `localhost..`, `127.0.0.1.`, `127.1`, `2130706433`, `0177.0.0.1` fail with "no such host"; `0x7f.0.0.1` is sent to DNS. Decisions: (1) **Rate limit** — one private key helper (`RateLimiter.hostLimiterLocked`) shared by `Check` and `Wait` keys buckets on the full `canonicalScopeHost` form, legacy inet_aton IPv4 included. The limiter is deny-like: putting more spellings on one key can only make a limit stricter, so the fold that is unsafe for an allow is exact here. All callers move together — CONNECT, SOCKS5, plain-HTTP forward and the nine MCP resend / fuzz / schema-discover paths through `waitRateLimit`; transparent routes already key on the unmapped original-dst IP. The fold also shrinks the set of distinct keys an attacker can mint against the `maxHostLimiters` eviction bound. (2) **Passthrough — changed, narrowly.** `Contains` compares `passthroughMatchHost(pattern)` (for a wildcard, the part after `*.`) with `passthroughMatchHost(host)`: `canonicalScopeHost` — lowercase, one trailing dot on a name, one `[...]` pair, IPv6 RFC 5952 text, IPv4-mapped IPv6 to dotted quad, zone dropped — except that a spelling `legacyIPv4Spelling` reports (integer / hex / octal / short IPv4, `127.0.0.1.`, `[127.0.0.1]`) is compared as written, on either side. Reason: a passthrough match means *less* inspection (allow-like), so only spellings proven to dial the same host are folded; Go's pure resolver sends a hex legacy spelling to DNS (search list applied), so folding it onto a pattern could relay an uninspected tunnel to whatever DNS returns — the same reasoning as USK-1273. Transparent TLS matches on the SNI but dials the original destination regardless. The match form is computed once in `Add` and stored next to the pattern; `List` / `Remove` / query output keep the pattern as added (lowercased, trimmed), and `Remove` needs that exact pattern. Nothing on the wire, in logs, in denial tags or in the dial target is rewritten (MITM Principle 1). Not changed: a name and the address it resolves to (`localhost` vs `127.0.0.1`) are still separate rate-limit buckets and separate passthrough patterns — joining them needs DNS at the gate, which a literal-host predicate does not do; IDNA (U-label vs A-label) is not folded; the limiter counts connections on the live gates, not requests inside a kept-alive connection.

**Acceptance record — `raw_passthrough_hosts` host comparison (USK-1385, 2026-10-26).** `ProxyConfig.IsRawPassthrough` compared the lowercased literal `host:port`, so `CONNECT localhost.:P`, `[::ffff:127.0.0.1]:P`, `localhost:0P`, a SOCKS5 domain `localhost.` or a transparent SNI `a.example.` missed an entry naming the same destination and took the normal L7 MITM path instead of the bytechunk relay. Raw bytes were recorded either way, but a host designated raw (e.g. for request-smuggling reproduction) was handled differently depending on spelling. Decision: entry and target are both compared as `JoinHostPort(hostcanon.FoldDialEquivalent(host), port)` — the same allow-like form as the TLS passthrough list in the previous record, because the raw route skips Safety Input / Intercept / Transform — with the port read as an integer when it is ASCII digits in 1..65535 (leading zeros allowed, as `SplitTargetHostPort` accepts and a real loopback dial confirms `:0P` reaches `P`). Legacy inet_aton IPv4 spellings (`127.1`, `2130706433`, `0x7f.0.0.1`, `0177.0.0.1`, `127.0.0.1.`) are compared as written, on either side; `localhost..` and `::a.b.c.d` stay distinct. An authority `net.SplitHostPort` cannot parse keeps the old literal case-insensitive compare; an empty one never matches. The single production seam `UpstreamTarget.isRawPassthrough` (CONNECT / SOCKS5 `classifyTunnelRoute`, `BuildConnectionStack`, the transparent no-ALPN stack) is unchanged and now sees the folded match; nothing is rewritten — dial target, TLS name, MITM certificate, upstream SNI, `EnvelopeContext.TargetHost`, recorded raw bytes and the stored entries stay verbatim (MITM Principle 1). Side effect, intended: a respelled raw-passthrough target is now admitted by the strict opaque scope gate (`CheckOpaqueTarget`) instead of the provisional one, like its canonical spelling. Known approximations, accepted (they apply equally to the TLS passthrough list): the trailing-dot strip folds a short name `db.` onto `db`, although Go's resolver may try the resolv.conf search list for `db` (`db.<search>`) and resolve `db.` only at the root; and the IPv6 zone is dropped, so `[fe80::1%eth0]:P` and `[fe80::1%eth1]:P` match the same entry. Either only widens which connections skip inspection; the scope gate still evaluates the host as written, so neither is a scope bypass. The canonicalizers moved from private helpers in `internal/connector` (`canonicalScopeHost`, `passthroughMatchHost`, `legacyIPv4Spelling`, …) into the stdlib-only leaf package `internal/hostcanon` (`Fold` deny-like, `FoldDialEquivalent` allow-like, `LegacyIPv4Spelling`, `NumericUnparsable`, `UnspecifiedOrEmpty`, `ParseLegacyIPv4`, and the strict port reader `ParseStrictPort`, formerly `connector.parseStrictPort`, now shared with `config.IsRawPassthrough`), so `internal/config` and `internal/connector/transport` can import them without a cycle; the earlier records name the old identifiers. The unused `config.RawPassthroughSet` (literal-compare semantics, no production caller) was deleted.

**Acceptance record — per-host TLS (`host_tls`) host comparison (USK-1384, 2026-10-26).** Two seams looked per-host TLS entries up by the lowercased literal host — `transport.HostTLSRegistry` (`Set` / `Remove` / `Lookup`; consulted by `resolvePerHostTLS` on every live upstream TLS dial and by `StandardTransport` / `UTLSTransport.TLSConnect` for the MCP resend / fuzz / schema-reflection connections) and `connector.HostTLSResolver` (built from `ProxyConfig.HostTLS`) — so a respelled TLS host silently fell back to the global settings. Probe (real loopback upstream, CA-signed leaf with SAN `localhost` / `127.0.0.1`, `BuildConnectionStack` and the MCP transports): with a `ca_bundle` entry for `localhost` / `127.0.0.1`, `localhost.`, `[::ffff:127.0.0.1]` and `[0:0::ffff:7f00:1]` failed with "unknown authority"; with a `tls_verify: true` entry under a global `-insecure`, the respelled host skipped verification (fail-open); with a `client_cert` entry, the upstream saw no client certificate. Decision: both seams compare in `hostcanon.FoldDialEquivalent` form through one shared pair of helpers — `hostcanon.DialEquivalentPatternKey` on the registration side (lowercase; a leading `*.` kept and the domain after it folded) and `hostcanon.DialEquivalentLookupKeys` on the lookup side (exact key, then the unchanged one-level wildcard `"*" + name[first dot:]`), so the two grammars cannot drift. Why the allow-like form and not `Fold`: an entry is mixed-direction. `client_cert` and `tls_verify: false` mean *less* protection toward the named host, so folding a legacy inet_aton spelling (`0x7f.0.0.1`, which Go's pure resolver sends to DNS) onto them could hand the client certificate to, or skip verification of, whatever DNS returns; `ca_bundle` and `tls_verify: true` are stricter, so under-folding is fail-open. The dial-equivalent form folds exactly the spellings verified to reach the same destination (case, one trailing dot, one `[...]` pair, IPv6 RFC 5952 text, IPv4-mapped IPv6, zone) and avoids both. `127.1`, `2130706433`, `0177.0.0.1`, `127.0.0.1.`, `[127.0.0.1]` (bare), `localhost..` and `::127.0.0.1` stay distinct; `*.example.com` still matches only one label (`a.b.example.com` and `example.com` miss). `Hosts()` keeps the pattern as passed to `Set`; `Remove` accepts any equivalent spelling. Two `host_tls` keys with the same folded key (`localhost` and `localhost.`, `API.x` and `a.x`) used to apply one of two TLS settings by map order; `ProxyConfig.Validate` now rejects them, naming both keys in sorted order (behaviour change). Nothing else is rewritten: dial target, TLS `ServerName` / SNI, MITM certificate, CONNECT reply, `UpstreamTarget`, `EnvelopeContext.TargetHost` and recorded bytes stay as the client wrote them (MITM Principle 1); Go's x509 verifies `localhost.` and `::ffff:127.0.0.1` server names once the right `RootCAs` apply. The h2 pool key already includes the resolved insecure / client-cert / CA-hash, so no change there. Known approximations, accepted: the trailing-dot and zone-drop approximations of the previous record apply here too; and with an upstream proxy that reads legacy IPv4 spellings as addresses, `CONNECT 0x7f.0.0.1:P` reaches `127.0.0.1` but gets the global TLS settings rather than the `127.0.0.1` entry (consistent with the passthrough lists; TargetScope refuses such dial hosts whenever rules exist). Out of scope: `tcp_forwards` `upstream_tls` has no per-host lookup; the one-level wildcard step also runs on IP literals (`*.0.0.1` matches `10.0.0.1`, pre-existing); a name and the address it resolves to are separate entries; IDNA is not folded.

All forwarded streams reuse the same `Pipeline` and `RecordStep`, so Flow / Stream recording (`flow.Stream.Scheme` reflects the client-side wire; per-Flow `Envelope.Raw` preserves wire bytes), plugin hooks, intercept / transform rules, and Safety Input Filter apply identically to forward traffic.

**gRPC-Web auto-classify (USK-934).** The `http` arm (and `auto` arm when it dispatches to HTTP/1.1) inspects the first request's `Content-Type` header per-exchange. When it matches `application/grpc-web[-text][+proto|…]`, the per-exchange client Channel is wrapped with `grpcweb.Wrap` (downstream) and the upstream Channel is wrapped via `connector.WrapH1UpstreamForDispatch` (upstream symmetry) — Stream `Protocol` is then re-tagged to `grpc-web` by `record_step.maybeRetagProtocol`. This mirrors the H2 sibling pattern (`connector.DispatchH2Stream`) so HTTP/1.1 keep-alive that mixes grpc-web POST and JSON POST on the same connection routes correctly per-exchange. See `internal/connector/h1_dispatch.go`.

#### 3.4.3 Upstream HTTP/2 Fingerprint Parity (USK-1007)

Anti-bot frontends (Cloudflare, Akamai) fingerprint a client's **HTTP/2 behaviour** — SETTINGS values + wire order, the connection-level WINDOW_UPDATE increment, and the request pseudo-header order — in addition to the TLS ClientHello. For the proxy's MITM identity to be coherent, its own *upstream* (ClientRole) H2 send-shape must match the browser it claims to be.

The shape is driven by the existing `tls_fingerprint` value (no separate `h2_fingerprint` config): `http2.WithH2Fingerprint(cfg.EffectiveTLSFingerprint())` is threaded through all four upstream ClientRole dial seams (`stack_builder.go` pool dial, `connect_inner_dispatch.go` h2c, `stack_builder_target_override.go` forward, `h2_redial.go` GOAWAY redial). The forward seam is `connector.NewForwardUpstreamH2Layer`, which both the forward connection's first upstream Layer and its GOAWAY redials (USK-1165) are built with, so a redialed forward connection keeps the first one's shape. Only `firefox` diverges:

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

**Step → RecordStep annotations (USK-1109).** A Step that lets an envelope continue but wants an observation kept on the recorded Stream sets `Result.Annotations` (`map[string]string`). `Pipeline.Run` merges the annotations of every continuing Step into a per-Run bag in `ctx` (later Steps win on a key collision; annotations survive later Steps that replace the envelope), and `RecordStep` appends the merged set to the Stream via `flow.StreamUpdate.AppendTags` once the Stream row exists — so an annotation on the stream's first Send lands too. Annotations are metadata, never wire data: setting them does not modify `env`, `env.Raw` or `env.Message`, and they do not trigger variant recording. A Drop / Respond Step's own annotations are ignored; the annotations of the Steps that continued before it are returned as `RunOutcome.Annotations` by `Pipeline.RunDetailed`, and the session passes them to the block recorder (`OnPipelineDrop`) via `pipeline.WithBlockAnnotations(ctx, …)`, which puts them on the audit Stream's tags — so an earlier `log_only` observation survives a later intercept drop or scope re-check. `RecordStep` writes each (Stream, key, value) once per process: repeats on a streaming protocol (one match per WS / gRPC frame) cost no further store write. The current producer is `SafetyStep` in `log_only` mode (§3.7).

What changes is that Steps are now *explicitly categorized* into two kinds:

#### 3.5.1 Envelope-Only Steps (protocol-agnostic)

These Steps only access fields on `Envelope` and `Envelope.Context`. They never type-assert on `env.Message`. They work identically for every protocol.

Examples:
- **RecordStep** — persists the envelope (Raw + Message serialized as opaque blob + identity).
- **RateLimitStep** — counts envelopes per `Context.ConnID` or `Context.TargetHost`.
- **HostScopeStep** — validates `Context.TargetHost` against a scope policy. Separate from path-based scoping, which is HTTP-specific.

**Acceptance record — `HostScopeStep` scheme derivation (USK-1081, 2026-09-15).** "Protocol-agnostic" constrains *what the Step may read*, not *how little it may pass on*. Until USK-1081, `HostScopeStep` handed `TargetScope.CheckTarget` a blank scheme, on the reasoning that a connection-level check "only validates hostname and port". `matchTargetRule` is AND logic, so every rule carrying a `Schemes` condition silently stopped matching there: allow rules blocked everything, and deny rules blocked nothing. Which allow-list check did the blocking depends on the layer the rule was written to — `CheckTarget` step 3 ("not in policy allow list") or step 4 ("not in agent allow list"). The example allow rule published in `internal/mcp/resources/help_security.md` is `Schemes`-bearing and sits under the `set_target_scope` action, which replaces **Agent Layer** rules, so an operator who copied it hit step 4 and got a 403 on every request.

The scheme is now derived from `Context.TLS` — non-nil ⇒ `https`, nil ⇒ `http`. `TargetRule.Schemes` means **transport confidentiality**, plaintext versus TLS, spelled with the `http` / `https` tokens; it is not the L7 application protocol. That is already the meaning the connection-level handler gates encode with their literals (`connectPolicyReject` scopes a CONNECT tunnel as `"https"` even when the tunnel carries SMTP; the plain-HTTP forward handler scopes as `"http"`). Deriving it from `Context.TLS` answers the same question without inspecting `Message`, so the §3.5.1 contract holds.

`Context.TLS` is per-Layer and not per-stack (§3.1), so the two legs of a connection with independent TLS axes — a `tcp_forwards` entry with `tls` and no `upstream_tls`, say — carry different snapshots and would derive different schemes. `HostScopeStep` therefore evaluates **Send-direction envelopes only**, matching its sibling `HTTPScopeStep`: a connection-level gate must reach one verdict per connection, and both legs are stamped with the same `Context.TargetHost`, so the Receive-leg check was already redundant on hostname and port and only ever added the axis that diverges.

Observable effect on existing operator configs. Allow-gated configurations are unaffected: an allow rule carrying only real scheme tokens matched nothing at this Step before, so anything that reached upstream still does, and the change only widens the allow set toward exactly what the operator authored. **Deny rules do newly take effect**, and that is a live behaviour change operators should be told about before upgrading: a `{hostname: X, schemes: ["https"]}` deny matched nothing here on the old code, and now blocks an HTTPS MITM connection to `X` at the host gate. That is the authored intent, but traffic that flows today can stop flowing.

One counterexample to the "matched nothing" claim is worth naming, because it moves the other way. `matchTargetRule` compares with `containsStringFold`, i.e. `strings.EqualFold`, and `EqualFold("", "")` is true — so a rule whose `Schemes` list contains the **empty string** *did* match the old blank scheme, and now matches neither `http` nor `https`. For a deny rule that is a fail-open change: it blocked everything at this Step before and blocks nothing now. It was reachable only because the Policy layer was unvalidated at the time; USK-1084 closed that — `config.TargetScopePolicyConfig.Validate` rejects `""` (and every other out-of-vocabulary token) on both boot sources, so startup refuses such a rule instead of loading it (§3.8).

Two adjacent sites were considered and deliberately **not** changed — `matchTargetRule`'s blank-scheme semantics and SOCKS5's own handshake-time check. Both are recorded with their re-open trigger in §11.

**Acceptance record — raw (bytechunk) envelopes carry `EnvelopeContext` (USK-1083, 2026-10-19).** USK-1081 made the scheme derivation correct, but raw envelopes never reached it: `bytechunk.Channel.Next` stamped only `ReceivedAt`, so `HostScopeStep` short-circuited on an empty `Context.TargetHost` for every raw flow. Every raw construction site now passes `bytechunk.WithEnvelopeContext` with `ConnID`, `TargetHost` and the snapshot of that Layer's own leg (§3.1) — the `bytechunk` ALPN route and `raw_passthrough_hosts` inside CONNECT / SOCKS5 MITM (`clientSnap` / `upstreamSnap`), the CONNECT / SOCKS5 plaintext inner fallback (`BuildBytechunkStack`, `TLS` nil on both legs), and `tcp_forwards` raw / `auto`-to-raw (the client leg carries the terminated-TLS snapshot when `tls: true`, the upstream leg the dial's snapshot when `upstream_tls: true`). The Step stays Send-only; Receive envelopes carry the context too because RecordStep (`conn_info` TLS, JA3 / JA4), the capture-scope per-stream decision (taken on the first envelope, which is a Receive banner for a server-speaks-first protocol) and plugin `ctx.tls` / scoped state read it. The MCP `resend_raw` / `fuzz_raw` Receive Layers are unchanged: those pipelines have no `HostScopeStep` and check scope before the dial.

Resulting schemes, per the derivation above: a plaintext raw stream inside a CONNECT tunnel is checked as `http` although the CONNECT gate admitted the tunnel as `https` — the same verdict plaintext HTTP/1.x inside a CONNECT tunnel already gets, and the reading §3.8 prescribes. A SOCKS5 tunnel, admitted with a blank scheme, is checked with the tunneled leg's real scheme.

A raw Send envelope Dropped by a target-scope verdict (including a live connection's `RevokePending`) closes the connection: `session.clientToUpstream` writes the audit Stream via `OnPipelineDrop`, aborts both bytechunk Channels and returns `errRawBlockedByTargetScope`, which `RunSession` maps back to a clean end. A byte stream has no message boundary at which a chunk can be refused, so dropping chunks and relaying the rest would corrupt it; WebSocket and gRPC keep their per-message Drop. Plugin `ctx.transaction_state` / `ctx.stream_state` (raw keys both on the client StreamID) are released once, from the client Layer's `Close` — not at the Channel's EOF, because after the client's FIN the session still runs Receive envelopes under the client StreamID through PluginStep.

**Deny and allow rules newly take effect on raw paths**, and that is a live behaviour change: a `tcp_forwards` raw entry to a Policy-denied target, or a raw tunnel matched by a `schemes`-bearing deny, used to relay and now closes. Capture-scope `hostname` rules now apply to raw streams (they matched nothing before), and raw Streams now record `conn_id` (so the query `conn_id` filter finds them) and the upstream leg's `conn_info` TLS fields. The accept-time gate for `tcp_forwards` and its live-connection registration are USK-1161.

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

**Acceptance record — `HTTPScopeStep` scheme derivation (USK-1086, 2026-10-19).** `HTTPScopeStep` handed `TargetScope.CheckTarget` the request's *declared* scheme, `HTTPMessage.Scheme`, verbatim — and fed the same value to `defaultPortForScheme` when the authority carried no port. The declared scheme is client-controlled. HTTP/2 records `:scheme` verbatim and the assembler flags its absence only for extended CONNECT, so a normal request that omits it reaches the Step with a blank; a client may also declare `:scheme: http` over a TLS MITM leg; and an intercept `modify_and_forward` can set `scheme` to any value, which the release re-check (USK-1159) re-runs through this same Step. Because `matchTargetRule` is AND logic, each of those silently stopped a `Schemes`-bearing deny from matching (a bypass; the upstream re-encode repairs the blank `:scheme` to `https`, so the bypass costs the client nothing) or an allow from matching (a false block), and a blank or out-of-vocabulary value (`""`, `HTTPS`, `ftp`) resolved the default port to 0, degrading `Ports`-bearing rules the same way.

The Step now derives the scheme from `Context.TLS` with the same helper as `HostScopeStep` (`transportScopeScheme`), **always** — not only when the declared scheme is blank. `TargetRule.Schemes` means transport confidentiality (§3.8), and the transport is what the client's connection actually is, not what its request says it is; consulting the declared value at all would leave the mismatched-declaration and `modify_and_forward` routes open. The Step is Send-only, and Send envelopes come from the client-facing Layer, so the derivation reads the client leg exactly as `HostScopeStep` does. On every live HTTP/1.x constructor the Layer's scheme already equals the client leg's TLS state, so HTTP/1.x verdicts are unchanged. `HTTPMessage.Scheme` is not rewritten: it is still recorded and forwarded as the wire declared it (MITM Principle 1); only the policy predicate reads the transport.

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
- **Behaviour**: blocks at wire time. HTTPMessage violations emit `Action=Respond` with a synthetic 403. Native gRPC Start/Data violations emit `Action=Respond` with a synthetic Receive `GRPCEndMessage` (grpc-status 7 PERMISSION_DENIED, `grpc-message: blocked by safety_filter`, `server: yorishiro-proxy`, `x-yorishiro-matched-rules`), which `internal/layer/grpc` renders as a Trailers-Only response (or as trailers once response HEADERS were relayed); the session then ends the RPC and closes any dialed upstream stream (USK-1202). Intercept `drop` of a held Send-direction native-gRPC Start/Data uses the same terminator with `BlockedBy=intercept_drop`. gRPC-Web Start/Data violations (and intercept drops) emit the same `GRPCEndMessage`; `internal/layer/grpcweb` renders an End sent before any response Start as HTTP 200 whose body is one trailer frame, in the request's content-type (base64 for `-text`), and the session ends the RPC before the Layer's Send End sentinel is forwarded, so the upstream Channel — which buffers the request until that sentinel — writes nothing and its buffer is discarded by the cascade-close (USK-1220). A Data block may already have dialed the upstream (lazy dial on the forwarded Start); no request byte is written on it. WS frames still emit `Action=Drop`. `BlockedBy=safety_filter` is stamped on the recorded flow.
- **`log_only` mode (USK-1109)**: `safety_filter.input.action` is section-level (`block` default, or `log_only`). Under `log_only` a match never blocks, on either path: the live `SafetyStep` (`WithLogOnly`, wired from `PerProtocolSafetyEngines.LogOnly` → `proxybuild.Deps.SafetyInputLogOnly`) logs at Info `safety: match observed (log_only, not blocked)` (`filter=safety_filter`, `rule_id`, `rule_name`, `target`, `match` as an `hmac:… len=N` digest — HMAC-SHA256 under a random per-process key, so low-entropy matches cannot be brute-forced from the log; stable within one process for correlation, not across restarts; never the raw fragment), forwards the envelope untouched, and returns `Result.Annotations{"safety_log_only:<rule_id>": <target>}` with one entry per matching rule (the live wire evaluates every rule via the per-protocol `CheckInputAll`, so an early noisy rule does not hide later ones; block mode stays first-match), which `RecordStep` appends to the Stream's tags (visible as `tags` in `query` `flows` / `flow`). The MCP plane (`safety.Engine.CheckInput`, used by resend / fuzz / macro) logs the same message and lets the request through; a blocking rule later in the list still blocks. The intercept modify_and_forward recheck inherits the mode because it reuses the same `*SafetyStep`. Block-mode logs carry the same redacted digest.
- **Protected target**: the **upstream server**.
- **Modify-and-forward recheck (USK-702)**: the Send-side modify_and_forward path in `InterceptStep.holdAndDispatch` re-runs the same `SafetyStep.Process` against the operator-supplied modified envelope, closing the bypass where an AI agent first issues a benign request and then rewrites the body to a destructive payload at hold time.
- **Release scope recheck (USK-1159)**: before that safety recheck, every release — manual, timeout auto-release, and modify_and_forward — re-runs `HostScopeStep` and `HTTPScopeStep` against the envelope about to be forwarded (the modified one for modify_and_forward), so a scope narrowed during the hold or a rewritten target is denied with the same 403 / Drop and `BlockedBy=target_scope` as at the head of the Pipeline. When a policy change revokes the live connection under a hold, `connector.LiveConns` defers the connection cut until the hold resolved and its Result was dispatched (USK-1192): the hold pins the connection — and on resolution hands the pin to the session relay loop that ran the pass (`connector.HoldPinHandoff`, USK-1196), which unpins it only after the Result was dispatched, so a sibling h2 stream's Settle or a second Reconcile cannot cut the connection under the in-flight Result — `HostScopeStep` blocks every new Send envelope on it meanwhile, and the session settles the cut after delivering the re-check's 403, so the held request is answered and recorded instead of vanishing with the connection.

#### Output Filter (MCP control plane, on AI return)

- **Purpose**: prevent AI agents from receiving sensitive information as **input**. Two driving concerns:
  1. **LLM training-data leakage** — sensitive bytes that flow into an AI agent's context window may be retained by upstream LLM operators.
  2. **Enterprise LLM Input Security Policy compliance** — many organizations regulate which categories of data their AI tooling is permitted to ingest.
- **Layer**: MCP control plane — `internal/safety.Engine` exposes `FilterOutput` / `FilterOutputHeaders`, invoked by `internal/mcp/safety_helper.go` at the moment a query / resend / fuzz / replay tool serializes its response to the AI client.
- **Behaviour**: masks (redacts) matched bytes in the response payload. `log_only` is also supported (`block` is rejected by config validation for the output section). The original wire-recorded bytes in flow.Store are never mutated — Output Filter operates on a copy at the MCP transport boundary.
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

### 3.8 TargetScope `schemes`: a transport-confidentiality predicate

`TargetRule.Schemes` (`internal/connector/scope.go`) is the one scope condition whose meaning is not inferable from its name, and getting it wrong is silent in both directions. This subsection is the authoritative definition.

#### What it means

`schemes` selects on **transport confidentiality — plaintext vs TLS — spelled with the `http` / `https` tokens**. It is *not* an L7 application-protocol axis.

The vocabulary is closed on **both** layers, enforced by one shared per-rule core, `config.ValidateTargetRule` (`internal/config/target_scope_policy.go`), which rejects anything but `http` / `https` (case-insensitively; `""` too — omit `schemes` to match both) with `scheme %q is not allowed (use http or https)`. The **Agent layer** reaches it through `validateTargetRules` in the `security` MCP tool. The **Policy layer** reaches it through `config.TargetScopePolicyConfig.Validate`, called from `ProxyConfig.Validate` (config-file `target_scope_policy` section, checked even when `-target-policy-file` shadows it) and from `config.LoadPolicyFile` (`-target-policy-file`); either failure is returned from `mcpserver.LoadConfigs`, so **startup refuses** an out-of-vocabulary rule rather than loading one that silently matches nothing. The operator's runtime reload (`SIGHUP`, USK-1115) re-reads the same source through the same loaders (`mcpserver.LoadPolicySource`), so it rejects such a rule too and keeps the running policy. Uppercase tokens are accepted and lowercased into `connector.TargetRule` by `mcpserver.ConvertTargetRules` (mirroring the Agent layer's `toTargetRules`); the config struct keeps the operator's spelling. A rule's `schemes` can therefore be relied on to hold only `http` / `https` regardless of which layer it came from.

Two existing data-path callers fix this reading:

- `internal/connector/http1_forward_handler.go` passes `http` explicitly (`CheckTarget("http", …)`) "so scope rules can disambiguate http vs https traffic for the same host". It is the plaintext forward-proxy leg; `internal/layer/http1/` contains no forward handler.
- `internal/connector/connect_handler.go` scopes a `CONNECT` tunnel as `"https"` — even though the tunnel may carry SMTP. The predicate is about the leg's confidentiality, not its payload. This is where the `https` half of the pair comes from.

Every caller therefore maps its own transport onto the same two tokens: WebSocket maps `ws → http` and `wss → https` (`resendWSUpgradeURL`); raw TCP and gRPC map their `use_tls` / `:scheme` decision the same way. Inventing per-protocol tokens (`ws`, `tcp`, `raw`, `tls`) is **rejected** — see Anti-patterns.

#### Why a blank scheme is never safe

`matchTargetRule` is AND logic: `if len(rule.Schemes) > 0 && !containsStringFold(rule.Schemes, scheme) { return false }`. A blank scheme matches no `schemes`-bearing rule, and `CheckTarget` evaluates deny → allow, so the same blank breaks both lists in opposite ways:

| Rule | Effect of a blank scheme | Security outcome |
|------|--------------------------|------------------|
| deny `{hostname: "169.254.169.254", schemes: ["http"]}` | rule stops matching; evaluation falls through to the allow check, which is empty | **BYPASS** — cloud metadata reachable |
| allow `{hostname: "internal.example", schemes: ["http"]}` | rule stops matching | **FALSE BLOCK** — `not in policy allow list` on a legitimate target |

There is no fail-safe blank semantic: deny wants "unknown matches everything" and allow wants "unknown matches nothing", so any *single* rule for the blank case is fail-open in exactly one direction. An asymmetric per-list semantic is conceivable but is a behaviour change to a live policy engine with deliberate blank callers, and is deferred (§11).

Consequently the fix for a blank scheme belongs at the **call sites**, not in `matchTargetRule` and not as a `"" → "http"` default inside the shared `checkTargetScopeAddr` seam: defaulting there would silently mis-scope a caller whose transport is genuinely unknown.

#### The one accepted blank caller

`internal/connector/socks5.go` passes `""`. SOCKS5 must send `REP=0x02` **before** any tunnel byte, so at check time the tunneled transport has not been observed and there is nothing to sniff. `schemes`-bearing rules do not match SOCKS5 targets; scope them by `hostname` / `ports`, or scope the tunneled protocol instead. This is documented at the call site and is the reason the blank case must stay expressible.

#### Anti-patterns (do not propose)

- **"Extend the vocabulary with `ws` / `wss` / `tcp` / `raw` / `tls`"** — it costs the config struct, `validateTargetRules`, `ruleCoversRule`'s policy-boundary subset logic, the `security` tool schema, `help_security.md` and the WebUI, and it creates a *new* silent-non-match class: every existing `schemes: ["http"]` deny would stop covering raw traffic the moment `raw` became a distinct token.
- **"Make `matchTargetRule` fail-safe for a blank scheme"** — provably impossible with one semantic (above).
- **"Default `""` to `"http"` in `checkTargetScopeAddr`"** — mis-scopes the genuinely-unknown SOCKS5 caller as plaintext, trading a visible gap for an invisible wrong answer.

This is **not** in tension with MITM Principle 2 ("each protocol has its own canonical form; do not unify across protocols"). Principle 2 governs *wire-data representation* — HTTP/1.x header casing vs RFC 9113 lowercase, and so on. `schemes` is a control-plane **policy predicate** that borrows URL scheme names for a transport property. Inventing per-protocol policy tokens would be the violation, not the fix.

#### The same structure for `path_prefix` (USK-1130)

Every connection-level check — the CONNECT, SOCKS5, plain-HTTP-forward and `tcp_forwards` gates, their live-connection predicates (USK-1160) and `HostScopeStep` — runs before any request path is known. `CheckTarget(…, path "")` is AND logic over `PathPrefix` exactly as over `Schemes`, so an unknown path breaks the two lists in opposite ways: a path-scoped **allow** never matches (false block — every connection to the host was refused "not in policy allow list" before `HTTPScopeStep` saw a path), and a path-scoped **deny** never matches (the connection is admitted and the deny is enforced per request). As with the blank scheme, no single "unknown path" semantic is right for both lists, and treating a path-scoped allow as a match would let a TLS passthrough relay or raw tunnel reach the host with no path check at all — wider than the operator wrote.

The fix is therefore again at the call sites, and `CheckTarget` is unchanged:

- `TargetScope.CheckHost(scheme, host, port)` evaluates deny rules exactly as `CheckTarget(…, "")` does and each allow layer ignoring `PathPrefix`; a layer whose only matches are path-scoped passes *conditionally* (`pathPending`). A non-path match in a layer beats a conditional one.
- **Provisional gates** — routes on which the Pipeline sees every request: CONNECT / SOCKS5 to a target that is neither in the TLS passthrough list nor in `raw_passthrough_hosts`, the plain-HTTP forward, and `tcp_forwards` `http` / `http2` / `websocket` / `sse` / `grpc` / `auto` — admit on `CheckHost` (the route classification is computed once per connection, so admission, the live-connection predicate and the passthrough decision agree).
- **Strict gates** — routes that can never yield a path: the TLS passthrough relay, `raw_passthrough_hosts`, and `tcp_forwards` `raw` — use `CheckOpaqueTarget` (= `CheckTarget(…, "")`, with reason `ReasonPathRequired` when only a path-scoped allow matched). SOCKS5 refuses them with `REP=0x02` via `SOCKS5Negotiator.OpaqueRoute`.
- `HostScopeStep` recomputes `CheckHost` per envelope, statelessly (so the USK-1159 release re-check and USK-1192 revoke path need nothing new): on `pathPending` an `http` envelope continues to `HTTPScopeStep`, a `ws` envelope continues (its frames ride a path-checked upgrade), a `grpc` / `grpc-web` envelope continues (its RPC's Send `GRPCStartMessage` is judged by `HTTPScopeStep`, USK-1236), and `raw` is blocked, failing closed.
- **Raw relay refusal (review S-1).** `HostScopeStep` sees only Send envelopes, so a server-first upstream on a provisionally admitted route that resolved to raw bytes would reach a silent client before any check fired. Every raw relay therefore converges on one seam (`proxybuild.runRawRelaySession`) that, before relaying a byte, re-runs the admitting gate's check strictly with the gate's own scheme (`LiveConn.AdmitOpaque` → `CheckOpaqueTarget`) and asks the Pipeline's `HostScopeStep` about the first client chunk (`Pipeline.AdmitsRawRelay`). A refusal is recorded as a payload-free `blocked_by: target_scope` audit Stream and the connection is closed. The same call (`LiveConnHandle.ResolveOpaque`) marks the live connection resolved before it runs the strict check, so every later re-evaluation (`Reconcile` / `Settle`) uses `AdmitOpaque` too: narrowing a host-only allow to a path-scoped one closes a raw relay that is already running, exactly as it refuses an identical new one (USK-1283). Connections whose route stays HTTP keep the provisional predicate and are judged per request.
- `HTTPScopeStep` checks the request path against both the client-written authority and `Context.TargetHost` (the host the upstream leg is bound to). Without the second check a provisional CONNECT to X plus `Host: Z` (Z allowed host-only) reached X on any path, and a path deny on X was bypassed by naming another host. Strictly stricter for denies; no verdict change for rules without `path_prefix`.
- gRPC / gRPC-Web never reach the Pipeline as an `HTTPMessage` (the h1 / h2 dispatchers wrap them first), so `HTTPScopeStep` judges a Send `GRPCStartMessage` through the same protocol-neutral request view (USK-1376, USK-1236): `Authority` (`:authority`, or the first `Host` of an HTTP/1.x gRPC-Web request), every `host` value in `Metadata`, `Context.AbsoluteFormAuthority`, and the path the Layers write (`envelope.GRPCStartWirePath`, shared with both Layers' `pathForStart`). Legs, Option B and the transparent DNS binding are unchanged; `TransformStep` re-judges a Start a rule modified. A native gRPC or gRPC-Web block answers `grpc-status 7` (`grpcPolicyDropResult`, the Safety / intercept shape; gRPC-Web renders it as HTTP 200 + a trailer frame, USK-1220). The session ends the call when the terminator is delivered, so a Start blocked here is never followed by its Data / End and the upstream is not dialed for it; the client connection stays usable (HTTP/1.x keep-alive, other HTTP/2 streams).

The MCP control-plane address checks (`resend_raw`, `fuzz_raw`, `resend_grpc`, gRPC schema discovery, `resend_ws`) keep the strict `CheckTarget(…, "")`; URL-carrying tools already pass the path (`CheckURL`). Residual limitations are recorded in §11.

#### Name legs: Host header values and the IP-literal allow exemption (USK-1167)

An HTTP request reaches a host by its dial target and is routed on that host by the names it carries. `HTTPMessage.Authority` is set once at parse time from the first `Host` (HTTP/1) or from `:authority` (HTTP/2), but the HTTP/1 serializer writes the Host line from `Headers` and never from `Authority`, and HTTP/2 forwards a regular `host` header next to `:authority`. Checking the authority alone therefore let a Host-only rewrite — intercept `modify_and_forward` headers, a Transform `set_header Host`, `resend_http` / `fuzz_http` header lists or positions — or a second `Host` on the wire reach a denied vhost on an allowed address.

Every `Host` value (`envelope.HostHeaderValues`: every header whose name equals `host` case-insensitively, wire order, duplicates kept, SP/HTAB trimmed for comparison only, returned whole, `Headers` never modified) is now a *name leg* next to the authority:

- `TargetScope.CheckNameLeg(scheme, name, port, path, dialTarget)` applies deny rules (both layers) to the name as `CheckTarget` does, except that a port-scoped deny matches on the name's own port **or** the dial target's port (USK-1306): the bytes reach the dial port, so `Host: portd.example:8080` sent to `10.0.0.5:80` is refused by `{portd.example, ports:[80]}`. With no dial target only the name's port counts. Per allow layer, the name is exempt from the allow list when the dial target was admitted by an allow rule of that layer whose `hostname` is an IP literal (any spelling `hostcanon.Fold` reads as an address; there is no CIDR form); otherwise the name must match an allow rule of that layer. An empty layer passes. With no dial target it is the full `CheckTarget`.
- `TargetScope.CheckHostHeader` splits a Host value as `uri-host [":" port]` (port-less or empty port → scheme default) and fails closed, when rules exist, on a port that is not decimal 1–65535 or a value that is neither `host:port`, `[v6]:port`, `[v6]` nor a bare IPv6 address, or whose bracket holds anything but an IPv6 literal (the `SplitTargetHostPort` stance, USK-1249 / USK-1264). The authority leg (`TargetScope.CheckAuthority`) keeps its existing lenient port parse for the whole value (a non-numeric or out-of-range port takes the scheme default) but refuses, when rules exist, the same uninterpretable forms — a multi-colon non-IPv6 value or a non-IPv6 bracket — so the HTTP/2 `:authority` leg (no `host` header) is not left open where the Host leg is closed.
- Other readings, deny only (USK-1304): `CheckHostHeader` and `CheckAuthority` also deny-check every comma-separated part of the value (split on `,`, SP/HTAB trimmed, empty parts skipped, each split strictly; an uninterpretable part fails closed) — HAProxy's `hdr(host)`, for one, routes on the last part — and, for an unbracketed IPv6 value, the last-colon reading (`2001:db8::1:8080` → `2001:db8::1` port 8080). Allow is judged on the whole value only, so a non-denied comma value still passes on an IP-allowed connection and reaches the wire unchanged. Whole value and parts are evaluated under one read lock.
- Live path: `HTTPScopeStep` checks authority (as a name leg against `Context.TargetHost`, `CheckAuthority`), `TargetHost` (full check) and every Host value; all must pass. The intercept release re-check runs `HTTPScopeStep`, and `TransformStep.WithScopeRecheck` re-runs the same `recheckScope` on a Send `HTTPMessage` a Transform rule modified.
- Absolute-form authority (USK-1274): an HTTP/1.x absolute-form request-target is forwarded verbatim, and RFC 9112 §3.2.2 has a server route on its authority and ignore `Host`. `parseRequestURI` keeps `HTTPMessage.Authority` = `Host` when one is present, so `GET http://denied.example/` + `Host: allowed` (inside a CONNECT / SOCKS5 MITM tunnel, or on the second and later requests of a plain forward keep-alive connection, which stay bound to the first request's upstream) was judged by `Host` alone. The client-facing HTTP/1.x Layer now stamps the wire authority (the part of `absoluteFormPrefix` after `://`, verbatim, userinfo included) on the request envelope's `Context.AbsoluteFormAuthority` — read-only context, not an `HTTPMessage` field, because it is never serialized and must not look like a writable knob. `HTTPScopeStep` judges it with `TargetScope.CheckAbsoluteFormAuthority`: `net/url` strips userinfo and the remaining `host[:port]` goes through `CheckHostHeader` (transport scheme, strict port, Option B). An authority `net/url` refuses, or one with more than one `@`, fails closed when rules exist; an empty authority (`http:///x`) names no host and passes. Any URI scheme is checked, not only `http`/`https`. Wire bytes, `Envelope.Raw` and the recorded request are unchanged; the intercept / Transform re-check sees it because `Context` survives the clone. HTTP/2 `:path` carrying an absolute URI is out of scope.
- MCP: `checkResendHTTPScope` (resend_http and the fuzz_http plan) and `checkFuzzHTTPVariantScope` (per variant, after positions and `§var§`) check every Host value against the dial address (`addr` / `plan.dialAddr`), and the authority as a name leg against it too (`checkAuthorityNameLeg`; additive, so an h2 resend — which carries no Host — with `override_host` still gets the dial-port and comma-part denies on `:authority`). Their canonical URL leg is unchanged (full check). `checkResendWSScope` (resend_ws, and fuzz_ws for the base plan and every variant) checks the upgrade request's Host — always `upgradeURL.Host` — as a Host name leg against `plan.dialAddr` the same way. They also judge the authority of an absolute-form `path` (USK-1274): the HTTP/1 encoder writes `path[?raw_query]` verbatim as the request-target, so `path: "http://denied.example/"` to an allowed authority with an allowed Host reached a server routing on that authority. `checkAbsoluteFormPathLeg` extracts it with the Layer's own splitter (`http1.SyntheticAbsoluteFormAuthority` = `absoluteFormAuthority` over the target `sendRequestSynthetic` builds) and runs `CheckAbsoluteFormAuthority` with the same scheme, path and dial address as the Host legs; the path is never rewritten, so a non-denied absolute-form path is still sent verbatim. The fuzz_http plan check skips this leg when a `path` position or a `§var§` in the path rewrites it (the per-variant check judges it). The macro HTTP step needs no such leg: it sends through `net/http`, which writes origin-form (`URL.RequestURI()`) whenever no proxy is configured.
- Forward targets (USK-1264): `connector.JoinDefaultPort` derives the plain-HTTP forward target (origin-form Host and absolute-form authority) and the `resend_http` / `fuzz_http` / `resend_ws` / `resend_grpc` dial address. A host with colons is accepted only when it is an IPv6 literal; `db.internal:5432:x` is a 400 (forward) or a tool error (MCP) before any dial — it used to become `[db.internal:5432:x]:80`, which the scope read as host `db.internal:5432:x` while an upstream proxy received the `CONNECT`. `SplitTargetHostPort` (forward, CONNECT, SOCKS5, tcp_forward, `override_host`) refuses a bracket whose content is not an IPv6 literal (`[db.internal:5432]:80`, `[db.internal]:80`).
- Deferred (USK-1274 review): `Context.AbsoluteFormAuthority` is captured at parse time, so a request-target rewrite *after* parse is re-checked against the stale (or empty) authority. Three routes reach it: a Transform rule or intercept `modify_and_forward` that sets an origin-form request's `path` to an absolute URI (written verbatim by `requestLine`); a `path` edit spliced behind an absolute-form prefix that moves the authority (`http://ok.example` + `@denied.example/`); and a plugin `msg["raw"]` that rewrites the request line. All three are authored by the operator, the agent driving the MCP tools, or an operator-loaded plugin — none is attacker-reachable from the wire, and each can already send arbitrary bytes by design (§9.3 D4). **Re-open trigger:** a deployment where intercept edits, Transform rules or plugins come from a party other than the one who authored the scope policy (an untrusted rule / plugin source), at which point `recheckScope` should derive the authority from the request-target the Layer will emit rather than from the parse-time context.

Why the exemption is keyed on an IP-literal allow: an operator who allows an address has authorized that machine, not a set of names, and testing other virtual hosts on it (or injecting a Host it does not expect) is a core assessment technique; an operator who allows a domain has authorized a name, and a different name on shared infrastructure may be a different tenant. Denies are never relaxed, so a vhost the operator must not reach is denied by name. This also relaxes the pre-existing authority leg: `allows:[10.0.0.5]` + CONNECT `10.0.0.5:443` + `Host: intranet.local` was refused "not in policy allow list" and is now forwarded. `CheckTarget` itself is unchanged for every other caller.

#### Acceptance record

- USK-1061 (Done, 2026-09-15) — five MCP control-plane scope call sites (`checkResendHTTPScope`, `checkResendGRPCScope`, `checkResendWSScope`, `checkResendRawScope`, `buildFuzzRawPlan`'s inline copy, reaching 8 MCP tools) passed `""` on the non-TLS path, no-opping every `schemes`-bearing rule. Each now passes the scheme its canonical leg already matched on (`canonicalURL.Scheme` / `plan.scheme` / `upgradeURL.Scheme`) or, for L4, the `use_tls → {http, https}` mapping. `plan.scheme` rather than `plan.useTLS` for gRPC, preserving USK-1056's "never derive scheme from useTLS". `fuzz_raw`'s duplicate now shares `checkRawDialScope`. Same change folded in the USK-1051 precedent for `resend_http` / `resend_ws`: the scheme allowlist was hoisted into the unconditional validator so the `flow_id` path is covered — previously `resend_ws {flow_id, scheme: "https"}` set `useTLS=false` (plaintext dial) while handing the scope check `"https"`, so an allow rule scoped to TLS approved a cleartext credential replay (CWE-319).
- USK-1061 review round 1 — two follow-ups inside the same change. (1) `resend_http` was the one fixed call site whose resolved scheme could still be `""`: a normal HTTP/2 request that omits `:scheme` is recorded verbatim — `internal/layer/http2`'s assembler flags a missing `:scheme` only for extended CONNECT (RFC 8441 §4) — and the blank survives into `Flow.URL`, so `buildResendHTTPEnvelopeWithMeta` now defaults it from the recorded `Stream.Scheme` (allowlisted, mirroring USK-920's gRPC fallback) and otherwise to `http`. (2) `checkResendGRPCScope` clamps `plan.scheme` into `{http, https}` **for the scope check only**, because `extractResendGRPCStartFields` reads the client-declared `:scheme` with no allowlist; an out-of-vocabulary value made both legs match nothing, which on the `applyResendGRPCDialGroundTruth` upgrade path replaced a deny that used to fire with one that never can. Neither change touches a recorded wire value (MITM Principle 1): the default belongs to the resend *plan*, the clamp to the policy predicate.
- USK-1081 — the same blank-scheme defect in the live data path (`internal/pipeline/host_scope_step.go`); tracked separately because the fix lives in a different layer.
- USK-1083 — raw (bytechunk) envelopes carried no `TargetHost`, so `HostScopeStep` never evaluated raw TCP at all; they now carry the per-leg context and a deny closes the connection (§3.5.1 acceptance record).
- USK-1086 (Done, 2026-10-19) — `internal/pipeline/http_scope_step.go` passed `msg.Scheme` verbatim, so the same recorded-but-schemeless HTTP/2 request reached the live scope check with a blank. Same layer as USK-1081, same defect class, separate Issue. `HTTPScopeStep` now always derives the scheme from `Context.TLS`, sharing `HostScopeStep`'s helper; acceptance record in §3.5.2.
- USK-1084 — the Policy layer validated nothing: `config.LoadPolicyFile` checked JSON validity only and `mcpserver.ConvertTargetRules` copied `Schemes` verbatim, so a `{"hostname": "chat.internal", "schemes": ["wss"]}` deny loaded and matched nothing. `config.TargetScopePolicyConfig.Validate` now runs from `ProxyConfig.Validate` and `LoadPolicyFile` and refuses startup on an out-of-vocabulary scheme (including `""`), a hostname that can never equal a data-path host (`*`, `host:port`, a URL, `*example.com`, mid-label wildcards), a port outside 1–65535, or a negative `rate_limits` / `budget` value; the policy file is also decoded strictly (unknown fields, e.g. a HAR document written over it, are refused). The per-rule core `config.ValidateTargetRule` is shared with the Agent layer, which therefore also accepts bare IPv6 literals and underscore labels (both match today).
- USK-1085 — the sibling validate/use discrepancy one field over: `net.SplitHostPort` accepts a service name in the port position, which `net.LookupPort` resolves at dial time (`http` → 80) while `targetDefaultPort` returns 0 for it, so a `ports`-bearing rule stops matching while the socket lands on the real port. `validateRawTargetAddr` / `validateOverrideHost` now require a decimal port in 1–65535.
- USK-1249 — the same discrepancy on the live plain-HTTP forward gate: `forwardScopeCheck` read the peeked target's port with `strconv.Atoi` and checked the error case as port 0, so origin-form `Host: db.internal:postgresql` missed a `{db.internal, ports:[5432]}` deny and was dialed on 5432 (or sent verbatim in the upstream proxy's `CONNECT`). Absolute-form was affected too: `url.Parse` accepts a 10-digit port, and Go's `net.parsePort` wraps it modulo 2^32 (`p + 4294967296` → `p`) while `Atoi` returns the unwrapped value. `peekForwardTarget` now validates the final target from both forms with `connector.SplitTargetHostPort` (ASCII digits only, 1–65535; the USK-1161 tcp_forward rule, which now delegates to it) and answers 400 otherwise; `forwardScopeCheck`, `connectScopeCheck` and `socks5ScopeCheck` fail closed on such a port when rules are present.
- USK-1262 (2026-10-25) — the same discrepancy on the MCP control plane. `net.Dial` wraps a decimal port modulo 2^32, skips a leading space or `+`, and resolves service names, while `CheckURL` read `u.Port()` with `strconv.Atoi` (a 10-digit value no `ports` rule names; error → 0, which matches nothing) and, for a URL built as a struct from the authority (`envelope.URLFromWirePath`), judged the whole `"127.0.0.1: 8080"` as the hostname on the default port because `u.Port()` is `""` for a non-digit port. Probe (loopback, deny `{127.0.0.1, ports:[p]}`): `resend_http` with an explicit `Host` header or `http_version: h2c`, `fuzz_http`, `resend_ws` / `fuzz_ws` / `resend_grpc` / `fuzz_grpc` `target_addr`, `grpc_schema discover`, and the macro / hook send funcs reached `p`; `resend_grpc` by `flow_id` without `target_addr` reached a recorded `:authority` of `127.0.0.1:+p` even under a hostname-only deny `127.0.0.1` (the address leg is skipped when the dial address equals the URL host). The default `resend_http` / `resend_ws` paths were blocked only **accidentally**, by the strict Host-header leg. Fix: (1) every MCP dial address — `resolveDialAuthority` (shared by the six resend / fuzz tools, with or without `target_addr`) and `grpc_schema discover`'s `target_addr` — must have a port that passes `SplitTargetHostPort`'s rule; otherwise a validation error before the scope check, **in open mode too** (user decision: input validation, not scope; `override_host` and the raw tools' `target_addr` already had it, USK-1085). (2) With rules, `CheckURL` reads the port from `u.Host` with that rule and fails closed on a present-but-invalid port or a host with colons that is neither `host:port` nor an IPv6 literal (bare unbracketed IPv6 keeps its old reading); the address leg (`checkTargetScopeAddrPathHelper`) and the name legs' dial port (`splitDialTarget`) likewise; `defaultPort`'s "Atoi error → 0" is gone (`schemeDefaultPort` takes no port string); `CheckTarget` / `CheckHost` refuse a port outside 0–65535. `CheckAuthority`'s lenient whole-value port is unchanged (§3.8 decision): the dial port it is compared with is now always strict. Only the dial address is validated; the wire authority / `Host` value and recorded flows are not rewritten. Not affected: `resend_raw` / `fuzz_raw` and `override_host` (already strict), pluginv2 and `internal/job` (no URL-driven dial). `security test_target` now reports the verdict the send path enforces for such URLs.

- USK-1167 — Host header values were never scope-checked (live, intercept release, Transform, `resend_http`, `fuzz_http`); they are now name legs with the IP-literal allow exemption described above, which also applies to the existing authority leg — a deliberate widening for names carried to an IP-allowed address (user decision; denies are unaffected). Transform gained a scope re-check on a modified request. Plugin rewrites and gRPC start paths are tracked separately.
- USK-1264 / USK-1304 / USK-1306 — three gaps in the name-leg seam, fixed together. (1) USK-1264: the forward target's default-port join wrapped a non-IPv6 multi-colon host in brackets and `SplitTargetHostPort` accepted any bracket content, so `Host: db.internal:5432:x`, `GET http://db.internal:5432:80/` and `Host: [db.internal:5432]:80` missed a `db.internal` deny and reached an upstream proxy as a `CONNECT`; the same join in the three MCP dial resolvers. All now fail closed (see "Forward targets" above). **Decision (unbracketed IPv6)**: `Host: ::1` and `Host: 2001:db8::1:8080` are still accepted at both seams and read as the whole IPv6 literal on the default port, so IP-literal Host-injection tests stay possible and the dial and the scope agree on the same address; the last-colon ambiguity is closed on the deny side only. (2) USK-1304: a comma-bearing Host / authority was judged as one name; its parts are now deny-checked (user decision: deny only, allow on the whole value, never rewritten). (3) USK-1306: name-leg denies now match on the dial port as well as the written port. Deferred: a plain-forward *dial target* derived from a comma Host (`ok.example, denied.example:80`) still reaches an upstream proxy as a malformed `CONNECT` line, although the request itself is refused by the Host leg.
- USK-1274 — the authority of an HTTP/1.x absolute-form request-target was not scope-checked when a `Host` header was present, although the target is forwarded verbatim and a server routes on it (RFC 9112 §3.2.2). It is now a name leg (`Context.AbsoluteFormAuthority`, `TargetScope.CheckAbsoluteFormAuthority`) with the same Option B semantic; uninterpretable authorities fail closed. Strictly stricter for denies; under an IP-literal allow a non-denied absolute-form authority is still forwarded verbatim.
- USK-1312 — an empty host or an unspecified address (`0.0.0.0`, `::` and their spellings) dials the proxy host but matched no loopback deny; with any rule configured such a dial host now fails closed on every dial leg, name legs unchanged (§3.4.2 acceptance record). The one exception to the "only stricter" note below: a deny-only config now also refuses `0.0.0.0` / `::` / empty dial hosts that no rule names.
- USK-1273 — USK-1250's legacy IPv4 fold let an allow for `127.0.0.1` admit `0x7f.0.0.1`, which Go's pure resolver looks up in DNS (search list applied), so the dial could land on a host the allow list never named. With any rule configured, an IPv4 dial host in any spelling other than canonical dotted-quad decimal now fails closed on every dial leg; name legs unchanged (§3.4.2 acceptance record). Like USK-1312, a deny-only config also refuses such dial hosts that no rule names.

**Observable change for existing operator configs**: deny rules become strictly stricter; allow rules become more permissive, but only to exactly what the operator authored. No configuration becomes more permissive than it was written to be.

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

The new RunSession in step 6 reads **both** directions immediately (USK-1171). Its upstream Channel was already built during the swap, so it is handed to RunSession pre-established instead of being dialled lazily on the first client envelope. Lazy dialling is an HTTP routing need, not a WebSocket one. Without this, a server-speaks-first protocol (greeting, push) would stall until the client sent a frame. When the client direction ends without the client having sent a Close frame, the session tears the upstream down. A ws Channel's `Next` ignores ctx cancellation, so this teardown is the only way to stop the upstream read from parking the session while the upstream is idle. A client-initiated closing handshake is left alone so the server's Close reply still reaches the client (RFC 6455 §7.1.1). RFC 8441 WebSocket over HTTP/2 (`runWSOverH2Relay`) was already eager.

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

   *HTTP/1.x start line (USK-1148).* The HTTP/1.x Layer snapshots the request line (`method`, `path`, `raw_query`) and status line (`status`, `status_reason`) it emitted the Message with. On send, a field that still equals its snapshot is written from the wire bytes verbatim — an unchanged request-target is the original `RequestURI` byte-for-byte (a bare trailing `?`, absolute-form, `*`), even when only the method changed. A changed `path` / `raw_query` is written as `path[?raw_query]`, behind the original `scheme://authority` prefix when the target was absolute-form. A changed `status` / `status_reason` is written as `<status> <status_reason>` (a status-only change keeps the Message's reason; an empty reason emits none). The Layer and its WireEncoder share one function for this, so the recorded modified variant's Raw equals the bytes sent. `authority` and `scheme` are **not** written to the HTTP/1.x wire — the `Host` header carries the authority, so a plugin changes it through `msg["headers"]`; HTTP/2 writes `:authority` / `:scheme` from the Message, a deliberate per-protocol difference (§1.4). Plugin-written line values are **not validated**: CR / LF / SP / HTAB reach the wire verbatim. A plugin can already write arbitrary bytes through `msg["raw"]` (item 4), so structured-field validation is no privilege boundary, and crafting request splitting from a plugin is a supported diagnostic capability.

3. **Headers as ordered list of pairs with case-insensitive read accessor.** `msg["headers"]` is a list of `(name, value)` 2-tuples preserving wire case, order, and duplicates. Mutation operations are `append`, `replace_at(index, pair)`, `delete_first(name)`, etc. — operations that preserve order. A read-only convenience method `headers.get_first(name)` does case-insensitive lookup but does **not** alter the list. The Layer never re-canonicalizes; any plugin attempt to invoke a re-sort or dedup operation raises a Starlark error explicitly (`fail("ordered list operations only")`) rather than silently re-ordering. This satisfies the §1.4 wire-fidelity invariant under plugin mutation.

4. **Both Message and Raw editable; Raw wins if both touched.** A plugin may write `msg["raw"] = b"..."` to inject byte-level content directly. If the plugin modified `msg["raw"]` (compared to its snapshot), the Layer takes the wire-faithful path and writes the bytes verbatim, ignoring any Message-field mutations. This preserves smuggling-test capability (the original motivation for §1.4) under the plugin API. If only Message fields changed, the Layer regenerates Raw via WireEncoder. If neither changed, the original Raw passes through zero-copy.

   *Carrier and precedence (USK-1079).* The decision travels on the envelope as `Envelope.RawAuthoritative` (§3.1), not in Pipeline-scoped state: the Layer writes the wire after `Pipeline.Run` returns, so only a per-envelope field reaches it. Layers honour it through `Envelope.RawWins()` (marker set **and** `Raw` non-empty); a plugin's raw bytes are the complete wire message, so a disk-spilled `RawBuffer` is dropped when the marker is set. Precedence is **pipeline order, last writer wins**: a later Step that changes the Message hands the wire back to the Message path — a later plugin hook with a Message-only mutation, a Transform rule that fires (the marker is cleared), or an intercept modify (it replaces the envelope with `Raw=nil`, so `RawWins()` is false). A plugin whose bytes must survive Transform and intercept therefore registers `phase="post_pipeline"`. RecordStep skips the WireEncoder when `RawWins()` holds, so the recorded modified variant equals the bytes written. On HTTP/1.x a raw-authoritative request is never replayed on a stale-connection retry (the Message does not describe the bytes, and a replay could duplicate a smuggled request), and the upstream connection is retired after that exchange's final response — responses to any extra requests the bytes carried are not attributed to the next exchange. Paths with an h1 redial chain (CONNECT MITM over TLS, transparent TLS MITM, plaintext CONNECT inner, and the plain-HTTP forward proxy) open a fresh upstream connection for the next exchange over the same transport as the original — TLS for `https` stacks, plain TCP for `http` stacks; a transparent connection whose ClientHello had no ALPN extension is redialed with the same no-ALPN standard-TLS ClientHello as its first dial, every other TLS stack with an `[http/1.1]` offer under the configured uTLS profile; if that redial fails, the client connection is closed, since HTTP/1.x cannot skip a response. The HTTP/2 GOAWAY redial (`RedialUpstreamH2`: reactive, refused-stream retry and pre-warm) follows the same transport rule (USK-1383): cleartext h2c inside a plaintext CONNECT / SOCKS5 tunnel is redialed as cleartext h2c on plain TCP with no TLS handshake, every other stack over TLS offering only `h2`. TCP forward (`tcp_forwards`) owns a single upstream connection and no redial chain, so it closes the client connection after the raw-authoritative exchange's response; the client reconnects for further requests. Response framing (HEAD / CONNECT body rules, RFC 9112 §6.3) follows the Message's `method`, not the method in the raw bytes: a plugin whose bytes change the method must set `msg["method"]` to match. Per-Layer support: HTTP/1.x (request and response), raw TCP (`bytechunk`), and WebSocket honour the marker, as does the session-side SSE event writer (USK-1239; covers h1 chunked, h1 identity, and h2 DATA, plus the synthetic `event: error` notification — the plugin bytes are the bare event, transport framing is still added per path, and nothing is appended or validated); gRPC Data and gRPC-Web Data/End already write a non-empty `Raw` verbatim. SSE intercept modify keeps `Raw` (USK-892 wire-fidelity invariant), so it clears the marker explicitly when the operator sets at least one field; a release that sets no field keeps the plugin's raw-wins marker.

   *HTTP/2 family: header blocks are read-only (USK-1237).* On an h2 `HTTPMessage`, a gRPC Start / End, and a gRPC-Web Start, `msg["raw"]` is a **read-only diagnostic view**: the h2 `HTTPMessage` Raw is the concatenated HPACK header-block fragment(s), DATA payloads and trailer block, without frame headers and HPACK-encoded against the *source* connection's dynamic table; gRPC Start / End Raw is the HPACK fragment; a gRPC-Web Start's Raw is a header snapshot the Layer never writes (the HTTP head is rebuilt from the Message on both HTTP/1.x and HTTP/2 transports). None of these can be written verbatim — doing so on a pooled upstream connection would desync HPACK state, stream ids and flow control for every multiplexed stream. A plugin write to them is therefore **refused** in the Pipeline (`pluginDispatcher.applyMutation`, before RecordStep) with a Warn naming the plugin, hook and phase: a raw-only write is treated as **unchanged** (no modified variant; the original is what the wire carried), and a write of both `msg["raw"]` and Message fields is treated as **Message-only** (the Message edit is applied and the modified variant's Raw is the WireEncoder output — for h2 that is semantically equal to the live wire after frame + HPACK decoding, not byte-equal, the existing h2 convention). Either way record == wire. The decision is per route, not per `envelope.Protocol`: each owning Layer package exports a `RawWinsSupported(env)` predicate next to its `EncodeWireBytes` (`httpaggregator`, `grpc`, `grpcweb`), registered on the route-scoped `WireEncoderRegistry` via `RegisterRawWinsPolicy` — the h2 route (and resend / fuzz over `h2` / `h2c`) registers the `httpaggregator` predicate for `ProtocolHTTP`, the h1 route does not; both routes and the resend / fuzz gRPC registries register the gRPC / gRPC-Web predicates. `HTTPMessage.HTTPVersion` is informational and is not consulted. The gRPC-Web malformed-body passthrough Start (USK-1203), whose Raw is the forwarded body, stays honoured. DATA-payload envelopes keep honouring `msg["raw"]` — gRPC Data (the LPM-framed DATA payload; the Layer still owns DATA framing, stream ids and flow control), gRPC-Web Data / End, WebSocket over h2 (RFC 8441), SSE over h2. As a backstop, `httpaggregator.Send` and the gRPC Send log a Warn if a raw-authoritative header-block envelope still reaches them (a registry without the policy) and send the Message. The plugin API does not raise on such a write: `pluginv2` cannot tell an h1 from an h2 `HTTPMessage`, and an error would abort the whole hook. Frame-level h2 injection is deferred (§11).

   *WebSocket (USK-1238).* The unit `msg["raw"]` replaces is one wire frame; the plugin's bytes are written as-is (mask bit and key, RSV bits, length encoding — also in RFC 8441 h2 mode) and may be malformed, partial, or several frames. A WS Transform rule that fires clears the marker as on HTTP/1.x. There is no request/response attribution, so nothing is retired. With permessage-deflate context takeover the Layer parses the written bytes and decompresses the compressed messages they carry through its send-side state, so its LZ77 window advances exactly as the peer's inflater does and later re-encoded compressed frames still decode; if those bytes do not parse or decompress, a Warn is logged and later compressed frames may desync on the peer. `msg["anomalies"]` is read-only and carried across a Message rebuild, so a plugin that edits an over-cap (`WSDecompressedTooLarge`) message cannot turn the Layer's refusal of a modified truncated message (§3.2.2) into a truncated forward; `msg["raw"]` on such a message is honoured as usual.

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
- **`("http", "on_request")` DROP over HTTP/1.x ends the client connection** (USK-1229). The dropped request gets no response, and HTTP/1.1 cannot answer a later request on that connection without the client pairing it with the dropped one, so the client-facing Layer closes the connection (§3.3.2 keep-alive rule). Over HTTP/2 the DROP affects only the stream. The same applies to every other Pipeline Drop of an HTTP/1.x request that writes no response.
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
- [x] gRPC-Web `:path` overlay — **done 2026-10-20 (USK-1069 / USK-1110, landed with USK-1219)**. `applyRequestOverlay` projects the inner `HTTPMessage`'s `Path` / `RawQuery` (the per-transport path source: the HTTP/1.x request-target or the HTTP/2 `:path`, both already split by the inner Layer), and the Send side uses `grpcweb.pathForStart`, the same precedence rule as the gRPC Layer, with `parseServiceMethod` made strict to match `parseGRPCPath`. The query reaches the upstream, `Flow.URL`, and the gRPC Input SafetyFilter's `url` / `query` targets. Original deferral: `internal/layer/grpcweb/channel.go` builds its `GRPCStartMessage` without populating `Path` / `RawQuery`, so the USK-1053 Send-side rule (the observed `:path` wins when `parseGRPCPath` cannot represent it) has nothing to act on there and a malformed gRPC-Web `:path` is still normalized to `/Service/Method`. The gRPC-Web Layer sits over both HTTP/1.x and HTTP/2, so the fix needs a per-transport path source rather than a copy of the h2-only projection, and it collides with the in-flight USK-1057 work on the same file. **Re-open trigger:** USK-1057 merges (removing the collision), at which point USK-1069 applies the same overlay + precedence rule to `grpcweb`.
- [ ] Blank-scheme handling: asymmetric fail-safe `matchTargetRule`, and the SOCKS5 handshake-time check — **deferred 2026-09-15 (USK-1061, USK-1081)**. `TargetRule.Schemes` matching is symmetric today: a blank scheme matches no `schemes`-bearing rule, in the deny list and the allow list alike (§3.8). No *single* semantic can be fail-safe in both — deny wants "unknown matches everything", allow wants "unknown matches nothing" — so the only correct-in-both-directions design is a per-list asymmetric rule: treat a blank scheme as matching every deny rule's `schemes` condition and no allow rule's. That is a behaviour change to a live policy engine, and its blast radius is not the call sites USK-1061 and USK-1081 fixed (the MCP resend/fuzz helpers, `HostScopeStep`, and — since USK-1086 — `HTTPScopeStep` now pass a resolved scheme) but the remaining deliberate blank callers — `internal/connector/socks5.go` and `TargetScope.CheckURL(nil)` — where it would start blocking traffic that a `schemes`-bearing deny rule was never written to cover. SOCKS5 keeps its blank scheme because `REP=0x02` must precede any tunnel byte and the tunneled transport has not been observed at that moment; USK-1081 narrowed the post-handshake residue to the TLS passthrough relay (no `ConnectionStack` is ever built) and the bytechunk route; USK-1083 closed the bytechunk route (its envelopes now carry `TargetHost` and per-leg TLS, §3.5.1), leaving the passthrough relay as the one residue, recorded at the call site. **Re-open trigger:** a third genuinely-unknown-transport caller appears (making the blank case structural rather than the SOCKS5 special case it is today), or a SOCKS5-side inner-byte peek lands that makes the blank scheme avoidable there, at which point the asymmetric rule protects only `CheckURL(nil)` and the trade-off becomes cheap. The current symmetric semantic is pinned by `TestCheckTarget_BlankScheme_DoesNotMatchSchemeRule` (`internal/connector/scope_test.go`) so it cannot be changed silently. Cross-referenced from §3.5.1 and §3.8.
- [ ] Path-scoped rules at path-unknown checks: residual limitations — **accepted 2026-10-20 (USK-1130)**, design in §3.8 "The same structure for `path_prefix`". (D1) A path-scoped **deny** never fires on a TLS passthrough relay or raw route to the same host: those routes never yield a path, and widening the deny to "unknown path matches" would refuse traffic the operator scoped to a path. It is not weakened — it never matched there before either. **Re-open trigger:** an operator expects a path deny to cover passthrough / raw traffic (documented in `help_security.md`: deny the host itself). (D2) ~~gRPC / gRPC-Web are refused on a path-pending connection because `HTTPScopeStep` does not path-check them~~ — **resolved by USK-1236 / USK-1376**: `HTTPScopeStep` judges each RPC's Start (authority, Host metadata, wire path) and `HostScopeStep.requestPathChecked` admits `grpc` / `grpc-web`; the `tcp_forwards` `grpc` arm is a provisional gate. (D3) A tunnel whose route is only discovered from its inner bytes (CONNECT / SOCKS5 plaintext bytechunk, unknown ALPN, `tcp_forwards` `auto` raw fallback) is admitted provisionally and refused at the raw relay seam before any byte is relayed in either direction (§3.8, review S-1); the upstream has already been dialled, though it receives no client byte and none of its bytes reach the client. **Re-open trigger:** a requirement that a path-scoped allow must never even contact the host over raw — that needs a pre-dial refusal in the inner-dispatch path.
- [ ] Two residual `:path` losses at the HTTP/2 Layer — **accepted 2026-09-15 (USK-1053)**, shared verbatim with `HTTPMessage` and therefore not gRPC-specific. (1) `:path: ""` is re-emitted as `/`, because `appendRequestPseudoHeaders` (`internal/layer/http2/channel.go`) substitutes `/` for an empty path. (2) A bare trailing `?` (`/x?`) is destroyed: `splitPath` (`internal/layer/http2/assembler.go`) yields `RawQuery=""`, and the rejoin only re-adds `?` when `RawQuery` is non-empty. Both are losses in the shared `Path`/`RawQuery` split, so fixing them means changing the H2 event representation for *all* HTTP traffic, not just gRPC; the wire-observed bytes remain intact in `Envelope.Raw` either way. **Re-open trigger:** a diagnostic scenario where re-emitting an empty or bare-`?` `:path` verbatim changes upstream behaviour (e.g. a WAF bypass reproduction that only fires on the exact byte form) — that would justify replacing the split pair with a single verbatim `:path` field plus derived accessors across the HTTP/2 Layer and `HTTPMessage` together.
- [ ] intercept / plugin `service` / `method` override on a flow whose observed `:path` is unparseable — **accepted as spec 2026-09-15 (USK-1075)**. `applyGRPCStartModify` (`internal/mcp/intercept_typed.go`) and the plugin `GRPCStartMessage` dict (`internal/pluginv2/convert.go`) both write `Service` / `Method` while carrying the USK-920 `Path` overlay verbatim, so on a flow whose `:path` `parseGRPCPath` cannot represent, the override is **deliberately inert**: `pathForStart` keeps the wire overlay, which is the only faithful representation of that path (MITM principle #1 — do not normalize what the wire did not normalize). This is a consequence of the USK-1053 precedence rule, not a regression — before USK-1053 the override "worked" only by silently re-normalizing the malformed path — and it is pinned by `TestPathForStart/unparseable_path_wins_even_against_a_populated_derived_view` (`internal/layer/grpc/channel_test.go`). The gap is bounded by what `service` / `method` cannot express: a `:path` without a leading `/` (`noslash`, `a/b/c`, or the empty path), a single-slash path other than `/` itself (`/admin`), and `//` — `buildGRPCPath` still renders `/a/b/c`, `//pkg/Do` and `/x/` through those fields. **Rejected alternative:** clearing `Path` whenever `service` / `method` are set explicitly would silently re-normalize a malformed path the agent never mentioned — re-introducing the exact surprise USK-1053 removed — and would overload `service` / `method` with hidden path semantics. **Re-open trigger:** an analyst needs to *emit* one of the unrepresentable shapes above from intercept or a plugin; at that point adding `path` / `raw_query` to `grpcStartMessageModify` is the correct shape, because it makes the wire field directly addressable rather than inferred.
- [ ] HTTP/2 upstream pre-warm cap — **accepted 2026-10-17 (USK-1179); early close deferred (USK-1191)**. The pre-warm worker no longer replaces a head it dialed itself that never carried a locally initiated stream (`http2.Layer.InitiatedStreams`, a client-side signal — not the attacker-controlled GOAWAY `last_stream_id`); the wake is counted as `h2_upstream.prewarm_suppressed` and the reactive path redials when a request needs the upstream. chain[0], reactive-minted heads, and pre-warmed heads that served a stream are pre-warmed past as before, so an idle CONNECT / `tcp_forward` connection against an upstream that GOAWAYs every connection holds at most two upstream connections, and each client request adds at most four (normally three: the reactive dial, a refused-stream retry, and one pre-warm off a head that carried the stream; a fourth arises only in a narrow race where a reactive head's GOAWAY lands between its publish and `OpenStream`, so the stream is refused and the worker still pre-warms off that unused head because reactive heads are exempt from suppression). Backoff was rejected (still unbounded, adds a timer). Replaced connections are still held until the client connection ends. **Re-open trigger (USK-1191):** a workload where held, GOAWAY-drained upstream connections exhaust fds or upstream connection limits within one long-lived client connection — closing a drained step once its streams finish is the follow-up.
- [ ] HTTP/2 frame-level `msg["raw"]` injection — **deferred 2026-10-20 (USK-1237)**. A plugin `msg["raw"]` on an h2 `HTTPMessage`, a gRPC Start / End or a gRPC-Web Start is refused with a Warn (§9.3 D4 "HTTP/2 family"), because the observed Raw is unframed HPACK against the source connection's table and upstream h2 connections are pooled across clients (`internal/connector/h2_pool.go`); there is no frame-level raw write path in `internal/layer/http2`. Injecting malformed per-stream h2 frames would need the Layer to own frame headers, re-run HPACK against the destination table, and isolate the connection from other clients. **Re-open trigger:** a concrete diagnostic scenario that needs malformed per-stream h2 frames through the MITM and cannot be done otherwise (e.g. with `resend_raw` over a fresh connection), together with a non-pooled upstream mode.

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

# RFC-001: Envelope + Layered Connection Model (日本語版)

**Status:** Accepted
**Authors:** usk6666, Claude
**Created:** 2026-04-12
**Accepted:** 2026-04-12
**Supersedes:** `docs/architecture-rewrite.md` (M36–M44)
**Companion docs:**
- `docs/rfc/envelope.md` — 英語原文 (これが正)
- `docs/rfc/envelope-implementation.md` — 実装戦略、ファイルコピー表、疑似コード friction 一覧、設計根拠の相互参照

> **Note:** この文書は `docs/rfc/envelope.md` (英語) の日本語訳です。原文との齟齬が生じた場合、英語版が正とします。

## TL;DR

HTTP に偏った単一の `Exchange` 構造体と、平坦な `Codec` 抽象を廃止し、以下に置き換える:

1. **`Envelope` + 型付き `Message` interface** — identity / raw bytes / 型付き payload を持つ最小限の protocol-agnostic な外枠。各プロトコルは自分の `Message` 実装を定義する (HTTPMessage, WSMessage, GRPCMessage, RawMessage, SSEMessage, TLSHandshakeMessage)
2. **`Layer` + `Channel` stack** — 接続を明示的な layer の積み重ねとして表現する (TCP → TLS → HTTP/1 または HTTP/2 → WebSocket/gRPC/SSE)。各 layer は 1 つ以上の `Channel` を yield する。Pipeline は接続ではなく `Channel` 上で動く
3. **Pipeline は型によって protocol-agnostic なまま残る** — Step は「Envelope-only」(identity/raw/context のみ使用) か「Message-typed」(`env.Message` で type-switch) のどちらか。Intercept/Transform/Safety の rule engine はプロトコルごとに split する

これによりデータモデルから HTTP bias を取り除き、HTTP request smuggling 診断 (raw-over-TLS) を実現可能にし、HTTP/2 多重化と gRPC/WebSocket のラッピングを構造的に正直な形にし、既存の M36–M39 実装の **約 70% をそのまま流用** できる。

---

## 1. 動機

### 1.1 `Exchange` における HTTP bias

現在の `exchange.Exchange` 構造体 (`internal/exchange/exchange.go` 定義) には以下の L7 フィールドが含まれる:

```go
Method   string       // HTTP verb
URL      *url.URL     // HTTP target
Status   int          // HTTP status code
Headers  []KeyValue   // HTTP 形式のヘッダ KV
Trailers []KeyValue   // HTTP/gRPC trailers
Body     []byte       // 非構造化 byte 列
```

これらは HTTP にとっては自然だが、他のプロトコルにとっては概念的に誤りである:

| フィールド | WebSocket | gRPC message | TCP | SSE |
|-------|-----------|--------------|-----|-----|
| `Method` | 該当概念なし | `/service/method` は path であり verb ではない | なし | なし |
| `URL` | 初回 Upgrade 時のみ | `service+method` のほうが近い | なし | URL + event 名 |
| `Status` | close code (4xx/5xx ではない) | `grpc-status` (HTTP status と別物) | なし | なし |
| `Headers` | フレームレベルのヘッダなし (`Opcode` のみ) | trailers は HTTP/2 layer の責務で gRPC message のものではない | なし | event フィールド |
| `Body` | 型付き (text vs binary) | length-prefixed な単一 message | raw chunk | 構造化イベント |

HTTP 以外のすべてのプロトコルは、多くのフィールドを空のまま放置するか `Metadata map[string]any` にデータを押し込むかのどちらかになっている。これは **型システム上の嘘** である: `Exchange` 構造体は protocol-agnostic を謳いながら、実態は「optional フィールド付きの HTTP」でしかない。

### 1.2 Pipeline Step における HTTP bias

`internal/pipeline/` の Step 実装もこの bias を受け継いでいる:

- `ScopeStep.Process` は `ex.URL` でマッチ判定する → 非 HTTP プロトコルでは絶対にマッチしない
- `InterceptStep.MatchRequestRules(ex.Method, ex.URL, ex.Headers)` → HTTP シグネチャ
- `TransformStep` は `rules.Pipeline.TransformRequest(Method, URL, Headers, Body)` に委譲する → HTTP シグネチャ
- `SafetyStep` は header+body をチェックする → header のないプロトコルでは no-op

結果: **Pipeline は全プロトコルで「動いている」が、非 HTTP に対しては事実上何もしない**。L4-capable 原則は README に書かれているがコードには存在しない。

### 1.3 `Codec` における Layer の融合

現行の `Codec` interface は「1 接続 = 1 Codec = 1 プロトコル」を前提としている。これが以下で破綻する:

- **HTTP request smuggling 診断** — ユーザーは TLS 終端された接続に対して HTTP パーサを介さずに任意の bytes を書きたい。現在は HTTP/1.x Codec を強制せずに TLS 済みチャネルを取得する手段がない
- **HTTP/2 多重化** — 現行設計では「多重化は Codec 内部で吸収する」としている。1 つの Codec インスタンスが内部で N 本の並行 stream を管理しつつ、単一の `Next()/Send()` 表面を露出することを要求する、構造的なミスマッチ
- **WebSocket Upgrade** — 現行計画では「Codec が内部的に parser を切り替える」。下層の byte 列は同じだが、抽象化が遷移を隠し、buffered-reader の引き継ぎが暗黙になる
- **gRPC over HTTP/2** — gRPC は本質的に「1 本の HTTP/2 stream を wrap するもの」。HTTP/2 と兄弟の `Codec` として並べるのはカテゴリーエラー
- **TLS メタデータの観察** — SNI / ALPN / peer cert / fingerprint は TLS 層の概念だが、現在は `Connector` と `DialOpts` に埋もれていて first-class な surface がない

### 1.4 MITM 診断ツールが本当に必要としているもの

第一原理に戻って考えると、プロトコルに関係なく MITM 観察が本質的に共有すべきものは極めて少ない:

1. **Identity** — stream/flow/sequence/direction。メッセージを時系列で位置付けるため
2. **Wire fidelity** — 観測された raw bytes を正確に保持
3. **Provenance** — どのプロトコル層がこの message を生成したか
4. **Recording hook** — すべてを永続化する統一的な経路
5. **Mutation trace** — variant recording 用の before/after snapshot

**共有すべきものはこれだけ**。それ以外 (Method, URL, Status, Headers, Opcode, grpc-status, CloseCode, SSE イベントフィールド) はすべてプロトコル固有であり、プロトコル固有の型に属すべきである。

---

## 2. Non-Goals

この RFC では以下は **扱わない**:

1. **HTTP/2 flow-control × Pipeline latency** — Intercept step が AI 応答待ちで数分ブロックしている間、HTTP/2 の connection-level WINDOW が埋まる問題。Open Question #1 (§9.1) として追跡
2. **gRPC message granularity** — headers/messages/trailers が別々の Envelope になるか 1 RPC = 1 Envelope になるか。Open Question #2 (§9.2) として追跡
3. **Upstream HTTP/2 connection pooling** — coalesced-connection の扱い、idle timeout、max streams per connection。§9.1 決着後の別設計書に委ねる
4. **MCP tool API 再設計** — protocol ごとに `resend_*` tool が split されるのは自然な帰結として記載するが、tool surface の再設計は別 deliverable

これらはすべて重要だが、データモデルと layer 構造からは直交している。

---

## 3. 主要概念

### 3.1 Envelope

外側の container。protocol-agnostic。identity、raw bytes、provenance、cross-layer context、型付き Message を保持する。

```go
package envelope

type Envelope struct {
    // --- Identity (全プロトコル共有) ---
    StreamID  string     // 接続/RPC レベルのグループ化
    FlowID    string     // 個別 message の unique id
    Sequence  int        // stream 内の順序 (0-origin)
    Direction Direction  // Send (client→server) | Receive (server→client)

    // --- Provenance ---
    Protocol Protocol    // どの layer がこの envelope を生成したか

    // --- Wire fidelity (Pipeline にとって read-only のビュー; authoritative な bytes) ---
    Raw []byte

    // --- プロトコル固有の構造化ビュー ---
    Message Message      // interface; Protocol によって型付けされる

    // --- 任意の Step がアクセスできる接続スコープの context ---
    Context EnvelopeContext

    // --- layer 内部の状態; Pipeline は type-assert してはならない ---
    Opaque any
}

type EnvelopeContext struct {
    ConnID     string        // client TCP 接続ごとに一意
    ClientAddr net.Addr      // 元の client アドレス
    TargetHost string        // CONNECT 先または SOCKS5 target
    TLS        *TLSSnapshot  // TLS layer が stack にあれば non-nil
    ReceivedAt time.Time     // Next() 時の wall-clock
}

type TLSSnapshot struct {
    SNI               string
    ALPN              string
    PeerCertificate   *x509.Certificate
    ClientFingerprint string // client ClientHello の JA3 または JA4 ハッシュ
    Version           uint16
    CipherSuite       uint16
}
```

**設計ルール:** `Envelope` (`Message` ではなく) の任意のフィールドは、raw TCP を含む *すべての* プロトコルにとって意味を持たねばならない。HTTP 形状のフィールドは `Envelope` ではなく `HTTPMessage` に属する。

### 3.2 Message

プロトコル固有の payload 型。最小限の interface を実装することで、`Envelope.Clone()` と汎用 Step コードが統一的に動作する。

```go
type Message interface {
    // Protocol はプロトコル識別子を返す。Envelope.Protocol と一致する必要がある
    Protocol() Protocol

    // CloneMessage は variant snapshot 用の deep copy を返す
    CloneMessage() Message
}
```

#### 3.2.1 HTTPMessage

1 つの HTTP リクエストまたはレスポンスを表す。HTTP/1.x と HTTP/2 の両方の layer で使用する。

```go
type HTTPMessage struct {
    // Request 側フィールド (Envelope.Direction == Send のとき有効)
    Method    string
    Scheme    string   // "http" | "https"
    Authority string   // Host ヘッダまたは :authority
    Path      string
    RawQuery  string

    // Response 側フィールド (Envelope.Direction == Receive のとき有効)
    Status       int
    StatusReason string  // "OK", "Not Found" (HTTP/1.x wire fidelity 用)

    // 双方向
    Headers    []KeyValue  // 順序保持・ケース保持
    Trailers   []KeyValue
    Body       []byte
    BodyStream io.Reader   // passthrough モード時 non-nil (Body == nil)
}
```

**注:** HTTP/2 と HTTP/1.x がこの型を共有する。wire 固有の表現との変換は下位の layer の責務。`HTTPMessage` は両者にとって *自然な* 形。

#### 3.2.2 WSMessage

1 つの WebSocket フレームを表す。message 単位ではなくフレーム単位 — 制御フレーム (Ping/Pong/Close) はそれぞれ独自の Envelope として surface される。

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

    // Close フレームのみ
    CloseCode   uint16
    CloseReason string

    // Per-message-deflate (RFC 7692)
    Compressed bool
}
```

#### 3.2.3 gRPC Messages

gRPC RPC は単一の Channel 上で **3 つの event 型のストリーム**として surface する。各 event 型は独自の Message 実装を持つ。メタデータと trailers も専用型を持ち、HTTPMessage は gRPC には **流用しない**。決定と根拠は §9.2 を参照。

```go
// GRPCStartMessage は gRPC metadata (HEADERS フレーム) を持つ。request 側・response
// 側それぞれの開始時に 1 回ずつ発火する。
type GRPCStartMessage struct {
    // request 側では :path から導出; response 側では mirror
    Service string
    Method  string

    // gRPC metadata — custom + reserved。HTTP/2 pseudo-header (:method,
    // :path, :status, ...) は含まない (transport 層の所管、Envelope.Context 経由で
    // 必要なら観察できる)
    Metadata []KeyValue

    // 便宜のための parsed metadata。wire コピーは Metadata にも残る (wire fidelity)
    Timeout        time.Duration // grpc-timeout parsed (0 = 未設定)
    ContentType    string        // application/grpc[+proto|+json|...]
    Encoding       string        // grpc-encoding (identity, gzip, deflate, ...)
    AcceptEncoding []string      // grpc-accept-encoding
}

// GRPCDataMessage は 1 つの length-prefixed gRPC message (LPM) を持つ。LPM 境界は
// HTTP/2 DATA フレーム境界とは独立に reassembly される。
type GRPCDataMessage struct {
    // 関連する GRPCStartMessage からの denormalization (read-only)
    Service string
    Method  string

    // wire-level フィールド (5-byte LPM prefix 由来)
    Compressed bool   // 5-byte prefix の 1 byte 目
    WireLength uint32 // 5-byte prefix の uint32 length

    // Compressed flag の値に関わらず、常に decompressed bytes (観察容易性のため)。
    // Send 時、Layer が Compressed + 交渉済み grpc-encoding に従って再圧縮する。
    // 意図的に malformed な圧縮 bytes を inject したい場合は Envelope.Raw を直書きする。
    Payload []byte
}

// GRPCEndMessage は gRPC RPC を終了させる trailer HEADERS フレーム (END_STREAM 付き)
// を持つ。常に Direction=Receive。
type GRPCEndMessage struct {
    Status        uint32   // grpc-status parsed (codes.OK, codes.Canceled, ...)
    Message       string   // grpc-message parsed (percent-decoded)
    StatusDetails []byte   // grpc-status-details-bin (raw protobuf Status)
    Trailers      []KeyValue // 上記 3 つを除く残りの trailer metadata
}
```

**gRPC envelope の Envelope.Raw** は当該 event の wire bytes を持つ:
- `GRPCStartMessage`: HEADERS フレームの HPACK エンコード済み block (HTTP/2 フレームラッパーは含まない)
- `GRPCDataMessage`: 5-byte LPM prefix + compressed payload の wire そのまま
- `GRPCEndMessage`: trailer HEADERS フレームの HPACK エンコード済み block

HTTP/2 frame レベルの bytes (frame header, SETTINGS, WINDOW_UPDATE 等) は HTTP/2 Layer の所管であり gRPC envelope には露出しない。観察したい場合は HTTP/2 Layer の event stream を直接 attach する (§3.3.2 参照)。

#### 3.2.4 RawMessage

TCP、raw モード TLS passthrough、および任意の byte chunk チャネル用。

```go
type RawMessage struct {
    Bytes []byte  // 1 回の Read() (または Write()) で受信した bytes そのまま
}
```

#### 3.2.5 SSEMessage

Server-Sent Events (RFC 8895)。

```go
type SSEMessage struct {
    Event string
    Data  string
    ID    string
    Retry time.Duration
}
```

#### 3.2.6 TLSHandshakeMessage

TLS 接続ごとに handshake 完了直後に **1 回だけ** 発火する。Pipeline Step が TLS メタデータを first-class イベントとして観察できるようにする (fingerprint ベースの scope ルールなど用)。

```go
type TLSHandshakeMessage struct {
    Side              TLSSide  // Client | Server
    SNI               string
    ALPN              string
    NegotiatedVersion uint16
    NegotiatedCipher  uint16
    PeerCertificate   *x509.Certificate
    ClientHelloRaw    []byte   // JA3/JA4 計算用
    Fingerprint       string
}
```

### 3.3 Layer と Channel

**Layer** は接続レベルのコンポーネントで、下位の layer を消費し、1 つ以上の **Channel** を上方向に生成する。**Channel** は Pipeline の入出力 surface — 1 つの Channel が 1 回の `session.RunSession` 呼び出しを駆動する。

```go
package layer

// Layer は下位 layer を消費し、上方向に Channel を yield する
// Byte-stream layer (TCP, TLS) はより簡単な interface を実装する; §3.3.1 参照
type Layer interface {
    // Channels は Channel が利用可能になるたびに yield する
    // 単一チャネル layer (HTTP/1.x, WS, gRPC wrapper) では 1 つだけ yield
    // して受信側を close する。多チャネル layer (HTTP/2) では stream ごと
    // に 1 つずつ yield する
    Channels() <-chan Channel

    // Close は layer をティアダウンする。layer が所有していない限り
    // 下位 layer を close しない。所有権は構築時に確立する
    Close() error
}

// Channel は Pipeline が動作する単位
type Channel interface {
    // StreamID はこのチャネルの生存期間中の stable な識別子を返す
    StreamID() string

    // Next はチャネルから次の Envelope を読む。通常終了では io.EOF、
    // 異常終了ではその他のエラーを返す
    Next(ctx context.Context) (*envelope.Envelope, error)

    // Send は Envelope をチャネルを通じて書き戻す
    Send(ctx context.Context, env *envelope.Envelope) error

    // Close はこのチャネルだけを close する。下位 layer のライフサイクル
    // とは別
    Close() error
}
```

#### 3.3.1 Byte-Stream Layer (TCP, TLS)

TCP と TLS は Pipeline に直接参加しない。これらは `net.Conn` を別の `net.Conn` に変換する:

```go
package tcp  // パッケージレベル — Layer 型は不要
// TCP は no-op: 呼び出し側が net.Conn を直接、それを消費する layer に渡す

package tlslayer
// Server は plain に対してサーバー側 TLS handshake を実行する
// *tls.Conn (または uTLS) でもある net.Conn を返す
func Server(ctx context.Context, plain net.Conn, cfg *tls.Config) (net.Conn, *TLSSnapshot, error)

// Client は upstream に向けてクライアント側 TLS handshake を実行する
func Client(ctx context.Context, plain net.Conn, opts ClientOpts) (net.Conn, *TLSSnapshot, error)
```

Byte-stream layer を Pipeline に対して *観察* または *公開* するには、`ByteChunkLayer` で wrap する:

```go
package bytechunk

// New は conn を単一チャネルの Layer で wrap し、Read() ごとに RawMessage
// envelope を yield する。raw TCP passthrough と TLS-terminate-only 診断
// モード (HTTP request smuggling) で使用する
func New(conn net.Conn, streamID string) layer.Layer
```

これは本質的に今日の `internal/codec/tcp/` を Layer として再パッケージしたもの。

#### 3.3.2 Message-Stream Layer

HTTP/1.x、HTTP/2、WebSocket、gRPC、SSE はすべて `Layer` を実装する。それぞれが自分の入力を受け取る:

```go
package http1layer
// New は net.Conn を HTTP/1.x layer で wrap する。keep-alive 順で
// request-response pair ごとに HTTPMessage envelope を生成する
// 単一の Channel をちょうど 1 つ yield する
func New(conn net.Conn, role Role) layer.Layer

// DetachStream は Upgrade レスポンス後に HTTP/1 layer をティアダウンし、
// buffered reader、writer、underlying closer を返す。これにより次の
// layer (WebSocket) を同じ wire 上に構築できる
// 呼び出し側がこれらのリソースの所有権を取得し、Layer は使用不可になる
func (l *Layer) DetachStream() (io.Reader, io.Writer, io.Closer, error)
```

```go
package http2layer
// New は net.Conn を HTTP/2 layer で wrap する。HTTP/2 stream ごとに
// Channel を 1 本 yield する。返される Layer は HPACK 状態、接続レベル
// フロー制御、SETTINGS ネゴシエーション、stream ライフサイクルを管理する
//
// 各 stream の Channel は EVENT-GRANULAR: Next() は H2HeadersEvent、
// H2DataEvent (各 DATA フレーム、または BodyBuffer drain chunk ごと)、
// H2TrailersEvent を yield する。HTTPMessage に集約したい Pipeline 消費者は
// HTTPAggregatorLayer で wrap する必要がある (下記)。gRPC 消費者は GRPCLayer
// で wrap する。根拠は §9.1 再起草版 resolution を参照。
//
// フロー制御: Layer は DATA bytes を stream ごとの BodyBuffer に append し、
// append 時点で WINDOW_UPDATE を送信する (Pipeline が event を消費したか否か
// には依存しない)。per-stream の soft cap で stream-level stall + ディスク
// spill、hard cap で RST_STREAM。接続レベル WINDOW は Pipeline レイテンシから
// decouple される。
func New(conn net.Conn, role Role) layer.Layer
```

```go
package httpaggregator
// Wrap は event-granular な HTTP/2 (または HTTP/1.x event-granular) stream
// Channel を消費し、request/response ごとに 1 つの HTTPMessage envelope を
// 生成する。plain HTTP/2 トラフィックを event stream ではなく request-response
// ペアとして扱いたい場合 (完全メッセージに対する intercept/transform) に使う。
//
// 集約は N6.5 BodyBuffer を流用する: 小さな body は HTTPMessage.Body、大きな body
// は HTTPMessage.BodyBuffer に格納され、materialize セマンティクスは HTTP/1.x と同一。
//
// gRPC stream (content-type: application/grpc) では呼び出し側が代わりに
// GRPCLayer.Wrap を使う必要がある。HTTPAggregatorLayer では streaming を表現できない。
func Wrap(stream layer.Channel, role Role) layer.Channel
```

```go
package wslayer
// New は upgrade 済みの双方向 byte stream を WebSocket layer で wrap する
// reader は HTTP/1 layer detach 時の upgrade 前にバッファされた bytes を
// 保持する bufio.Reader である可能性がある
func New(reader io.Reader, writer io.Writer, closer io.Closer, role Role) layer.Layer
```

```go
package grpclayer
// Wrap は event-granular な HTTP/2 stream Channel を受け取り、その event を
// gRPC envelope として surface する。マッピングは:
//   H2HeadersEvent  → GRPCStartMessage envelope
//   H2DataEvent*    → GRPCDataMessage envelope (LPM ごとに 1 つ。LPM 再組立は
//                     wrapper 内部で行い、DATA フレーム境界とは独立)
//   H2TrailersEvent → GRPCEndMessage envelope
//
// 呼び出し側は Wrap 呼び出し前に、content-type 検出のために最初の H2HeadersEvent
// を peek しておく必要がある。peek した event は Wrap によって消費され、wrap 済
// Channel の最初の envelope として再発出される。
func Wrap(stream layer.Channel, firstHeaders *envelope.Envelope, role Role) layer.Channel
```

### 3.4 ConnectionStack

layer stack を表す接続ごとのランタイムオブジェクト。接続が生きている間は Connector が保持し、`RunSession` の期間は Session が所有する。

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

// Push は新しい top layer を追加し、それを現在の topmost にする
func (s *ConnectionStack) PushClient(l layer.Layer)
func (s *ConnectionStack) PushUpstream(l layer.Layer)

// Replace は topmost layer をアトミックに入れ替える (Upgrade 遷移で使用)
func (s *ConnectionStack) ReplaceClientTop(l layer.Layer) (old layer.Layer)
func (s *ConnectionStack) ReplaceUpstreamTop(l layer.Layer) (old layer.Layer)
```

stack は mutable — WebSocket Upgrade は `ReplaceClientTop(wsLayer)` として表現する。Session は各イテレーションの開始時に現在の topmost channel を観察する; 置き換えが発生したとき、既存の goroutine はティアダウンし、新しい channel 上で再開する必要がある (§4.3 参照)。

### 3.5 Pipeline Step の分類

Pipeline interface は変更なし:

```go
package pipeline

type Step interface {
    Process(ctx context.Context, env *envelope.Envelope) Result
}

type Pipeline struct { steps []Step }
func (p *Pipeline) Run(ctx, *Envelope) (*Envelope, Action, *Envelope)  // 変更なし
```

変わるのは、Step が明示的に 2 種類に *分類* されること。

#### 3.5.1 Envelope-Only Step (protocol-agnostic)

これらの Step は `Envelope` と `Envelope.Context` のフィールドのみにアクセスする。`env.Message` に対して type-assert しない。すべてのプロトコルで同一に動作する。

例:
- **RecordStep** — envelope を永続化する (Raw + Message を opaque blob としてシリアライズ + identity)
- **RateLimitStep** — `Context.ConnID` または `Context.TargetHost` ごとに envelope をカウント
- **HostScopeStep** — `Context.TargetHost` を scope ポリシーに対して検証。HTTP 固有のパスベース scope とは分離

#### 3.5.2 Message-Typed Step (protocol-aware)

これらの Step は `env.Message` で type-switch し、プロトコル固有エンジンに dispatch する。

```go
type InterceptStep struct {
    http  *httprules.InterceptEngine
    ws    *wsrules.InterceptEngine
    grpc  *grpcrules.InterceptEngine
    raw   *rawrules.InterceptEngine  // byte パターンマッチ
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
        return Result{} // 未知の Message: そのまま通過
    }
}
```

各ブランチは独自のマッチ DSL、独自の intercept UI surface、独自の編集操作を持つ独自のルールエンジンを持つ。これは **重複ではない** — 「HTTP リクエストを intercept する」ことと「WebSocket フレームを intercept する」ことが本質的に異なる操作であることを認めるものである。

共有できる関心事 (ブロッキングキュー調整、タイムアウト処理、ルールコンパイル用ユーティリティ) は helper パッケージに切り出し、プロトコル別エンジンから呼び出す。

### 3.6 Rule Engine の分割

現在の `internal/safety/`、`internal/proxy/intercept/`、`internal/proxy/rules/` (transform) は HTTP を中心に構造化されている。これらをプロトコルごとに分割する:

```
internal/rules/
  http/       HTTP 固有のマッチ DSL、編集操作、UI surface
  ws/         WebSocket フレームのマッチ + 編集
  grpc/       gRPC service/method/message のマッチ + 編集
  raw/        byte パターンマッチ (正規表現、バイナリパターン、オフセットベース)
  common/     共有: ルールコンパイルユーティリティ、ブロッキングキュー基本機能
```

各 `internal/rules/<proto>/` は `InterceptEngine`、`TransformEngine`、`SafetyEngine` を protocol-typed に公開する。Pipeline Step (例: `InterceptStep`) はプロトコルごとに 1 つのエンジンを保持し、dispatch する。

---

## 4. 典型シナリオ

このセクションでは、本 RFC のもとで 4 つの典型シナリオがどう end-to-end で動くかを示す。これらはこの設計の動機となったシナリオであり、すべてが自然に表現できなければならない。

### 4.1 HTTPS MITM, 通常の HTTP/1.1

```
Client TCP conn
  → tlslayer.Server(cfg) が *tls.Conn を yield
    → http1layer.New(tlsConn, ServerRole)
      → HTTPMessage envelope を生成する単一 Channel

Upstream:
  DialUpstream(target) が *tls.Conn を返す
    → http1layer.New(upstreamTLS, ClientRole)
      → HTTPMessage envelope を消費する単一 Channel

Session.RunSession(clientChan, dialFunc, pipeline)
  HTTPMessage envelope を Pipeline 経由で反復処理
```

型名を除けば現行モデルから変更なし。これがベースライン。

### 4.2 HTTP Request Smuggling 診断

```
Client TCP conn
  → tlslayer.Server(cfg) が *tls.Conn を yield
    → bytechunk.New(tlsConn)
      → RawMessage envelope を生成する単一 Channel

Upstream:
  DialUpstreamRaw(target) が *tls.Conn を返す (Codec は attach しない)
    → bytechunk.New(upstreamTLS)
      → RawMessage envelope を消費する単一 Channel

Pipeline:
  - RecordStep が Raw bytes + RawMessage を記録
  - HostScopeStep が Context.TargetHost を検証
  - Intercept/Transform/Safety はなし — これらは HTTP に対するもので raw bytes には無効
```

**設定メカニズム:** ホストごとの passthrough モードは設定で指定する。Connector は client stack を構築する *前に* CONNECT target を passthrough リストと照合する。passthrough リストに含まれるホストは `bytechunk` を top layer に持ち、その他はネゴシエートされた ALPN に応じて `http1` または `http2` を持つ。

意図的に不正な bytes (重複 Content-Length / Transfer-Encoding、難読化された chunk サイズ) は解釈されずにそのまま流れる。上流のパーサはクライアントの正確な bytes を見る。front-end と back-end のパーサ差は観測可能になる。

### 4.3 WebSocket Upgrade

```
初期 stack:
  Client:   [TCP → TLS → HTTP/1.x]
  Upstream: [TCP → TLS → HTTP/1.x]

HTTPMessage (request) が Upgrade: websocket ヘッダ付きで到着
Pipeline が転送; HTTPMessage (response) が Status: 101 で到着

Session が upgrade 成功を検出して以下を実行:
  1. http1Client.DetachStream() を呼ぶ → (bufReader, writer, closer)
  2. http1Upstream.DetachStream() を呼ぶ → (bufReader, writer, closer)
  3. detach した stream を使って各側で wslayer.New(...) を構築
  4. Stack.ReplaceClientTop(wsClient)
     Stack.ReplaceUpstreamTop(wsUpstream)
  5. 現在の RunSession をキャンセル、両 goroutine の終了を待つ
  6. 新しい topmost channel 上で新しい RunSession を開始
```

HTTP/1.x layer が保持していた bufio.Reader はそのまま WebSocket layer に渡されるので、HTTP/1.x layer が 101 レスポンスの `\r\n\r\n` を超えて読んだ bytes は WS フレームパーサで利用可能になる。

ステップ 5 (cancel-and-restart) は醜い部分。代替案として `RunSession` をループ観測可能にすることも考えられるが、cancel-and-restart のほうが単純で正しい。perf が問題になったら再検討。

### 4.4 HTTP/2 多重化 + gRPC 検出

```
初期 stack:
  Client:   [TCP → TLS(ALPN=h2) → HTTP/2]  (event-granular)
  Upstream: [TCP → TLS(ALPN=h2) → HTTP/2]  (event-granular、プール)

HTTP/2 layer の Channels() は新しい stream ごとに 1 つの event-granular Channel を yield:
  for clientStreamChan := range clientH2.Channels():
    go handleStream(clientStreamChan)

handleStream(clientStreamChan):
  // raw H2 Channel で最初の event (H2HeadersEvent) を peek
  firstHeaders := clientStreamChan.Next(ctx)

  upstreamStreamChan := upstreamH2.OpenStream(ctx)

  if isGRPC(firstHeaders):
    // 両側を GRPCLayer で wrap: GRPCStart + GRPCData* + GRPCEnd
    clientGRPC   := grpclayer.Wrap(clientStreamChan, firstHeaders, ServerRole)
    upstreamGRPC := grpclayer.Wrap(upstreamStreamChan, firstHeaders, ClientRole)
    Session.RunSession(clientGRPC, staticDial(upstreamGRPC), pipeline)
  else:
    // plain HTTP/2: HTTPAggregatorLayer で request/response ごとに 1 つの
    // HTTPMessage にまとめる (HTTP/1.x と同じユーザ可視挙動)
    clientHTTP   := httpaggregator.Wrap(clientStreamChan, ServerRole, firstHeaders)
    upstreamHTTP := httpaggregator.Wrap(upstreamStreamChan, ClientRole, nil)
    Session.RunSession(clientHTTP, staticDial(upstreamHTTP), pipeline)
```

HTTP/2 layer は内部的に以下を処理する:
- HPACK エンコーダ/デコーダ状態 (接続ごと)
- SETTINGS と WINDOW_UPDATE フレーム
- stream ごと + 接続ごとのフロー制御
- stream をまたぐ write 直列化 (単一の write goroutine + キュー)

上流 `http2.Layer.OpenStream()` は Session/Job が既存の上流接続上に新しい outbound stream を要求するための API。接続プールのキーは `(target_host, tls_config_hash)`; プール管理はこの RFC のスコープ外 (§2)。

---

## 5. Variant Snapshot (変更なし)

Pipeline.Run はエントリ時に `env.Clone()` を取得して context に格納する。RecordStep が snapshot を読んで Envelope のフィールド *および* Message のフィールド (`CloneMessage` 経由) を比較して変更を検出する。すべての Message 実装が `CloneMessage` を提供するので snapshot 機構は統一的に動作する。

```go
// internal/pipeline/snapshot.go (更新)
func withSnapshot(ctx context.Context, env *envelope.Envelope) context.Context {
    snap := &envelope.Envelope{
        StreamID: env.StreamID, FlowID: env.FlowID, Sequence: env.Sequence,
        Direction: env.Direction, Protocol: env.Protocol,
        Raw:     cloneBytes(env.Raw),
        Message: env.Message.CloneMessage(),
        Context: env.Context,
        // Opaque はクローンしない — Layer の責務
    }
    return context.WithValue(ctx, snapshotKey, snap)
}
```

---

## 6. 現行コードからの移行

現在のファイル/パッケージを RFC-001 構造にマッピング:

| 現状 | RFC-001 移行先 | 流用率 |
|---------|----------------|---------|
| `internal/exchange/exchange.go` (Exchange struct) | `internal/envelope/envelope.go` (フィールドを削減した Envelope struct) + `internal/envelope/message.go` (Message interface + HTTPMessage/WSMessage/...) | 60% |
| `internal/pipeline/pipeline.go` (Pipeline.Run, snapshot) | `internal/pipeline/pipeline.go` (変更なし) | 95% |
| `internal/pipeline/scope_step.go`, `intercept_step.go`, `transform_step.go`, `safety_step.go` | `env.Message` で type-switch してプロトコル別エンジンに dispatch する形に書き直し | 40% |
| `internal/pipeline/record_step.go`, `ratelimit_step.go` | Envelope-Only Step に昇格; マイナー調整 | 80% |
| `internal/codec/http1/parser/` | `internal/layer/http1/parser/` に移動、byte レベルのパーサロジックは変更なし | 100% |
| `internal/codec/http1/codec.go` | `internal/layer/http1/layer.go` (Layer interface) + `channel.go` (Channel interface) として書き直し。raw-first patching と `opaqueHTTP1` diff ロジックは新しい Channel の `Send` パスに移動 | 50% |
| `internal/codec/tcp/tcp.go` | `internal/layer/bytechunk/layer.go` として書き直し | 90% |
| `internal/codec/codec.go` (Codec interface) | **削除。** `internal/layer/layer.go` (Layer + Channel interface) に置き換え | 0% |
| `internal/layer/http2/` (N6/N6.5/N6.6 で in-layer aggregation として実装済み) | **分割**: `internal/layer/http2/` (event-granular Channel: H2HeadersEvent/H2DataEvent/H2TrailersEvent、BodyBuffer 駆動フロー制御) + `internal/layer/httpaggregator/` (plain HTTP/2 向けに HTTPMessage を生成する wrapper)。aggregation アルゴリズムと BodyBuffer integration は **そのまま流用**、API 境界のみ移動。N6.7 aftermath として追跡 | 85% |
| `internal/rules/grpc/` (新規) | gRPC-typed engine: GRPCStartMessage / GRPCDataMessage / GRPCEndMessage 上で動作する InterceptEngine/TransformEngine/SafetyEngine。LPM reassembly は Layer で、engine は論理 event を見る | 0% (新規) |
| `internal/connector/dial.go` (DialUpstream) | ほぼ変更なし; raw モード用に `DialUpstreamRaw` を追加し、stack 構築 helper を公開。TLS/uTLS/mTLS handshake コードは保持 | 90% |
| `internal/connector/listener.go`, `detect.go`, `tunnel.go`, `socks5.go` (USK-561 経由) | 構造的にはほぼ変更なし; 単一 Codec を選ぶ代わりに `ConnectionStack` を構築するよう更新 | 70% |
| `internal/session/session.go` | Codec → Channel に名前変更; `Stack.ReplaceClientTop` 駆動の session 再起動サポートを追加 | 70% |
| `internal/job/job.go` | `ExchangeSource` → `EnvelopeSource` に名前変更。L7 resend のソースは `HTTPMessage` envelope を構築; L4 resend のソースは `RawMessage` envelope を構築して `DialUpstreamRaw` を呼ぶ | 60% |
| `internal/safety/`, `internal/proxy/intercept/`, `internal/proxy/rules/` | `internal/rules/http/`, `internal/rules/ws/`, `internal/rules/grpc/`, `internal/rules/raw/` に分割。既存のルールコンパイルコードはほぼ流用 | 55% |
| `internal/flow/` (Store) | Message interface のシリアライズを追加; それ以外は変更なし | 85% |
| `internal/mcp/` (resend_tool.go など) | `resend` アクションを `resend_http`、`resend_ws`、`resend_grpc`、`resend_raw` に分割。各々が protocol-typed な schema を取る | 30% |
| `internal/plugin/` (Starlark hook) | hook シグネチャを `HTTPMessage`/`WSMessage`/等に更新。既存の hook インフラは保持 | 60% |

**加重流用率見積: 約 70%。** 削除部分 (Codec interface、HTTP 偏重の Step シグネチャ、統一ルールエンジン) はまさにこの RFC で議論した設計摩擦の原因そのもの。

---

## 7. 提案マイルストーン

M36–M44 を置き換える。現在の M36–M44 Linear issue はすべて **Cancelled** に移し、新しいマイルストーン下で再作成する。

```
N1: Foundation Types
    Envelope, Message interface, HTTPMessage, RawMessage
    Layer と Channel interface
    ConnectionStack 型
    Pipeline.Run snapshot を Message.CloneMessage 用に更新
    成果物: interface がコンパイルできること; ランタイムはまだなし

N2: TCP + TLS + ByteChunk + raw smuggling E2E
    tlslayer パッケージ (uTLS/mTLS 込みで server/client handshake を保持)
    bytechunk layer
    最小 Connector: listener, CONNECT negotiator, ConnectionStack builder
    Pipeline: RecordStep + HostScopeStep のみ
    成果物: raw-passthrough モードで「curl → yorishiro → target」が動作
           request-smuggling payload が wire 上で観測可能

N3: HTTP/1.x Layer + 通常の HTTPS MITM E2E
    http1 layer (既存の parser パッケージを再利用)
    HTTP-typed Pipeline Step: InterceptStep, TransformStep, SafetyStep,
                              http ルールエンジンに dispatch する ScopeStep
    internal/rules/http/ (HTTP 用 intercept/transform/safety)
    成果物: 通常の HTTPS MITM が L7 intercept/transform 込みで end-to-end 動作

N4: Connector 完成
    プロトコル検出 (peek + ALPN)
    SOCKS5 negotiator (ホストごとのモード選択が適用される)
    ConnectionStack は設定から宣言的に構築 (ホストごとのポリシー)
    成果物: Connector 機能完成、現行 proxy と機能同等

N5: Job + Macro 統合
    EnvelopeSource interface
    L7 resend: HTTPMessage source + http1 Channel upstream
    L4 resend: RawMessage source + DialUpstreamRaw + bytechunk upstream
    Job.Run 周りの Macro hook 呼び出し
    成果物: resend_http、resend_raw が両方動作; smuggling payload fuzz が動作

N6: HTTP/2 Layer  [DONE: N6 / N6.5 / N6.6]
    http2 layer (フレームコーデック、HPACK、stream ごとの channel)
    上流接続プール (基本: target ごと、LRU eviction)
    成果物: HTTPS + h2 通常通信が動作

N6.7: HTTP/2 Layer 分割 (aftermath)  [N7 の prerequisite]
    現 HTTP/2 Layer (in-layer aggregation) を分割:
      - internal/layer/http2/ — event-granular Channel (H2HeadersEvent /
        H2DataEvent / H2TrailersEvent); BodyBuffer 駆動フロー制御
      - internal/layer/httpaggregator/ — HTTPMessage を生成する wrapper
    BodyBuffer と集約アルゴリズムはそのまま流用; API のみ移動
    根拠: §9.1 再起草 resolution (2026-04-23) + §9.2 resolution
    成果物: plain HTTP/2 通信は end-to-end で変化なし; event-granular Channel が
           GRPCLayer (N7) から利用可能

N7: Application Layer
    grpclayer: event-granular な HTTP/2 Channel を消費し、
               GRPCStartMessage / GRPCDataMessage / GRPCEndMessage envelope を発火
    wslayer (HTTP/1 Upgrade から; HTTP/2 CONNECT+:protocol すなわち
             RFC 8441 は延期)
    ssehlayer (HTTP/1 レスポンスから)
    internal/rules/{ws,grpc}/ 配下の対応するルールエンジン
    成果物: WS/gRPC/SSE フローが記録可能かつ intercept 可能

N8: MCP + WebUI 再接続
    resend アクション分割: resend_http, resend_ws, resend_grpc, resend_raw
    Query tool: Protocol (Message 型) でフィルタ
    WebUI: プロトコル別フロー詳細ビュー
    成果物: 新アーキ上に MCP tool surface が完成

N9: レガシー削除 + ドキュメント
    internal/protocol/, internal/codec/, internal/proxy/ を削除
    CLAUDE.md, README.md, docs/ を更新
    残った移行項目の最終処理
    成果物: 単一アーキテクチャ、ドキュメント一貫性
```

**マイルストーン依存:** N1 → N2 → N3 → (N4 || N5) → N6 → N6.7 → N7 → N8 → N9。N4 と N5 は N3 着地後に並行で進められる。N6.7 は §9.1/§9.2 resolution (2026-04-23) の aftermath であり、N7 を block する。

---

## 8. 既存作業 (M36–M39) との関係

**保持されるもの:**
- `internal/codec/http1/parser/` (byte レベル HTTP/1.x パーサ) — 100%
- `internal/connector/dial.go` の TLS/uTLS/mTLS/upstream-proxy/ALPN-cache ロジック — 90%
- `internal/pipeline/pipeline.go` の Run ループと snapshot 機構 — 95%
- `http1/codec.go` の raw-first patching アルゴリズム (http1 Layer の Channel.Send に移動)
- `internal/cert/` の CA + Issuer — 変更なし
- `internal/flow/` の Stream/Flow ストア — ほぼ変更なし (Message シリアライズを追加)
- safety/intercept/transform ルールの *コンパイル* ロジック — 分割されるが内部は保持
- `internal/macro/` エンジン — send 関数シグネチャを除き変更なし

**置き換えられるもの:**
- `Codec` interface → `Layer` + `Channel` interface
- `Exchange` 構造体 → `Envelope` 構造体 + `Message` interface
- 統一 Pipeline Step → プロトコル別エンジンに dispatch する型付き Step 実装
- 単一 Codec を返す `MakeDialFunc` → `ConnectionStack` を返す stack 構築 helper

**削除されるもの:**
- 「HTTP/2 Codec が多重化を吸収する」設計 — HTTP/2 Layer が自然に N 本の Channel を yield
- 「単一の統一ルールエンジン」前提 — プロトコルが独自のエンジンを持つ
- すべての接続が 1 つの Pipeline session を生成するという暗黙の前提 — WebSocket Upgrade は stack を置き換え、HTTP/2 は N 個の session を生成

---

## 9. Open Questions

### 9.1 HTTP/2 フロー制御 × 長時間ブロックする Pipeline Step — RESOLVED

**解決:** 2026-04-15
**再起草:** 2026-04-23 (2026-04-15 の in-layer aggregation モデルを置換。動機は OQ#2 resolution を参照)

**問題:** HTTP/2 には stream ごとと接続ごとのフロー制御 (WINDOW_UPDATE フレーム) がある。Pipeline Step が数分ブロックする (例: AI エージェントのアクション待ちの `InterceptStep`) と、その stream の WINDOW が埋まり、下流側が stall する。同じ接続上の *多数の* 並行 stream が同時にブロックすると、接続レベル WINDOW が埋まり、HTTP/2 接続全体が stall して無関係な stream にも影響する。

**Resolution: event-granular な HTTP/2 Layer + per-stream bounded buffer。集約は上位 wrapper Layer。**

初版 resolution (2026-04-15) は HTTP/2 Layer の内部で集約を行い、`Channel.Next()` は stream ごとに完全な `HTTPMessage` を返す設計だった。OQ#2 (gRPC 粒度) の検討で、このモデルは streaming gRPC と両立しない (長時間 bidi stream は「完了」しないため集約対象が無い) ことが明らかになった。根本的な設計ミスは、Pipeline のレイテンシを transport 層に伝搬させていた点。以下の再起草はこの結合を decouple することで是正する。

**決定:**

1. **HTTP/2 Layer は常に event-granular**。Channel は 3 種類の event を yield する: `H2HeadersEvent` (HEADERS フレーム由来)、`H2DataEvent` (DATA フレーム、もしくは BodyBuffer drain chunk 由来)、`H2TrailersEvent` (END_STREAM 付き trailer HEADERS 由来)。
2. **per-stream buffer がフロー制御を駆動する**。各 stream は `BodyBuffer` (N6.5 の memory-then-spill primitive を流用) を所有。DATA フレームは到着次第 buffer に append され、WINDOW_UPDATE は **append 時点で** 送信される (Pipeline 消費時点ではない)。接続レベル WINDOW は Pipeline レイテンシから完全に decouple され、どれだけ長い Pipeline hold でも他 stream に影響を及ぼさない。
3. **back-pressure は stream-scoped であり、connection-scoped ではない**。Pipeline が stream を hold している間に buffer が per-stream soft cap を超えたら、Layer は *その stream の* WINDOW 補充を停止し (stream-level stall)、次にディスクへ spill し、hard cap を超えたら RST_STREAM する。他 stream には影響しない。
4. **集約は HTTP/2 Layer の性質ではなく wrapper Layer の責務**。plain HTTP/2 トラフィック向けに `HTTPAggregatorLayer` が H2 event を消費し、request/response ごとに 1 つの `HTTPMessage` を生成する (N6.5 のユーザ可視挙動を保持、HTTP/1.x と parity)。gRPC 向けには `GRPCLayer` が同じ event を消費し `GRPCStartMessage` / `GRPCDataMessage` / `GRPCEndMessage` を生成する (集約しない)。

**なぜこれでフロー制御が解決するか:**

- transport 層の ACK が application 層の処理速度から独立。WINDOW_UPDATE は frame reader goroutine が socket から frame を取り出した直後 (マイクロ秒単位で) per-stream buffer に到達した時点で発射される。Pipeline が個別 stream をブロックしても接続への back-pressure は発生しない。
- 接続あたりの最悪メモリは `perStreamSoftCap × MAX_CONCURRENT_STREAMS`。soft cap に達した stream はディスク spill する。soft cap は調整可能。ディスク spill パスは N6.5 で実証済み。
- plain HTTP ユーザは HTTPAggregatorLayer 経由で「1 exchange あたり 1 HTTPMessage」の同じ ergonomics を維持する。streaming プロトコル (gRPC、将来の SSE) のユーザは event を到着順に見る。

**却下した代替案:**
- **In-layer aggregation (2026-04-15 resolution):** streaming gRPC をサポート不能。bidi stream で body inspection が passthrough モード化する。
- **Frame-per-envelope streaming without buffering (2026-04-15 以前の原案):** Pipeline hold が接続レベル WINDOW を詰まらせる。本再起草では buffer drain を Pipeline drain から decouple することで修正。
- **Pipeline-driven back-pressure:** 接続レベル stall 問題が同じ。
- **Async Intercept:** MCP tool surface が依存する「intercept は forwarding をブロックする」契約を壊す。

**移行メモ:** N6 / N6.5 / N6.6 で構築した HTTP/2 Layer は in-layer aggregation 実装。これを `HTTP2Layer` (event-granular) + `HTTPAggregatorLayer` (wrapper) に分割する作業は N6 系列 aftermath Issue として N6.7 で追跡。集約アルゴリズムと BodyBuffer integration はそのまま流用し、API 境界のみ移動する。

### 9.2 gRPC Message Envelope の粒度 — RESOLVED

**解決:** 2026-04-23

**問題:** gRPC RPC は event stream である: (request HEADERS) + (request DATA*) + (response HEADERS) + (response DATA*) + (trailers HEADERS)。unary ですら概念的には「start + 1 message + end」。これらをどう Pipeline に surface するか?

**Resolution: event-per-envelope + 専用 gRPC Message 型。**

論理的に異なる各 gRPC event はそれぞれ自身の Message 型を持つ Envelope となる。暫定案と異なり HTTPMessage は headers / trailers に **流用しない** — gRPC 固有のセマンティクス (grpc-status, grpc-timeout, grpc-encoding) は HTTPMessage の型契約 ("HTTPMessage の全フィールドは HTTP として有意でなければならない") に収まらない。新しい Message 型の対応は:

| wire event | Envelope.Message 型 | 発火条件 |
|------------|---------------------|----------|
| Request HEADERS | `GRPCStartMessage` | Direction=Send, Sequence=0 |
| 各 length-prefixed request message | `GRPCDataMessage` | Direction=Send, LPM ごとに 1 つ |
| Response HEADERS | `GRPCStartMessage` | Direction=Receive, Sequence=0 |
| 各 length-prefixed response message | `GRPCDataMessage` | Direction=Receive, LPM ごとに 1 つ |
| Trailer HEADERS (END_STREAM 付き) | `GRPCEndMessage` | Direction=Receive, 末尾 |

5 種類の event は同じ `Envelope.StreamID` (HTTP/2 stream ID) を共有し、`Sequence` が stream 内の順序を示す。「完全な RPC」単位で動作したい Pipeline Step は StreamID で envelope を束ねて集約する。

**粒度は length-prefixed gRPC message (LPM) であって HTTP/2 DATA フレームではない。** 1 つの gRPC message が複数の DATA フレームにまたがる場合も、1 つの DATA フレームが複数の gRPC message を含む場合もある。gRPC Layer は H2 Layer が surface する raw byte stream (`H2DataEvent`) から LPM 境界を reassembly する。`GRPCDataMessage` envelope の `Envelope.Raw` は 5-byte prefix + payload の wire bytes そのまま (圧縮が有効なら compressed)。

**圧縮の扱い:**
- `GRPCDataMessage.Compressed` は wire の flag (5-byte prefix の 1 byte 目) を保持。
- `GRPCDataMessage.Payload` は **常に decompressed** bytes (観察容易性のため)。
- `GRPCDataMessage.WireLength` は wire レベル長 (compressed bytes 長)。
- `Envelope.Raw` は wire そのまま (5-byte prefix + compressed payload)。
- Send 時: `Compressed=true` なら gRPC Layer が交渉済み `grpc-encoding` で `Payload` を再圧縮して書き込む。意図的に malformed な compressed bytes を送り込みたい場合は `Envelope.Raw` を直書きする low-level bypass を使う (raw TCP layer と同じパターン)。

**なぜこれで決着したか:**

- wire の実態と一致 (wire は event stream、型システムもそう)。
- gRPC streaming が first-class: bidi stream は event が到着順に発火し、Pipeline は任意の 1 message を stream 完了を待たずに intercept/transform できる。
- `HTTPMessage` の型契約違反を作らない: 各 Message 型の全フィールドがその event にとって有意。
- Pipeline フロー制御懸念は §9.1 再起草 resolution に委譲 (transport buffer が Pipeline から decouple)。
- MCP `resend_grpc` tool が自然にマップする: 「この stream の event 列を再生、任意で event ごとに edit」。

**却下した代替案:**
- **暫定案 (HTTPMessage を headers / trailers に流用):** Method/URL/Status/Body 空の HTTPMessage を生み、§3.1 design rule (全フィールドが型にとって有意であること) に違反。
- **Aggregated-per-message (メタデータを最初の message に bundle):** headers 観察が最初の LPM 完了まで遅延し、server-streaming で不整合 (headers は message 到着より遥かに早く観察可能なことが多い)。
- **Aggregated-per-RPC:** unary 専用、streaming で不可能。

**付随決定事項:**
- `GRPCDataMessage` 上の Service/Method は関連する `GRPCStartMessage` からの **read-only 非正規化**。service/method を変更したい場合は Start envelope を intercept する。
- grpc-web は本 resolution のスコープ外。独自 layer (`GRPCWebLayer`) が HTTP/1 または HTTP/2 aggregated `HTTPMessage` を wrap する (base64 または binary framing)。`envelope-implementation.md` の Friction 4-C を参照。
- HTTP/2 CONNECT + `:protocol` 拡張 CONNECT (RFC 8441) による WebSocket-over-H2 は N7 milestone の scope 外のまま据え置き。

### 9.3 Starlark Plugin API Shape

**問題:** 現在の `internal/plugin/` は `request.method`、`request.url` などを Starlark 値として公開する。typed Message に変わると、plugin は protocol-shape なオブジェクトを見なければならない。

**提案:** Plugin hook は Protocol フィルタ付きで登録される。例: `register_hook("http", "on_request", ...)`。ハンドラは HTTPMessage、WSMessage などに合った Starlark dict を受け取る。プロトコルが一致しない hook は一切発火しない。

**N8 着手前に決定必須。**

---

## 10. 検討した代替案

### 10.1 Exchange を維持して、すべてを Metadata map[string]any に入れる

**却下理由:** 型安全でない、すべての Step と plugin が map に対して string キーアクセスをする必要がある、IDE 補完が失われる、HTTP bias を型レベルで符号化する (フィールドが技術的には存在しなくても)。

### 10.2 固定フィールドのsum型 (`HTTP *HTTPMessage; WS *WSMessage; ...`)

```go
type Envelope struct {
    // identity + raw...
    HTTP *HTTPMessage
    WS   *WSMessage
    GRPC *GRPCMessage
    Raw  *RawMessage
}
```

**検討したが `Message` interface 方式を優先して却下** した理由:
- 新しいプロトコルを追加するたびに `Envelope` 構造体を触る必要がある
- Pipeline Step は結局 `if env.HTTP != nil {}` のチェーンを書くことになり、それは type-switch と等価だが Go では idiomatic でない
- interface メソッドとしての `CloneMessage()` は、各フィールドを個別にクローンするよりクリーン

interface アプローチのほうが Go idiomatic で拡張可能。トレードオフ (interface メソッド呼び出しオーバーヘッド) はこのワークロードでは無視できる。

### 10.3 プロトコルごとの Pipeline (共有 Pipeline 型なし)

```go
type HTTPPipeline struct { steps []HTTPStep }
type WSPipeline struct { steps []WSStep }
// ... プロトコルごとに 1 つ
```

**却下理由:**
- 共有 Step (Record、RateLimit、HostScope) をプロトコルごとにインスタンス化する必要がある
- Pipeline.Without() のロジックを重複実装する必要がある
- Snapshot 機構の重複
- 「汎用 pipeline + 型付き dispatch」アプローチは、30% の複雑さで 95% の型安全性を提供する

### 10.4 Pipeline を Hook システムで置き換える

Step チェーンの代わりに、well-defined なライフサイクル hook (`on_http_request`、`on_ws_frame`、`on_tcp_chunk`、…) を公開して subscriber に登録させる。

**却下理由:**
- 順序管理が分散する (すべての hook に priority が必要)
- variant-snapshot の配置が曖昧 (hook ごとに 1 回? 全体で 1 回?)
- macro 用の `Pipeline.Without()` が難しい
- Pipeline の線形性は MITM 処理の実際の流れと一致する (Scope → Safety → Intercept → Transform → Record)

Pipeline という concept は健全; 問題は `Exchange` であり `Pipeline` ではない。

### 10.5 Envelope を極限まで縮小 (identity + raw のみ)

```go
type Envelope struct {
    StreamID, FlowID string
    Sequence int
    Direction Direction
    Protocol Protocol
    Raw []byte
    // Message なし
}
```

そうすると各プロトコルは完全に独立した Channel 型を持ち、それぞれが独自の message オブジェクトを公開する。

**却下理由:**
- Pipeline Step interface が generic か protocol ごとに重複する必要がある
- 共有 Step (Record) は reporting 用にも Message フィールドを観察できない
- よくあるケース (1 つの Envelope 型が 1 つの Pipeline を通る) が、実際には必要ない極端論のために犠牲になる

現在の提案 (Envelope + Message interface) は、*有用な* 共有型の最小形である。

---

## 11. 承認記録と延期項目

この RFC は 2026-04-12 をもって **accepted** となった。実装は N1 から進める。

**承認時点で完了:**
- [x] 日本語翻訳が存在する (`envelope-ja.md`)
- [x] 実装戦略が文書化されている (`envelope-implementation.md`)
- [x] N1–N9 マイルストーンを Linear で作成済み
- [x] M36–M44 マイルストーンと未完了 issue をキャンセル済み

**実装フェーズに延期 (マイルストーン別のゲート):**
- [x] Open Question #1 (HTTP/2 フロー制御 vs Pipeline レイテンシ) — **解決済 2026-04-15; 再起草 2026-04-23: event-granular HTTP/2 Layer + HTTPAggregatorLayer wrapper (§9.1)**
- [x] Open Question #2 (gRPC envelope 粒度) — **解決済 2026-04-23: event-per-envelope + GRPCStart/Data/End 専用型 (§9.2)**
- [ ] Open Question #3 (Starlark plugin API shape) — **N8 着手前に解決**
- [ ] Envelope + Message Go interface がコンパイル・検証できている — **N1 の成果物**
- [ ] InterceptStep の疑似コードレベル実装で dispatch パターンが証明されている — **N3 の成果物**
- [ ] 移行の再利用 % が実ファイルサイズで検証されている — **各 N マイルストーンの振り返りで検証**

---

## Appendix A: 命名の決定

- `Envelope` over `Message` — 外側の container は typed message を包む envelope。payload 型は `Message` と呼び内部 interface とする
- `Layer` over `Stage` — ネットワーク文献の用語と一致させる
- `Channel` over `Stream` or `Codec` — "Codec" は取り除きたい融合を引きずる; "Stream" は既存の `flow.Stream` 用語と衝突
- `ConnectionStack` over `LayerStack` — 接続ごとのライフタイムを強調
- `HTTPMessage` over `HTTPExchange` — "Exchange" は旧モデルの残滓

## Appendix B: 用語集

| 用語 | 意味 |
|------|---------|
| Envelope | identity、raw bytes、typed Message を持つ protocol-agnostic な外側の container |
| Message | プロトコル固有の構造化 payload (interface + 実装) |
| Layer | Channel を yield する接続レベルのコンポーネント |
| Channel | Pipeline の入出力単位; 1 つの Channel が 1 回の RunSession を駆動する |
| ConnectionStack | クライアント接続ごとの mutable な layer stack、Connector が所有 |
| Byte-stream layer | TCP、TLS — `net.Conn` を `net.Conn` に変換する |
| Message-stream layer | HTTP/1、HTTP/2、WS、gRPC、SSE — Channel を生成する |
| Envelope-only Step | `Envelope` フィールドのみを使う Pipeline Step (protocol-agnostic) |
| Message-typed Step | `env.Message` で type-switch する Pipeline Step |
| Variant snapshot | Pipeline.Run エントリ時に取る Envelope のクローン、変更検出に使用 |

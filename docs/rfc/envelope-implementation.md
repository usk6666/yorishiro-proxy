# RFC-001 Implementation Guide

**Status:** Active · Companion to `envelope.md`
**Created:** 2026-04-12
**Language:** Japanese (working doc)
**Scope:** RFC-001 本文に入れ切れなかった実装戦略、設計決定の根拠、疑似コード検証で発見した friction 一覧、次セッションへの引き継ぎ事項

> **Purpose:** この文書は「RFC-001 が accepted になった直後 (2026-04-12) のセッションで得られた全知見」を未来のセッションが漏れなく引き継げるように保存するためのもの。RFC 本文 (`envelope.md`) は「仕様」、この文書は「仕様に至った理由・実装時の進め方・既知の罠」を受け持つ。

## 目次

1. [実装戦略: Scrap-and-Build with File-Level Copy](#1-実装戦略)
2. [ファイル別 コピー vs スクラッチ判定](#2-ファイル別-コピー-vs-スクラッチ判定)
3. [具体的進行手順 (Step 0–7)](#3-具体的進行手順)
4. [Vertical Slice 哲学: N2 が最重要チェックポイント](#4-vertical-slice-哲学)
5. [やってはいけないこと (Don't Do List)](#5-やってはいけないこと)
6. [リスクと対処](#6-リスクと対処)
7. [疑似コード検証で発見した Friction 一覧](#7-疑似コード検証で発見した-friction-一覧)
8. [設計決定の根拠 (RFC 本文に入り切らなかったもの)](#8-設計決定の根拠)
9. [HTTP Bias 議論の原点と MITM プロキシの本質](#9-http-bias-議論の原点と-mitm-プロキシの本質)
10. [現状コードベースで確認済みの事実](#10-現状コードベースで確認済みの事実)
11. [次セッションへの引き継ぎチェックリスト](#11-次セッションへの引き継ぎチェックリスト)

---

## 1. 実装戦略

### 決定: Scrap-and-Build (ただしファイル単位で「コピー」対象を厳選)

**短答:** ゼロから書き直す。ただし「新しいツリーをスクラッチで書き、実績のあるパッケージは *ファイル単位でそのままコピー*」という形。

**このアプローチを選んだ理由:**

以下 4 つの条件がすべて揃っているので、incremental migration より scrap-and-build のほうが素直に速い。

1. **抽象の軸が変わっている** — Codec → Layer+Channel、Exchange → Envelope+Message は rename ではなく concept の組み直し。incremental にやると「古い Codec を Layer に寄せる」中間状態のコードが発生して、それ自体にバグが宿る
2. **テストもどうせ書き直し** — 既存の Codec/Exchange/Pipeline Step の unit test はそれぞれの型に密結合している。incremental でも書き直す必要がある。E2E テストを acceptance criteria にしたほうが最終的に速い
3. **ユーザが明言: 互換性不要** — incremental のご利益 (途中でも main がビルドできる/動く) が要らない。branch 上で好きに壊せる
4. **単独開発** — 他の開発者のブランチとコンフリクトする心配がない

**Joel Spolsky の「ゼロから書き直すな」原則との関係:**

Spolsky の警告は「既存コードに蓄積された無数のエッジケース fix が失われる」こと。これが当てはまるのは `parser`、`crypto`、`macro`、`flow/store` などの **しっかりテストされた純粋機能パッケージ**。逆に `codec`、`pipeline step`、`session` のように **抽象が間違っている** コードはエッジケース fix が多いほどかえって引きずる。

**この 2 つを両立させる解:** エッジケースの宝庫はコピー、抽象が間違ってる部分はスクラッチ、と **ファイル単位で判断** する。

---

## 2. ファイル別 コピー vs スクラッチ判定

### コピー対象 (中身を見ない、package 名と import だけ直す)

| コピー元 | コピー先 | 理由 |
|---------|---------|------|
| `internal/codec/http1/parser/*` (types.go, parser.go, chunked.go, fuzz_test.go, parser_test.go, types_test.go, doc.go) | `internal/layer/http1/parser/*` | HTTP/1.x パーサ。fuzz test 付き、エッジケース多数。M32 で書かれた high-quality code |
| `internal/cert/*` | 同名 | CA + 動的 cert 発行。セキュリティ上 replace したくない |
| `internal/macro/*` (engine.go, template.go, guard.go, extract.go, encoder.go, types.go と対応する test) | 同名 | template/guard/extract/encoder。独立した engine。SendFunc シグネチャだけ変更 |
| `internal/flow/*` (Store 実装) | 同名 | sqlite schema と index logic は独立。Message serialization 部だけ差分追加 |
| `internal/plugin/` の Starlark engine 本体 | 同名 (ただし hook 登録 API 部は除外) | Starlark sandbox は難しくて再実装したくない |
| `internal/safety/preset*.go` (pattern list: destructive-sql, destructive-os-command, credit-card, japan-my-number, email, japan-phone) | `internal/rules/common/preset*.go` | pattern 自体は使える。wiring は書き直すが list は流用 |
| `internal/connector/dial.go` の TLS handshake 本体 (standard / uTLS / mTLS / upstream proxy CRLF guard) | `internal/connector/dial.go` | セキュリティクリティカル、既にテスト済み。M39 で精密に作ったばかりで無傷 |
| `internal/connector/peekconn.go`, `ratelimit.go`, `upstream_proxy.go`, `scope.go`, `passthrough.go`, `context.go` | 同名 | 単機能ユーティリティ、置き換え不要 |
| `internal/codec/http1/parser/*` 用テストファイル | parser と一緒に移動 | parser の正しさを担保する |
| `cmd/yorishiro-proxy/client.go`, `client_params.go`, `client_format.go`, `serverjson.go` | 同名 | CLI client は MCP server とは疎結合。tool schema が変わる部分だけ手を入れる |

### スクラッチで書き直し (古い実装は *参照しない*)

| 対象 | 理由 |
|------|------|
| `internal/envelope/` 全体 | Exchange からの移行ではなく、RFC §3.1/3.2 を仕様書として見ながら新規に書く |
| `internal/layer/layer.go` (interface) | Layer と Channel という新 concept |
| `internal/layer/bytechunk/` | tcp codec を layer 形状に書き直し。`tcp.go` は参考にしない (interface 設計が違う) |
| `internal/layer/tlslayer/` | TLS handshake の関数群を Server/Client の関数として再編 |
| `internal/layer/http1/layer.go`, `channel.go` | parser は流用、しかし Codec → Layer の concept 変換がある |
| `internal/layer/http2/` 全体 | HTTP/2 の multiplexing を layer として再設計 (M40 以前の設計は放棄) |
| `internal/layer/httpaggregator/` (新規) | 2026-04-23 §9.1/§9.2 改訂の aftermath。event-granular H2 Channel 上で HTTPMessage を作る wrapper。N6.7 で N6/N6.5/N6.6 の aggregation ロジックをここに切り出す (アルゴリズム流用 85%) |
| `internal/layer/ws/`, `grpc/`, `grpcweb/`, `sse/` | application layer として再設計 |
| `internal/pipeline/*_step.go` 全部 | type-switch dispatch の書き方は現行と別物 |
| `internal/pipeline/pipeline.go`, `snapshot.go` | interface 自体はほぼ同じだが、Envelope 型になるのと Message.CloneMessage() を使うので書き直し (コピペではなく) |
| `internal/session/session.go` | layer stack 書き換え対応の新設計。2 goroutine から 1 goroutine への変更可能性もここで検討 |
| `internal/connector/listener.go`, `detect.go`, `tunnel.go`, `socks5.go` | ConnectionStack 構築に書き直し |
| `internal/connector/scope.go` (TargetScope) の wiring 部 | HostScope に名前と責務を再設計 |
| `internal/job/job.go` + EnvelopeSource 実装 | L7/L4 resend を正面から設計 |
| `internal/rules/http/`, `ws/`, `grpc/`, `raw/` の engine wiring | プロトコル別の組み立て方を新規決定 |
| `internal/mcp/resend_tool.go` 系 | tool schema をプロトコル別に split |
| `internal/mcp/server.go` の deps struct | 28 フィールドの巨大 deps を整理 |

### 最後に削除

feature parity 到達後、以下は `git rm -r`:

```
internal/exchange/
internal/codec/                   (http1 parser を除いて全削除)
internal/pipeline/ の旧 step      (pipeline.go, snapshot.go は新規書き直し)
internal/session/                 (旧)
internal/job/                     (旧)
internal/protocol/                (M44 で消える予定だったもの、予定通り)
internal/proxy/                   (同上)
internal/safety/engine.go         (preset 以外)
internal/proxy/intercept/, rules/ (rules/ に吸収済み)
```

### 流用率の見積 (加重)

`internal/pipeline/pipeline.go` (Pipeline.Run と snapshot 機構) と `internal/codec/http1/parser/` が最大の流用源。以下の通り:

| 対象 | 流用率 |
|------|--------|
| HTTP/1.x parser (byte-level) | 100% |
| cert / CA / issuer | 100% |
| TLS handshake (dial.go の handshake 部分) | 100% |
| connector utilities (peekconn, ratelimit, etc.) | 100% |
| Pipeline.Run snapshot アルゴリズム | 95% (型名変更のみ) |
| macro engine | 90% (SendFunc シグネチャのみ変更) |
| flow Store | 85% (Message シリアライズ追加のみ) |
| plugin Starlark engine (hook 登録部除く) | 80% |
| Safety/Intercept/Transform rule patterns | 55% (pattern 流用、wiring 再設計) |
| connector (listener/detect/tunnel/socks5) 構造 | 60% (handler 選択ロジックは再設計) |
| session.RunSession | 30% (2 goroutine は維持するが layer stack 書き換え対応) |
| Codec / Exchange / Pipeline Steps (旧) | 0% (完全再設計) |
| proxy/ と protocol/ (M44 で消える予定) | 0% |

**加重平均: ≈70%** (主要な proven packages が大きく残るので、物量ベースで見ると 70% が正しい感覚値)

---

## 3. 具体的進行手順

```
Step 0: branch 作成
  git checkout -b rewrite/rfc-001

Step 1: 新規ツリー骨格を作る (ファイルは空 or stub)
  internal/envelope/    (Envelope, Message interface と HTTPMessage, RawMessage 最小)
  internal/layer/       (Layer, Channel interface)
  internal/layer/bytechunk/
  internal/layer/tlslayer/
  internal/rules/common/

Step 2: コピー対象をまとめて移動
  git mv internal/codec/http1/parser internal/layer/http1/parser
  (他のコピー対象も同様。package 名は後でまとめて rename)
  コンパイルが壊れる → 一時的に OK

Step 3: N1 (Foundation Types) 相当を完成
  envelope/, layer interface, pipeline.go (snapshot 調整のみ) がコンパイル通る
  まだランタイムはない

Step 4: N2 (TCP+TLS+ByteChunk + smuggling E2E) を縦に通す
  これが最初の「動く」チェックポイント
  curl --proxy yorishiro https://target/ が raw passthrough モードで通ること
  既存の E2E test を 1 本だけ新 MCP 表面に合わせて通す
  ← ここで主要な設計の穴が炙り出される (必ず何か出る)

Step 5: N3 (HTTP/1 Layer + 通常 HTTPS MITM) を通す
  既存の L7 intercept/transform の E2E test を複数本通す

Step 6: N4 以降は並行可能

Step 7: feature parity 達成
  旧ツリー削除 (git rm -r)
  CLAUDE.md / README.md 更新
  PR を main に merge
```

**重要:** Step 3 → Step 4 の間の「動かない期間」を短く保つこと。Interface だけ書いて実行できない期間が長引くと、設計の欠陥が実装時まで隠れて後で痛手になる。N2 の vertical slice (raw smuggling の curl → yorishiro → target) を **最初のマイルストーン** にすれば、「Envelope と Layer が正しく噛み合うか」を早期に検証できる。

---

## 4. Vertical Slice 哲学

### N2 が最重要チェックポイント

N1 は interface 定義だけなのでコンパイルが通るだけで終わる。**本当の検証は N2** で起きる:

- Envelope と Message interface が実用に耐える shape か
- Layer と Channel interface が TCP / TLS / ByteChunk に素直にハマるか
- ConnectionStack が per-host モード選択を自然に表現できるか
- Pipeline が byte chunk Exchange を扱えるか (Intercept/Transform は no-op になるが、Record と HostScope が動くか)
- session.RunSession が Channel-based で動くか

N2 で問題が出たら、**RFC 本文に戻って修正** する。「accepted」は「永久不変」ではなく「実装に入る準備が整った」という意味。実装で見つかった不備は draft ステータスに戻して改訂する。

**N2 の成功基準:**

```
1. yorishiro-proxy を起動
2. 設定で target.example.com:443 を raw_passthrough にする
3. curl --proxy http://localhost:8080 https://target.example.com/ \
      --resolve target.example.com:443:127.0.0.1  (ローカルで test server)
4. レスポンスが返ってくる
5. query tool で raw bytes が記録されていることを確認
6. 記録内容がクライアントの送信バイトと完全一致すること
```

これが動けば、以降の N3-N9 は「同じパターンの適用」なので加速する。

### なぜ smuggling シナリオから始めるのか

通常の HTTPS MITM (N3) から始めるほうが「普通」に見えるが、**N2 の raw smuggling モードから始めたほうが設計検証として鋭い** 理由:

1. **smuggling モードは Envelope + Message の **最小構成** を使う**。RawMessage しか要らない。HTTPMessage を実装する前に Envelope 自体の健全性を確認できる
2. **smuggling モードは既存のアーキテクチャで *明確に実現できない* ケースだった**。新アーキで動くことを実証すれば、新アーキが旧アーキに対して真に優位であることの証拠になる
3. **smuggling モードは N3 以降のすべてのモードより *シンプル*** 。L7 パース・intercept・transform・plugin がない。最小サブセットで Layer モデルが成立することを示せる

ここが通れば N3 (HTTP/1 Layer 追加) は「layer を 1 枚積む」だけの増分作業になる。

---

## 5. やってはいけないこと

RFC を accepted にした以上、実装時の誘惑に抗うために明示化しておく:

1. **新コードを書いている最中に古い同名ファイルを開かない**
   - 古い実装の「工夫」を見てしまうと incremental 的思考に引きずられる。迷ったら RFC を読む
   - 例外: `parser`, `cert`, `macro` 等、コピー対象として確定したファイルのみ参照 OK

2. **`internal/protocol/` 以下を参考にしない**
   - ここは消える側のコードで、HTTP 偏重を含めて現在の問題の震源地
   - 新コードの参考には絶対にしない

3. **「念のため互換 shim を書く」をしない**
   - 互換性不要なフェーズ、と user が明言している
   - 互換 shim は scrap-and-build の意味を無効化する

4. **旧ツリーを「削除する日」を先延ばしにしない**
   - feature parity に達した瞬間に `git rm -r`
   - 並行存続期間が長いほど混乱が増える

5. **テストを「後で書く」にしない**
   - N2 の vertical slice 時点で E2E test を 1 本通すところまで含めて初めて「動く」
   - unit test は後回しでもいいが、E2E test は常に 1 本は通る状態を維持

6. **「Codec を Layer に rename するだけ」の変更をしない**
   - Layer は Codec の rename ではない。別 concept
   - ファイルの中身を読みながら「このメソッドを Layer の interface に合わせる」ことをしないこと
   - 新しく書く

7. **Open Question を「後で決める」のまま先に進まない**
   - Open Question #1 は N6 前に、#2 は N7 前に、#3 は N8 前に **必ず** 結論を出す
   - 結論なしで実装に入ると手戻りコストが極端に高い (特に #1: HTTP/2 flow control は後から変えると layer 構造まで影響する)

8. **Starlark plugin の hook シグネチャを「なんとなく残す」をしない**
   - **OQ#3 RESOLVED (2026-04-29)**: hook identity は `(protocol, event, phase)` の 3 軸。Pipeline 上に `PluginStepPre` / `PluginStepPost` の 2 段。詳細は RFC §9.3
   - 旧 8-hook (`on_receive_from_client` 等) は完全廃止。compat alias は禁止 (rule 5「shim 無し」と整合)
   - 中途半端な互換 hook を書くと削除コストが発生する

9. **WebUI を「後で対応」と言って temporarily broken にしない**
   - WebUI は dist/ が embed されている (`internal/mcp/webui/embed.go`)
   - dist/ がないとコンパイルエラーになる
   - N8 までは WebUI は古いバージョンを embed したままにしておく (ビルド可能状態を維持)

---

## 6. リスクと対処

| リスク | 対処 |
|-------|------|
| Scrap-and-build が当初見積より遅延する | branch 上で作業するので main は安全。遅延しても本体が壊れない。Stuck したら RFC に立ち返る |
| N2 の vertical slice で致命的な設計欠陥が見つかる | むしろそれが目的。N2 は **設計検証マイルストーン** と位置付ける。欠陥が見つかったら RFC を draft に戻して改訂 OK |
| コピーしたファイルの中に古い型依存が残る (例: parser が Exchange 参照) | 事前に grep で "exchange" / "codec" / "proxy" への参照を洗い出しておく |
| Starlark plugin hook インターフェース変更でユーザ script が全部壊れる | **解決 (2026-04-29, RFC §9.3 resolved)**: hard break + 1ページ migration table を N9 release notes に同梱。Hook identity は `(protocol, event, phase)` の 3 軸。`PluginStepPre` / `PluginStepPost` の 2 段構成で Pipeline 前後どちらでも fire 可能 (resend/fuzz は post のみ)。compat shim 無し |
| HTTP/2 flow control 問題 (§9.1) の解決が N6 に間に合わない | N6 の最初に「Flow Control 設計ミニセッション」を単独で実行。他の作業に着手する前にブロック |
| gRPC granularity (§9.2) の frame-per-envelope 暫定案が実装時に破綻 | 暫定案が破綻したら N7 を一時中断して §9.2 を再議論。破綻パターンを記録してからでないと代替案を選べない |
| flow/store の DB migration で既存の test データが失われる | yorishiro は開発中なので既存データは捨ててよい。ただし migration script は書かず drop-and-create で十分 |
| 並行マイルストーン (N4 || N5) のマージコンフリクト | N3 着地後に両者 branch を別に切り、base を共有。先に merge された方を他方が rebase する |
| 旧 proxy/ を参照しているテストが残って気づかず動き続ける | 旧ツリー削除直前に `grep -r "internal/protocol\\|internal/proxy"` でゼロ確認 |

---

## 7. 疑似コード検証で発見した Friction 一覧

2026-04-12 のセッションで 4 シナリオ (normal MITM / smuggling / WS upgrade / h2+gRPC) を疑似コードに落として設計検証した際に見つかった friction の完全リスト。RFC §9 に Open Question として上げたもの以外もここで追跡する。

### Friction 1-A: ScopeStep が ctx-level target host を参照する必要

**問題:** 現在の ScopeStep は `ex.URL` を見て判定するが、RawMessage Envelope には URL がない。smuggling モードでも target host は把握したい。

**解決:** `Envelope.Context.TargetHost` に CONNECT 先 or SOCKS5 target を入れる。HostScopeStep (renamed from ScopeStep) がこのフィールドを使う。Path ベースの scope (HTTP 専用) は別途 HTTPScopeStep として HTTPMessage 専用で作る。

**状態:** 解決済み (RFC §3.1 EnvelopeContext, §3.5.1 HostScopeStep に反映)

### Friction 1-B: Raw mode の chunk 境界が曖昧

**問題:** TCP read が返す chunk サイズは non-deterministic。smuggling payload を 1 個の論理単位として扱いたいが、TCP segmentation で分割される可能性がある。

**選択肢:**
- **書き込み側**: client の 1 回の write() = 1 Envelope にする (net.Conn.Write の呼び出し粒度を追える場合)
- **読み込み側**: N ms の idle でフラッシュする heuristic
- または: raw mode では「chunk-per-Envelope」で、Pipeline の側で統合したい場合は accumulator を書く

**解決 (暫定):** chunk-per-Envelope をデフォルトとし、記録・observation は chunk 単位で OK。Intercept はそもそも raw mode では rule engine が byte pattern match で対応する。統合が必要な場合は将来 accumulator を追加する。

**状態:** N2 実装時に決定する。暫定案で進めて問題が出たら再検討。

### Friction 2-A: Buffered Reader 残量の引き継ぎ (WS Upgrade)

**問題:** HTTP/1 layer が bufio.Reader を使って先読みしている場合、Upgrade 後の WS layer が先読み分を拾えないとデータが失われる。

**解決:** `http1layer.Layer.DetachStream()` が `(io.Reader, io.Writer, io.Closer)` の triple を返す。Reader は bufio.Reader 本体 (先読み分を含む)。WS layer の constructor がこれを受け取る。

**状態:** 解決済み (RFC §3.3.2, §4.3 に反映)

### Friction 2-B: 2 goroutine モデルを Upgrade でどう止めるか

**問題:** 現在の session.go は client→upstream と upstream→client の 2 goroutine。Upgrade 時は両方を同時に止めて、新しい layer 上で再起動する必要がある。

**選択肢:**
- **A: cancel-and-restart** — ctx を cancel、両 goroutine の終了を errgroup で待つ、stack を差し替えて新しい RunSession を再起動
- **B: loop-observable** — goroutine のループが「stack が差し替わっていないか」を毎イテレーションでチェック

**解決:** A (cancel-and-restart) を選ぶ。B は一見効率的に見えるが、atomic な stack 差し替えとメモリバリアが複雑化する。A は goroutine を 1 回捨てる代わりに logic が単純。perf が問題になったら再検討。

**状態:** 解決済み (RFC §4.3 に「cancel-and-restart」明記)

### Friction 2-C: Upgrade 判定順序のデッドロック懸念

**問題:** Upgrade のフローは「req を upstream に送る → 101 resp を client に返す → 両側を剥がして WS に移行」。この順序を間違えると、client が WS フレームを送り始めたのに yorishiro 側が HTTP/1 layer のまま読もうとしてデッドロックする。

**対処:** 実装時のテストで担保する。特に WS frame を「最初の 1 フレーム」だけ受けて upgrade 完了フラグを立てるテストを書く。

**状態:** N7 (wslayer 実装) 時の注意事項。この文書に明記しておく。

### Friction 3-A: HTTP/2 upstream connection pool

**問題:** HTTP/2 は 1 接続上で多数の stream を多重化する。client の 1 接続上で複数 host 宛の stream が来る可能性もある (coalesced connection)。upstream connection pool が必要。

**選択肢:**
- **単純版**: 1 client 接続 = 1 upstream 接続。同一 target への並行 stream は同じ upstream で多重化
- **coalesced 対応**: `(target_host, tls_config_hash)` ごとに pool を持つ。複数 client から同じ target への stream を集約
- **LRU eviction**: idle な upstream 接続を切断

**解決 (暫定):** 単純版から始める。coalesced 対応は後から追加可能。pool key は `(target_host, tls_config_hash)` を当初から設計する (後から変えにくい)。

**状態:** N6 の実装時に最終決定。RFC §2 で「non-goal」として正式にはカバー外だが、ここで前提を記録しておく。

### Friction 3-B: HTTP/2 write serialization

**問題:** 複数 stream Channel が同じ net.Conn に書こうとする。HPACK encoder は状態を持つので直列化が必要。

**解決:** write goroutine を 1 本立てて、frame queue を持たせる。stream Channel.Send() は frame を queue に put するだけ。HPACK encode は write goroutine 内で実行。

**状態:** 解決済み (RFC §4.4 に「single write goroutine + queue」明記)

### Friction 3-C: HTTP/2 flow control × Pipeline latency

**問題:** Intercept step が AI エージェントの応答を待つ間、stream 単位の WINDOW が埋まる。多数の stream で同時に起こると connection-level WINDOW が枯渇して HTTP/2 接続全体が止まる。

**選択肢 (RFC §9.1 に記載済み):**
1. Layer read loop から stream Pipeline を分離、stream ごとにバッファ + 自由 consume
2. Pipeline 駆動の back-pressure
3. Intercept を非同期化

**解決 (RFC 正式 resolution, 2026-04-23 再起草版):** event-granular HTTP/2 Layer + per-stream BodyBuffer + soft/hard cap。WINDOW_UPDATE は buffer append 時点で送信 (Pipeline 消費とは decouple)。plain HTTP 用の aggregation は `HTTPAggregatorLayer` に分離 (Friction 4-D 参照)。

**状態:** **RESOLVED** (RFC §9.1 正式 resolution, 2026-04-23 再起草)。実装は N6 / N6.5 / N6.6 で in-layer aggregation 版が完了しており、N6.7 で event-granular + HTTPAggregatorLayer へリファクタする。

### Friction 3-D: stream lifecycle error の区別

**問題:** HTTP/2 の RST_STREAM は「正常 cancellation」と「error」の両方で発生する。Pipeline Step (特に RecordStep) はこれらを区別したい。

**解決:** 新しい error type を導入する:
```go
type StreamError struct {
    Code ErrorCode  // Canceled | Aborted | InternalError | Refused | Protocol
    Reason string
}
```
HTTP/2 layer が RST_STREAM frame を受けたとき、ErrorCode を翻訳して Channel.Next() が StreamError を返す。

**状態:** N6 実装時の詳細。RFC には書かない (細かすぎる)。

### Friction 4-A: First Envelope peek before wrap

**問題:** HTTP/2 stream の最初の Envelope (HEADERS 由来の HTTPMessage) を **Pipeline の前に** 読んで content-type を見ないと、gRPC 用ラッパー layer を被せられない。

**解決:** `grpclayer.Wrap(stream, firstHTTP, role)` が first envelope を引数に取る。wrapper 内部で「まだ Next() されていない」扱いで queue しておき、1 回目の Next() 呼び出しで first を返す。

**状態:** 解決済み (RFC §3.3.2, §4.4 に反映)

### Friction 4-B: gRPC Envelope 粒度 [RESOLVED 2026-04-23]

**問題:** 1 gRPC RPC = HEADERS + DATA* + trailer-HEADERS。これをどう Envelope に割るか。

**解決 (RFC §9.2 正式 resolution):** **event-per-envelope + 専用 Message 型**。
- `GRPCStartMessage` (HEADERS; request-side / response-side 各 1)
- `GRPCDataMessage` (each length-prefixed gRPC message; LPM 単位で reassembly)
- `GRPCEndMessage` (trailer HEADERS; grpc-status / grpc-message / grpc-status-details-bin を parsed で持つ)

粒度は **LPM 単位** であって HTTP/2 DATA frame 単位ではない (frame 境界と LPM 境界は独立)。`Envelope.Raw` は wire そのままの bytes を持つ (compressed なら compressed のまま)。`GRPCDataMessage.Payload` は常に decompressed (UI/intercept での観察容易性)。

**HTTPMessage は流用しない**。理由: trailers を HTTPMessage に詰めると Method/URL/Status/Body 空の "type-system lie" が生まれ、§3.1 design rule に反する。

**関連決定 (Friction 4-D / 4-E として分離管理)**:
- §9.1 の "in-layer aggregation" 初版 resolution は、gRPC streaming と両立しないため 2026-04-23 に再起草。HTTP/2 Layer は event-granular になり、aggregation は `HTTPAggregatorLayer` wrapper に分離 (下記 Friction 4-D 参照)。
- N6/N6.5/N6.6 で実装した HTTP/2 Layer の aggregation ロジックは破棄せず、HTTPAggregatorLayer へそのまま移設する (N6.7 aftermath、85% 流用)。

**状態:** **RESOLVED**。N7 着手前の blocker は解除。実装詳細は N6.7 で Layer 切り分け完了後に N7 (gRPC 実装) に着手する。

### Friction 4-D: HTTP/2 Layer 分割 (N6 aftermath)

**問題:** §9.1 初版 resolution は HTTP/2 Layer が HEADERS+DATA+TRAILERS を aggregate して HTTPMessage を返す設計だった。しかし §9.2 で gRPC streaming を first-class に扱うことが決まった (event-per-envelope)。streaming RPC では aggregate する対象 (END_STREAM) がいつ来るか分からないため、in-layer aggregation は成立しない。

**解決:** HTTP/2 Layer を二層構造に分解する。

```
internal/layer/http2/          ← event-granular (H2HeadersEvent / H2DataEvent / H2TrailersEvent)
                                  BodyBuffer-driven flow control
                                  per-stream soft cap → stream-level stall / disk spill
                                  per-stream hard cap → RST_STREAM
internal/layer/httpaggregator/ ← wrapper: 上記 event stream → HTTPMessage (plain HTTP/2 向け)
                                  GRPCLayer は別 wrapper として並列に存在
```

**移設方針:**
- 現 http2 Layer の内部 aggregation ロジック・BodyBuffer integration は **アルゴリズムそのまま** httpaggregator へ。
- 公開 API: 現 http2 Channel の Next() が HTTPMessage を返していたのを、event 型 (H2HeadersEvent / H2DataEvent / H2TrailersEvent) を返すように変更。
- plain HTTP/2 呼び出し経路に httpaggregator.Wrap を挿入。ユーザから見た挙動は完全に変わらない (N6.5 の e2e test がそのまま通るのが受け入れ基準)。
- gRPC 検出経路 (peek first HEADERS → isGRPC) は httpaggregator を通さず、直接 GRPCLayer.Wrap に渡す。

**状態:** **N6.7 として Linear に追加**。N7 (gRPC) 着手の prerequisite。N6.5 の BodyBuffer 資産がそのまま per-stream buffer として効く (新規実装ほぼ不要)。

### Friction 4-C: gRPC-Web の HTTP/1 と HTTP/2 両対応

**問題:** gRPC-Web は HTTP/1.1 上と HTTP/2 上の両方で走りうる。wrapper は下層が HTTP/1 Channel でも HTTP/2 Channel でも動く必要がある。

**解決:** grpcweblayer.Wrap は下層 Channel の type を問わない (Channel interface さえ満たしていれば動く)。下層が yield する HTTPMessage envelope を読んで、grpc-web frame format (binary or base64) をパースする。

**状態:** 解決済み (Channel interface が protocol-agnostic なので自動的に両対応)

### Friction 5-A: Plugin の Pipeline 配置と resend/fuzz 経路 [RESOLVED 2026-04-29]

**問題:** Plugin が Pipeline 上のどこで fire するかが、ユースケースで分裂する。

1. **observation/annotation 系** (URL fingerprint、危険パターン警告タグ付け、AI agent が intercept UI で見るための注釈付与): Intercept より **前** で fire したい。Safety を経由してから走る必要があるが、user/AI が intercept で編集する前であるべき
2. **signing/last-mile 系** (HMAC、`Content-Length` 再計算、最終 wire の forensic stamping): Intercept/Transform/Macro variant 全部の確定後、Layer encode の **直前** で fire したい

旧 8-hook 設計の `on_receive_from_client` / `on_before_send_to_server` の対は、direction と Pipeline timing を 1 つの hook 名に conflate していたためスケールしない。RFC-001 で hook 名を `(protocol, event)` の 2 軸に整理する以上、この timing 軸は別軸として持つ必要がある。

**解決 (RFC §9.3 resolution):**

- Pipeline に plugin Step を **2 段** 設置:

```
Layer decode → Scope → RateLimit → Safety → PluginStepPre → Intercept
            → Transform → Macro → PluginStepPost → Record → Layer encode
```

- Hook 登録時に `phase="pre_pipeline"` (default) / `phase="post_pipeline"` を指定。`PluginStepPre` は前者だけ、`PluginStepPost` は後者だけを fire させる
- **Resend / Fuzz / Macro variant 経路は `PluginStepPre` を bypass** し、`Transform → Macro → PluginStepPost → Record → Layer encode` だけを通る。よって `post_pipeline` plugin は通常 wire でも resend でも fuzz でも「Send 直前の最終形を 1 回見る」セマンティクスで一貫して fire し、signing plugin は 1 回の登録で全経路をカバーできる
- 中間 phase (例: 「Intercept 後 Transform 前」) は **意図的に提供しない**。Pipeline Step の内部順序に plugin が依存すると将来の Step 追加で plugin が壊れる。Plugin が頼って良いのは「declarative な変更が全部入ったかどうか」の二値だけ
- Lifecycle / 観察専用 hook (`connection.on_*`, `tls.on_handshake`, `socks5.on_connect`, `*.on_close`, `grpc.on_end`) には phase 軸を持たせない (Pipeline を通過しないため)

**状態:** 解決済み (RFC §9.3 Decision item 1, item 5)

### Friction 5-B: Plugin の Message dict と Header mutation の wire 忠実性 [RESOLVED 2026-04-29]

**問題:** Plugin に Message を渡すとき、

1. Header を Go の `gohttp.Header` 風 map で渡すと case と order と duplicate が壊れる (CLAUDE.md MITM 原則違反)
2. Message field 名を Go 側の PascalCase で渡すと Starlark 慣習 (snake_case) と乖離し、AI agent script が読みにくい
3. Plugin が Raw byte を直接編集できないと smuggling 診断 (N2 vertical slice) のユースケースが pluging API でカバーできない
4. Mutation した結果を `Envelope.Raw` に正しく反映しないと wire との同期が崩れる

**解決 (RFC §9.3 resolution):**

- **dict は snake_case** (Go field 名から機械的変換、`convertMessageToDict` ヘルパで実装)
- **Header は ordered list of `(name, value)` 2-tuple**。case/order/duplicate を保つ。`headers.append` / `replace_at` / `delete_first` のみ提供。`headers.get_first(name)` は **read-only** な case-insensitive lookup ヘルパ。re-sort や dedup を試みた場合は `fail("ordered list operations only")` で明示エラー (silent 正規化禁止)
- **Raw 編集は first-class**: `msg["raw"] = b"..."` で byte 直接注入可能。Hook return 後、Layer は (a) raw が変わっていれば raw を wire に書き出し、(b) Message field が変わっていれば WireEncoder で raw 再生成、(c) どちらも変わっていなければ original.raw zero-copy。raw と Message 両方変更時は raw が勝つ (smuggling 用途優先)
- **監査証跡** は既存の Variant Snapshot メカニズム (RFC §5) で自動カバー。plugin mutation も TransformStep mutation と同じ shape の variant row を生成

**状態:** 解決済み (RFC §9.3 Decision item 2, 3, 4)

### Friction 5-C: Plugin の per-stream / per-transaction 状態管理 [RESOLVED 2026-04-29]

**問題:** gRPC bidi / WebSocket / SSE のような long-lived stream で plugin が「同じ stream の前のイベントの値を覚える」必要がある (例: `grpc.on_start` で取った `service`/`method` を `grpc.on_data` で参照)。Plugin が自前 dict を持つと、stream 終了時の cleanup を plugin が忘れた瞬間にメモリリーク。

**解決 (RFC §9.3 resolution):**

- `ctx` 引数に `ctx.transaction_state` (HTTP request/response 1 対 / WS upgrade 1 対 単位) と `ctx.stream_state` (HTTP/2 StreamID 単位) を提供
- Lifetime は Layer が管理。`transaction_state` は Pipeline session 終了で GC、`stream_state` は H2 stream の `complete`/`error`/`reset` で GC
- Plugin が独自 dict を `streams[stream_id] = {...}` で管理する pattern は **禁止しないが推奨もしない**。leak 検出はできないので、自前管理する plugin が leak したら自己責任

**状態:** 解決済み (RFC §9.3 Decision item 6)

### Friction 9: Layer lifecycle と Close() cascading

**問題:** 下層 (TCP conn) が切れたとき、上層の layer はどう知るか。上層の layer が Close() されたとき、下層は閉じるべきか閉じないべきか。

**解決:**
- **所有権ベース**: Layer の constructor 時に「下層を所有するか」を決める (デフォルト: 所有する)
- **所有する場合**: 上層の Close() は下層を cascade close する
- **所有しない場合** (例: WS layer が HTTP/1 layer から DetachStream で奪った net.Conn): Close() は自分だけ閉じる
- **下層が切れた場合**: 上層の Next() が io.EOF を返す (既に Channel interface の契約)

**状態:** N1 実装時の Layer interface 設計で明文化する。この文書に記録。

### Friction 10: Context propagation through layer stack

**問題:** ConnID、client address、TLS state などは layer をまたいで Pipeline Step まで伝搬する必要がある。

**解決:** `Envelope.Context` (struct) に first-class で載せる。layer が Envelope を作るときに context を埋める。`EnvelopeContext` の具体フィールドは RFC §3.1 に定義済み。

**状態:** 解決済み (RFC §3.1 に明記)

### Friction 11: Error propagation across layers

**問題:** HTTP/2 の RST_STREAM、TLS handshake の失敗、TCP reset など、異なる原因の error が layer をまたいで上に伝わる必要がある。

**解決:**
- Channel.Next() が返す error は error 種別を表現する (io.EOF は正常終了、StreamError は stream-level エラー、TLSError は TLS 関連など)
- Pipeline Step は原則として error を無視 (Layer 責務) し、Session がエラーを受けたら `OnComplete(err)` に流す
- RecordStep はエラー情報を EnvelopeContext.Error に記録する (あれば)

**状態:** N1-N3 実装時の詳細。interface の error 型定義で担保。

### Friction 12: Codec vs Channel 命名

**問題:** 既存の「Codec」という名前を再利用するか、新しい名前にするか。

**解決:** 「Channel」を採用する。理由:
- Codec という名前は「parse/serialize をする何か」という意味を背負っており、layer/connection の意味は入っていない
- Pipeline 入出力の単位という意味では Channel のほうが適切
- Go の chan とは別物だが文脈で区別できる

**状態:** 解決済み (RFC Appendix A に命名決定記録)

---

## 8. 設計決定の根拠

RFC 本文に入り切らなかった設計議論の記録。

### なぜ Pipeline (Step chain) 構造を維持したか

代替案として「Hook system (protocol-specific lifecycle hook)」を検討したが却下した。却下理由:

1. **順序管理が分散する** — Pipeline なら「Steps の並び順 = 実行順」で自明だが、hook 方式だと各 hook に priority を管理する必要がある
2. **Variant recording の snapshot 点が曖昧になる** — Pipeline なら Run() 入口で 1 回 clone すれば済むが、hook では「各 hook 前で clone か全 hook 前で 1 回か」が決まらない
3. **Pipeline.Without() のような derivation が書きにくい** — macro が Intercept Step だけ外したいケースが実現できない
4. **過剰な柔軟性** — MITM の処理は本質的に linear なので graph 的自由度は余剰

→ Pipeline という concept は正しい。問題は `Exchange` であり `Pipeline` ではなかった。

### なぜ Sum type (`HTTP *HTTPMessage; WS *WSMessage; ...`) ではなく interface を選んだか

RFC §10.2 に記載済みだが補足:

- **拡張性**: 新しいプロトコルを追加するたびに Envelope 構造体を touch しなくてよい
- **Go idiomatic**: type-switch は Go の自然な pattern
- **CloneMessage interface メソッド**: 統一的な deep copy が可能

interface 呼び出しのオーバーヘッドは無視できる (このワークロードでは一切の hot path ではない)。

### なぜ EnvelopeContext は Envelope に埋め込み (context.Context 経由ではなく)

Pipeline Step は `ctx context.Context` を受け取るが、ここに TargetHost 等を value key で入れることもできる。しかし Envelope に埋め込んだ理由:

1. **Variant snapshot に含めたい** — EnvelopeContext が変更されたら記録したい (TLS renegotiation 等)
2. **型安全** — context.Value は untyped
3. **Shallow でいい** — 中身は TLSSnapshot のようなポインタで、実体は共有して軽量

context.Context は request-scoped cancellation と timeout のためだけに使う。データ伝搬には使わない。

### なぜ TLSSnapshot と TLSHandshakeMessage を両方用意するか

一見冗長だが別物:

- **TLSSnapshot** (`EnvelopeContext.TLS`): 以降の全 Envelope に載る「この接続は TLS 下で動いている」という情報
- **TLSHandshakeMessage** (1 回だけ流れる Envelope): handshake 完了イベントとして Pipeline に流せる。fingerprint ベースの scope rule が pipe 上で動けるようにするため

後者は「fingerprint が特定の JA3 なら接続を drop する」のような policy が Pipeline で完結できる利点がある。

### なぜ HTTP/1.x と HTTP/2 で HTTPMessage を共有するか

HTTP/1.x の header は大文字小文字保持、HTTP/2 は lowercase 強制という違いがあるが、両方とも `[]KeyValue` で表現する。HTTP/2 layer は上流に送る際に :method / :path などの pseudo-header を展開し、HTTP/1.x layer はそのまま wire 形式で送る。**HTTPMessage は論理表現で、wire 変換は layer の責務**。

この設計の利点:
- Pipeline Step が HTTP/1 と HTTP/2 で共通のコードで動く
- Rule engine が HTTP 全般で統一的
- gRPC も HTTP/2 layer の上に乗るので、HEADERS が HTTPMessage として自然に surface する

---

## 9. HTTP Bias 議論の原点と MITM プロキシの本質

このセッションで最も重要な洞察:

### MITM プロキシが共通して持つべき本質は 5 つだけ

1. **Identity** (StreamID / FlowID / Sequence / Direction)
2. **Wire fidelity** (Raw bytes preserved as observed)
3. **Provenance** (which protocol produced this message)
4. **Recording hook** (uniform persistence path)
5. **Mutation trace** (before/after snapshot)

**これ以外はすべてプロトコル固有**。Method, URL, Status, Headers, Trailers, Body すらも共通の本質ではない (HTTP にしか自然に収まらない)。

### 旧 Exchange 型の嘘

`internal/exchange/exchange.go` は `Method`, `URL`, `Status`, `Headers`, `Trailers`, `Body` を持っていた。これは HTTP にとっては自然だが、他プロトコルでは以下のように破綻していた:

| フィールド | WebSocket | gRPC message | TCP | SSE |
|-------|-----------|--------------|-----|-----|
| Method | ない | /service/method は verb じゃない | ない | ない |
| URL | 初回 Upgrade 時のみ | service+method のほうが近い | ない | URL + event 名 |
| Status | close code | grpc-status | ない | ない |
| Headers | フレーム header なし | trailers は h2 layer 責務 | ない | event field |
| Trailers | ない | ある | ない | ない |
| Body | text vs binary の型あり | length-prefixed message | raw chunk | event-structured |

旧モデルはこれらを「空フィールドで誤魔化す」か「Metadata map に押し込む」かしていた。これは **型システム上の嘘**。

### Pipeline Step の HTTP bias

さらに既存 Pipeline Step のコードも HTTP bias を引きずっていた:

- `ScopeStep.Process` が `ex.URL` を見る
- `InterceptStep.MatchRequestRules(ex.Method, ex.URL, ex.Headers)` のシグネチャ
- `TransformStep` が `rules.Pipeline.TransformRequest(Method, URL, Headers, Body)` を呼ぶ
- `SafetyStep` は header + body チェックのみ

結果: Pipeline は全プロトコルで「動く」ことになっていたが、実態は **非 HTTP に対してほぼ no-op**。L4-capable 原則が README にあるがコードにはない、という状態だった。

### RFC-001 の根本的な修正

RFC-001 は「共有 5 項目だけ Envelope に置き、それ以外はプロトコル固有の Message 型に移す」ことで、**型レベルで正直な MITM プロキシ** を実現する。L7 は L7、L4 は L4、それぞれのプロトコルが自分の自然な shape で Pipeline に流れる。これができて初めて「L7-first, L4-capable」が建前ではなく実装になる。

---

## 10. 現状コードベースで確認済みの事実

セッション中に実コードを読んで確認した事実。次セッションで「これ既にあるよね?」と確認しなくても良いように記録する。

### internal/codec/http1/codec.go の Send() は Synthetic Exchange を弾く

```go
func (c *Codec) sendRequest(ex *exchange.Exchange) error {
    opaque, ok := ex.Opaque.(*opaqueHTTP1)
    if !ok || opaque == nil || opaque.rawReq == nil {
        return fmt.Errorf("http1 codec send request: missing opaque data")
    }
    ...
}
```

- `*opaqueHTTP1` が存在しないと即エラー
- これは「Next() で生成した Exchange を再 Send() する」前提
- 現行テスト `TestSendRequest_MissingOpaque` がこの挙動を固定している
- **Resend 用の synthetic Exchange は現状構築できない** のはこの制約が原因
- 新アーキでは http1 Layer に `BuildSendExchange(method, url, headers, body)` helper を用意するか、Send() 側に fallback path を追加する

### Raw Intercept mode のバグ

`internal/pipeline/intercept_step.go:109-130` を見ると:

```go
case intercept.ActionModifyAndForward:
    if action.IsRawMode() {
        ex.RawBytes = action.RawOverride
        return Result{}
    }
```

これは `ex.RawBytes` を書き換えているが、**`http1.Codec.Send` は `ex.RawBytes` を読まない**。zero-copy path は `opaque.rawReq.RawBytes` (つまり Opaque の方) を使うので、ここへの代入は wire に反映されない。

→ **これは現行コードに既に存在するバグ**。RFC-001 実装時に自動修正される (Layer/Channel モデルでは Exchange.RawBytes が wire の source of truth になる raw mode が明示化されるので)。

### TCP Codec (`internal/codec/tcp/tcp.go`) は identity codec として機能している

```go
func (c *Codec) Send(ctx context.Context, ex *exchange.Exchange) error {
    _, err := c.conn.Write(ex.Body)
    return err
}
```

- `*tls.Conn` を渡せば TLS 上で raw bytes を write 可能
- **問題は TCP Codec を適用するための Connector 経路が存在しないこと**。ALPN ベース自動選択で http1 codec が強制されてしまう
- 新アーキの bytechunk layer は本質的にこれの書き直し

### connector.DialUpstream は `*DialResult{Conn, ALPN, Codec}` を返す

```go
// internal/connector/dial.go:116
func DialUpstream(ctx context.Context, target string, opts DialOpts) (*DialResult, error)
```

- `DialResult.Conn` は TLS 完了後の `*tls.Conn` を持っている
- `MakeDialFunc` 経由で Session に渡されるのは `result.Codec` のみで、Conn は取り出せない
- **新アーキで `DialUpstreamRaw` を追加するだけで raw mode upstream は実現可能** (既に下地はある)

### Job.ExchangeSource interface は定義されているが使用例が 1 つもない

```go
// internal/job/job.go:33
type ExchangeSource interface {
    Next(ctx context.Context) (*exchange.Exchange, error)
}
```

- 現状使ってる Source は mockSource (test 用) のみ
- 実装用 Source (ReplaySource, FuzzSource) は未実装
- → 新アーキでは `EnvelopeSource` として再定義し、L7 用と L4 用の実装を N5 で初めて書く

### M38 の HTTP/1.x Codec に raw-first patching アルゴリズムがある

`internal/codec/http1/codec.go:520-570` の `applyHeaderPatch` 関数:
- origKV と newKV を diff して minimal patch を RawHeaders に適用
- 変更がない header の RawValue (OWS 含む) を完全保持
- 順序・大文字小文字を保持

このアルゴリズムは wire fidelity の核心で、**N3 (http1 layer) 実装時にそのまま流用する**。parser は layer/http1/parser/ にコピー、このアルゴリズム単体は layer/http1/channel.go の中に移植する (同名の private 関数として)。

### Pipeline.Run の snapshot 機構

`internal/pipeline/pipeline.go:86-100`:

```go
func (p *Pipeline) Run(ctx context.Context, ex *exchange.Exchange) (...) {
    snapshot := ex.Clone()
    ctx = withSnapshot(ctx, snapshot)
    for _, step := range p.steps {
        r := step.Process(ctx, ex)
        ...
    }
}
```

- 入口で Clone → context に格納 → RecordStep が context から snapshot を取り出して variant 検出
- **このアルゴリズムは RFC-001 でも変わらない**。Clone 対象が Envelope になり、deep copy に `Message.CloneMessage()` を呼ぶ点だけ変更

### flow.Store の schema は Stream + Flow の 2 階層

`internal/flow/` パッケージ:
- Stream (旧名 Flow): 接続レベルのグループ化
- Flow (旧名 Message): 個別の Send/Receive

RFC-001 の Envelope.StreamID / Envelope.FlowID はこの schema にそのまま乗る。Message 型のシリアライズだけ追加すれば流用可能。

---

## 11. 次セッションへの引き継ぎチェックリスト

次セッションが N3 以降を進めるにあたり、このセッションで済ませたことと、次セッションが確認すべきこと。

### このセッションで完了 (2026-04-11 〜 2026-04-12)

- [x] RFC-001 本文 (`docs/rfc/envelope.md`) 作成・accepted
- [x] RFC-001 日本語版 (`docs/rfc/envelope-ja.md`) 作成
- [x] 実装ガイド (`docs/rfc/envelope-implementation.md` = 本文書) 作成
- [x] 疑似コード検証 (4 シナリオ × 12 friction) 実施、結果を本文書 §7 に記録
- [x] scrap-and-build 戦略の合意
- [x] ファイル別コピー vs スクラッチの判定 (本文書 §2)
- [x] M36-M44 milestones と incomplete issues を Linear で Cancel
- [x] N1-N9 milestones を Linear で作成
- [x] N1 と N2 の seed issues を Linear で作成

### 次セッション (N1/N2 実装) が最初にやること

1. **このドキュメント (`envelope-implementation.md`) を必ず読む** — 疑似コード friction の解決案や do/don't が書いてある
2. **RFC 本文 (`envelope.md`) を仕様書として読む** — interface 定義の正
3. **CLAUDE.md は古い記述を引きずっている** — M36-M44 の記述があるが無視してよい。N9 で更新する予定
4. **Branch を切る**: `git checkout -b rewrite/rfc-001`
5. **N1 から開始**: Linear の N1 milestone 配下の issue を確認
6. **N2 の vertical slice (raw smuggling curl E2E) を最初のマイルストーンにする** — ここが通れば後は加速する

### 次セッションが参照すべき memory

- Architecture Rewrite (project_architecture_rewrite.md) → **outdated**。次セッションで削除 or supersede note 追加
- Rewrite Implementation Policy (feedback_rewrite_impl_policy.md) → **部分的に有効**。MITM wire fidelity 原則は保持
- M37-M39 design decisions → **outdated**。N1-N3 実装の参考にはしないこと
- Concurrency checklist (feedback_concurrency_checklist.md) → **有効**。layer/session の goroutine 設計で使う
- MITM wire fidelity (feedback_mitm_no_normalize.md) → **強く有効**。新アーキでも中心原則
- Test fix policy (feedback_test_fix_policy.md) → **有効**
- No TLS version floor (feedback_no_tls_version_floor.md) → **有効**
- RFC-001 memory (new) → **必読**

### Open Questions の解決タイミング (再掲)

- **Open Question #1 (HTTP/2 flow control × Pipeline latency)** — ✅ **RESOLVED** 2026-04-15 (初版) / 2026-04-23 (再起草: event-granular Layer + HTTPAggregatorLayer wrapper)
- **Open Question #2 (gRPC envelope granularity)** — ✅ **RESOLVED** 2026-04-23 (event-per-envelope + GRPCStart/Data/End 型)
- **Open Question #3 (Starlark plugin API shape)** — ✅ **RESOLVED** 2026-04-29 (`(protocol, event, phase)` 3 軸 hook identity + `PluginStepPre`/`PluginStepPost` 2 段 Pipeline + mutable Starlark dict + Raw 編集可能)

解決は「RFC §9 を読み返す → 選択肢の pros/cons を再評価 → RFC に decision ブロックを追加 → 実装開始」の順。

### 最重要事項

1. **新コードを書きながら旧コード (internal/codec/, internal/pipeline/*_step.go, internal/protocol/, internal/proxy/) を *絶対に開かない***
2. **RFC を仕様として守る** — RFC に書いてあることと違う実装をしたいと思ったら、まず RFC を改訂する (draft に戻してもいい)
3. **N2 の vertical slice を何よりも優先する** — 他の N1 タスクより先に N2 の smuggling E2E を通すと設計検証が早い
4. **疑問が出たら本文書 §7 の Friction 一覧を見る** — 既にこのセッションで議論済みのものは結論が書いてある

---

## Appendix: セッション知見の由来一覧

この文書の各セクションが、セッションのどの議論フェーズで得られた知見を元にしているかの対応表。次セッションが「この部分の根拠は?」と疑問を持ったときに、会話ログを遡る必要を減らすための参照。

| §  | 内容 | 由来 |
|----|------|------|
| §1 | Scrap-and-build 選択 | 最終フェーズ (user が「スクラッチ効率的?」と聞いた時) |
| §2 | ファイル別判定 | 同上 + 実コードベース探索 |
| §3 | Step 0-7 進行 | 同上 |
| §4 | Vertical slice philosophy | 同上、N2 を特別扱いする判断 |
| §5 | Don't do list | 同上、誘惑への対抗 |
| §6 | リスクと対処 | 同上 + 過去の architecture-rewrite.md 経験 |
| §7 | 疑似コード friction | 「疑似コード書くと課題検出できる?」の議論フェーズ |
| §8 | Pipeline 維持の根拠、Sum type 却下 | RFC §10 とその前の議論 |
| §9 | HTTP bias と MITM 本質 | 「exchangeとpipelineのモデル、HTTP に寄り過ぎ?」議論 |
| §10 | 現状コード事実 | 各所で実コードを読んで確認した事実 (resend_tool.go, codec.go, intercept_step.go 等) |
| §11 | 引き継ぎチェックリスト | 本セッション完了時に整理 |

---

**最終更新:** 2026-04-29 (§9.3 resolved + Friction 5-A 追加 + 全 Open Question 解決済み)

**次の変更タイミング:** N8 (Plugin + MCP + WebUI Reconnection) 完了時、N9 (Legacy Removal) 完了時。N9 完了をもって本文書は移行ガイドとしての役割を終え、CLAUDE.md / README.md に統合される。

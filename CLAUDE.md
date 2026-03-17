# yorishiro-proxy

AI エージェント向けネットワークプロキシツール — AI のための MITM プロキシ。
MCP (Model Context Protocol) サーバとして動作し、脆弱性診断のためのトラフィック傍受・記録・リプレイ機能を提供する。

**ステータス**: OSS (Apache License 2.0)・開発中

## アーキテクチャ

### 原則: L7-first, L4-capable

1. **デフォルトの操作インターフェースは構造化された L7 ビュー** — AI エージェントの Token 効率を優先し、method, URL, headers, body 等の構造化データで通信を表現する
2. **全プロトコルで raw bytes の記録・閲覧・改変が可能であること** — 診断ツールとして、プロトコルレベルの異常検出・再現ができなければならない（SOCKS5 など純粋なトランスポート層プロトコルはトンネル先プロトコルに対して適用）
3. **L7 パースは raw bytes の上に乗るオーバーレイであり、wire-observed な raw bytes スナップショット自体を破壊・改変してはならない** — 記録された raw bytes は常にワイヤー上の元データを反映し、改変は必ず別の派生データ（例: modified variant）として扱う

### パイプライン

```
TCP リスナ (Layer 4)
  → プロトコル検出 (peek bytes)
    → プロトコルハンドラ (HTTP/S, HTTP/2, gRPC, WebSocket, Raw TCP)
      → セッション記録 (L7 構造化 + L4 raw bytes)
        → MCP Tool (傍受・リプレイ・検索)
```

### プロトコル別 L7/L4 対応状況

| プロトコル | L7 構造化ビュー | L4 raw bytes | 備考 |
|-----------|---------------|-------------|------|
| HTTP/1.x | YES | YES (captureReader) | intercept raw forwarding は M27 |
| HTTP/2 | YES | YES (フレーム codec) | M26 で自前フレームエンジン実装 |
| gRPC | YES | YES (HTTP/2 経由) | |
| WebSocket | YES | YES (フレーム単位) | |
| Raw TCP | N/A | YES (バイトストリーム) | |
| SOCKS5 | N/A | N/A (トランスポート層として自身は対象外) | ハンドシェイク/トンネル後に委譲されたプロトコルで raw bytes/L7 を適用 |

### 設計方針

- Layer 4 (TCP) でコネクションを受け取り、モジュラー化されたプロトコルハンドラにルーティング
- 外部プロキシライブラリは使用しない — 標準ライブラリベースで自前実装
- MCP-first: すべての操作は MCP ツールとして公開

## パッケージレイアウト

```
cmd/yorishiro-proxy/       # エントリポイント
internal/
  mcp/                     # MCP サーバ・ツール定義・ハンドラ
  proxy/
    listener.go            # TCP リスナ (Layer 4)
    handler.go             # ProtocolHandler インターフェース
    peekconn.go            # バッファ付き net.Conn ラッパー
  protocol/
    detect.go              # プロトコル検出ロジック
    http/                  # HTTP/1.x, HTTPS MITM 実装
      handler.go           # HTTP forward proxy ハンドラ
      connect.go           # CONNECT トンネル・HTTPS MITM
    httputil/              # HTTP 共通ユーティリティ (TLS トランスポート, ホスト別 TLS 設定, タイミング)
  safety/                  # SafetyFilter エンジン (Input Filter + Output Filter)
    engine.go              # ルールコンパイル・CheckInput・FilterOutput
    rule.go                # Rule/Target/Action 型定義・Preset 構造
    preset.go              # Input Filter プリセット (destructive-sql, destructive-os-command)
    preset_pii.go          # Output Filter PII プリセット (credit-card, japan-my-number, email, japan-phone)
  plugin/                  # Starlark プラグインエンジン・レジストリ
  flow/                    # リクエスト/レスポンス記録・フロー管理・HAR エクスポート
  cert/                    # TLS 証明書生成・CA 管理
    ca.go                  # ルート CA 生成・読み込み
    issuer.go              # 動的サーバ証明書発行
  config/                  # 設定読み込み
  logging/                 # 構造化ロギング (log/slog)
```

## ビルド・テスト

```bash
make build          # build-ui → vet → go build（常に UI を再ビルド）
make build-ui       # web/ の React/Vite アプリをビルドし dist/ を生成
make ensure-ui      # dist/ が存在しない場合のみ build-ui を実行（軽量）
make test           # ensure-ui → go test -race -v ./...（ユニットテストのみ）
make test-e2e       # ensure-ui → go test -race -v -tags e2e ./...（e2e 含む全テスト）
make test-cover     # ensure-ui → カバレッジレポート付きテスト
make vet            # ensure-ui → go vet ./...
make fmt            # gofmt -w . で全ファイルをフォーマット
make lint           # gofmt check + go vet + staticcheck + ineffassign
make bench          # ensure-ui → ベンチマーク実行
make clean          # 成果物削除
```

> **e2e テスト**: `*_integration_test.go` ファイルには `//go:build e2e` タグが付与されている。
> `make test` ではスキップされ、`make test-e2e` で実行される。
> 新規 integration テストを追加する際は必ずこのタグを付けること。

> **重要**: `go test` / `go vet` / `go build` を直接実行しないこと。
> `internal/mcp/webui/embed.go` が `//go:embed dist/*` で Web UI を埋め込むため、
> `dist/` が存在しないとコンパイルエラーになる。必ず `make` ターゲット経由で実行する。

### e2e テストのサブシステム検証チェックリスト

新規 e2e テスト (`*_integration_test.go`) を追加する際、通信の成功だけでなく
サブシステム連携を必ず検証すること。以下のチェックリストを満たしているか確認する。

- [ ] **通信の成功**: データが正しく透過・変換されること（リクエスト送信 → レスポンス受信 → 内容検証）
- [ ] **フロー記録**: Store に正しいプロトコル名 (`Protocol`)、FlowType (`unary` / `bidirectional` / `stream`)、State で保存されること
- [ ] **メッセージ内容**: リクエスト/レスポンスのヘッダー・ボディが `store.GetMessages(ctx, flowID, opts)` で正しく記録されていること
- [ ] **状態遷移**: progressive recording が正しく動作すること（`State` が `active` → `complete` に遷移）
- [ ] **プラグインフック発火**: 該当プロトコルのフックが呼ばれること（プラグイン対応プロトコルの場合）
- [ ] **エラーパス**: 接続失敗、タイムアウト時にフローが `State="error"` で記録されること
- [ ] **raw bytes 記録**: wire-observed な raw bytes (`Message.RawBytes`) が正しく記録されていること（L4-capable 原則、M26/M27 で確立）
- [ ] **variant recording**: intercept/transform による改変時、original と modified variant が両方記録されること（M27 で導入）
- [ ] **MCP ツール統合**: `query` ツール（`resource: "flows"` / `resource: "flow"` パラメータ指定）経由でフローが正しく取得できること

> **適用範囲**: 全項目が全テストに必須ではない。プロトコル特性やテスト目的に応じて該当項目を検証する。
> 例: Raw TCP は L7 構造化ビューを持たないため「メッセージ内容」のヘッダー検証は不要。
> SOCKS5 はトランスポート層として自身のフロー記録対象外のため、トンネル先プロトコルで検証する。

## コーディング規約

- Go 標準スタイル (`gofmt` / `goimports`)
- エラーは `fmt.Errorf("context: %w", err)` でラップ
- `context.Context` は第一引数で伝播
- パッケージコメントは doc.go または先頭ファイルに記載
- テストは `_test.go` ファイル、テーブル駆動テスト推奨
- `t.Logf` で未検証を記録するパターンは禁止。未実装機能は `t.Skip("not yet implemented: <issue-id>")` を使用すること
- `internal/` 配下は外部公開しない

### ログレベル使い分けガイドライン

`log/slog` のレベル選択は以下の基準に従う。

| レベル | 用途 | 例 |
|--------|------|-----|
| `slog.Debug` | 開発者・診断向けの詳細情報。`-log-level debug` 時のみ出力 | プロトコル検出結果、TLS SNI、ルールマッチ判定、フレーム送受信、ハンドシェイク進行 |
| `slog.Info` | 正常動作の主要イベント。デフォルトで出力される | サーバ起動/停止、プロキシ開始/停止、設定ロード完了、プラグインロード |
| `slog.Warn` | 異常だが処理続行可能な状態。運用者の注意を引くべき事象 | TLS 証明書検証失敗（insecure モード）、非推奨機能の使用、リトライ発生、リソース枯渇の兆候 |
| `slog.Error` | 処理失敗。回復不能またはリクエスト単位の致命的エラー | DB 書き込み失敗、リスナ起動失敗、CA 証明書読み込み失敗 |

#### 判断基準

- **Debug vs Info**: そのログが無くても運用者が正常動作を確認できるなら Debug。起動・停止・設定変更など「何が起きたか」を示すイベントは Info
- **Info vs Warn**: 正常フローの一部なら Info。想定外だが処理を継続する場合は Warn。Warn は「運用者が確認すべき」レベルであり、頻発するなら Info か Debug に降格する
- **Warn vs Error**: 処理を続行できるなら Warn。呼び出し元にエラーを返す、またはリクエストが失敗する場合は Error

#### 迷いやすいケースの判断例

| ケース | レベル | 理由 |
|--------|--------|------|
| クライアントが不正なリクエストを送信（400 系） | `Debug` | クライアント側の問題であり、プロキシの異常ではない |
| 上流サーバが 5xx を返した | `Debug` | プロキシは正常に中継しており、上流の問題。フロー記録で追跡可能 |
| intercept ルールにマッチしたリクエスト | `Debug` | 正常動作の詳細。診断時に有用だがデフォルトでは不要 |
| Safety Filter がリクエストをブロック | `Info` | セキュリティイベントとして運用者に通知すべき |
| プラグインの Starlark スクリプトが実行時エラー | `Warn` | プラグインの問題だが、プロキシ自体は動作継続可能 |
| WebSocket 接続の正常クローズ | `Debug` | 正常動作の詳細 |
| WebSocket 接続の異常切断 | `Warn` | 想定外だが処理続行可能 |
| フローの DB 保存に失敗 | `Error` | データ損失が発生。回復不能 |
| 設定ファイルが見つからずデフォルト値を使用 | `Info` | 正常フローの一部（デフォルト値で動作可能な設計） |
| CONNECT トンネル先への接続タイムアウト | `Debug` | ネットワーク状態に依存。クライアントにはエラーレスポンスを返すが、プロキシの異常ではない |

## 依存ライセンスポリシー

### 許可

MIT, BSD (2-clause, 3-clause), Apache-2.0, ISC, MPL-2.0

### 禁止

GPL 系全般 (GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, AGPL-3.0)

### 承認済み依存

- `github.com/modelcontextprotocol/go-sdk` — MCP 公式 Go SDK
- `modernc.org/sqlite` — Pure Go SQLite ドライバ (BSD-3-Clause)
- `github.com/google/uuid` — UUID 生成 (Apache-2.0)
- `golang.org/x/sync` — singleflight 等の並行制御 (BSD-3-Clause)
- `go.starlark.net` — Starlark スクリプトエンジン (BSD-3-Clause)

新しい外部依存を追加する場合は `/license-check` スキルでライセンスを確認すること。

## 開発ワークフロー

1. `/project status` — マイルストーン進捗を確認し、次に取り組む対象を決定
2. `/project plan <milestone>` — ロードマップから Linear Issue を作成・整備
3. `/orchestrate` — マイルストーン単位で複数 Issue をサブエージェントに並行実装
4. `/implement <Issue ID>` — 単一 Issue の実装・テスト・コミット・PR 作成
5. `/review-gate` — PR に対して Code Review + Security Review を並行実行。問題があれば自動修正→再レビュー（最大 2 ラウンド）
6. `/project sync` — 実装完了後、ロードマップ文書を更新

> **注意**: `/implement` は単一セッションでの単独実行を前提とする。複数 Issue を並行実装する場合は `/orchestrate` を使用すること。

### 新機能マイルストーンの config 対応チェックリスト

`/project plan` で新機能マイルストーンの Issue を分割する際、以下を必須確認項目とする。
config 対応が暗黙の前提として漏れることを防ぐ。

- [ ] `internal/config/` の config struct にフィールド追加が必要か
- [ ] config バリデーション (`Validate()`) の追加・更新が必要か
- [ ] init 系関数 (`cmd/yorishiro-proxy/main.go`) の変更が必要か
- [ ] config → runtime パスの結合テストが必要か
- [ ] 上記のいずれかに該当する場合、config 対応の Issue を明示的に起票する

### 新プロトコル追加時の e2e テストチェックリスト

`/project plan` で新プロトコル対応の Issue を分割する際、以下を必須確認項目とする。
e2e テストの観点漏れを防ぐ。個々のテスト項目の検証内容は「e2e テストのサブシステム検証チェックリスト」を参照。

- [ ] プロキシ経由の通信成功 e2e テスト (`internal/proxy/*_integration_test.go`)
- [ ] フロー記録の完全性検証（プロトコル名、FlowType、State 遷移、メッセージ数）
- [ ] raw bytes 記録の完全性検証（フレーム境界、バイナリデータの round-trip）— L4-capable 原則
- [ ] variant recording テスト（intercept 改変時の original/modified 保存）
- [ ] progressive recording テスト（streaming プロトコルの中間状態検証）
- [ ] プラグインフック発火の検証（該当フックが存在する場合）
- [ ] Safety Filter / Output Filter の適用検証
- [ ] エラーパス（接続失敗、タイムアウト、不正データ）の e2e テスト
- [ ] 派生プロトコル（例: HTTP/2 → gRPC）がある場合、派生パスの独立テスト
- [ ] MCP ツール統合テスト（query ツール経由でフロー詳細が正しく返ること）
- [ ] WebUI 表示テスト（新プロトコル用コンポーネントの null guard 含む）
- [ ] 上記のいずれかに該当する場合、テスト Issue を明示的に起票する

> **サブシステム検証チェックリストとの関係**: 本チェックリストは新プロトコル追加の Issue 分割時に使う計画レベルのリスト。
> サブシステム検証チェックリストは個々の e2e テストファイルを書く際の実装レベルのリスト。両方を参照すること。

## エージェント隔離戦略 (Worktree)

サブエージェントによる並行作業での git 競合を防ぐため、以下のルールを適用する。

### 原則

- **メイン worktree（リポジトリのクローン元）は main ブランチに固定し、直接の作業を禁止する** — ブランチ切り替えやコミットは全て worktree 内で行う。main ブランチは branch protection により直接 push できない
- **全てのサブエージェントは `isolation: "worktree"` で起動する** — 並列実行時にメイン worktree の HEAD を checkout すると、他のエージェントが読み取るコードの状態と競合するため、読み取り専用のレビューエージェントも worktree で隔離する

### Task ツールでの分類

| エージェント種別 | 操作 | isolation |
|---------------|------|-----------|
| implementer | コード実装・コミット・プッシュ | `"worktree"` |
| fixer | レビュー所見の修正・コミット・プッシュ | `"worktree"` |
| code-reviewer | 対象ブランチの checkout・差分の読み取り・レビュー投稿 | `"worktree"` |
| security-reviewer | 対象ブランチの checkout・差分の読み取り・レビュー投稿 | `"worktree"` |

### 新規エージェント追加時

1. 全てのサブエージェントは原則 `isolation: "worktree"` を使用する
2. 起動元のスキル（`.claude/skills/*/SKILL.md`）に isolation 設定を明記

### Worktree クリーンアップ

Claude Code の Task ツールは worktree に変更がある場合、完了後も自動削除しない。
**呼び出し元スキルがクリーンアップの責務を持つ。**

#### クリーンアップのタイミング

| スキル | クリーンアップタイミング |
|--------|------------------------|
| `/orchestrate` | Phase 3-3（全バッチ・レビュー完了後）|
| `/review-gate` | Phase 6（レビューサイクル完了後）|
| `/code-review` | Step 7（結果報告後）|

各スキルは自分が起動したサブエージェントの agent ID を追跡し、**その worktree のみ**を削除する。
別セッションのアクティブな worktree を破壊しないため、一括削除は行わない。

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
git worktree prune
```

stale な worktree が蓄積した場合は `git worktree list` で確認し、個別に `git worktree remove` すること。

## ブランチ戦略

- `main` — 常にビルド・テスト通過状態を維持
- 機能ブランチ: `feat/<issue-id>-<short-desc>` (例: `feat/USK-12-http-handler`)
- バグ修正: `fix/<issue-id>-<short-desc>`
- PR はすべて CI 通過後にマージ

## コミット規約

Conventional Commits 形式:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

type: `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `chore`

## Linear

- チーム: Usk6666
- プロジェクト: yorishiro-proxy

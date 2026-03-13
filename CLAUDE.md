# yorishiro-proxy

AI エージェント向けネットワークプロキシツール — AI のための MITM プロキシ。
MCP (Model Context Protocol) サーバとして動作し、脆弱性診断のためのトラフィック傍受・記録・リプレイ機能を提供する。

**ステータス**: OSS (Apache License 2.0)・開発中

## アーキテクチャ

```
Layer 4 TCP リスナ
  → プロトコル検出 (peek bytes)
    → プロトコルハンドラ (HTTP/S, HTTP/2, gRPC, WebSocket, Raw TCP)
      → セッション記録 (Request/Response)
        → MCP Tool (傍受・リプレイ・検索)
```

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

## コーディング規約

- Go 標準スタイル (`gofmt` / `goimports`)
- エラーは `fmt.Errorf("context: %w", err)` でラップ
- `context.Context` は第一引数で伝播
- パッケージコメントは doc.go または先頭ファイルに記載
- テストは `_test.go` ファイル、テーブル駆動テスト推奨
- `internal/` 配下は外部公開しない

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

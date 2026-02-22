# katashiro-proxy

AI エージェント向けネットワークプロキシツール — AI のための PacketProxy。
MCP (Model Context Protocol) サーバとして動作し、脆弱性診断のためのトラフィック傍受・記録・リプレイ機能を提供する。

**ステータス**: 商用非公開・開発中

## アーキテクチャ

```
Layer 4 TCP リスナ
  → プロトコル検出 (peek bytes)
    → プロトコルハンドラ (HTTP/S, gRPC, WebSocket, Raw TCP, QUIC, ...)
      → セッション記録 (Request/Response)
        → MCP Tool (傍受・リプレイ・検索)
```

- Layer 4 (TCP) でコネクションを受け取り、モジュラー化されたプロトコルハンドラにルーティング
- 外部プロキシライブラリは使用しない — 標準ライブラリベースで自前実装
- MCP-first: すべての操作は MCP ツールとして公開

## パッケージレイアウト

```
cmd/katashiro-proxy/       # エントリポイント
internal/
  mcp/                     # MCP サーバ・ツール定義・ハンドラ
  proxy/
    listener.go            # TCP リスナ (Layer 4)
    handler.go             # ProtocolHandler インターフェース
  protocol/
    detect.go              # プロトコル検出ロジック
    http/                  # HTTP/1.x, HTTP/2 MITM 実装
  session/                 # リクエスト/レスポンス記録・セッション管理
  cert/                    # TLS 証明書生成・CA 管理
  config/                  # 設定読み込み
```

## ビルド・テスト

```bash
make build          # bin/katashiro-proxy にビルド
make test           # go test -race -v ./...
make test-cover     # カバレッジレポート付きテスト
make vet            # go vet ./...
make clean          # 成果物削除
```

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

新しい外部依存を追加する場合は `/license-check` スキルでライセンスを確認すること。

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
- プロジェクト: katashiro-proxy

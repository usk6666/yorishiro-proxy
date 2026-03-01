# Playwright-CLI 連携キャプチャ手順

katashiro-proxy と playwright-cli を組み合わせて、ブラウザ操作のトラフィックをキャプチャする。

## 前提条件

- `katashiro-proxy setup` が実行済み (CA 証明書インストール済み、`.playwright/cli.config.json` のプロキシ設定済み)
- playwright-cli スキルがインストール済み

## Step 1: プロキシ起動

対象ホストのみキャプチャするスコープを設定して起動する。

```json
// proxy_start
{
  "listen_addr": "127.0.0.1:8080",
  "capture_scope": {
    "includes": [
      {"hostname": "target.example.com"}
    ],
    "excludes": [
      {"hostname": "static.example.com"},
      {"url_prefix": "/assets/"}
    ]
  },
  "tls_passthrough": ["*.googleapis.com", "*.gstatic.com"]
}
```

**スコープ設計のポイント:**
- `includes` で対象ホストのみに限定する (ノイズ削減)
- `excludes` で静的アセット、ヘルスチェック等を除外する
- `tls_passthrough` で証明書ピンニングされたサービスを除外する

## Step 2: playwright-cli でブラウザ操作

playwright-cli を使って対象アプリケーションの操作を行う。
プロキシ設定は `katashiro-proxy setup` で `.playwright/cli.config.json` に自動設定済み。

操作例:
1. ログインページにアクセスしてログイン
2. テスト対象の機能を操作 (CRUD 操作、設定変更等)
3. ログアウト

**重要**: 後で Macro のステップとして参照するため、各操作を意識的に分けて行う。

## Step 3: キャプチャされたセッション確認

```json
// query
{"resource": "sessions", "limit": 50}
```

特定の URL パターンでフィルタする:

```json
// query
{
  "resource": "sessions",
  "filter": {"url_pattern": "/api/", "method": "POST"},
  "limit": 50
}
```

## Step 4: セッション詳細の確認

各セッションの詳細を確認し、Macro で使うセッション ID を特定する。

```json
// query
{"resource": "session", "id": "<session-id>"}
```

レスポンスから以下を確認する:
- リクエスト/レスポンスのヘッダとボディ
- CSRF トークンの位置 (ヘッダ or ボディ)
- セッションクッキーの名前
- レスポンスの JSON 構造 (抽出ルール設計のため)

## Step 5: セッション ID のマッピング

キャプチャしたセッションを用途別に整理する:

```
login-session:          <session-id-1>  -- ログインリクエスト
csrf-page-session:      <session-id-2>  -- CSRF トークン取得ページ
target-api-session:     <session-id-3>  -- テスト対象 API
create-item-session:    <session-id-4>  -- テスト用リソース作成
delete-item-session:    <session-id-5>  -- テスト用リソース削除
logout-session:         <session-id-6>  -- ログアウト
```

これらのセッション ID を Macro 定義 (`define_macro`) の各ステップで `session_id` として参照する。

## 実行中のスコープ変更

テスト中にスコープを変更する必要がある場合は `configure` を使う:

```json
// configure
{
  "capture_scope": {
    "add_includes": [{"hostname": "api2.target.example.com"}]
  }
}
```

## Tips

- キャプチャ中に不要なセッションが増えたら、スコープを絞る
- セッション一覧が多い場合は `filter` と `limit` を活用する
- WebSocket セッションは `protocol` フィルタで確認: `{"filter": {"protocol": "WebSocket"}}`

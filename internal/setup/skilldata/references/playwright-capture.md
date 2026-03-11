# Playwright-CLI 連携キャプチャ手順

yorishiro-proxy と playwright-cli を組み合わせて、ブラウザ操作のトラフィックをキャプチャする。

## 前提条件

- `yorishiro-proxy install` が実行済み (CA 証明書インストール済み、`.playwright/cli.config.json` のプロキシ設定済み)
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
- Cloudflare 等の WAF で bot 検知される場合は `tls_fingerprint` を設定する（デフォルト: "chrome"）

## Step 2: playwright-cli でブラウザ操作

playwright-cli を使って対象アプリケーションの操作を行う。
プロキシ設定は `yorishiro-proxy install` で `.playwright/cli.config.json` に自動設定済み。

**必須**: playwright-cli 起動時は必ず `.playwright/cli.config.json` を使用すること。独自の設定ファイルを作成してはならない。

操作例:
1. ログインページにアクセスしてログイン
2. テスト対象の機能を操作 (CRUD 操作、設定変更等)
3. ログアウト

**重要**: 後で Macro のステップとして参照するため、各操作を意識的に分けて行う。

最初のページアクセスが完了したら、**必ず次の Step 2.5 でプロキシ接続を確認する**。

## Step 2.5: プロキシ接続確認 (必須)

最初のページアクセス後、トラフィックがプロキシ経由で記録されているか確認する。

```json
// query
{"resource": "flows", "limit": 5}
```

### フローが 1 件以上ある場合

プロキシ接続は正常。Step 3 に進む。

### フローが 0 件の場合

ブラウザがプロキシを経由していない。以下の手順で修正する:

1. playwright-cli のブラウザを閉じる
2. `.playwright/cli.config.json` を確認し、プロキシ設定が正しいことを検証する:
   - `proxy.server` が `proxy_start` の `listen_addr` と一致しているか
   - CA 証明書のパスが正しいか
3. 設定を修正した上で、playwright-cli を再起動して Step 2 からやり直す

**このステップを省略してはならない。** プロキシ未接続のまま操作を続行すると:
- 全操作をやり直す必要がある (フローが記録されていないため)
- `capture_scope` や `security` のターゲットスコープ制御が機能しない

## Step 3: キャプチャされたフロー確認

```json
// query
{"resource": "flows", "limit": 50}
```

特定の URL パターンでフィルタする:

```json
// query
{
  "resource": "flows",
  "filter": {"url_pattern": "/api/", "method": "POST"},
  "limit": 50
}
```

## Step 4: フロー詳細の確認

各フローの詳細を確認し、Macro で使うフロー ID を特定する。

```json
// query
{"resource": "flow", "id": "<flow-id>"}
```

レスポンスから以下を確認する:
- リクエスト/レスポンスのヘッダとボディ
- CSRF トークンの位置 (ヘッダ or ボディ)
- セッションクッキーの名前
- レスポンスの JSON 構造 (抽出ルール設計のため)

## Step 5: フロー ID のマッピング

キャプチャしたフローを用途別に整理する:

```
login-flow:          <flow-id-1>  -- ログインリクエスト
csrf-page-flow:      <flow-id-2>  -- CSRF トークン取得ページ
target-api-flow:     <flow-id-3>  -- テスト対象 API
create-item-flow:    <flow-id-4>  -- テスト用リソース作成
delete-item-flow:    <flow-id-5>  -- テスト用リソース削除
logout-flow:         <flow-id-6>  -- ログアウト
```

これらのフロー ID を Macro 定義 (`define_macro`) の各ステップで `flow_id` として参照する。

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

- キャプチャ中に不要なフローが増えたら、スコープを絞る
- フロー一覧が多い場合は `filter` と `limit` を活用する
- WebSocket フローは `protocol` フィルタで確認: `{"filter": {"protocol": "WebSocket"}}`

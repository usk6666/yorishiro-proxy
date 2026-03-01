---
description: "katashiro-proxy を使ったセキュリティテスト支援"
user-invokable: true
---

# /katashiro

katashiro-proxy (MCP プロキシ) を使ったセキュリティテストを支援するスキル。
プロキシの起動、トラフィックキャプチャ、リクエストの改変・リプレイを自然言語で指示できる。

## 使い方

- `/katashiro start` — プロキシを起動してトラフィックキャプチャを開始
- `/katashiro sessions` — キャプチャされたセッション一覧を表示
- `/katashiro resend <session-id>` — 指定セッションのリクエストを再送
- `/katashiro fuzz <session-id>` — 指定セッションに対してファジングを実行

## プロキシ起動

```json
// proxy_start
{"listen_addr": "127.0.0.1:8080"}
```

## セッション確認

```json
// query
{"resource": "sessions", "limit": 20}
```

## リクエスト再送

```json
// execute
{
  "action": "resend",
  "params": {
    "session_id": "<session-id>",
    "override_headers": {"Authorization": "Bearer <token>"}
  }
}
```

## セキュリティテストパターン

### 認可テスト
1. 正規ユーザーでリクエストをキャプチャ
2. 別ユーザーの認証情報でリクエストを再送
3. レスポンスを比較して認可バイパスを確認

### パラメータ改ざん
1. リクエストをキャプチャ
2. body_patches でパラメータを変更して再送
3. 想定外のレスポンスがないか確認

### ファジング
1. 対象リクエストを特定
2. payload positions を設定
3. ワードリストまたは数値範囲でファジング実行
4. レスポンスの差異を分析

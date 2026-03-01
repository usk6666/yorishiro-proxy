---
description: "katashiro-proxy を使った脆弱性検証ワークフロー"
user-invokable: true
---

# /katashiro

katashiro-proxy (MCP プロキシ) を使った脆弱性検証を支援するスキル。
ソースコードレビューで検出された脆弱性を実環境で検証するユースケースに特化。

## トリガー

以下のような指示を受けたとき、このスキルを適用する:

- 「脆弱性を検証して」「このエンドポイントをテストして」
- 「IDOR/SQLi/XSS/CSRF をテストして」
- 「認可バイパスを確認して」「権限昇格を検証して」
- 「このリクエストを改ざんして送り直して」
- 「ファジングを実行して」

## MCP ツール概要

katashiro-proxy は 5 つの MCP ツールを提供する:

| ツール | 用途 |
|--------|------|
| `proxy_start` | プロキシ起動・キャプチャスコープ設定 |
| `proxy_stop` | プロキシ停止 |
| `configure` | 実行中のプロキシ設定変更 (スコープ・TLS パススルー等) |
| `query` | セッション一覧・詳細・ファズ結果等の情報取得 |
| `execute` | リクエスト再送・ファジング・マクロ定義/実行 |

### proxy_start -- プロキシ起動

```json
{
  "listen_addr": "127.0.0.1:8080",
  "capture_scope": {
    "includes": [{"hostname": "target.example.com"}],
    "excludes": [{"hostname": "static.example.com"}]
  },
  "tls_passthrough": ["*.googleapis.com"]
}
```

### query -- 情報取得

```json
// セッション一覧
{"resource": "sessions", "filter": {"url_pattern": "/api/"}, "limit": 50}

// セッション詳細
{"resource": "session", "id": "<session-id>"}

// ファズ結果
{"resource": "fuzz_results", "fuzz_id": "<fuzz-id>", "sort_by": "status_code"}
```

### execute -- アクション実行

主要アクション: `resend`, `fuzz`, `define_macro`, `run_macro`, `delete_macro`

```json
// リクエスト再送
{
  "action": "resend",
  "params": {
    "session_id": "<session-id>",
    "override_headers": {"Authorization": "Bearer <token>"},
    "body_patches": [{"json_path": "$.user_id", "value": 999}],
    "tag": "idor-test"
  }
}
```

## ワークフロー選択ディシジョンツリー

```
指示を受けた
  |
  +-- トラフィックキャプチャが必要?
  |     |
  |     +-- YES --> references/playwright-capture.md を参照
  |     +-- NO (既にセッションがある) --> 次へ
  |
  +-- テスト対象の操作はステートフル? (ログイン必要、CSRF トークン、削除系 API 等)
  |     |
  |     +-- YES --> references/self-contained-iteration.md を参照して Macro 設計
  |     +-- NO --> 直接 resend / fuzz で実行
  |
  +-- 攻撃ペイロードの選定が必要?
  |     |
  |     +-- YES --> references/payload-patterns.md を参照
  |     +-- NO --> 次へ
  |
  +-- 単発テスト or 網羅テスト?
        |
        +-- 単発確認 --> execute resend
        +-- 網羅テスト --> execute fuzz
```

検証の全体フローは `references/verify-vulnerability.md` を参照。

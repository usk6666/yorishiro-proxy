---
description: "yorishiro-proxy を使った脆弱性検証ワークフロー"
user-invokable: true
---

# /yorishiro

yorishiro-proxy (MCP プロキシ) を使った脆弱性検証を支援するスキル。
ソースコードレビューで検出された脆弱性を実環境で検証するユースケースに特化。

## トリガー

以下のような指示を受けたとき、このスキルを適用する:

- 「脆弱性を検証して」「このエンドポイントをテストして」
- 「IDOR/SQLi/XSS/CSRF をテストして」
- 「認可バイパスを確認して」「権限昇格を検証して」
- 「このリクエストを改ざんして送り直して」
- 「ファジングを実行して」

## MCP ツール概要

yorishiro-proxy は 10 の MCP ツールを提供する:

| ツール | 用途 |
|--------|------|
| `proxy_start` | プロキシ起動・キャプチャスコープ設定 |
| `proxy_stop` | プロキシ停止 |
| `configure` | 実行中のプロキシ設定変更 (スコープ・TLS パススルー・インターセプトルール・自動変換等) |
| `query` | 統一情報検索 (resource: flows, flow, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results) |
| `resend` | リクエスト再送・リプレイ (action: resend, resend_raw, tcp_replay) |
| `manage` | フローデータ管理・CA 証明書 (action: delete_flows, export_flows, import_flows, regenerate_ca_cert) |
| `fuzz` | ファジング (action: fuzz, fuzz_pause, fuzz_resume, fuzz_cancel) |
| `macro` | マクロワークフロー (action: define_macro, run_macro, delete_macro) |
| `intercept` | インターセプト操作 (action: release, modify_and_forward, drop) |
| `security` | ターゲットスコープ制御 (action: set_target_scope, update_target_scope, get_target_scope, test_target) |

### MCP Resources

各ツールの詳細なヘルプとスキーマは MCP Resources として提供される。
ツールのパラメータや使用例を確認するには、以下の URI でリソースを取得する:

**ヘルプ (使い方・パラメータ説明・例)**:
- `yorishiro://help/proxy_start`, `yorishiro://help/proxy_stop`
- `yorishiro://help/query`, `yorishiro://help/resend`, `yorishiro://help/manage`
- `yorishiro://help/fuzz`, `yorishiro://help/macro`, `yorishiro://help/intercept`
- `yorishiro://help/configure`, `yorishiro://help/security`
- `yorishiro://help/examples` (ワークフロー別の使用例集)

**スキーマ (JSON Schema)**:
- `yorishiro://schema/proxy_start`, `yorishiro://schema/query`
- `yorishiro://schema/resend`, `yorishiro://schema/manage`
- `yorishiro://schema/fuzz`, `yorishiro://schema/macro`
- `yorishiro://schema/intercept`, `yorishiro://schema/configure`

パラメータの正確な構造が不明な場合は、まずヘルプリソースを参照すること。

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
// フロー一覧
{"resource": "flows", "filter": {"url_pattern": "/api/"}, "limit": 50}

// フロー詳細
{"resource": "flow", "id": "<flow-id>"}

// ファズ結果
{"resource": "fuzz_results", "fuzz_id": "<fuzz-id>", "sort_by": "status_code"}
```

### resend -- リクエスト再送

```json
// リクエスト再送
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>",
    "override_headers": {"Authorization": "Bearer <token>"},
    "body_patches": [{"json_path": "$.user_id", "value": 999}],
    "tag": "idor-test"
  }
}
```

### fuzz -- ファジング

```json
{
  "action": "fuzz",
  "params": {
    "flow_id": "<flow-id>",
    "attack_type": "sequential",
    "positions": [
      {
        "id": "pos-0",
        "location": "body_json",
        "json_path": "$.user_id",
        "payload_set": "user-ids"
      }
    ],
    "payload_sets": {
      "user-ids": {"type": "range", "start": 1, "end": 20}
    },
    "tag": "idor-fuzz"
  }
}
```

### macro -- マクロ定義・実行

```json
// マクロ定義
{
  "action": "define_macro",
  "params": {
    "name": "auth-flow",
    "steps": [
      {
        "id": "login",
        "flow_id": "<login-flow-id>",
        "extract": [
          {
            "name": "session_cookie",
            "from": "response",
            "source": "header",
            "header_name": "Set-Cookie",
            "regex": "PHPSESSID=([^;]+)",
            "group": 1
          }
        ]
      }
    ]
  }
}

// マクロ実行
{
  "action": "run_macro",
  "params": {"name": "auth-flow"}
}
```

### manage -- フローデータ管理

```json
// フロー削除
{"action": "delete_flows", "params": {"flow_id": "<flow-id>"}}

// 古いフロー一括削除
{"action": "delete_flows", "params": {"older_than_days": 30, "confirm": true}}

// フローエクスポート
{"action": "export_flows", "params": {"format": "jsonl", "output_path": "/tmp/export.jsonl"}}

// フローインポート
{"action": "import_flows", "params": {"input_path": "/tmp/export.jsonl"}}
```

### intercept -- インターセプト操作

```json
// リクエストを改変して転送
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "<intercept-id>",
    "override_headers": {"Authorization": "Bearer injected-token"}
  }
}

// リクエストをそのまま転送
{"action": "release", "params": {"intercept_id": "<intercept-id>"}}

// リクエストをドロップ
{"action": "drop", "params": {"intercept_id": "<intercept-id>"}}
```

### security -- ターゲットスコープ制御

```json
// ターゲットスコープ設定
{
  "action": "set_target_scope",
  "params": {
    "allows": [{"hostname": "api.target.com", "ports": [443], "schemes": ["https"]}],
    "denies": [{"hostname": "admin.target.com"}]
  }
}

// URL のスコープ判定テスト
{
  "action": "test_target",
  "params": {"url": "https://api.target.com/v1/users"}
}
```

## ワークフロー選択ディシジョンツリー

```
指示を受けた
  |
  +-- トラフィックキャプチャが必要?
  |     |
  |     +-- YES --> references/playwright-capture.md を参照
  |     +-- NO (既にフローがある) --> 次へ
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
        +-- 単発確認 --> resend ツール
        +-- 網羅テスト --> fuzz ツール
```

検証の全体フローは `references/verify-vulnerability.md` を参照。

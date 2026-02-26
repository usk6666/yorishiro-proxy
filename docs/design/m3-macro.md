# M3: Macro 詳細設計

**ステータス**: Draft
**最終更新**: 2026-02-26

---

## 概要

Resender や Fuzzer の送信前・送信後にフックポイントを設定し、そのタイミングで自動実行される一連のリクエストシーケンス。セッション間のパラメータ引き継ぎ、値の抽出・注入、エンコード変換を統合的に管理する。

BurpSuite の Session Handling Rules + Macros に相当するが、MCP ツール経由で AI エージェントが宣言的に定義・実行する。

## 決定事項

| # | 項目 | 決定 | 理由 |
|---|------|------|------|
| 1 | Macro 定義の永続化 | DB 永続化 | macros テーブルに保存。プロキシ再起動後も利用可能 |
| 2 | エラーハンドリング | abort / skip / retry をオプションで選択可 | ステップ単位で指定可能 |
| 3 | 条件分岐 | ステップガード (`when` 条件) | 条件を満たさないステップをスキップ。goto なし、ループなし。線形実行を維持 |
| 4 | ネスト | 不要 | Macro 内から別の Macro は呼べない。複雑性・無限再帰リスクの回避 |
| 5 | 最大ステップ数 | 50 | 無限ループ防止 |
| 6 | タイムアウト | 全体: 5分 (300s)、ステップ単位: 1分 (60s) | オーバーライド可 |
| 7 | エンコーダ実装範囲 | M3: 組み込みエンコーダのみ。M5: WASM プラグイン | 段階的に拡張 |
| 8 | 変数スコープ | Fuzzer イテレーション間で KV Store は共有しない | 各イテレーションで独立した KV Store |
| 9 | Macro の再利用性 | 定義はテンプレートとして共有、実行時の KV Store は呼び出しごとに独立 | #8 で包含 |
| 10 | AI エージェントの利便性 | 現状の設計を維持。MCP Resources のヘルプ・例示で補助 | AI は長い JSON 生成が得意。API 増加の方がリスク |

## コア概念

### Macro = 名前付きリクエストシーケンス

```
Macro "auth-flow":
  Step 1: POST /login         → extract Set-Cookie → store as "session_cookie"
  Step 2: GET /api/csrf-token → extract $.token    → store as "csrf_token"
```

### Hook = Macro の実行トリガー

```
Hook Points:
  pre-send     : Resender/Fuzzer のリクエスト送信前に Macro を実行
  post-receive : Resender/Fuzzer のレスポンス受信後に Macro を実行
```

### KV Store = セッション間のパラメータ受け渡し

```
KV Store (Macro 実行コンテキスト内):
  "session_cookie" → "PHPSESSID=abc123"
  "csrf_token"     → "x9f2k..."
  "base_url"       → "https://target.com"
```

- Macro **定義**は DB に永続化され、名前で参照可能（テンプレート）
- Macro **実行時**の KV Store は呼び出しごとに独立したインスタンス
- Fuzzer の各イテレーション間で KV Store は共有されない

## アーキテクチャ

```
┌─────────────────────────────────────────────────────┐
│                   execute: resend / fuzz             │
│                                                      │
│  1. pre-send hook                                    │
│     └─ Macro "auth-flow" 実行                        │
│        ├─ Step 1: POST /login → extract cookie       │
│        ├─ Step 2: GET /csrf   → extract token        │
│        └─ KV Store に値を格納                         │
│                                                      │
│  2. メインリクエスト送信                               │
│     ├─ KV Store の値でパラメータを置換                 │
│     │   (例: {{csrf_token}} → 実際の値)               │
│     └─ リクエスト送信 → レスポンス受信                  │
│                                                      │
│  3. post-receive hook                                │
│     └─ Macro "validate-response" 実行                │
│        ├─ レスポンスから値を抽出 → KV Store            │
│        └─ (Fuzzer の場合: 次イテレーションには引き継がない) │
└─────────────────────────────────────────────────────┘
```

## MCP インターフェース

### Macro 定義: execute `define_macro` アクション

```json
{
  "action": "define_macro",
  "params": {
    "name": "auth-flow",
    "description": "ログインしてCSRFトークンを取得する",

    "steps": [
      {
        "id": "login",
        "session_id": "recorded-login-session",
        "override_headers": {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "override_body": "username=admin&password={{password}}",
        "on_error": "abort",
        "timeout_ms": 60000,

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
      },
      {
        "id": "get-csrf",
        "session_id": "recorded-csrf-session",
        "override_headers": {
          "Cookie": "PHPSESSID={{session_cookie}}"
        },
        "on_error": "abort",

        "extract": [
          {
            "name": "csrf_token",
            "from": "response",
            "source": "body",
            "regex": "name=\"csrf\" value=\"([^\"]+)\"",
            "group": 1
          }
        ]
      }
    ],

    // --- 初期値 ---
    "initial_vars": {
      "password": "admin123"
    },

    // --- 制限 ---
    "timeout_ms": 300000
  }
}
```

### ステップ単位のエラーハンドリング

| `on_error` | 動作 |
|------------|------|
| `abort` (デフォルト) | Macro 全体をエラー終了。KV Store の現在値を返す |
| `skip` | そのステップをスキップし、次のステップに進む |
| `retry` | 指定回数リトライ。`retry_count` (デフォルト: 3)、`retry_delay_ms` (デフォルト: 1000) で制御 |

```json
{
  "id": "fragile-step",
  "session_id": "...",
  "on_error": "retry",
  "retry_count": 3,
  "retry_delay_ms": 1000
}
```

### タイムアウト

| レベル | パラメータ | デフォルト |
|--------|-----------|-----------|
| Macro 全体 | `timeout_ms` (define_macro の params 直下) | 300000 (5分) |
| ステップ単位 | `timeout_ms` (各 step 内) | 60000 (1分) |

- ステップ単位のタイムアウトが先に発動した場合は `on_error` の挙動に従う
- Macro 全体のタイムアウトが発動した場合は即座に abort（`on_error` 無視）

### Macro 実行: execute `run_macro` アクション

```json
{
  "action": "run_macro",
  "params": {
    "name": "auth-flow",
    "vars": {
      "password": "override-password"
    }
  }
}
```

#### レスポンス

```json
{
  "macro_name": "auth-flow",
  "status": "completed",
  "steps_executed": 2,
  "kv_store": {
    "password": "override-password",
    "session_cookie": "PHPSESSID=abc123def456",
    "csrf_token": "x9f2k8m3n..."
  },
  "step_results": [
    {
      "id": "login",
      "session_id": "new-session-001",
      "status_code": 302,
      "duration_ms": 250
    },
    {
      "id": "get-csrf",
      "session_id": "new-session-002",
      "status_code": 200,
      "duration_ms": 120
    }
  ]
}
```

### Hook 設定: Resender / Fuzzer のパラメータとして

```json
{
  "action": "resend",
  "params": {
    "session_id": "target-request",
    "override_headers": {
      "Cookie": "PHPSESSID={{session_cookie}}",
      "X-CSRF-Token": "{{csrf_token}}"
    },

    "hooks": {
      "pre_send": {
        "macro": "auth-flow",
        "vars": {"password": "admin123"}
      },
      "post_receive": {
        "macro": "log-response",
        "pass_response": true
      }
    }
  }
}
```

Fuzzer との連携:

```json
{
  "action": "fuzz",
  "params": {
    "session_id": "target-request",
    "attack_type": "sequential",
    "positions": [
      {
        "id": "pos-0",
        "location": "body_json",
        "json_path": "$.user_id",
        "payload_set": "ids"
      }
    ],
    "payload_sets": {
      "ids": {"type": "range", "start": 1, "end": 100, "step": 1}
    },
    "override_headers": {
      "Cookie": "PHPSESSID={{session_cookie}}",
      "X-CSRF-Token": "{{csrf_token}}"
    },

    "hooks": {
      "pre_send": {
        "macro": "auth-flow",
        "run_interval": "every_n",
        "n": 10
      }
    }
  }
}
```

## 値抽出ルール

### 抽出ソース

| source | 対象 | 指定方法 |
|--------|------|----------|
| `header` | レスポンス/リクエストヘッダ | `header_name` + `regex` |
| `body` | レスポンス/リクエストボディ | `regex` |
| `body_json` | JSON ボディ | `json_path` |
| `status` | ステータスコード | (そのまま数値) |
| `url` | レスポンスの Location 等 | `regex` |

### 抽出ルール構造

```json
{
  "name": "variable_name",
  "from": "response",
  "source": "header",
  "header_name": "Set-Cookie",
  "regex": "token=([^;]+)",
  "group": 1,
  "default": "fallback-value",
  "required": true
}
```

- `from`: `"request"` | `"response"` — 抽出元
- `group`: 正規表現のキャプチャグループ番号 (0 = 全体マッチ)
- `default`: マッチしない場合のフォールバック値
- `required`: true の場合、抽出失敗で Macro をエラー終了

## 変数テンプレート構文

`{{variable_name}}` で KV Store の値を参照。

### 適用箇所

- `override_headers` の値
- `override_body` の文字列
- `override_url` の文字列
- Macro ステップ内の各 override フィールド
- Resender / Fuzzer の override フィールド (hooks 経由で KV Store が注入された場合)

### エンコーダ (M3: 組み込みのみ)

変数参照時にパイプ構文でエンコーダを適用:

```
{{variable_name | url_encode}}
{{variable_name | base64}}
{{variable_name | html_encode}}
{{csrf_token | url_encode | base64}}     ← チェーン
```

#### 組み込みエンコーダ

| エンコーダ | 説明 |
|-----------|------|
| `url_encode` | URL パーセントエンコーディング |
| `base64` | Base64 エンコード |
| `base64_decode` | Base64 デコード |
| `html_encode` | HTML エンティティエンコード |
| `hex` | 16 進エンコード |
| `lower` | 小文字化 |
| `upper` | 大文字化 |
| `md5` | MD5 ハッシュ |
| `sha256` | SHA-256 ハッシュ |

#### カスタムエンコーダ (M5: WASM プラグイン)

```
{{raw_data | custom:my_encoder}}         ← M5 で実装予定
```

```json
{
  "action": "register_encoder",
  "params": {
    "name": "my_encoder",
    "wasm_path": "encoders/my_encoder.wasm",
    "function": "encode"
  }
}
```

> **Note**: WASM プラグインは M5 スコープ。M3 では組み込みエンコーダのみ。設計上の拡張ポイントとして `custom:` プレフィックスを予約しておく。

## Macro のライフサイクル

```
define_macro  → Macro 定義を DB に保存 (名前で参照可能)
run_macro     → 単独実行 (テスト用)
resend/fuzz   → hooks.pre_send / hooks.post_receive で自動実行
list_macros   → 定義済み Macro 一覧 (query resource)
delete_macro  → Macro 定義を削除
```

## Hook 実行タイミング

### pre_send

| オプション | 説明 |
|-----------|------|
| `always` (デフォルト) | 毎回実行 |
| `once` | 最初の 1 回のみ |
| `every_n` | N リクエストごとに実行 (トークンリフレッシュ等) |
| `on_error` | 前回のメインリクエストがエラー (4xx/5xx) だった場合のみ |

### post_receive

| オプション | 説明 |
|-----------|------|
| `always` (デフォルト) | 毎回実行 |
| `on_status` | 特定のステータスコード時のみ |
| `on_match` | レスポンスボディが特定パターンにマッチ時 |

## 制限事項

| 制限 | 値 | 理由 |
|------|-----|------|
| 最大ステップ数 | 50 | 無限ループ防止 |
| Macro ネスト | 不可 | Macro 内から別の Macro を呼ぶことは禁止。無限再帰防止 |
| Macro 全体タイムアウト | 300s (デフォルト) | オーバーライド可 |
| ステップ単位タイムアウト | 60s (デフォルト) | オーバーライド可 |

## ステップガード (`when` 条件)

各ステップに `when` を付与すると、条件を満たす場合のみ実行され、満たさない場合はスキップされる。`when` 未指定のステップは常に実行される。

### 条件構造

```json
{
  "id": "mfa-step",
  "when": {
    "step": "login",
    "status_code": 302,
    "header_match": {"Location": "/mfa.*"}
  },
  "session_id": "recorded-mfa-session",
  "override_body": "otp={{otp_code}}",
  "extract": [...]
}
```

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `step` | string | 参照先ステップ ID。そのステップの実行結果に対して条件評価 |
| `status_code` | int | ステータスコード完全一致 |
| `status_code_range` | [int, int] | ステータスコード範囲 (例: [200, 299]) |
| `header_match` | map[string]string | ヘッダ値の正規表現マッチ (全条件 AND) |
| `body_match` | string | レスポンスボディの正規表現マッチ |
| `extracted_var` | string | KV Store 内の変数名。値が存在すれば true |
| `negate` | bool | true の場合、条件全体を反転 (NOT) |

複数条件を指定した場合は **AND** で評価。

### 使用例: MFA 分岐

```json
{
  "action": "define_macro",
  "params": {
    "name": "auth-with-mfa",
    "steps": [
      {
        "id": "login",
        "session_id": "recorded-login",
        "override_body": "user=admin&pass={{password}}",
        "extract": [
          {"name": "session_cookie", "from": "response", "source": "header",
           "header_name": "Set-Cookie", "regex": "sid=([^;]+)", "group": 1}
        ]
      },
      {
        "id": "mfa",
        "when": {"step": "login", "status_code": 302, "header_match": {"Location": "/mfa.*"}},
        "session_id": "recorded-mfa",
        "override_headers": {"Cookie": "sid={{session_cookie}}"},
        "override_body": "otp=123456",
        "extract": [
          {"name": "session_cookie", "from": "response", "source": "header",
           "header_name": "Set-Cookie", "regex": "sid=([^;]+)", "group": 1}
        ]
      },
      {
        "id": "get-csrf",
        "session_id": "recorded-csrf",
        "override_headers": {"Cookie": "sid={{session_cookie}}"},
        "extract": [
          {"name": "csrf_token", "from": "response", "source": "body_json",
           "json_path": "$.csrf_token"}
        ]
      }
    ],
    "initial_vars": {"password": "admin123"}
  }
}
```

動作:
1. `login` → 常に実行
2. `mfa` → login が 302 + Location が `/mfa.*` にマッチした場合のみ実行
3. `get-csrf` → 常に実行 (when なし)

### 使用例: エンドポイントフォールバック

```json
{
  "steps": [
    {"id": "try-v2", "session_id": "api-v2-req", "extract": [...]},
    {
      "id": "fallback-v1",
      "when": {"step": "try-v2", "status_code": 404},
      "session_id": "api-v1-req",
      "extract": [...]
    }
  ]
}
```

### 評価ルール

- `when` で参照する `step` はそのステップより前に定義されている必要がある (前方参照のみ)
- 参照先ステップがスキップされていた場合、`when` は false と評価される
- `when` の条件評価は Macro エンジン内部で行い、リクエスト送信は発生しない

## セキュリティ考慮事項

- Macro ステップも SSRF 防御対象
- KV Store の値は機密情報 (トークン等) を含む可能性 — ログ出力時のマスキング
- WASM プラグイン (M5) のサンドボックス実行
- 最大ステップ数 + タイムアウトで暴走防止

## データモデル拡張

```sql
CREATE TABLE macros (
  name        TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  config      TEXT NOT NULL,       -- JSON: steps, initial_vars, timeout_ms, etc.
  created_at  DATETIME NOT NULL,
  updated_at  DATETIME NOT NULL
);
```

## 実装方針

- `internal/macro/` パッケージとして分離
  - `engine.go` — Macro 実行エンジン (ステップ実行、値抽出、KV Store)
  - `template.go` — `{{var | encoder}}` テンプレート展開 + エンコーダチェーン
  - `extract.go` — 値抽出ルール (regex, json_path, header)
  - `encoder.go` — 組み込みエンコーダ群
- `execute_tool.go` に `define_macro` / `run_macro` / `delete_macro` アクション追加
- `query_tool.go` に `macros` resource 追加
- Resender / Fuzzer の `hooks` パラメータを追加
- hooks 実行は Resender/Fuzzer のメインループ内でインライン呼び出し
- 各実行コンテキスト (resend 呼び出し / fuzz イテレーション) ごとに独立した KV Store インスタンスを生成

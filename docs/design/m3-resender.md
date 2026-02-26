# M3: Resender 詳細設計

**ステータス**: Draft
**最終更新**: 2026-02-25

---

## 概要

記録済みリクエストの内容を改変して再送する機能。
既存の `execute` ツールの `replay` / `replay_raw` アクションを `resend` / `resend_raw` にリネームし、改変オプションを拡張する。

## 命名

**決定**: 機能名 **Resender**、アクション名 `resend`

| 候補 | 根拠 | 採否 |
|------|------|------|
| `replay` (現行) | 既に実装済み。「記録を再生する」のニュアンス | 不採用 |
| `repeat` | BurpSuite の Repeater に近い | 不採用 |
| `resend` | 最もジェネリック。ツール非依存 | **採用** |

既存の `replay` / `replay_raw` アクションは `resend` / `resend_raw` にリネーム。
後方互換のため旧名を非推奨エイリアスとして一定期間維持するかは要検討。

## 現状 (M2 完了時点)

`execute` の `replay` アクションで以下の改変が可能:

```json
{
  "action": "replay",
  "params": {
    "session_id": "abc-123",
    "override_method": "POST",
    "override_url": "https://target.com/api/v2/users",
    "override_headers": {"Authorization": "Bearer new-token"},
    "override_body": "{\"name\": \"test\"}"
  }
}
```

### 現行の制約

- `override_headers` は単一値のみ（同名ヘッダの複数値に非対応）
- `override_body` は文字列のみ（バイナリ非対応）
- ボディの部分改変不可（全置換のみ）
- リクエストのプレビュー（dry-run）なし
- `replay_raw` は改変オプションなし（完全忠実リプレイのみ）

## 決定事項

| # | 項目 | 決定 | 理由 |
|---|------|------|------|
| 1 | URL 改変の粒度 | `override_url` のみ | `override_url` で path / query を包含できるため、部品分割は不要 |
| 2 | body_patches | Resender に実装する | Fuzzer とは用途が異なる。Resender は手動精密改変、Fuzzer は自動反復。両方に必要 |
| 3 | diff サマリ | 不要 | レスポンスに含めない |
| 4 | dry-run | 実装する | AI エージェントが改変結果を送信前に確認するために必要 |
| 5 | resend_raw 拡張 | 生バイト部分改変を実装 | TLS 復号後の平文に対して編集する。暗号化状態での改変需要はない |

## resend アクション仕様

### パラメータ

```json
{
  "action": "resend",
  "params": {
    "session_id": "abc-123",

    // --- リクエストライン改変 ---
    "override_method": "POST",
    "override_url": "https://target.com/api/v2/users?page=2",

    // --- ヘッダ改変 ---
    "override_headers": {"Authorization": "Bearer new-token"},
    "add_headers": {"X-Custom": "value"},
    "remove_headers": ["X-Unwanted"],

    // --- ボディ改変 (全置換) ---
    "override_body": "{\"name\": \"test\"}",
    "override_body_base64": "...",

    // --- ボディ改変 (部分パッチ) ---
    "body_patches": [
      {"json_path": "$.user.name", "value": "injected"},
      {"regex": "csrf_token=[^&]+", "replace": "csrf_token=newvalue"}
    ],

    // --- 接続先変更 ---
    "override_host": "staging.target.com:8443",

    // --- オプション ---
    "follow_redirects": false,
    "timeout_ms": 10000,
    "dry_run": false,
    "tag": "auth-bypass-test-01"
  }
}
```

### パラメータ詳細

| パラメータ | 型 | 説明 |
|-----------|-----|------|
| `session_id` | string | **必須**。テンプレートとなる記録済みセッション ID |
| `override_method` | string | HTTP メソッドを変更 |
| `override_url` | string | リクエスト URL 全体を変更 (scheme + host + path + query) |
| `override_headers` | map[string]string | ヘッダ値を上書き (既存キーは置換、新規キーは追加) |
| `add_headers` | map[string]string | ヘッダを追加 (既存キーと共存、値を追記) |
| `remove_headers` | []string | 指定ヘッダを削除 |
| `override_body` | string | ボディ全体を文字列で置換 |
| `override_body_base64` | string | ボディ全体を Base64 デコードしたバイナリで置換 |
| `body_patches` | []BodyPatch | ボディの部分改変ルール (後述) |
| `override_host` | string | 接続先ホスト:ポートを変更 (URL の host と独立に TCP 接続先を指定) |
| `follow_redirects` | bool | リダイレクトを自動追従するか (デフォルト: false) |
| `timeout_ms` | int | リクエストタイムアウト (デフォルト: 30000) |
| `dry_run` | bool | true の場合、送信せず改変後リクエストをプレビュー返却 |
| `tag` | string | 結果セッションにタグを付与 |

### ボディ改変の優先順位

1. `override_body` / `override_body_base64` が指定された場合 → ボディ全体を置換 (body_patches は無視)
2. `body_patches` のみ指定された場合 → 元のボディに対してパッチを順次適用

### BodyPatch 構造

```json
// JSON Path によるパッチ
{"json_path": "$.user.name", "value": "injected"}

// 正規表現によるパッチ
{"regex": "csrf_token=[^&]+", "replace": "csrf_token=newvalue"}
```

| フィールド | 型 | 説明 |
|-----------|-----|------|
| `json_path` | string | JSON Path 式。ボディが JSON の場合にマッチした値を置換 |
| `regex` | string | 正規表現パターン。ボディをテキストとしてマッチ |
| `value` | string | `json_path` 使用時の置換値 |
| `replace` | string | `regex` 使用時の置換文字列 (キャプチャグループ `$1` 等使用可) |

`json_path` と `regex` は排他。1 つの BodyPatch にどちらか一方を指定する。

### ヘッダ改変の適用順序

1. `remove_headers` — 指定ヘッダを削除
2. `override_headers` — 既存ヘッダを上書き (キーが存在すれば値を置換、存在しなければ追加)
3. `add_headers` — ヘッダ値を追記 (同名ヘッダの複数値に対応)

### レスポンス形式

#### 通常レスポンス

```json
{
  "new_session_id": "def-456",
  "status_code": 200,
  "response_headers": {"Content-Type": ["application/json"]},
  "response_body": "{\"result\": \"ok\"}",
  "response_body_encoding": "text",
  "duration_ms": 145,
  "tag": "auth-bypass-test-01"
}
```

#### dry-run レスポンス

```json
{
  "dry_run": true,
  "request_preview": {
    "method": "POST",
    "url": "https://target.com/api/v2/users?page=2",
    "headers": {
      "Authorization": ["Bearer new-token"],
      "X-Custom": ["value"],
      "Content-Type": ["application/json"]
    },
    "body": "{\"user\": {\"name\": \"injected\"}}",
    "body_encoding": "text"
  }
}
```

## resend_raw アクション仕様

TLS 復号済みの平文バイト列に対して部分改変を行い、再送する。

### パラメータ

```json
{
  "action": "resend_raw",
  "params": {
    "session_id": "abc-123",

    // --- 接続先 ---
    "target_addr": "target.com:443",
    "use_tls": true,

    // --- 生バイト部分改変 ---
    "patches": [
      {"offset": 128, "data_base64": "bmV3LXZhbHVl"},
      {"find_base64": "b2xkLXZhbHVl", "replace_base64": "bmV3LXZhbHVl"},
      {"find_text": "old-value", "replace_text": "new-value"}
    ],

    // --- 全置換 (patches と排他) ---
    "override_raw_base64": "...",

    // --- オプション ---
    "timeout_ms": 10000,
    "dry_run": false,
    "tag": "raw-test-01"
  }
}
```

### RawPatch 構造

| パッチ方式 | フィールド | 説明 |
|-----------|-----------|------|
| オフセット指定 | `offset` + `data_base64` | 指定バイト位置から Base64 デコードしたデータで上書き |
| バイナリ検索置換 | `find_base64` + `replace_base64` | バイト列の検索・置換 |
| テキスト検索置換 | `find_text` + `replace_text` | テキストとして検索・置換 |

### TLS の扱い

- `raw_bytes` は **TLS 復号後の平文**として保存されている
- パッチは平文に対して適用する
- 送信時に `use_tls: true` であれば TLS ハンドシェイク後に送信
- 暗号化状態のまま編集する機能は提供しない

### レスポンス形式

```json
{
  "new_session_id": "ghi-789",
  "response_data": "...",
  "response_data_encoding": "base64",
  "response_size": 4096,
  "duration_ms": 230,
  "tag": "raw-test-01"
}
```

#### dry-run レスポンス

```json
{
  "dry_run": true,
  "raw_preview": {
    "data_base64": "...",
    "data_size": 512,
    "patches_applied": 3
  }
}
```

## Macro との連携ポイント

- Macro の pre-send hook で Resender のパラメータを動的に上書きできる
- Macro の post-receive hook で Resender のレスポンスから値を抽出できる
- `{{variable}}` テンプレート構文で KV Store の値をパラメータに注入
- 詳細は [m3-macro.md](./m3-macro.md) を参照

## セキュリティ考慮事項

- 既存の SSRF 防御 (`denyPrivateNetwork`) を維持
- `override_host` / `target_addr` にもプライベートネットワーク検証を適用
- レスポンスサイズ上限 (1MB) を維持
- タイムアウト制御

## 実装方針

- `execute_tool.go` の `handleExecuteReplay` → `handleExecuteResend` にリネーム・拡張
- `handleExecuteReplayRaw` → `handleExecuteResendRaw` にリネーム・拡張
- `executeParams` 構造体にフィールド追加
- ボディパッチエンジンは `internal/mcp/` 内のヘルパーとして実装
- MCP Resources (`katashiro://help/execute`) のヘルプ更新
- 既存テストの互換性維持（後方互換）

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

yorishiro-proxy は 11 の MCP ツールを提供する:

| ツール | 用途 |
|--------|------|
| `proxy_start` | プロキシ起動・キャプチャスコープ設定。マルチリスナー・SOCKS5 対応 |
| `proxy_stop` | プロキシ停止。名前指定で個別停止、省略で全停止 |
| `configure` | 実行中のプロキシ設定変更 (スコープ・TLS パススルー・インターセプトルール・自動変換・upstream proxy・接続制限・SOCKS5 認証等) |
| `query` | 統一情報検索 (resource: flows, flow, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results, technologies) |
| `resend` | リクエスト再送・リプレイ・比較 (action: resend, resend_raw, tcp_replay, compare) |
| `manage` | フローデータ管理・CA 証明書 (action: delete_flows, export_flows, import_flows, regenerate_ca_cert) |
| `fuzz` | ファジング (action: fuzz, fuzz_pause, fuzz_resume, fuzz_cancel) |
| `macro` | マクロワークフロー (action: define_macro, run_macro, delete_macro) |
| `intercept` | インターセプト操作。リクエスト/レスポンス両 phase 対応 (action: release, modify_and_forward, drop) |
| `security` | ターゲットスコープ・レート制限・診断バジェット・SafetyFilter 制御。Policy/Agent 2 層構造 (action: set_target_scope, update_target_scope, get_target_scope, test_target, set_rate_limits, get_rate_limits, set_budget, get_budget, get_safety_filter) |
| `plugin` | Starlark プラグイン管理 (action: list, reload, enable, disable) |

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
// 基本起動
{
  "listen_addr": "127.0.0.1:8080",
  "capture_scope": {
    "includes": [{"hostname": "target.example.com"}],
    "excludes": [{"hostname": "static.example.com"}]
  },
  "tls_passthrough": ["*.googleapis.com"]
}

// マルチリスナー・追加オプション付き起動
{
  "name": "socks-listener",
  "listen_addr": "127.0.0.1:1080",
  "protocols": ["SOCKS5", "HTTPS", "HTTP/1.x"],
  "upstream_proxy": "http://corporate-proxy:3128",
  "max_connections": 256,
  "peek_timeout_ms": 5000,
  "request_timeout_ms": 30000
}
```

#### proxy_start パラメータ

| パラメータ | 型 | 説明 |
|-----------|------|------|
| `name` | string | リスナー名（デフォルト: "default"）。マルチリスナー時に識別用 |
| `listen_addr` | string | リッスンアドレス（デフォルト: "127.0.0.1:8080"） |
| `upstream_proxy` | string | 上流プロキシ URL（http:// または socks5://[user:pass@]host:port） |
| `capture_scope` | object | キャプチャスコープ（includes/excludes） |
| `tls_passthrough` | string[] | TLS パススルー対象パターン |
| `intercept_rules` | object[] | インターセプトルール（id, enabled, direction, conditions） |
| `auto_transform` | object[] | 自動変換ルール（id, enabled, priority, direction, conditions, action） |
| `tcp_forwards` | map | TCP ポートフォワード（port -> upstream_host:port） |
| `protocols` | string[] | 有効プロトコル（HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, SOCKS5, TCP） |
| `socks5_auth` | string | SOCKS5 認証方法（"none" or "password"） |
| `socks5_username` | string | SOCKS5 ユーザー名 |
| `socks5_password` | string | SOCKS5 パスワード |
| `max_connections` | int | 最大同時接続数（デフォルト: 128、範囲: 1-100000） |
| `peek_timeout_ms` | int | プロトコル検出タイムアウト（デフォルト: 30000） |
| `request_timeout_ms` | int | HTTP リクエストヘッダ読み込みタイムアウト（デフォルト: 60000） |
| `tls_fingerprint` | string | TLS フィンガープリントプロファイル（"chrome", "firefox", "safari", "edge", "random", "none"。デフォルト: "chrome"） |
| `client_cert` | string | PEM クライアント証明書パス（mTLS 用、client_key と併用） |
| `client_key` | string | PEM クライアント秘密鍵パス（mTLS 用、client_cert と併用） |

### proxy_stop -- プロキシ停止

```json
// 特定リスナーを停止
{"name": "socks-listener"}

// 全リスナーを停止
{}
```

### query -- 情報取得

```json
// フロー一覧
{"resource": "flows", "filter": {"url_pattern": "/api/"}, "limit": 50}

// フロー詳細
{"resource": "flow", "id": "<flow-id>"}

// 状態フィルタ（active/complete/error）
{"resource": "flows", "filter": {"state": "complete", "tag": "idor-test"}}

// プロトコルフィルタ
{"resource": "flows", "filter": {"protocol": "SOCKS5+HTTPS"}}

// ブロックされたフロー
{"resource": "flows", "filter": {"blocked_by": "target_scope"}}

// WebSocket/gRPC メッセージ（direction フィルタ）
{"resource": "messages", "id": "<flow-id>", "filter": {"direction": "send"}}

// ファズジョブ一覧（status/tag フィルタ）
{"resource": "fuzz_jobs", "filter": {"status": "running", "tag": "sqli-fuzz"}}

// ファズ結果
{"resource": "fuzz_results", "fuzz_id": "<fuzz-id>", "sort_by": "status_code"}

// ファズ結果の外れ値のみ取得
{"resource": "fuzz_results", "fuzz_id": "<fuzz-id>", "filter": {"outliers_only": true}}

// コネクション ID でフロー検索
{"resource": "flows", "filter": {"conn_id": "abc-conn-123"}}

// ホストでフロー検索
{"resource": "flows", "filter": {"host": "example.com"}}

// 技術スタック検出結果
{"resource": "technologies"}
```

#### query フィルタパラメータ

| パラメータ | 対象リソース | 説明 |
|-----------|-------------|------|
| `protocol` | flows | プロトコル名（HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP, SOCKS5+HTTPS 等） |
| `scheme` | flows | URL スキーム / トランスポートフィルタ（"https", "http", "wss", "ws", "tcp"）。TLS フローの検索に使用 |
| `method` | flows | HTTP メソッド |
| `url_pattern` | flows | URL サブストリング検索 |
| `status_code` | flows, fuzz_results | HTTP レスポンスコード |
| `state` | flows | フロー状態（"active", "complete", "error"） |
| `blocked_by` | flows | ブロック理由（"target_scope", "intercept_drop", "rate_limit", "safety_filter"） |
| `conn_id` | flows | コネクション ID 完全一致。同一接続のフローを検索 |
| `host` | flows | ホスト名フィルタ。server_addr または URL のホスト部分にマッチ |
| `technology` | flows | 技術スタック名（大文字小文字不問のサブストリングマッチ、例: "nginx"） |
| `tag` | fuzz_jobs | タグ完全一致 |
| `direction` | messages | メッセージ方向（"send", "receive"） |
| `status` | fuzz_jobs | ジョブ状態（"running", "paused", "completed", "cancelled", "error"） |
| `body_contains` | fuzz_results | レスポンスボディサブストリング |
| `outliers_only` | fuzz_results | 外れ値のみ返す（ステータスコード・ボディ長・タイミングの偏差で検出） |

fuzz_results には集約統計（`summary.statistics`: status_code_distribution, body_length, timing_ms の min/max/median/stddev）と外れ値検出（`summary.outliers`: by_status_code, by_body_length, by_timing）が含まれる。

フロー詳細には `protocol_summary`（プロトコル固有情報）、ストリーミング系フローには `message_preview`（最初 10 メッセージ）が含まれる。resend で生成されたフローは `variant: "modified"` となる。

### resend -- リクエスト再送・比較

```json
// HTTP リクエスト再送（ヘッダ追加・削除）
{
  "action": "resend",
  "params": {
    "flow_id": "<flow-id>",
    "override_headers": {"Authorization": "Bearer <token>"},
    "add_headers": {"X-Forwarded-For": "127.0.0.1"},
    "remove_headers": ["Cookie"],
    "body_patches": [{"json_path": "$.user_id", "value": 999}],
    "follow_redirects": false,
    "tag": "idor-test"
  }
}

// 生リクエスト再送（HTTP パースをバイパス）
{
  "action": "resend_raw",
  "params": {
    "flow_id": "<flow-id>",
    "override_raw_base64": "<base64-encoded-raw-request>",
    "target_addr": "api.target.com:443",
    "use_tls": true,
    "tag": "smuggling-test"
  }
}

// TCP リプレイ（WebSocket/TCP フローのメッセージを再送）
{
  "action": "tcp_replay",
  "params": {
    "flow_id": "<websocket-flow-id>",
    "message_sequence": 3,
    "timeout_ms": 10000,
    "tag": "ws-replay"
  }
}

// 2 フローの構造化比較
{
  "action": "compare",
  "params": {
    "flow_id_a": "<original-flow-id>",
    "flow_id_b": "<modified-flow-id>"
  }
}
```

#### resend 追加パラメータ

| パラメータ | アクション | 説明 |
|-----------|-----------|------|
| `override_method` | resend | HTTP メソッド上書き |
| `override_url` | resend | URL 上書き |
| `add_headers` | resend | ヘッダ追加 |
| `remove_headers` | resend | ヘッダ削除 |
| `override_host` | resend | ホスト上書き（host:port 形式） |
| `follow_redirects` | resend | リダイレクト追従（デフォルト: false） |
| `message_sequence` | resend | WebSocket メッセージシーケンス番号（WebSocket フロー必須） |
| `timeout_ms` | resend, resend_raw, tcp_replay | タイムアウト（ミリ秒） |
| `override_raw_base64` | resend_raw | Base64 エンコード済み生リクエストデータ |
| `target_addr` | resend_raw | ターゲットアドレス（host:port） |
| `use_tls` | resend_raw | TLS 使用フラグ |
| `patches` | resend_raw | バイトレベルパッチ |
| `dry_run` | resend, resend_raw | 送信せず改変内容をプレビュー |
| `tag` | resend, resend_raw, tcp_replay | 結果フローにタグを付与 |

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
      "user-ids": {"type": "range", "start": 1, "end": 20, "step": 2}
    },
    "rate_limit_rps": 10,
    "delay_ms": 100,
    "timeout_ms": 15000,
    "max_retries": 2,
    "concurrency": 1,
    "tag": "idor-fuzz"
  }
}
```

#### fuzz 追加パラメータ

| パラメータ | 説明 |
|-----------|------|
| `rate_limit_rps` | RPS リミット（0 = 無制限） |
| `delay_ms` | リクエスト間の固定遅延（ミリ秒） |
| `timeout_ms` | リクエストタイムアウト（デフォルト: 30000） |
| `max_retries` | リトライ回数 |
| `stop_on` | 自動停止条件 |

#### PayloadSet の type

| type | フィールド | 説明 |
|------|-----------|------|
| `wordlist` | `values` | 文字列リスト |
| `file` | `path` | ファイルパス（1 行 1 ペイロード） |
| `range` | `start`, `end`, `step` | 整数範囲（step デフォルト: 1） |
| `sequence` | `start`, `end`, `format` | フォーマット付き連番（例: "user%04d"） |

### macro -- マクロ定義・実行

```json
// マクロ定義（条件付きステップ・リトライ・初期変数）
{
  "action": "define_macro",
  "params": {
    "name": "auth-flow",
    "initial_vars": {"base_url": "https://api.target.com"},
    "macro_timeout_ms": 30000,
    "steps": [
      {
        "id": "login",
        "flow_id": "<login-flow-id>",
        "retry_count": 2,
        "retry_delay_ms": 1000,
        "timeout_ms": 10000,
        "extract": [
          {
            "name": "session_cookie",
            "from": "response",
            "source": "header",
            "header_name": "Set-Cookie",
            "regex": "PHPSESSID=([^;]+)",
            "group": 1,
            "required": true
          },
          {
            "name": "user_data",
            "from": "response",
            "source": "body_json",
            "json_path": "$.data.id",
            "default": "unknown"
          }
        ]
      },
      {
        "id": "fetch-profile",
        "flow_id": "<profile-flow-id>",
        "when": {
          "step": "login",
          "status_code": 200
        }
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

#### extract ルール追加フィールド

| フィールド | 説明 |
|-----------|------|
| `json_path` | JSON パスによる値抽出（source: body_json 時） |
| `required` | true の場合、抽出失敗でステップをエラーにする |
| `default` | 抽出失敗時のデフォルト値 |

#### when (条件付きステップ)

| フィールド | 説明 |
|-----------|------|
| `step` | 参照する先行ステップ ID |
| `status_code` | 期待するステータスコード |
| `status_code_range` | ステータスコード範囲（例: [200, 299]） |
| `header_match` | ヘッダ値マッチ（map） |
| `body_match` | ボディ正規表現マッチ |
| `extracted_var` | 抽出変数の存在チェック |
| `negate` | 条件を反転 |

### manage -- フローデータ管理

```json
// フロー削除（プロトコルフィルタ付き）
{"action": "delete_flows", "params": {"protocol": "TCP", "older_than_days": 7, "confirm": true}}

// フローエクスポート（フィルタ・ボディ制御）
{
  "action": "export_flows",
  "params": {
    "format": "jsonl",
    "output_path": "/tmp/export.jsonl",
    "include_bodies": false,
    "filter": {"protocol": "HTTPS", "url_pattern": "/api/"}
  }
}

// フローインポート（競合時の動作指定）
{
  "action": "import_flows",
  "params": {
    "input_path": "/tmp/export.jsonl",
    "on_conflict": "replace"
  }
}
```

#### manage 追加パラメータ

| パラメータ | アクション | 説明 |
|-----------|-----------|------|
| `protocol` | delete_flows | プロトコルフィルタ |
| `include_bodies` | export_flows | メッセージボディを含めるか（デフォルト: true） |
| `filter` | export_flows | エクスポートフィルタ（protocol, url_pattern, 時間範囲等） |
| `on_conflict` | import_flows | 競合時の動作（"skip" or "replace"、デフォルト: skip） |

### intercept -- インターセプト操作

```json
// リクエスト phase: 改変して転送
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "<intercept-id>",
    "override_method": "PUT",
    "override_url": "/api/v2/users/1",
    "override_headers": {"Authorization": "Bearer injected-token"},
    "add_headers": {"X-Debug": "true"},
    "remove_headers": ["X-Request-Id"]
  }
}

// レスポンス phase: ステータス・ヘッダ・ボディを改変
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "<intercept-id>",
    "override_status": 200,
    "override_response_headers": {"Content-Type": "application/json"},
    "add_response_headers": {"X-Injected": "true"},
    "remove_response_headers": ["X-Frame-Options"],
    "override_response_body": "{\"admin\": true}"
  }
}

// リクエストをそのまま転送
{"action": "release", "params": {"intercept_id": "<intercept-id>"}}

// リクエストをドロップ
{"action": "drop", "params": {"intercept_id": "<intercept-id>"}}

// raw モードで生バイトを転送
{
  "action": "modify_and_forward",
  "params": {
    "intercept_id": "<intercept-id>",
    "mode": "raw",
    "raw_override_base64": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg=="
  }
}
```

#### intercept パラメータ

| パラメータ | phase | 説明 |
|-----------|-------|------|
| `override_method` | request | HTTP メソッド上書き |
| `override_url` | request | URL 上書き |
| `override_headers` | request | リクエストヘッダ上書き |
| `add_headers` | request | リクエストヘッダ追加 |
| `remove_headers` | request | リクエストヘッダ削除 |
| `override_body` | request | リクエストボディ上書き |
| `override_status` | response | ステータスコード上書き |
| `override_response_headers` | response | レスポンスヘッダ上書き |
| `add_response_headers` | response | レスポンスヘッダ追加 |
| `remove_response_headers` | response | レスポンスヘッダ削除 |
| `override_response_body` | response | レスポンスボディ上書き |
| `override_body` | websocket_frame | WebSocket フレームペイロード上書き |
| `mode` | all | 転送モード（"structured" or "raw"。デフォルト: "structured"） |
| `raw_override_base64` | all (raw mode) | Base64 エンコード済み生バイト（raw モード時の modify_and_forward 用） |

### security -- ターゲットスコープ制御

yorishiro-proxy のスコープ制御は 2 層構造:

- **Policy Layer**: 設定ファイルで定義される不変のスコープ。エージェントからは変更不可
- **Agent Layer**: MCP ツールで動的に変更可能。Policy Layer の制約内でのみ有効

```json
// ターゲットスコープ設定
{
  "action": "set_target_scope",
  "params": {
    "allows": [{"hostname": "api.target.com", "ports": [443], "schemes": ["https"], "path_prefix": "/api/v1"}],
    "denies": [{"hostname": "admin.target.com"}]
  }
}

// ターゲットスコープ更新（既存に追加）
{
  "action": "update_target_scope",
  "params": {
    "add_allows": [{"hostname": "staging.target.com", "ports": [443]}],
    "add_denies": [{"hostname": "internal.target.com"}]
  }
}

// 現在のスコープ取得
{"action": "get_target_scope"}

// URL のスコープ判定テスト
{
  "action": "test_target",
  "params": {"url": "https://api.target.com/v1/users"}
}

// レート制限設定（グローバル 10 RPS、ホスト別 5 RPS）
{
  "action": "set_rate_limits",
  "params": {
    "max_requests_per_second": 10,
    "max_requests_per_host_per_second": 5
  }
}

// 現在のレート制限取得
{"action": "get_rate_limits"}

// 診断バジェット設定（最大 1000 リクエスト、30 分）
{
  "action": "set_budget",
  "params": {
    "max_total_requests": 1000,
    "max_duration": "30m"
  }
}

// 現在のバジェット・使用状況取得
{"action": "get_budget"}
```

#### ターゲットルール パラメータ

| パラメータ | 説明 |
|-----------|------|
| `hostname` | ホスト名 |
| `ports` | ポートリスト（省略時は全ポート） |
| `schemes` | スキーム（http, https 等。省略時は全スキーム） |
| `path_prefix` | パスプレフィックス（省略時は全パス） |

#### レート制限パラメータ

| パラメータ | 説明 |
|-----------|------|
| `max_requests_per_second` | グローバル RPS 制限（0 = 無制限） |
| `max_requests_per_host_per_second` | ホスト別 RPS 制限（0 = 無制限） |

#### 診断バジェットパラメータ

| パラメータ | 説明 |
|-----------|------|
| `max_total_requests` | セッション全体の最大リクエスト数（0 = 無制限） |
| `max_duration` | セッション最大時間（Go duration 形式、例: "30m", "1h"。"0s" = 無制限） |

レート制限・バジェットも Policy/Agent 2 層構造。Agent Layer は Policy Layer 以下の制限のみ設定可能。バジェット超過時はプロキシが自動停止。

### SafetyFilter（入力フィルタ）

SafetyFilter は Policy Layer として動作し、破壊的ペイロード（DROP TABLE、rm -rf 等）がターゲットに送信されることを防止する。AI エージェントからは変更不可で、設定ファイル (`config.json`) で定義する。

#### プリセット選択の指針

| プリセット | 用途 | 対象 |
|-----------|------|------|
| `destructive-sql` | SQL データベースを持つアプリケーション | DROP TABLE/DATABASE、TRUNCATE、無条件 DELETE/UPDATE 等 |
| `destructive-os-command` | OS コマンドインジェクション検証時 | rm -rf、shutdown、mkfs、dd、format 等 |

- Web アプリケーション診断: 両方のプリセットを有効化推奨
- API のみの診断: 対象に応じてプリセットを選択
- `log_only` モードで事前テスト後、`block` モードに切り替える運用を推奨

#### カスタムルール追加

プリセットに加え、アプリケーション固有のパターンをカスタムルールとして追加可能:

```json
{
  "safety_filter": {
    "enabled": true,
    "input": {
      "action": "block",
      "rules": [
        {"preset": "destructive-sql"},
        {"preset": "destructive-os-command"},
        {
          "id": "custom-dangerous-api",
          "name": "Dangerous API endpoint",
          "pattern": "(?i)/api/v[0-9]+/(delete-all|reset|purge)",
          "targets": ["url"]
        }
      ]
    }
  }
}
```

#### 現在の設定確認

```json
// security
{"action": "get_safety_filter"}
```

`get_safety_filter` は読み取り専用で、現在有効なルール一覧と `immutable: true` を返す。

### configure -- プロキシ設定変更

実行中のプロキシ設定を動的に変更する。

```json
// upstream proxy と接続制限を変更（merge モード）
{
  "operation": "merge",
  "upstream_proxy": "socks5://proxy.internal:1080",
  "max_connections": 256,
  "peek_timeout_ms": 5000
}

// インターセプトキューの設定
{
  "intercept_queue": {
    "timeout_ms": 120000,
    "timeout_behavior": "auto_release"
  }
}

// SOCKS5 認証の設定
{
  "socks5_auth": {
    "method": "password",
    "username": "user",
    "password": "pass"
  }
}
```

#### configure パラメータ

| パラメータ | 説明 |
|-----------|------|
| `operation` | "merge"（デフォルト）または "replace" |
| `upstream_proxy` | 上流プロキシ URL |
| `capture_scope` | キャプチャスコープ |
| `tls_passthrough` | TLS パススルー設定 |
| `intercept_rules` | インターセプトルール |
| `intercept_queue` | インターセプトキュー（timeout_ms, timeout_behavior） |
| `auto_transform` | 自動変換ルール |
| `socks5_auth` | SOCKS5 認証（method, username, password） |
| `max_connections` | 最大同時接続数（1-100000） |
| `peek_timeout_ms` | プロトコル検出タイムアウト（100-600000） |
| `request_timeout_ms` | HTTP リクエストタイムアウト（100-600000） |
| `tls_fingerprint` | TLS フィンガープリントプロファイル変更 |
| `budget` | object | 診断バジェット（max_total_requests, max_duration） |
| `client_cert` | object | mTLS クライアント証明書設定（cert_path, key_path） |

### plugin -- プラグイン管理

```json
// プラグイン一覧
{"action": "list"}

// 特定プラグインのリロード
{"action": "reload", "params": {"name": "<plugin-name>"}}

// 全プラグインのリロード
{"action": "reload"}

// プラグイン無効化
{"action": "disable", "params": {"name": "<plugin-name>"}}

// プラグイン有効化
{"action": "enable", "params": {"name": "<plugin-name>"}}
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
  |     +-- YES --> references/payload-patterns.md を参照 (必ず「安全なペイロード選定の原則」を確認)
  |     +-- NO --> 次へ
  |
  +-- 単発テスト or 網羅テスト?
  |     |
  |     +-- 単発確認 --> resend ツール
  |     +-- 網羅テスト --> fuzz ツール (外れ値検出: outliers_only フィルタ)
  |     +-- HTTP パースをバイパスしたい --> resend_raw (HTTP Request Smuggling 等)
  |     +-- WebSocket/TCP メッセージ再送 --> tcp_replay
  |
  +-- レスポンスの差分分析が必要?
  |     |
  |     +-- YES --> resend compare で 2 フローを構造化比較
  |     +-- NO --> 次へ
  |
  +-- レート制限・バジェット設定が必要?
  |     |
  |     +-- YES --> security set_rate_limits / set_budget
  |     +-- NO --> 次へ
  |
  +-- SafetyFilter の設定確認が必要?
  |     |
  |     +-- YES --> security get_safety_filter で現在のルール確認
  |     +-- NO --> 次へ
  |
  +-- プロトコル固有の操作?
        |
        +-- SOCKS5 トラフィック監視 --> protocols に "SOCKS5" を指定して proxy_start
        +-- TCP 生データ --> tcp_forwards で TCP フォワード設定
```

検証の全体フローは `references/verify-vulnerability.md` を参照。

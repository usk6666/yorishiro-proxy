# M3: Fuzzer 詳細設計

**ステータス**: Draft
**最終更新**: 2026-02-26

---

## 概要

記録済みリクエストをテンプレートとし、指定したパラメータ位置にペイロードリストを順次代入して自動送信する機能。BurpSuite の Intruder に相当するが、よりジェネリックな名称として **Fuzzer** を採用する。

`execute` ツールの新アクション `fuzz` として実装。結果は `query` ツールの新リソース `fuzz_results` で参照。

## 命名

**決定**: 機能名 **Fuzzer**、アクション名 `fuzz`

| 候補 | 根拠 | 採否 |
|------|------|------|
| `intruder` | BurpSuite 由来。セキュリティ業界での認知度高い | 不採用 |
| `fuzzer` / `fuzz` | ジェネリック。Go 標準の fuzzing (`go test -fuzz`) とも用語統一 | **採用** |
| `scanner` | 広すぎる。脆弱性スキャナと混同 | 不採用 |
| `brute` | 限定的。ブルートフォース以外のユースケースを表現できない | 不採用 |

## 決定事項

| # | 項目 | 決定 | 理由 |
|---|------|------|------|
| 1 | 命名 | `fuzz` (action) / Fuzzer (機能名) | ジェネリック、Go 標準と統一 |
| 2 | 非同期実行モデル | ポーリング (query) + 制御アクション | `fuzz_cancel`, `fuzz_pause`, `fuzz_resume` を提供 |
| 3 | 結果の永続化 | DB 永続化 | fuzz_jobs + fuzz_results テーブル |
| 4 | rate_limit と concurrency | 両方提供 | 異なる制御軸。concurrency = 同時接続数、rate_limit = 秒間リクエスト数 |
| 5 | 停止条件 | 過負荷検知を含める | 応答遅延増加の自動検知 |
| 6 | ペイロード数の上限 | 設けない | AI エージェントの判断に委ねる |
| 7 | Resender との改変パイプライン共有 | 共有 | 各 fuzz イテレーションは内部的に resend と同じ改変パイプラインを通す。将来分離が必要になった場合に備え、インターフェースは意識して設計する |
| 8 | ポジション指定方法 | 構造化指定 (location + name + match) | AI エージェントが JSON を組み立てる前提に適合 |
| 9 | 攻撃タイプ | `sequential` + `parallel` の 2 タイプ | sniper → sequential、pitchfork → parallel にリネーム。battering_ram / cluster_bomb は不採用 |
| 10 | ポジション操作モード | `replace` / `add` / `remove` | パラメータ・ヘッダの追加/削除テストに対応 |
| 11 | ペイロード file のセキュリティ | `~/.katashiro-proxy/wordlists/` に制限。相対パス指定 | シンボリックリンク解決後のパス検証。フルパス不可 |
| 12 | 過負荷検知アルゴリズム | 複合方式 (絶対閾値 OR ベースライン比率) | スライディングウィンドウの中央値で判定。単発外れ値に耐性 |

## コア概念

### ペイロードポジション

テンプレートリクエスト内で値を操作する**位置**と**操作モード**を定義する。

```
位置の種類:
- header    : ヘッダ値 (名前で指定)
- path      : URL パスセグメント
- query     : クエリパラメータ値 (キーで指定)
- body_regex: ボディ内の正規表現マッチ部分
- body_json : JSON Path で指定した値
- cookie    : Cookie 値 (名前で指定)
```

#### 操作モード

| mode | 動作 | ペイロード |
|------|------|-----------|
| `replace` (デフォルト) | 既存の値を置換。`match` でキャプチャグループ指定可 | 必須 |
| `add` | パラメータ/ヘッダを新規追加 (存在しなくてもOK) | 必須 (追加する値) |
| `remove` | 対象を削除してリクエスト送信 | 不要 |

#### 正規表現キャプチャグループ

`replace` モードで正規表現を使用する場合、**キャプチャグループ**で置換対象を明示する:

```
"match": "Bearer (.*)"     ← グループ1 の部分がペイロードで置換される
"match": "token=([^&]+)"   ← グループ1 の部分がペイロードで置換される
```

キャプチャグループが無い場合はマッチ全体を置換する。

### 攻撃タイプ

| タイプ | 説明 | ペイロードセット数 |
|--------|------|-------------------|
| `sequential` | 1 ポジションずつ順番にペイロードを代入。他は元の値を維持 | 1 |
| `parallel` | 各ポジションに対応するペイロードセットを並行代入 (zip) | N (= ポジション数) |

- `sequential`: ポジション A に全ペイロードを試行 → ポジション B に全ペイロードを試行 → ...
- `parallel`: ポジション A の i 番目とポジション B の i 番目を同時に代入。最短のセットが尽きたら終了

### ペイロード生成

| タイプ | 説明 | パラメータ |
|--------|------|-----------|
| `wordlist` | 静的リスト | `values: ["val1", "val2", ...]` |
| `file` | ローカルファイルから読み込み (1行1ペイロード) | `path: "passwords.txt"` (相対パス) |
| `range` | 数値レンジ | `start, end, step` |
| `sequence` | フォーマット文字列 + レンジ | `format: "user%04d", start, end, step` |

> **将来拡張**: Macro 連携によるペイロード動的生成、エンコーダチェーンによる変換

## MCP インターフェース

### execute: `fuzz` アクション

```json
{
  "action": "fuzz",
  "params": {
    "session_id": "abc-123",
    "attack_type": "sequential",

    "positions": [
      {
        "id": "pos-0",
        "location": "header",
        "name": "Authorization",
        "mode": "replace",
        "match": "Bearer (.*)",
        "payload_set": "tokens"
      },
      {
        "id": "pos-1",
        "location": "body_json",
        "json_path": "$.password",
        "mode": "replace",
        "payload_set": "passwords"
      },
      {
        "id": "pos-2",
        "location": "header",
        "name": "X-Forwarded-For",
        "mode": "add",
        "payload_set": "ips"
      },
      {
        "id": "pos-3",
        "location": "query",
        "name": "debug",
        "mode": "remove"
      }
    ],

    "payload_sets": {
      "tokens": {
        "type": "wordlist",
        "values": ["token1", "token2", "admin-token"]
      },
      "passwords": {
        "type": "file",
        "path": "passwords.txt"
      },
      "ips": {
        "type": "wordlist",
        "values": ["127.0.0.1", "10.0.0.1", "::1"]
      }
    },

    // --- 実行制御 ---
    "concurrency": 5,
    "rate_limit_rps": 10,
    "delay_ms": 0,
    "timeout_ms": 10000,
    "max_retries": 0,

    // --- 停止条件 ---
    "stop_on": {
      "status_codes": [503],
      "error_count": 10,
      "latency_threshold_ms": 5000,
      "latency_baseline_multiplier": 3.0,
      "latency_window": 10
    },

    // --- メタデータ ---
    "tag": "auth-bruteforce-01"
  }
}
```

### 即時レスポンス

Fuzz は非同期実行。即時レスポンスで `fuzz_id` を返す。

```json
{
  "fuzz_id": "fuzz-789",
  "status": "running",
  "total_requests": 3,
  "tag": "auth-bruteforce-01",
  "message": "Fuzzing started. Query fuzz_results with fuzz_id to check progress."
}
```

### ジョブ制御アクション

```json
// 一時停止
{"action": "fuzz_pause",  "params": {"fuzz_id": "fuzz-789"}}

// 再開
{"action": "fuzz_resume", "params": {"fuzz_id": "fuzz-789"}}

// キャンセル
{"action": "fuzz_cancel", "params": {"fuzz_id": "fuzz-789"}}
```

### query: `fuzz_results` リソース

```json
{
  "resource": "fuzz_results",
  "fuzz_id": "fuzz-789",
  "filter": {
    "status_code": 200,
    "body_contains": "admin"
  },
  "fields": ["index", "session_id", "payloads", "status_code", "duration_ms"],
  "sort_by": "status_code",
  "limit": 50,
  "offset": 0
}
```

#### レスポンス

```json
{
  "fuzz_id": "fuzz-789",
  "status": "completed",
  "progress": {"completed": 3, "total": 3, "errors": 0},
  "results": [
    {
      "index": 0,
      "session_id": "new-001",
      "payloads": {"pos-0": "token1", "pos-1": "password"},
      "status_code": 401,
      "duration_ms": 120
    },
    {
      "index": 1,
      "session_id": "new-002",
      "payloads": {"pos-0": "token2", "pos-1": "admin"},
      "status_code": 200,
      "duration_ms": 95
    }
  ],
  "summary": {
    "status_distribution": {"200": 1, "401": 2},
    "avg_duration_ms": 110,
    "total_duration_ms": 850
  }
}
```

## ペイロード file タイプ

### ファイル配置ルール

- ベースディレクトリ: `${HOME}/.katashiro-proxy/wordlists/`
- `path` パラメータは**相対パス**のみ受け付ける (フルパス不可)
- サブディレクトリ可: `"path": "sqli/error-based.txt"`
- 初回起動時にベースディレクトリが無ければ自動作成

### パス検証

1. `path` が絶対パス (`/` 始まり) ならエラー
2. `filepath.Join(baseDir, path)` でフルパス構築
3. `filepath.EvalSymlinks` でシンボリックリンクを解決
4. 解決後のパスが `baseDir` 内にあることを `strings.HasPrefix` で検証
5. 検証失敗なら `path traversal detected` エラー

## 過負荷検知

### 複合方式

2 つの検知手法を OR 結合。どちらかに抵触したら自動停止。

#### パラメータ

| パラメータ | デフォルト | 説明 |
|-----------|-----------|------|
| `latency_threshold_ms` | なし (無効) | 絶対閾値。直近ウィンドウの中央値がこれを超えたら停止 |
| `latency_baseline_multiplier` | なし (無効) | ベースライン比率。最初の window 件の中央値に対する倍率 |
| `latency_window` | 10 | スライディングウィンドウサイズ (判定対象のリクエスト数) |

#### 動作フロー

1. 最初の `latency_window` 件の中央値を**ベースライン**として計測
2. 以降、直近 `latency_window` 件の中央値を常時更新 (リングバッファ)
3. 停止判定 (毎リクエスト後):
   - `latency_threshold_ms` 指定時: `直近中央値 > latency_threshold_ms` → 停止
   - `latency_baseline_multiplier` 指定時: `直近中央値 > ベースライン中央値 * multiplier` → 停止
4. どちらも未指定の場合は遅延による自動停止なし

#### 中央値を使用する理由

- 平均値は 1 件の異常値 (GC pause、ネットワーク瞬断等) で閾値を超えやすい
- 中央値はウィンドウの半数以上が遅延しない限り反応しないため、安定した判定が可能

## 決定済み: query のフィールド選択方式

**決定**: fields 配列方式を採用。GraphQL 化はしない。

- `"fields": ["index", "status_code", "duration_ms"]` でレスポンスのキーをフィルタ
- 未指定時は全フィールド返却
- 将来ネスト取得の需要が出たら `"expand": ["session"]` のような軽量拡張で対応
- query ツール全体 (sessions, messages 等) にも同様に fields パラメータを追加可能

## Macro との連携ポイント

- pre-send hook: Macro で取得したトークンを Fuzzer のヘッダに自動注入
- post-receive hook: Fuzzer の各レスポンスを Macro に渡して検証ロジック実行
- ペイロード動的生成: Macro のステップで生成した値をペイロードセットとして利用
- Resender の改変オプション仕様は [m3-resender.md](./m3-resender.md) を参照
- Macro の詳細は [m3-macro.md](./m3-macro.md) を参照

## セキュリティ考慮事項

- SSRF 防御の維持
- concurrency / rate_limit のデフォルト値は保守的に設定
- タイムアウト制御
- ターゲットサーバへの影響を最小化するデフォルト設定
- ペイロード `file` タイプ: `~/.katashiro-proxy/wordlists/` に制限、シンボリックリンク解決後のパス検証

## データモデル拡張

```sql
-- Fuzz ジョブ管理
CREATE TABLE fuzz_jobs (
  id            TEXT PRIMARY KEY,
  session_id    TEXT NOT NULL,       -- テンプレートセッション
  config        TEXT NOT NULL,       -- JSON: positions, payload_sets, attack_type, etc.
  status        TEXT NOT NULL,       -- "running", "paused", "completed", "cancelled", "error"
  tag           TEXT NOT NULL DEFAULT '',
  created_at    DATETIME NOT NULL,
  completed_at  DATETIME,
  total         INTEGER NOT NULL DEFAULT 0,
  completed_count INTEGER NOT NULL DEFAULT 0,
  error_count   INTEGER NOT NULL DEFAULT 0
);

-- Fuzz 結果 (各ペイロード送信の結果)
CREATE TABLE fuzz_results (
  id              TEXT PRIMARY KEY,
  fuzz_id         TEXT NOT NULL REFERENCES fuzz_jobs(id) ON DELETE CASCADE,
  index_num       INTEGER NOT NULL,
  session_id      TEXT NOT NULL REFERENCES sessions(id),  -- 記録されたセッション
  payloads        TEXT NOT NULL,       -- JSON: {"pos-0": "value", ...}
  status_code     INTEGER,
  response_length INTEGER,
  duration_ms     INTEGER,
  error           TEXT,

  UNIQUE(fuzz_id, index_num)
);

CREATE INDEX idx_fuzz_jobs_status ON fuzz_jobs(status);
CREATE INDEX idx_fuzz_jobs_tag ON fuzz_jobs(tag);
CREATE INDEX idx_fuzz_results_fuzz_id ON fuzz_results(fuzz_id);
CREATE INDEX idx_fuzz_results_status_code ON fuzz_results(status_code);
```

## 実装方針

- `execute_tool.go` に `handleExecuteFuzz` / `handleExecuteFuzzCancel` / `handleExecuteFuzzPause` / `handleExecuteFuzzResume` を追加
- `query_tool.go` に `fuzz_results` resource を追加
- Fuzz エンジンは `internal/fuzzer/` パッケージとして分離
- 各 fuzz イテレーションは Resender と同じ改変パイプライン (`internal/mcp/` のボディパッチ等) を再利用
- 非同期実行は goroutine + context.Cancel で管理
- pause/resume は sync.Cond または channel ベースの制御

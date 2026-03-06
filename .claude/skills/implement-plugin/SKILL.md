---
description: "Starlark プラグインの雛形生成・実装・テスト支援。プロトコル・フック選択からサンプルテスト実行まで"
user-invokable: true
---

# /implement-plugin

Starlark プラグインの作成を支援するワークフロー。対話的にプロトコルとフックを選択し、動作する雛形を生成する。

## 引数

- `/implement-plugin` — 対話モードでプラグインを作成
- `/implement-plugin <description>` — 説明からプラグインを自動生成（例: `/implement-plugin HTTPリクエストにX-Request-IDヘッダを付与する`）

## 手順

### Phase 1: 要件確認

引数に説明がない場合は、以下を対話で確認:

1. **目的**: プラグインで何をしたいか
2. **プロトコル**: 対象プロトコル（http, https, h2, grpc, websocket, tcp）
3. **フック**: 使用するフックポイント
4. **アクション**: CONTINUE（修正）/ DROP（破棄）/ RESPOND（即時応答）

引数に説明がある場合は、内容から自動判定する。

### Phase 2: コンテキスト収集

以下を読んでプラグイン API を把握:

1. `docs/plugins.md` — プラグイン開発ガイド（フックリファレンス、データマップ、アクション）
2. `examples/plugins/` — 既存サンプルプラグイン
3. `internal/plugin/engine.go` — Engine API（action 定数、dispatch の仕組み）
4. `internal/plugin/hook.go` — Hook 定数一覧

### Phase 3: プラグイン生成

`examples/plugins/` にプラグインファイルを作成:

- ファイル名: `<snake_case_name>.star`
- 先頭にコメントで目的・設定例を記載
- プロトコル固有のデータマップキーを正しく使用
- `action.CONTINUE` / `action.DROP` / `action.RESPOND` を適切に使い分け

#### テンプレート構造

```python
# <Plugin Name>
#
# Purpose: <目的の説明>
#
# Config:
#   protocol: "<protocol>"
#   hooks: [<hook list>]
#   on_error: "skip"

def <hook_name>(data):
    # Protocol: data["protocol"] == "<protocol>"
    # Available keys: <protocol-specific keys>

    return {"action": action.CONTINUE}
```

#### プロトコル別データマップ早見表

| プロトコル | キー |
|-----------|------|
| http/https | protocol, method, url, headers, body, status_code, conn_info |
| h2 | 同上（protocol="h2"） |
| grpc | protocol, method, url, headers, body, conn_info（observe-only） |
| websocket | protocol, opcode, payload, is_text, direction, conn_info |
| tcp | protocol, data, direction, conn_info, forward_target |

#### アクション制約

| アクション | 使用可能なフック | プロトコル制限 |
|-----------|----------------|---------------|
| CONTINUE | 全フック | なし |
| DROP | on_receive_from_client | なし |
| RESPOND | on_receive_from_client | HTTP/HTTPS/H2 のみ |

### Phase 4: 動作確認

1. プラグインの Starlark 構文を検証（`go.starlark.net` の構文ルールに準拠しているか目視確認）
2. 既存テストパターンを参考に、プラグインが Engine に正しくロードできることを確認:

```bash
make build
go test -v ./internal/plugin/ -run TestLoad
```

### Phase 5: 設定例の提示

生成したプラグインの PluginConfig を提示:

```json
{
  "path": "examples/plugins/<name>.star",
  "protocol": "<protocol>",
  "hooks": ["<hook1>", "<hook2>"],
  "on_error": "skip"
}
```

MCP plugin ツールでの管理方法も案内:

```json
// plugin tool: list
{"action": "list"}

// plugin tool: reload after editing
{"action": "reload", "params": {"name": "<name>"}}

// plugin tool: disable temporarily
{"action": "disable", "params": {"name": "<name>"}}
```

## 注意事項

- gRPC は observe-only。DROP/RESPOND は使用不可（CONTINUE のみ）
- WebSocket のコントロールフレーム（Close, Ping, Pong）はプラグイン dispatch をスキップする
- TCP チャンクのプラグイン修正後サイズは 1MB 以下に制限される（超過時は元データを使用）
- ライフサイクルフック（on_connect, on_tls_handshake, on_disconnect）は 5秒タイムアウト付き
- Starlark は Python のサブセット。`import`, `class`, ファイル I/O, ネットワークアクセスは不可
- `print()` はプロキシのログに出力される（デバッグ用）
- **モジュールレベル変数はロード後にフリーズされる** — リスト・dict などの可変オブジェクトをモジュールレベルに置くと、フック関数内で変更できない（ランタイムエラー）。`on_error: "skip"` 時はサイレントにスキップされるため注意。文字列・int・タプルなどの不変値のみモジュールレベルで使用すること

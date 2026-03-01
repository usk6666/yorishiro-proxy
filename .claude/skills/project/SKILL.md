---
description: "プロジェクトの進捗把握・Issue 整備・ロードマップ同期を行う開発計画ツール"
user-invokable: true
---

# /project

開発フローの「計画→実装→追跡」サイクルにおいて、orchestrate (実装) の前後を担うスキル。
マイルストーン進捗の把握、ロードマップからの Issue 作成、実装後のドキュメント同期を提供する。

## 固定パラメータ

- **チーム**: Usk6666
- **プロジェクト**: yorishiro-proxy
- **ロードマップ doc ID**: d413edd7-d296-433a-ab94-11d4dd57d883

## サブコマンド

- `/project status` — マイルストーン進捗の全体俯瞰
- `/project plan <milestone>` — ロードマップ → Linear Issue のギャップ分析・Issue 作成
- `/project sync` — 実装完了後のロードマップ文書更新

---

## `/project status`

マイルストーン進捗を確認し、次に取り組む対象を決定するための入口。

### 手順

1. `mcp__linear-server__list_milestones(project=yorishiro-proxy)` で全マイルストーンの進捗を取得
2. 以下を **並行で** 取得:
   - `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy, state=started)`
   - `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy, state=backlog)`
   - `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy, state=unstarted)`
3. Issue を `projectMilestone` フィールドでグループ化
4. 以下を報告:

### 出力形式

```markdown
## プロジェクト進捗

### マイルストーン進捗
| Milestone | Progress | 残り Issue | ステータス |
|-----------|----------|-----------|----------|
| M1: Foundation | 100% | — | 完了 |
| M2: MCP Interface v2 | 79% | 3 issues | ← ACTIVE |
| M3: Active Testing | 0% | N issues | 未着手 |
| M4: Multi-Protocol | 0% | N issues | 未着手 |
| M5: Production Ready | 0% | N issues | 未着手 |

### アクティブ: M2 — MCP Interface v2
| ID | タイトル | ステータス | 優先度 |
|----|---------|----------|--------|
| USK-79 | ... | Backlog | High |
| USK-80 | ... | Todo | Normal |
| ...

### ブロッカー
- M3 は M2 の完了に依存 (現在 79%)

### 推奨アクション
- `/orchestrate milestone M2` で残り 3 Issue を実装
- または `/project plan M3` で M3 の Issue を事前整備
```

---

## `/project plan <milestone>`

orchestrate の前提条件を整える最も重要なサブコマンド。
ロードマップ (あるべき姿) と Linear (実際の Issue) のギャップを埋める。

### 手順

1. `mcp__linear-server__get_document(id=d413edd7-d296-433a-ab94-11d4dd57d883)` でロードマップ文書を取得
2. 対象マイルストーンセクションの Issue テーブルを解析
   - Issue ID、タイトル、説明、優先度、依存関係を抽出
3. `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy)` で当該マイルストーンの既存 Issue を取得
   - `milestone` パラメータでフィルタリングできない場合は全件取得後にフィルタ
4. ギャップ分析:
   - **ロードマップにあるが Linear にない** → Issue 作成を提案
   - **Linear にあるがマイルストーン未割当** → 割り当て修正を提案
   - **説明が不十分な Issue** → 説明の充実を提案
5. 分析結果をユーザーに提示し、承認を得る
6. 承認後、`create_issue` / `update_issue` を実行
7. 作成した Issue 間の依存関係 (`blockedBy`/`blocks`) も設定

### 出力形式

```markdown
## <Milestone名> — Issue Plan

### 作成予定
| # | タイトル | 優先度 | 根拠 |
|---|---------|--------|------|
| 1 | Intercept rule engine | High | ロードマップ M3 セクション |
| 2 | Intruder engine | High | ロードマップ M3 セクション |
| ...

### 既存 (変更なし)
| ID | タイトル | マイルストーン | ステータス |
|----|---------|-------------|----------|
| USK-64 | Auto-transform rules | M3 | Backlog |

### 修正提案
| ID | 変更内容 |
|----|---------|
| USK-XX | マイルストーン未割当 → M3 に割り当て |
| USK-YY | 説明を充実 (ロードマップの仕様を反映) |

### 依存関係
| Issue | blockedBy |
|-------|-----------|
| #2 Intruder engine | #1 Intercept rule engine |

N 件の Issue を作成し、M 件を更新しますか?
```

### 注意事項

- Issue 作成前に必ずユーザーの承認を得ること
- ロードマップに記載のない Issue は作成しない
- 既存 Issue の説明を上書きする場合は差分を明示すること
- 依存関係は Issue の内容から推論し、blockedBy/blocks を設定する

---

## `/project sync`

実装完了後、ロードマップ文書を実態に合わせて更新する。

### 手順

1. `mcp__linear-server__get_document(id=d413edd7-d296-433a-ab94-11d4dd57d883)` でロードマップ文書を取得
2. `mcp__linear-server__list_milestones(project=yorishiro-proxy)` で最新の進捗を取得
3. 以下を **並行で** 取得:
   - `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy, state=completed)`
   - `mcp__linear-server__list_issues(team=Usk6666, project=yorishiro-proxy, state=started)`
4. ロードマップの各マイルストーンセクションを更新:
   - Issue テーブルのステータスマーカーを更新 (✅ 完了, 🔄 進行中, ⏳ 未着手)
   - マイルストーン進捗サマリーを更新
   - 完了日がある場合は記載
5. 変更差分をユーザーに表示し、承認を得る
6. 承認後 `mcp__linear-server__update_document` で反映

### 出力形式

```markdown
## ロードマップ同期

### 変更内容
- M2: Progress 79% → 100% (完了)
- USK-75: ⏳ → ✅
- USK-78: ⏳ → ✅
- USK-79: ⏳ → ✅

### 更新後のマイルストーンサマリー
| Milestone | Progress | ステータス |
|-----------|----------|----------|
| M1: Foundation | 100% | 完了 |
| M2: MCP Interface v2 | 100% | 完了 |
| M3: Active Testing | 0% | 次のターゲット |

ロードマップを更新しますか?
```

### 注意事項

- sync は completed Issue を取得するが、これは文書更新の目的のみ
- ドキュメント更新前に必ずユーザーの承認を得ること
- ロードマップの構造（マイルストーンの順序・説明）は変更しない — ステータスのみ更新

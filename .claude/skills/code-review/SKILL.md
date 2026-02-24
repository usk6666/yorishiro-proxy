---
description: "PR のコード品質をレビューする。Go 慣習、アーキテクチャ準拠、テスト品質を検査"
user-invokable: true
---

# /code-review

Pull Request に対してコード品質レビューを実施するスキル。

## 引数パターン

- `/code-review <PR番号>` — 指定 PR をレビュー
- `/code-review` — 現在のブランチに紐づく PR をレビュー

---

## 手順

### Step 1: PR の特定

引数が指定された場合:
- `<PR番号>` を使用する

引数が省略された場合:
- `gh pr view --json number -q .number` で現在のブランチの PR 番号を取得する
- PR が存在しない場合はエラーメッセージを表示して終了する

### Step 2: PR 情報の取得

以下を **並行で** 取得する:

```bash
gh pr view <PR番号> --json title,body,headRefName,baseRefName,number,url
gh pr diff <PR番号> --name-only
```

- PR タイトル、ブランチ名、PR URL を記録
- 変更ファイル一覧を取得

### Step 3: Issue 情報の取得（任意）

PR の本文から Linear Issue ID（`USK-XX` 形式）を抽出する。
見つかった場合は `mcp__linear-server__get_issue` で Issue 説明を取得する。
見つからない場合は Issue 関連のプレースホルダーを空にして続行する。

### Step 4: プロダクトコンテキストの構築

```
katashiro-proxy は AI エージェント向けネットワークプロキシ（MCP サーバ）。
脆弱性診断のトラフィック傍受・記録・リプレイ機能を提供する。
アーキテクチャ: TCP リスナ → プロトコル検出 → プロトコルハンドラ → セッション記録 → MCP Tool
```

### Step 5: Code Review Agent の起動

`.claude/agents/code-reviewer.md` を Read ツールで読み込み、
`## プロンプト本文` セクション内のコードブロックを抽出する。

プレースホルダーを置換:
- `{{PR_NUMBER}}` → PR 番号
- `{{PR_TITLE}}` → PR タイトル
- `{{ISSUE_ID}}` → Issue ID（または "N/A"）
- `{{ISSUE_DESCRIPTION}}` → Issue 説明（または "N/A"）
- `{{PRODUCT_CONTEXT}}` → Step 4 で構築したコンテキスト
- `{{CHANGED_FILES}}` → 変更ファイル一覧

Task ツールで起動:
- `subagent_type`: `"general-purpose"`
- `isolation`: `"worktree"`
- `description`: `"Code review PR #<N>"`
- `prompt`: 置換後のプロンプト

### Step 6: 結果の報告

サブエージェントの結果を解析し、ユーザーに以下の形式で報告する:

```markdown
## Code Review 結果: PR #<N>

**判定**: APPROVED / CHANGES_REQUESTED
**PR**: <PR URL>

### 所見サマリー

| ID | Severity | File | Category | Description |
|----|----------|------|----------|-------------|
| F-1 | HIGH | ... | ... | ... |

### 統計

- CRITICAL: X, HIGH: X, MEDIUM: X, LOW: X, NIT: X
```

---
description: "PR のレビュー → Fix → 再レビューサイクルを管理するゲート。Code Review + Security Review を並行実行し、問題があれば自動修正"
user-invokable: true
---

# /review-gate

PR に対してコードレビューとセキュリティレビューを並行実行し、
問題が見つかった場合は自動修正 → 再レビューのサイクルを最大 2 ラウンドまで実行するゲートスキル。

## 引数パターン

- `/review-gate <PR番号>` — 指定 PR にフルレビューサイクルを実行
- `/review-gate <PR番号> --issue <ISSUE_ID>` — Issue ID を明示指定
- `/review-gate` — 現在のブランチに紐づく PR にフルレビューサイクルを実行

---

## 手順

### Phase 1: PR 情報の収集

#### 1-1. PR の特定

引数が指定された場合:
- `<PR番号>` を使用する

引数が省略された場合:
- `gh pr view --json number -q .number` で現在のブランチの PR 番号を取得する

#### 1-2. PR 情報の取得

以下を **並行で** 取得する:

```bash
gh pr view <PR番号> --json title,body,headRefName,baseRefName,number,url
gh pr diff <PR番号> --name-only
```

#### 1-3. Issue 情報の取得

`--issue` で指定された場合はそれを使用。
未指定の場合は PR 本文から `USK-XX` 形式の Issue ID を抽出し、
`mcp__linear-server__get_issue` で詳細を取得する。

#### 1-4. コンテキストの構築

**プロダクトコンテキスト:**
```
katashiro-proxy は AI エージェント向けネットワークプロキシ（MCP サーバ）。
脆弱性診断のトラフィック傍受・記録・リプレイ機能を提供する。
アーキテクチャ: TCP リスナ → プロトコル検出 → プロトコルハンドラ → セッション記録 → MCP Tool
```

**セキュリティコンテキスト:**
```
katashiro-proxy は MITM プロキシとして動作するため:
- 攻撃者が制御するトラフィックを直接処理する
- CA 秘密鍵を保持し、動的に証明書を発行する
- セッション記録に認証情報が含まれる可能性がある
- MCP 経由で AI エージェントがコマンドを実行する
```

---

### Phase 2: レビューの並行実行

#### 2-1. エージェントテンプレートの読み込み

`.claude/agents/code-reviewer.md` と `.claude/agents/security-reviewer.md` を Read ツールで読み込み、
各テンプレートの `## プロンプト本文` セクション内のコードブロックを抽出する。

#### 2-2. プレースホルダー置換

**Code Review Agent:**
- `{{PR_NUMBER}}` → PR 番号
- `{{PR_TITLE}}` → PR タイトル
- `{{ISSUE_ID}}` → Issue ID
- `{{ISSUE_DESCRIPTION}}` → Issue 説明
- `{{PRODUCT_CONTEXT}}` → プロダクトコンテキスト
- `{{CHANGED_FILES}}` → 変更ファイル一覧

**Security Review Agent:**
- `{{PR_NUMBER}}` → PR 番号
- `{{PR_TITLE}}` → PR タイトル
- `{{ISSUE_ID}}` → Issue ID
- `{{PRODUCT_CONTEXT}}` → プロダクトコンテキスト
- `{{SECURITY_CONTEXT}}` → セキュリティコンテキスト

#### 2-3. 並行起動

**同一メッセージ内**で 2 つの Task ツールを並行起動する:

```
Task(description="Code review PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Code Review プロンプト>)
Task(description="Security review PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Security Review プロンプト>)
```

**注意**: レビューは read-only だが、並列実行時に対象ブランチの checkout がメイン worktree の状態と競合するため `isolation: "worktree"` を使用する。

---

### Phase 3: 判定集約

#### 3-1. 結果のパース

各エージェントの出力から `VERDICT:` 行を抽出し、判定を記録する。

```
code_review_verdict = APPROVED | CHANGES_REQUESTED
security_review_verdict = APPROVED | CHANGES_REQUESTED
```

#### 3-2. 集約判定

| Code Review | Security Review | 集約判定 | 次のアクション |
|-------------|----------------|---------|-------------|
| APPROVED | APPROVED | **APPROVED** | Phase 5 (結果報告) |
| APPROVED | CHANGES_REQUESTED | **CHANGES_REQUESTED** | Phase 4 (Fix) |
| CHANGES_REQUESTED | APPROVED | **CHANGES_REQUESTED** | Phase 4 (Fix) |
| CHANGES_REQUESTED | CHANGES_REQUESTED | **CHANGES_REQUESTED** | Phase 4 (Fix) |

---

### Phase 4: Fix サイクル（最大 2 ラウンド）

#### 4-1. Fixer Agent の起動

`.claude/agents/fixer.md` を Read ツールで読み込み、プレースホルダーを置換する:

- `{{PR_NUMBER}}` → PR 番号
- `{{BRANCH_NAME}}` → PR のヘッドブランチ名
- `{{CODE_REVIEW_FINDINGS}}` → Code Review の所見（CHANGES_REQUESTED の場合のみ。APPROVED なら "None — Code review passed."）
- `{{SECURITY_REVIEW_FINDINGS}}` → Security Review の所見（CHANGES_REQUESTED の場合のみ。APPROVED なら "None — Security review passed."）
- `{{ORIGINAL_ISSUE_ID}}` → Issue ID
- `{{PRODUCT_CONTEXT}}` → プロダクトコンテキスト

Task ツールで起動:
- `subagent_type`: `"general-purpose"`
- `isolation`: `"worktree"`
- `description`: `"Fix review findings PR #<N> round <R>"`
- `prompt`: 置換後のプロンプト

#### 4-2. 修正結果の確認

Fixer Agent の出力から各所見のステータスを抽出する:
- `FIXED`: 修正完了
- `PARTIALLY_FIXED`: 部分修正
- `UNRESOLVED`: 未解決

#### 4-3. 再レビュー

**CHANGES_REQUESTED だったレビューのみ** 再実行する:

- Code Review のみ CHANGES_REQUESTED → Code Review Agent のみ再起動
- Security Review のみ CHANGES_REQUESTED → Security Review Agent のみ再起動
- 両方 CHANGES_REQUESTED → 両方を並行で再起動

#### 4-4. ラウンド管理

```
current_round = 1

while current_round <= 2:
    if 集約判定 == APPROVED:
        break  → Phase 5

    Fixer Agent 起動
    再レビュー実行（CHANGES_REQUESTED だった側のみ）
    判定集約

    current_round += 1

if current_round > 2 and 集約判定 == CHANGES_REQUESTED:
    → ESCALATE
```

---

### Phase 5: 結果報告

#### 5-1. 最終ステータス

| 結果 | 意味 |
|-----|------|
| **APPROVED** | 両方のレビューが通過（初回またはFix後） |
| **ESCALATED** | 2 ラウンドの修正後もレビュー不通過。手動対応が必要 |

#### 5-2. ユーザーへの報告

```markdown
## Review Gate 結果: PR #<N>

**最終判定**: APPROVED / ESCALATED
**PR**: <PR URL>
**Fix ラウンド数**: 0 / 1 / 2

### レビュー結果

| レビュー | 初回 | Round 1 | Round 2 | 最終 |
|---------|------|---------|---------|------|
| Code Review | APPROVED/CHANGES_REQUESTED | — | — | APPROVED |
| Security Review | CHANGES_REQUESTED | APPROVED | — | APPROVED |

### 所見サマリー

| ID | Severity | Category | Status |
|----|----------|----------|--------|
| F-1 | HIGH | Correctness | FIXED (Round 1) |
| S-1 | MEDIUM | InputValidation | FIXED (Round 1) |

### エスカレーション（ESCALATED の場合のみ）

以下の所見が 2 ラウンドの修正で解決できませんでした。手動対応をお願いします:

| ID | Severity | File | Description |
|----|----------|------|-------------|
| ... | ... | ... | ... |
```

#### 5-3. Linear ステータス更新（Issue ID がある場合）

| イベント | Linear コメント |
|---------|----------------|
| レビュー通過 | "PR #N: Code Review APPROVED, Security Review APPROVED" |
| Fix サイクル開始 | "PR #N: Review found issues. Fix round 1 starting." |
| Fix 後通過 | "PR #N: All findings resolved after N fix round(s)." |
| エスカレーション | "PR #N: ESCALATION - N unresolved findings after 2 fix rounds. Manual intervention needed." |

`mcp__linear-server__create_comment` で Issue にコメントを投稿する。

### Phase 6: Worktree クリーンアップ

レビューサイクル完了後、**自分が起動したサブエージェントの worktree のみ**を削除する。

**重要**: 別セッションがアクティブに使用中の worktree を破壊する事故を防ぐため、
一括削除は行わない。

**手順:**

1. Phase 2 〜 4 の各 Task 呼び出し結果から agent ID を記録しておく
2. 記録した agent ID ごとに以下を実行:

```bash
git worktree remove .claude/worktrees/agent-<agentId> --force 2>/dev/null || true
```

3. 全削除後にメタデータを清掃:

```bash
git worktree prune
```

注意: `/orchestrate` 内から呼ばれた場合は Phase 3-3 で一括削除されるため重複するが、
冪等なので問題ない。`/review-gate` 単独実行時にのみ実質的に機能する。

---

## 並行度戦略

| シナリオ | 戦略 | 同時 Agent 数 |
|---------|------|-------------|
| 初回レビュー | Code + Security 並行 | 2 |
| 再レビュー（一方のみ） | 単独実行 | 1 |
| 再レビュー（両方） | Code + Security 並行 | 2 |
| Fix | Fixer 1 agent のみ | 1 |

## 最大エージェント呼び出し数（1 PR あたり最悪ケース）

初回レビュー 2 + Fix 1 + 再レビュー 2 + Fix 1 + 再レビュー 2 = **8 回**

---

## 注意事項

- レビューエージェントは **read-only** — コード変更は一切行わない
- Fixer Agent は **worktree** で動作 — PR のブランチを直接操作する
- LOW / NIT の所見は Fix 対象外（APPROVED 判定に影響しない）
- エスカレーション時は修正を試みず、ユーザーに判断を委ねる

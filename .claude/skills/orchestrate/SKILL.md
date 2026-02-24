---
description: "Linear Issue を並行実装するオーケストレーター。ロードマップと依存関係を分析し、最適な順序・並行度でサブエージェントに実装を委任"
user-invokable: true
---

# /orchestrate

ロードマップを理解し、依存関係を分析した上で、複数の Linear Issue をサブエージェントに実装させるオーケストレーションスキル。

## 引数

- `/orchestrate` — ロードマップを分析し、次に実装すべき Issue を提案
- `/orchestrate <Issue ID> [Issue ID...]` — 指定 Issue を依存関係を考慮して実装
- `/orchestrate phase <N>` — 指定 Phase の Issue を依存順に実装
- `/orchestrate status` — 実行中のサブエージェントの状況を確認

---

## 手順

### Phase 0: プロダクト理解 — ロードマップと現状の把握

**すべての実行で最初に行うこと。** オーケストレーターはまず自分がプロダクトオーナーの視点を持つ。

#### 0-1. ロードマップの読み込み

`mcp__linear-server__list_documents` (project=katashiro-proxy) でドキュメント一覧を取得し、
「ロードマップ」を含むドキュメントを `mcp__linear-server__get_document` で全文読み込む。

ロードマップから以下を抽出・理解する:

- **プロダクトのゴール**: 何を作っているのか、誰のためのツールか
- **Phase 構造**: 各 Phase のゴールと提供価値
- **Phase 間の依存**: どの Phase がどの Phase に依存するか
- **Phase 内の Issue 順序**: 各 Phase 内の Issue の自然な実装順
- **技術的決定**: ストレージ選定、プロトコル戦略など既に決まっている設計判断

#### 0-2. プロジェクト現状の把握

以下を **並行で** 取得する:

- `mcp__linear-server__list_issues` (team=Usk6666, project=katashiro-proxy, state=completed) — 完了済み Issue
- `mcp__linear-server__list_issues` (team=Usk6666, project=katashiro-proxy, state=started) — 進行中 Issue
- `mcp__linear-server__list_issues` (team=Usk6666, project=katashiro-proxy, state=backlog) — 未着手 Issue
- `mcp__linear-server__list_issues` (team=Usk6666, project=katashiro-proxy, state=unstarted) — Todo Issue

これにより「今どの Phase のどこにいるか」を特定する。

#### 0-3. コードベースの現状確認

プロジェクトルートで以下を確認し、実装済みの機能を把握する:

- `ls internal/` でパッケージ構造を確認
- 主要ファイルの存在確認（スタブ vs 実装済み）
- `go test ./...` の現在のパス状況（必要な場合）

#### 0-4. 現状サマリーの生成

上記の分析結果をユーザーに提示する:

```markdown
## プロジェクト現状分析

### ロードマップ進捗
- **Phase 0 (スキャフォールディング)**: ✅ 完了
- **Phase 1 (Core Proxy + SQLite)**: 🔄 進行中 (2/6 完了)
- **Phase 2-6**: ⏳ 未着手

### 完了済み Issue
- USK-XX: ...
- USK-YY: ...

### 次に実装可能な Issue
(依存分析に基づく — 詳細は後述)
```

---

### Phase 1: 依存関係の分析と実行計画

#### 1-1. Issue 間の依存グラフ構築

ロードマップの Phase 構造と Issue 説明から、以下の依存関係を分析する:

**Phase 間依存** (ロードマップに明記):
- Phase 2 → Phase 1
- Phase 3 → Phase 1, Phase 2
- Phase 4 → Phase 3, Phase 1
- Phase 5 → Phase 2, Phase 1
- Phase 6 → Phase 1-4

**Phase 内依存** (Issue の内容から推論):
各 Issue の説明を `mcp__linear-server__get_issue` で取得し、以下の観点で依存を判定する:

1. **データ依存**: Issue A が作る型・インターフェースを Issue B が使う
2. **機能依存**: Issue A の機能が動いていないと Issue B がテストできない
3. **統合依存**: Issue A と B の成果物を結合する Issue C がある

例 (Phase 1):
```
Issue 1 (PeekConn) ──→ Issue 2 (Detector wiring) ──→ Issue 5 (main.go wiring) → Issue 6 (E2E test)
Issue 3 (SQLite Store) ──→ Issue 4 (HTTP handler) ──↗          ↗
                                                    Issue 4 ──↗
```

Linear の `blockedBy` / `blocks` フィールドも参照するが、設定されていない場合は
ロードマップの Issue 順序と Issue 内容から依存関係を推論する。

#### 1-2. 並行実行可能グループの特定

依存グラフから、同時に実行できる Issue のグループ (並行実行バッチ) を導出する。

**並行実行の条件:**
- 相互に依存関係がない
- 異なるパッケージ/ファイルを主に変更する（衝突リスクが低い）
- 同一 Phase 内または依存が満たされた Phase の Issue

**例 (Phase 1):**
```
Batch 1 (並行可能): Issue 1 (PeekConn), Issue 3 (SQLite Store)
  ↓ 両方完了後
Batch 2 (並行可能): Issue 2 (Detector wiring), Issue 4 (HTTP handler)
  ↓ 両方完了後
Batch 3 (直列):     Issue 5 (main.go wiring)
  ↓
Batch 4 (直列):     Issue 6 (E2E test)
```

#### 1-3. 実行計画の提示

ユーザーに以下の形式で計画を提示し、承認を得る:

```markdown
## 実行計画

### Batch 1 (並行実行)
| Issue | タイトル | ブランチ | 理由 |
|-------|---------|---------|------|
| USK-XX | PeekConn buffered reader | feat/USK-XX-peek-conn | 依存なし、独立したユーティリティ |
| USK-YY | SQLite session Store | feat/USK-YY-sqlite-store | 依存なし、独立したストレージ層 |

### Batch 2 (Batch 1 完了後、並行実行)
| Issue | タイトル | ブランチ | 依存 |
|-------|---------|---------|------|
| USK-AA | Detector wiring | feat/USK-AA-detector-wiring | USK-XX (PeekConn) |
| USK-BB | HTTP handler | feat/USK-BB-http-handler | USK-YY (SQLite Store) |

### Batch 3 (Batch 2 完了後)
...

### 並行度: 最大 2 (Batch 1, 2) → 直列 (Batch 3, 4)
### 推定 PR 数: 6
```

---

### Phase 2: サブエージェントの起動と管理

#### 2-1. バッチ単位の実行

計画に基づき、バッチごとにサブエージェントを起動する。
**バッチ内の Issue は並行で起動し、バッチ間は直列で実行する。**

各 Issue に対する Task ツールの設定:

- `subagent_type`: `"general-purpose"`
- `isolation`: `"worktree"` — 各サブエージェントが独立した git worktree で作業
- `description`: Issue ID を含む短い説明 (例: `"Implement USK-30"`)
- `prompt`: `.claude/agents/implementer.md` のプロンプトテンプレートを読み込み、
  プレースホルダーを実際の値に置換して渡す

**プレースホルダー一覧:**
- `{{ISSUE_ID}}` → Issue ID (例: `USK-30`)
- `{{ISSUE_TITLE}}` → Issue タイトル
- `{{ISSUE_DESCRIPTION}}` → Issue 説明 (Markdown)
- `{{ISSUE_LABELS}}` → ラベル名のカンマ区切り
- `{{BRANCH_NAME}}` → ブランチ名 (例: `feat/USK-30-http-handler`)
- `{{BRANCH_TYPE}}` → `feat` / `fix` / `chore`
- `{{PRODUCT_CONTEXT}}` → Phase 0 で構築したプロダクトコンテキスト (後述)
- `{{DEPENDENCY_CONTEXT}}` → この Issue の依存コンテキスト (後述)

**`{{PRODUCT_CONTEXT}}` の構築:**

Phase 0 で得た情報から、サブエージェントが「自分の Issue がプロダクト全体のどこに位置するか」を
理解できるサマリーを構築する。以下を含める:

```
katashiro-proxy は AI エージェント向けネットワークプロキシ（MCP サーバ）。
脆弱性診断のトラフィック傍受・記録・リプレイ機能を提供する。

アーキテクチャ: TCP リスナ → プロトコル検出 → プロトコルハンドラ → セッション記録 → MCP Tool
ストレージ: SQLite (modernc.org/sqlite, WAL モード)

現在の Phase: Phase N — <Phase のゴール>
この Issue は Phase N の M 番目の Issue で、<Issue の位置づけの説明>。

関連する設計判断:
- <この Issue に関係する技術的決定事項>
```

**`{{DEPENDENCY_CONTEXT}}` の構築:**

この Issue が依存する完了済み Issue の成果物を具体的に記述する。
サブエージェントが「何が既にあるか」を把握し、正しく連携できるようにする。

依存がない場合:
```
この Issue には先行する依存がない。基盤となる型定義やインターフェースは
既にスキャフォールディング (Phase 0) で定義済み。CLAUDE.md のパッケージレイアウトを参照。
```

依存がある場合:
```
この Issue は以下の完了済み Issue の成果物に依存する:

### USK-XX: <タイトル>
- パッケージ: internal/proxy/
- 提供する型: `PeekConn` (net.Conn ラッパー、Peek メソッド付き)
- 使用方法: Listener.handleConn で PeekConn を生成し、Detector に渡す
- 主要ファイル: internal/proxy/peek_conn.go

### USK-YY: <タイトル>
- パッケージ: internal/session/
- 提供するインターフェース: `Store` (Save, Get, List, Delete メソッド)
- 使用方法: HTTP handler のコンストラクタに Store を注入する
- 主要ファイル: internal/session/store.go, internal/session/sqlite_store.go
```

依存コンテキストの情報は、完了済み Issue の PR や実際のコードベースから取得する。
具体的な型名・メソッドシグネチャ・ファイルパスを含めることで、
サブエージェントが正確に既存コードと連携できるようにする。

**ブランチ名の決定ルール:**
- Issue のラベルまたはタイトルに "bug" / "fix" が含まれる → `fix/`
- それ以外 → `feat/`
- ブランチ名: `<type>/<issue-id>-<short-desc>` (Issue タイトルから kebab-case、最大 40 文字)

**プロンプト構築手順:**
1. `.claude/agents/implementer.md` を Read ツールで読み込む
2. `## プロンプト本文` セクション内のコードブロックを抽出する
3. プレースホルダーを実際の値に置換する
4. 置換後の文字列を Task ツールの `prompt` パラメータに渡す

#### 2-2. バッチ完了の待機と次バッチの起動

バッチ内の全サブエージェントが完了したら:

1. **結果を検証**: 各サブエージェントの成否を確認
2. **成功した PR をマージ判断**: 次のバッチが依存する PR がある場合、
   ユーザーに「この PR をマージしてから次のバッチに進みますか?」と確認する
3. **main を更新**: マージされた場合、次バッチのサブエージェントは最新の main から作業する
4. **失敗の対処**: 失敗した Issue が後続バッチのブロッカーかどうかを判定
   - ブロッカーの場合: 修正を試みるか、後続バッチからブロックされた Issue を除外
   - 非ブロッカーの場合: 後続バッチを続行し、失敗した Issue は後で対処
5. **次バッチを起動**: 上記が完了したら次のバッチに進む

#### 2-3. 並行起動例

```
# Batch 1: 並行で起動
同一メッセージ内で複数の Task ツールを呼び出す:
Task(description="Implement USK-XX", subagent_type="general-purpose", isolation="worktree", prompt=<プロンプト>)
Task(description="Implement USK-YY", subagent_type="general-purpose", isolation="worktree", prompt=<プロンプト>)

# Batch 1 完了を待つ → 結果検証 → PR マージ判断

# Batch 2: 並行で起動
Task(description="Implement USK-AA", subagent_type="general-purpose", isolation="worktree", prompt=<プロンプト>)
Task(description="Implement USK-BB", subagent_type="general-purpose", isolation="worktree", prompt=<プロンプト>)
```

---

### Phase 2.5: レビューゲート

バッチ内で成功した PR に対してレビューゲートを実行する。
レビューは PR 単位で順次実行し、各 PR 内では Code Review + Security Review を並行起動する。

#### 2.5-1. レビュー対象の特定

バッチ内で PR が作成された Issue を対象とする。失敗した Issue（PR なし）はスキップ。

#### 2.5-2. PR ごとのレビューサイクル

各 PR に対して `/review-gate` スキルと同等のフローを実行する。
`.claude/agents/code-reviewer.md` と `.claude/agents/security-reviewer.md` を Read ツールで読み込み、
プレースホルダーを置換して起動する。

**Step A: 初回レビュー（並行）**

同一メッセージ内で 2 つの Task ツールを並行起動:

```
Task(description="Code review PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Code Review プロンプト>)
Task(description="Security review PR #<N>", subagent_type="general-purpose", isolation="worktree", prompt=<Security Review プロンプト>)
```

プレースホルダー構築:
- `{{PRODUCT_CONTEXT}}` → Phase 0 で構築したプロダクトコンテキストを再利用
- `{{SECURITY_CONTEXT}}` → katashiro-proxy の脅威モデル（MITM プロキシ、CA 鍵保持、MCP 経由コマンド）
- `{{ISSUE_ID}}`, `{{ISSUE_DESCRIPTION}}` → Phase 1 で取得した Issue 情報
- `{{PR_NUMBER}}`, `{{PR_TITLE}}`, `{{CHANGED_FILES}}` → サブエージェントの結果から取得

**Step B: 判定集約**

各エージェントの出力から `VERDICT:` を抽出:
- 両方 `APPROVED` → この PR のレビュー完了。次の PR へ
- いずれか `CHANGES_REQUESTED` → Step C へ

**Step C: Fix サイクル（最大 2 ラウンド）**

`.claude/agents/fixer.md` を Read ツールで読み込み、プレースホルダーを置換して起動:

```
Task(description="Fix review findings PR #<N> round <R>", subagent_type="general-purpose", isolation="worktree", prompt=<Fixer プロンプト>)
```

- `{{CODE_REVIEW_FINDINGS}}` → Code Review の所見（APPROVED なら "None"）
- `{{SECURITY_REVIEW_FINDINGS}}` → Security Review の所見（APPROVED なら "None"）
- `{{BRANCH_NAME}}` → PR のヘッドブランチ名

Fix 後、`CHANGES_REQUESTED` だったレビューのみ再実行。
2 ラウンドで解決しない場合は `ESCALATED` としてユーザーに報告する。

#### 2.5-3. 並行度戦略

| シナリオ | 戦略 | 同時 Agent 数 |
|---------|------|-------------|
| 1 PR のレビュー | Code + Security 並行 | 2 |
| 2+ PR のレビュー | PR 単位で順次、各 PR 内は並行 | 2 |
| Fix 中 | Fixer 1 agent のみ（排他） | 1 |

#### 2.5-4. レビュー結果の記録

各 PR のレビュー結果を以下の形式で記録し、Phase 3 で集約する:

```
pr_review_results[PR番号] = {
  code_review: APPROVED | CHANGES_REQUESTED,
  security_review: APPROVED | CHANGES_REQUESTED,
  final_verdict: APPROVED | ESCALATED,
  fix_rounds: 0 | 1 | 2,
  unresolved_findings: [...]
}
```

#### 2.5-5. Linear ステータス連携

| イベント | Linear コメント |
|---------|----------------|
| レビュー開始 | "PR #N created. Automated review starting." |
| レビュー通過 | "PR #N: Code Review APPROVED, Security Review APPROVED" |
| Fix サイクル開始 | "PR #N: Review found issues. Fix round N starting." |
| Fix 後通過 | "PR #N: All findings resolved after N fix round(s)." |
| エスカレーション | "PR #N: ESCALATION - N unresolved findings after 2 fix rounds." |

`mcp__linear-server__create_comment` で Issue にコメントを投稿する。

#### 2.5-6. エスカレーション時の対処

エスカレーションされた PR がある場合:
- バッチの他の PR の処理は続行する
- ユーザーに未解決所見の詳細を報告し、手動対応を依頼する
- 後続バッチの実行はユーザーの判断に委ねる（ブロッカーかどうかによる）

---

### Phase 3: 結果の集約と報告

#### 3-1. 全体サマリー

全バッチ完了後、結果を集約:

```markdown
## 実装結果サマリー

### Phase 1: Core Proxy Engine + SQLite Session Store

#### Batch 1
| Issue | タイトル | ステータス | PR | テスト | Code Review | Security Review | Fix Rounds |
|-------|---------|----------|-----|-------|-------------|----------------|------------|
| USK-XX | PeekConn buffered reader | ✅ 成功 | #4 | 8 passed | ✅ APPROVED | ✅ APPROVED | 0 |
| USK-YY | SQLite session Store | ✅ 成功 | #5 | 12 passed | ✅ APPROVED | ⚠️ Fix→✅ | 1 |

#### Batch 2
| Issue | タイトル | ステータス | PR | テスト | Code Review | Security Review | Fix Rounds |
|-------|---------|----------|-----|-------|-------------|----------------|------------|
| USK-AA | Detector wiring | ✅ 成功 | #6 | 5 passed | ✅ APPROVED | ✅ APPROVED | 0 |
| USK-BB | HTTP handler | ❌ 失敗 | — | 2 failed | — | — | — |

### 失敗した Issue
- **USK-BB**: HTTP handler — テスト失敗 (`TestHTTPHandler_Proxy`)
  - ワークツリー: `/path/to/worktree` (手動確認可能)
  - 推奨: エラーログを確認し、手動修正または再実行

### エスカレーションされた Issue（レビュー未通過）
- **USK-ZZ**: ... — Security Review で N 件の未解決所見
  - 未解決: S-1 (HIGH), S-3 (MEDIUM)
  - 推奨: 手動レビューと修正

### 次のステップ
- USK-BB を修正後、Batch 3 (Issue 5: main.go wiring) に進行可能
- Phase 1 完了後、Phase 2 (TLS/CA) の着手が可能
```

#### 3-2. Issue ステータス更新

- 実装成功 + レビュー通過: ステータスを "In Review" に更新
- 実装成功 + レビューエスカレーション: "In Review" に更新し、未解決所見をコメントに記録
- 実装失敗: "In Progress" のまま維持し、`mcp__linear-server__create_comment` でエラー詳細を記録

#### 3-3. 後処理

- 成功したサブエージェントの worktree は自動クリーンアップされる
- 失敗した worktree はユーザーが手動確認できるよう残す
- 次に実行可能な Phase/Batch を提案する

---

## 依存分析のガイドライン

### Phase 間依存 (ロードマップに基づく)

```
Phase 1 (Core Proxy + SQLite) ← 依存なし
  ↓
Phase 2 (TLS/CA + HTTPS MITM) ← Phase 1
  ↓
Phase 3 (MCP Tools) ← Phase 1, Phase 2
  ↓
Phase 4 (Intercept Rules) ← Phase 3, Phase 1
Phase 5 (Protocol Extensions) ← Phase 2, Phase 1
  ↓
Phase 6 (Hardening) ← Phase 1-4
```

### Phase 内の依存推論ルール

1. **インフラ/ユーティリティ系 Issue は先**: バッファリーダー、ストレージ層など基盤は最初
2. **ハンドラ/ビジネスロジックは中盤**: 基盤の上に構築するロジック
3. **統合/結合 Issue は後半**: 複数コンポーネントを繋ぐ Issue は依存先が揃ってから
4. **E2E テスト/統合テストは最後**: 全コンポーネントが揃ってから
5. **MCP ツール定義は対応する内部実装の後**: 内部 API が固まってからツールを公開

### 並行実行の判定基準

**並行実行可能:**
- 異なるパッケージを主に変更する (例: `internal/proxy/` と `internal/session/`)
- 共通のインターフェースを実装するが、相互に呼び出さない
- テストが互いの実装に依存しない

**直列実行が必要:**
- Issue B が Issue A の生成する型やインターフェースを import する
- Issue B のテストが Issue A の実装を前提とする
- Issue B が Issue A で変更されるファイルの同じ箇所を変更する

---

## 注意事項

- 最大同時実行数: 3 Issue まで（リソース制約のため）
- ロードマップは最新版を毎回読み込む（キャッシュしない）
- Phase をまたいだ実装は原則行わない（前の Phase の PR がマージされてから次に進む）
- 各サブエージェントは完全に独立して動作する — 相互参照はしない
- Linear Issue のステータス更新はオーケストレーター側の責務（サブエージェントは行わない）
- 依存分析の結果に確信が持てない場合は、ユーザーに確認を取る

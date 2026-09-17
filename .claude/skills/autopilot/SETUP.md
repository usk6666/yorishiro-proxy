# /autopilot セットアップ & 運用ガイド

Claude Desktop の **ローカル定期タスク**（Routines → Local）から `/autopilot` を定期起動し、
「既存 PR のフォローアップ → Issue を 1 件選定 → 設計レビュー → 実装 → review-gate → PR」までを
人の介入なしで進めるための手順です。スキル本体は `SKILL.md` を参照してください。

## 全体像

```
[Desktop 定期タスク] ──(worktree で新規セッション)──▶ /autopilot
   Phase 0  事前チェック（gh / Linear / golangci-lint / pnpm）
   Phase 1  棚卸し + クラッシュした前回実行の claim を回収
   Phase 2  autopilot PR のフォローアップ（コンフリクト / CI 失敗 / あなたのレビューコメント）
   Phase 3  アクティブ MS から依存解決済みの Issue を 1 件だけ選定 → Linear で claim
   Phase 4  design-reviewer → implementer（draft PR 作成）
   Phase 5  review-gate（sub-agent に委譲）→ APPROVED なら Ready for review / だめなら needs-human
   Phase 6  自分が作った worktree だけ掃除（agent ledger 経由）→ 実行レポート
```

**人間がやること**は「PR のレビューとマージ」と「`needs-decision` / `needs-human` への回答」だけです。
autopilot はマージ・force push・main への push・依存追加・`.github/` や `.claude/` の変更を一切しません。

## 1. 初回セットアップ

### 1-1. スキルを main に入れる

定期タスクは worktree で起動するため、**コミットされていないファイルは見えません**。
`.claude/skills/autopilot/` と `CLAUDE.md` の変更をブランチに積んで PR → マージしてください。

```bash
git switch -c chore/autopilot-skill origin/main
git add .claude/skills/autopilot/SKILL.md .claude/skills/autopilot/SETUP.md CLAUDE.md
git commit -m "chore(claude): add /autopilot skill for scheduled unattended runs"
git push -u origin chore/autopilot-skill && gh pr create --fill
```

### 1-2. GitHub ラベルを作成（1 回だけ）

```bash
gh label create autopilot             --color 5319E7 --description "PR opened by /autopilot"
gh label create "autopilot:needs-human" --color D93F0B --description "/autopilot gave up; human action needed"
gh label create "autopilot:hands-off"   --color 0E8A16 --description "Human took over; /autopilot must not touch"
```

Linear 側のラベル（`autopilot`, `autopilot:skip`, `autopilot:needs-decision`,
`autopilot:needs-human`, `autopilot:retried`）は初回実行時に自動作成されます。

### 1-3. ローカル環境の確認

- `golangci-lint version --short` が `.golangci-lint-version` と一致すること（不一致だと毎回 ABORTED）
- `ghtkn info --log-level warn | jq -r '.agent.running, .agent.locked'` が `true` / `false` であること
  （`gh` は呼び出しごとに `ghtkn get` でトークンを取る alias なので、agent が停止・ロック中だと
  `gh auth status` が**失敗ではなくハング**します。Phase 0 はこれを `gh auth status` より先に見ます）
- `gh auth status` が OK、`pnpm` / `go` / `jq` が PATH にあること
- Claude Code の Linear MCP（`.mcp.json` の `linear-server`）が認証済みであること
- Desktop の **Settings → Desktop app → General → Keep computer awake** を ON
  （スリープ中の回は skip され、復帰時に 1 回だけ catch-up 実行されます）

### 1-4. 定期タスクを作成

Desktop の **Code タブ → Routines → New routine → Local**

| 項目 | 設定値 |
|---|---|
| Name | `yorishiro-autopilot` |
| Description | yorishiro-proxy の Issue を自律実装して PR 化 |
| Folder | `/home/user/repos/yorishiro-proxy` |
| **Worktree** | **ON**（必須。メインクローンの作業状態に触れないため） |
| Permission mode | **Auto**（`settings.json` の allow/ask/deny は auto mode 前提で設計済み） |
| Model | Opus 系を推奨（設計レビューと実装の品質に直結） |
| Schedule | まず **Daily** で作成 → 慣れたら Desktop のセッションで「yorishiro-autopilot を 9 時〜翌 1 時の 2 時間おきに変更して」と頼む |

**Instructions**（そのまま貼り付け）:

```
/autopilot

これはスケジュール起動の無人実行です。人間は応答しません。
.claude/skills/autopilot/SKILL.md の手順と Hard Rules に厳密に従い、質問や確認待ちをせずに最後まで進めてください。
判断が必要な事項は Linear コメントとラベルに記録してスキップしてください。
最終メッセージは SKILL.md Phase 6-2 の実行レポート形式で、日本語で書いてください。
```

### 1-5. 試運転

1. Instructions の 1 行目を一時的に `/autopilot dry-run` にして **Run now** → 選定結果と除外理由を確認
2. `/autopilot` に戻して **Run now** → 途中で出た許可プロンプトは「Always allow」
   （以降の実行では自動承認されます。タスク詳細の *Always allowed* で確認・取り消し可能）
3. 1 回目の PR ができたら、下の運用ルールに沿ってレビュー

## 2. 日々の運用

### あなたへのシグナル

| 見る場所 | 意味 | あなたのアクション |
|---|---|---|
| Ready for review の PR（`autopilot` ラベル） | review-gate 通過済み | レビュー → マージ。修正依頼はコメント or Request changes でOK（次回実行で対応） |
| PR に `autopilot:needs-human` | 修正 2 ラウンド超過 / フォローアップ 3 回超過 | 自分で直すか、ラベルを外して再挑戦させる |
| Linear `autopilot:needs-decision` | 設計上の未決事項（提案付き） | コメントで回答 → **ラベルを外す**（次回、回答を前提に再開） |
| Linear `autopilot:needs-human` | 保護パス / 依存追加 / 巨大すぎる Issue / 連続失敗 | Issue を分割・手動実装、または対応後にラベルを外す |
| Desktop の Scheduled セッション | 各回の実行レポート | 「Needs you」欄だけ見れば十分 |

### 制御用ラベル

- Issue を自動対象から外す → Linear で `autopilot:skip`
- PR を引き取る（autopilot に触らせない）→ GitHub で `autopilot:hands-off`
- 全体を止める → Routines のタスクを **Paused** に

### 注意点

- autopilot が反応するレビューコメントは **`usk6666` のものだけ**です（公開リポジトリでの第三者コメントによるプロンプトインジェクション対策）。
- PR のマージで後続 Issue の依存が解決します。autopilot は **In Review の依存を満たしたとみなさない**（スタック PR を作らない）ので、マージが滞ると新規着手も止まります。
- 1 回の実行で新規 Issue は 1 件まで、オープンな autopilot PR は 3 件まで（WIP 制限）。調整は `SKILL.md` の Run Configuration で。
- review-gate・PR トリアージ（Phase 2-1）・Issue 選定（Phase 3-3）は sub-agent に委譲され、生ログやレビュー本文はそちらの context に留まります。本体に戻るのは判定と PR に貼るレポート表だけなので、実行レポートにレビューの全文は出ません（PR のコメントを見てください）。
- ラベルを書き換えたり Issue を claim するのは常に本体です。委譲先は報告するだけで、書き込みは一箇所に集約されています（クラッシュ時の回収を成立させるため）。
- `.github/`・`.claude/`・`CLAUDE.md`・`Makefile` 等を変更する Issue（例: M51 の CI 系）は自動で `needs-human` になります。

## 3. トラブルシュート

| 症状 | 確認ポイント |
|---|---|
| レポートが `ABORTED` | Phase 0 のどのチェックか。多いのは golangci-lint のバージョン不一致、Linear MCP の再認証 |
| セッションが止まっている | まず ghtkn。agent がロック/停止中だと最初の `gh` で入力待ちになります（`ghtkn auth` は対話必須なので人間が実行）。そうでなければ許可プロンプト待ち — 承認して「Always allow」。`ask` リストのコマンドを使っていたらスキルの不具合なので報告 |
| 実行されない | PC スリープ / アプリ終了 / 前回実行がまだ継続中（重複実行は自動 skip） |
| `.claude/worktrees/agent-*` が増える | レポートの Health 欄に件数が出ます。Phase 6-1 は `~/.claude/autopilot-runs/<RUN_ID>.agents`（agent ledger）を読んで消すので、残っている場合はその ledger と `git worktree list` を突き合わせる。入れ子 worktree は親の中（`agent-<親>/.claude/worktrees/agent-<子>`）にあるので、トップレベルだけ見ても見つからない |
| 同じ Issue で何度も失敗 | 2 回目で `autopilot:retried` → `needs-human` に自動エスカレーションされます |

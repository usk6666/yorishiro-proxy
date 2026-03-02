---
description: "Linear Issue を読み込み、ブランチ作成から実装・テスト・コミット・PR 作成までを一気通貫で実行"
user-invokable: true
---

# /implement

Linear Issue に基づいて実装から PR 作成までを行う一気通貫ワークフロー。

## 引数

- `/implement <Issue ID>` — 指定 Issue を実装する (例: `/implement USK-12`)

## 手順

1. **Issue 読み込み**: `mcp__linear-server__get_issue` で Issue の詳細を取得
2. **Issue ステータス更新**: ステータスを "In Progress" に更新
3. **ブランチ作成**: Issue から適切なブランチ名を生成
   - feat: `feat/<id>-<short-desc>`
   - fix: `fix/<id>-<short-desc>`
   - その他: `chore/<id>-<short-desc>`
4. **実装計画**: Issue の内容を分析し、EnterPlanMode で実装計画を立てる
5. **実装**: 計画に基づいてコードを実装
6. **テスト作成**: 実装に対するテストを書く
7. **検証**:
   - `make build`
   - `make test`
8. **コミット**: Conventional Commits 形式でコミット
   - コミットメッセージのフッターに `Refs: <Issue ID>` を含める
9. **プッシュ**: `git push -u origin <branch-name>` でリモートにプッシュ
10. **PR 作成**:
    - `git diff main...HEAD` で差分を確認
    - PR タイトルは Conventional Commits 形式 (例: `feat(protocol): add HTTP handler`)
    - PR 本文は以下のテンプレートに従う
    - `gh pr create` で PR を作成
11. **Issue ステータス更新**: ステータスを "In Review" に更新
12. **結果報告**: 実装サマリー + PR URL を表示

## PR 本文テンプレート

```markdown
## Summary
- <変更の箇条書き>

## Test plan
- [ ] テスト項目

Resolves <Issue ID>
Linear: https://linear.app/usk6666/issue/<Issue ID>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

## 注意事項

- ビルドまたはテストが失敗した場合は修正してから再実行
- Issue のラベルや説明から実装のスコープを判断する
- 大きな変更の場合は計画を立ててからユーザーに確認を取る
- ステップ 7 でビルド・テスト検証済みのため、PR 作成時に再実行しない
- PR 作成が失敗した場合は `/pr` を手動実行するよう案内する

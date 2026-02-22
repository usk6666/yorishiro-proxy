---
description: "PR を作成する。ビルド・テスト通過を確認してから gh pr create を実行"
user-invokable: true
---

# /pr

Pull Request を作成するスキル。

## 手順

1. **ビルド検証**: `go vet ./...` と `go build ./...` を実行し、エラーがないことを確認
2. **テスト実行**: `go test -race ./...` を実行し、全テストがパスすることを確認
3. **差分確認**: `git diff main...HEAD` で変更内容を確認
4. **PR タイトル生成**: Conventional Commits 形式 (`feat(scope): description`) でタイトルを作成
5. **PR 本文生成**: 変更の要約、テスト計画を含む本文を生成
6. **PR 作成**: `gh pr create --title "<title>" --body "<body>"` を実行
7. **結果表示**: PR の URL を表示

## PR 本文テンプレート

```markdown
## Summary
- <変更の箇条書き>

## Test plan
- [ ] テスト項目

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

## 注意事項

- ビルドまたはテストが失敗した場合、PR は作成せず問題を報告する
- base ブランチはデフォルトで `main`

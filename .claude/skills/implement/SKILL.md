---
description: "Linear Issue を読み込み、ブランチ作成から実装・テスト・コミットまでを一気通貫で実行"
user-invokable: true
---

# /implement

Linear Issue に基づいて実装を行う一気通貫ワークフロー。

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
   - `go vet ./...`
   - `go test -race ./...`
   - `go build ./...`
8. **コミット**: Conventional Commits 形式でコミット
   - コミットメッセージのフッターに `Refs: <Issue ID>` を含める
9. **結果報告**: 実装内容のサマリーを表示

## 注意事項

- ビルドまたはテストが失敗した場合は修正してから再実行
- Issue のラベルや説明から実装のスコープを判断する
- 大きな変更の場合は計画を立ててからユーザーに確認を取る

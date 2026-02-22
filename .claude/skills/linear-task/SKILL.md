---
description: "Linear Issue の作成・更新・一覧を行う"
user-invokable: true
---

# /linear-task

Linear の Issue を管理するスキル。チーム・プロジェクトは固定。

## 固定パラメータ

- **チーム**: Usk6666
- **プロジェクト**: katashiro-proxy

## 使い方

引数なしで実行すると、現在の Issue 一覧を表示する。

### 引数パターン

- `/linear-task` — アクティブな Issue 一覧を表示
- `/linear-task create <title>` — 新規 Issue を作成
- `/linear-task <ID>` — 指定 Issue の詳細を表示
- `/linear-task update <ID> <field>=<value>` — Issue を更新

## 手順

1. 引数を解析して操作を判定する
2. `mcp__linear-server__*` ツールを使用して操作を実行する
   - 一覧: `list_issues` (team=Usk6666, project=katashiro-proxy)
   - 作成: `create_issue` (team=Usk6666, project=katashiro-proxy)
   - 詳細: `get_issue`
   - 更新: `update_issue`
3. 結果を見やすく整形して表示する

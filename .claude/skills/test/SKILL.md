---
description: "Go テストを実行する"
user-invokable: true
---

# /test

Go テストを実行するスキル。

## デフォルト動作

```bash
go test -race -v ./...
```

## 引数パターン

- `/test` — 全パッケージのテストを実行
- `/test ./internal/proxy/...` — 指定パッケージのみ実行
- `/test -cover` — カバレッジ付きで実行 (`make test-cover`)
- `/test -run TestName` — 特定のテストのみ実行

## 手順

1. 引数を解析する
2. `-cover` が指定された場合は `make test-cover` を実行
3. それ以外は `go test -race -v` に適切な引数を付けて実行
4. 結果を表示し、失敗がある場合は失敗箇所を強調する

---
description: "Go テストを実行する"
user-invokable: true
---

# /test

Go テストを実行するスキル。

## デフォルト動作

```bash
make test
```

## 引数パターン

- `/test` — 全パッケージのテストを実行 (`make test`)
- `/test ./internal/proxy/...` — 指定パッケージのみ実行 (`make ensure-ui && go test -race -v ./internal/proxy/...`)
- `/test -cover` — カバレッジ付きで実行 (`make test-cover`)
- `/test -run TestName` — 特定のテストのみ実行 (`make ensure-ui && go test -race -v -run TestName ./...`)

## 手順

1. 引数を解析する
2. `-cover` が指定された場合は `make test-cover` を実行
3. 引数なしの場合は `make test` を実行
4. パッケージ指定や `-run` 指定がある場合は `make ensure-ui && go test -race -v <引数>` を実行
5. 結果を表示し、失敗がある場合は失敗箇所を強調する

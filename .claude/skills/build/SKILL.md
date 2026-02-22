---
description: "Go プロジェクトをビルドする"
user-invokable: true
---

# /build

Go プロジェクトをビルドするスキル。

## デフォルト動作

```bash
make build
```

これは内部的に `go vet ./...` → `go build -o bin/katashiro-proxy ./cmd/katashiro-proxy` を実行する。

## 引数パターン

- `/build` — `make build` を実行
- `/build clean` — `make clean && make build` を実行

## 手順

1. 引数を解析する
2. `clean` が指定された場合は `make clean` を先に実行
3. `make build` を実行
4. 成功の場合はバイナリパスを表示、失敗の場合はエラーを報告

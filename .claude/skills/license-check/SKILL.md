---
description: "全依存のライセンスを確認し、禁止ライセンスを検出"
user-invokable: true
---

# /license-check

プロジェクトの全依存ライブラリのライセンスを確認するスキル。

## ライセンスポリシー

### 許可

MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC, MPL-2.0

### 禁止

GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, AGPL-3.0 およびその他 GPL 系

## 手順

1. `go list -m -json all` で全依存を列挙
2. 各依存のリポジトリ/パッケージの LICENSE ファイルを確認
3. ライセンスをポリシーと照合
4. 結果をテーブル形式で表示:
   - 依存名 | バージョン | ライセンス | ステータス (OK / PROHIBITED / UNKNOWN)
5. 禁止ライセンスまたは不明なライセンスがある場合は警告を出す

## 注意事項

- UNKNOWN の場合は手動確認を推奨する旨を報告
- 推移的依存（indirect）も対象に含める

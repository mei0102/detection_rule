# detection_rule

TTPを起点に、MITRE ATT&CK × 対象ログで検知を育てるリポジトリです。
初期10ルールは **experimental**。合成ログで条件を検証済みですが、実環境の検知率・誤検知率やSplunk上での実行は未検証です。

## はじめに

- [TTP × ログのマトリクス](docs/matrix.md)：記載は候補カバレッジであり、技法全体の検知保証ではありません。
- [対象ログと必要フィールド](docs/log-sources.md)：採取設定、型、正規化の契約。
- [導入と検証](docs/deployment.md)：SPLの実行条件、テスト、チューニング。
- [参考資料と出典管理](docs/references.md)：SigmaHQ、Splunk ESCU、YARAの位置づけ。
- [日次追加の手順](docs/daily.md)：未カバーのTTPを優先して1日1件以上追加。
- `rules/`：機械可読な独自JSON仕様。SigmaやYARAの形式ではありません。
- `queries/`：JSON仕様から生成したSplunk SPL。ESCU/CIMへの依存なし。
- `docs/rules/`：各ルールの必要フィールド、前提、誤検知、調査手順。
- `tests/fixtures/`：無害な合成イベント。攻撃コマンドの実行は不要です。

```sh
python tools/build.py
python -m unittest discover -s tests -v
```

Python 3.11以上、追加パッケージ不要。利用するSIEM・製品名が決まったら、正規化マッピングとネイティブ検索を追加します。
ルールの件数を増やすことより、ログで観測できる根拠とテストを優先します。

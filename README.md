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
- `docs/rules/`：検知SPL・調査SPLをMarkdown本文に収録。条件は `=` / `~=` / `>=` 表記。必要フィールド、誤検知、具体的な調査と限界、タイトル・概要付き参考文献も記載。
- `data/attack.json`：公式STIXから抽出した戦術の順序と対象技法。固定commitと確認日を記録。
- `tests/fixtures/`：無害な合成イベント。攻撃コマンドの実行は不要です。

```sh
python tools/build.py
python -m unittest discover -s tests -v
```

SIEMは **Splunk Enterprise / Splunk Cloud Platform** を想定。ESCU/CIMの導入は必須ではありません。各カードのSPLを利用し、製品別のフィールド抽出を[導入手順](docs/deployment.md)に沿って合わせます。
Python 3.11以上、追加パッケージ不要。JSONは再生成・合成テスト用の内部定義です。
ルールの件数を増やすことより、ログで観測できる根拠とテストを優先します。

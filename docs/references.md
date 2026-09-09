# 参考資料と出典管理

確認日：2026-09-09。初期ルールは独自実装で、他者のルール本文や説明文の一括コピーは行っていません。

|資料|確認した版／用途|
|---|---|
|[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)|commit 5c9b21756f4e3ba137c1773ac9ba5a8332188961。PowerShell検知のプロセス条件・誤検知の考え方を参照。ルールのライセンスはDRL 1.1との記載|
|[Splunk security_content / ESCU](https://github.com/splunk/security_content)|commit 4cd62e811c5eddf1245c780d48823d7b38998566。Encoded Command analyticのデータ要件・調査前提を参照。Apache-2.0との記載|
|[MITRE ATT&CK Enterprise STIX](https://github.com/mitre-attack/attack-stix-data/tree/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack)|公式マトリクスの戦術列順、技法・サブ技法の名前と所属を確認。data/attack.jsonは必要なメタデータの抜粋。commit 6cda5ad8462c79e14fbb872f4e09059b18e0cfc4に固定|
|[YARA公式](https://yara.readthedocs.io/en/stable/)|ファイルやメモリのパターンマッチング用。FW/Proxy/NDR/Windowsのログ相関用のYARAルールは作成しない|

WIN-001のJSONには確認した具体的なSigma／ESCUの固定commitリンクを収録。他のルールはATT&CKの挙動とログイベントから独自に設計しています。
各ルールカードの参考文献にはタイトル、概要・利用箇所、URL、確認日を掲載します。Microsoftのイベント仕様とZeek DNS仕様も該当カードから参照できます。
監査ログ消去の旧T1070.001は現行T1685.005（Defense Impairment）へ更新し、Administrators追加はT1098.007へ詳細化しています。
YARAを追加する場合は`rules/yara/`に分離し、対象ファイル種別、取得経路、スキャン範囲、正負サンプル、コンパイル結果を揃えます。
YARA-Lは別の言語であり、このリポジトリのYARAという記載とは区別します。

今後他者ルールを移植する場合は、元URL・commit・著者・元ライセンス・変更点を明記し、必要なLICENSE/NOTICEを同梱してください。
新しいファイルに他者コンテンツのライセンスを無根拠に付与しないでください。

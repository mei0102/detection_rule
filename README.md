# detection_rule

Splunk向けの検知ルール集。SPLは各Markdownに掲載しています。

[ATT&CKマトリクス・ログ別集計](MATRIX.md)

Windows Event **5件** ／ FW **2件** ／ Proxy **2件** ／ DNS **1件**（合計 **10件**）

|対象ログ|ルール|
|---|---|
|FW|[FW-001 単一宛先への多数ポート接続試行](rules/fw/FW-001.md)|
|FW|[FW-002 内部複数ホストへのRDPポート接続許可](rules/fw/FW-002.md)|
|DNS|[DNS-001 長いDNSラベルを持つ多数の異なる問い合わせ](rules/dns/DNS-001.md)|
|Proxy|[PROXY-001 実行形式を示すURLからの取得成功](rules/proxy/PROXY-001.md)|
|Proxy|[PROXY-002 PowerShell User-AgentからのHTTP取得](rules/proxy/PROXY-002.md)|
|Windows Event|[WIN-001 EncodedCommandを使うPowerShell](rules/windows/WIN-001.md)|
|Windows Event|[WIN-002 Security監査ログの消去](rules/windows/WIN-002.md)|
|Windows Event|[WIN-003 同一送信元・利用者への認証失敗集中](rules/windows/WIN-003.md)|
|Windows Event|[WIN-004 ローカルAdministratorsへのメンバー追加](rules/windows/WIN-004.md)|
|Windows Event|[WIN-005 新規スケジュールタスクの作成](rules/windows/WIN-005.md)|

`index=detection_lab` とフィールド名は環境に合わせて読み替えてください。SPLは正規化済みログを前提に、5分間隔・5分遅延で検索します。

ATT&CKの位置は検知対象との対応を示します。各ルールは実環境での動作を保証するものではありません。

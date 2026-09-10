# detection_rule

Splunk向けの検知ルール集。各Markdownに汎化、検知意図と限界、誤検知、SPL、Splunk ES設定案、閾値、人が評価すべき点を掲載しています。

[ATT&CKマトリクス・ログ別集計](MATRIX.md)

Windows Event **25件** ／ FW **10件** ／ Proxy **8件** ／ DNS **7件**（合計 **50件**）

公開ルールを参考に、順序・集約・通信方向などを組み合わせて独自SPL化しています。元ルールの単純コピーではありません。

`index=detection_lab` と必要フィールドを実際のログへ対応づけて使用します。時間窓はルールごとに記載し、記載のない基礎ルールは5分窓。実行は5分間隔・5分遅延を想定し、長い窓では同じ対象が再び出る場合があります。

数値フィールドは数値、HTTP methodは大文字、actionはallow/deny、zoneは組織のinternal/external分類を前提とします。hostは監視対象端末、userはドメイン付き対象ユーザー、bytes_out/inは送信元→宛先／逆方向です。CIMマクロや未提供lookupには依存しません。

閾値・感度変更・ES設定は未検証の案です。実ログでの効果・処理負荷・Splunk上の動作は未確認です。テストや独立したチューニング資料は含めていません。

必要フィールドは実装要件であり、実環境での取得確認済み一覧ではありません。CIM対応・Data Model加速の有無は未確認です。「検知意図と限界」「誤検知」「drilldown」で取りこぼす行動と次の確認先を示します。

現行SPLは変更前のリポジトリ版（5d42ac6）を折りたたみ表示しています。提案SPLは検知条件を維持し、ES用の出力列を追加した版です。Risk Analysis・Notableのアクション設定や顧客環境への適用は行っていません。

## Windows Event

|ルール|ATT&CK|
|---|---|
|[WIN-001 EncodedCommandを使うPowerShell](rules/windows/WIN-001.md)|T1059.001|
|[WIN-002 Security監査ログの消去](rules/windows/WIN-002.md)|T1685.005|
|[WIN-003 同一送信元・利用者への認証失敗集中](rules/windows/WIN-003.md)|T1110.001|
|[WIN-004 ローカルAdministratorsへのメンバー追加](rules/windows/WIN-004.md)|T1098.007|
|[WIN-005 新規スケジュールタスクの作成](rules/windows/WIN-005.md)|T1053.005|
|[WIN-006 複数ユーザーへの低回数パスワード試行](rules/windows/WIN-006.md)|T1110.003|
|[WIN-007 認証失敗の集中後に同じ主体がログオン成功](rules/windows/WIN-007.md)|T1110.001|
|[WIN-008 新規アカウントの管理者追加後のログオン](rules/windows/WIN-008.md)|T1098.007|
|[WIN-009 ドメイン特権グループへのメンバー追加](rules/windows/WIN-009.md)|T1098.007|
|[WIN-010 書込可能パスやシェルを使うサービス登録](rules/windows/WIN-010.md)|T1543.003|
|[WIN-011 高権限タスクに書込可能パスの実行を設定](rules/windows/WIN-011.md)|T1053.005|
|[WIN-012 作成から5分以内に削除されたタスク](rules/windows/WIN-012.md)|T1053.005|
|[WIN-013 comsvcsを使ったプロセスメモリのダンプ](rules/windows/WIN-013.md)|T1003.001|
|[WIN-014 CertUtilでHTTPファイル取得を指定](rules/windows/WIN-014.md)|T1105|
|[WIN-015 Regsvr32でリモートScriptletを指定](rules/windows/WIN-015.md)|T1218.010|
|[WIN-016 Officeから起動したMSHTAがURLを指定](rules/windows/WIN-016.md)|T1218.005|
|[WIN-017 BITSAdminジョブにHTTP転送元を指定](rules/windows/WIN-017.md)|T1197|
|[WIN-018 PowerShellスクリプト内の取得と動的実行](rules/windows/WIN-018.md)|T1059.001|
|[WIN-019 復元用シャドウコピーの一括削除指定](rules/windows/WIN-019.md)|T1490|
|[WIN-020 NetshでWindowsファイアウォールを無効化](rules/windows/WIN-020.md)|T1686|
|[WIN-021 Defenderリアルタイム保護の無効化](rules/windows/WIN-021.md)|T1685|
|[WIN-022 非コンピュータアカウントによるディレクトリ複製権限利用](rules/windows/WIN-022.md)|T1003.006|
|[WIN-023 短時間に多数のRC4サービスチケットを要求](rules/windows/WIN-023.md)|T1558.003|
|[WIN-024 管理共有への実行形式の書込み権限チェック](rules/windows/WIN-024.md)|T1570|
|[WIN-025 WinRM配下で転送ツールを起動](rules/windows/WIN-025.md)|T1021.006|

## FW

|ルール|ATT&CK|
|---|---|
|[FW-001 単一宛先への多数ポート接続試行](rules/fw/FW-001.md)|T1046|
|[FW-002 内部複数ホストへのRDPポート接続許可](rules/fw/FW-002.md)|T1021.001|
|[FW-003 同一ポートへの内部横断スキャン](rules/fw/FW-003.md)|T1046|
|[FW-004 時間分散した内部ポート探索](rules/fw/FW-004.md)|T1046|
|[FW-005 外部へのSMB接続で双方向通信を観測](rules/fw/FW-005.md)|T1187|
|[FW-006 外部LDAPへの繰り返し接続](rules/fw/FW-006.md)|T1190|
|[FW-007 同じ通信先への複数拒否後に許可](rules/fw/FW-007.md)|T1686|
|[FW-008 HTTPSポート上で識別されたSSH通信](rules/fw/FW-008.md)|T1571|
|[FW-009 外部非Web宛先への持続的な送信集中](rules/fw/FW-009.md)|T1048|
|[FW-010 内部SMB経由の複数端末へのデータ配布](rules/fw/FW-010.md)|T1570|

## Proxy

|ルール|ATT&CK|
|---|---|
|[PROXY-001 実行形式を示すURLからの取得成功](rules/proxy/PROXY-001.md)|T1105|
|[PROXY-002 PowerShell User-AgentからのHTTP取得](rules/proxy/PROXY-002.md)|T1105|
|[PROXY-003 BITSによる外部IP直指定ダウンロード](rules/proxy/PROXY-003.md)|T1105|
|[PROXY-004 クラウド保存先への継続的・集中的アップロード](rules/proxy/PROXY-004.md)|T1567.002|
|[PROXY-005 外部WebDAV探索後のスクリプト取得](rules/proxy/PROXY-005.md)|T1105|
|[PROXY-006 Curl／Wgetによる実行形式の取得](rules/proxy/PROXY-006.md)|T1105|
|[PROXY-007 Webhookへの反復・大容量POST](rules/proxy/PROXY-007.md)|T1567.004|
|[PROXY-008 同一URLへの低揺らぎ周期通信](rules/proxy/PROXY-008.md)|T1071.001|

## DNS

|ルール|ATT&CK|
|---|---|
|[DNS-001 長いDNSラベルを持つ多数の異なる問い合わせ](rules/dns/DNS-001.md)|T1071.004|
|[DNS-002 多様な名前への継続的なNXDOMAIN探索](rules/dns/DNS-002.md)|T1568.002|
|[DNS-003 TXT応答にダウンロード・実行の文字列](rules/dns/DNS-003.md)|T1071.004|
|[DNS-004 DNS ANY問い合わせの宛先集中](rules/dns/DNS-004.md)|T1498.002|
|[DNS-005 複数ゾーンへの転送要求](rules/dns/DNS-005.md)|T1590.002|
|[DNS-006 逆引きDNSによる多数ホスト探索](rules/dns/DNS-006.md)|T1018|
|[DNS-007 同じDNS名への低揺らぎ周期照会](rules/dns/DNS-007.md)|T1071.004|

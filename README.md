# detection_rule

Splunk向けの検知ルール集。各Markdownに汎化、検知意図と限界、誤検知、SPL、Splunk ES設定案、閾値、人が評価すべき点を掲載しています。

[ATT&CKマトリクス・ログ別集計](MATRIX.md)

Windows Event **32件** ／ FW **10件** ／ Proxy **20件** ／ DNS **7件**（合計 **69件**）

公開ルールを参考に、順序・集約・通信方向などを組み合わせて独自SPL化しています。元ルールの単純コピーではありません。

`index=detection_lab` と必要フィールドを実際のログへ対応づけて使用します。時間窓はルールごとに記載し、記載のない基礎ルールは5分窓。実行は5分間隔・5分遅延を想定し、長い窓では同じ対象が再び出る場合があります。

数値フィールドは数値、HTTP methodは大文字、actionはallow/deny、zoneは組織のinternal/external分類を前提とします。hostは監視対象端末、userはドメイン付き対象ユーザー、bytes_out/inは送信元→宛先／逆方向です。CIMマクロや未提供lookupには依存しません。

閾値・感度変更・ES設定は未検証の案です。実ログでの効果・処理負荷・Splunk上の動作は未確認です。テストや独立したチューニング資料は含めていません。

必要フィールドは実装要件であり、実環境での取得確認済み一覧ではありません。CIM対応・Data Model加速の有無は未確認です。「検知意図と限界」「誤検知」「drilldown」で取りこぼす行動と次の確認先を示します。

各ルールは「検知概要・検知意図・過検知予想」から読み始められます。既存50件の現行SPLは変更前の版（5d42ac6）を折りたたみ表示しています。提案SPLにはES用の出力列・調査優先度を記載し、新規分は現行SPLなしと示しています。Risk Analysis・Notableのアクション設定や顧客環境への適用は行っていません。

新規PROXY-009〜020は外向きForward Proxyの調査ルールです。Web攻撃要求のルールも、社内端末から外部サイトへ送信した要求を扱います。社内Webサーバーへの受信攻撃を検知するには、別途Reverse Proxy／WAFログへの対応が必要です。

## どれから調べるか

重要度は「この条件で発報したときの調査順」です。技法の危険性・情報源の知名度・新しさ・スコアを、そのまま悪性の確度には置き換えません。P1でも自動隔離や感染確定を意味しません。

|重要度|位置づけ|件数|
|---|---|---:|
|P1|先行トリアージ。資格情報・復旧手段・侵入の定着に関係する具体的な操作|10|
|P2|通常調査。追加証拠と業務確認で優先度を上げる|34|
|P3|補助シグナル。単独Notableは原則非推奨|25|

## 高度化ルールを選ぶ入口

**導入の優先順位と、発報時のP1〜P3は別です。** 必要ログがないルールは、P1でも実装候補になりません。新しさは参考文献の観測・公開時期で判断し、重要度は実際に捉える行動と影響で判断します。

|まず読むルール|選ぶ理由|残る不確実性|
|---|---|---|
|[WIN-027](rules/windows/WIN-027.md)|Deno起動と同じ実行パス・URLのタスク登録を結び付ける|タスク実行成功と取得コードの悪性|
|[WIN-028](rules/windows/WIN-028.md)|画像通信だけでなく画素読取・バイナリ保存を捉える|4104の断片化とコードの実行成否|
|[WIN-029](rules/windows/WIN-029.md)・[WIN-030](rules/windows/WIN-030.md)|RMM配下の複数スクリプト起動、同じパスの自動起動登録を追う|正規配布との区別、4657の監査取得|
|[WIN-032](rules/windows/WIN-032.md)|ネットワークログオンとサービス登録を同一セッションで関連付け、接続元を示す|サービス実行成功、長時間セッション、正規遠隔管理|

WIN-027〜030は2026年の事例を参照。WIN-032は2026年更新の調査知見を参考にした汎用相関で、新規攻撃の報告ではありません。各カードの「疑いを強める追加証拠」を満たすかで調査を進めます。件数やSPLの長さだけで高度化を評価しません。

## 今回優先した2026年の事例

|ルール|補った穴|報告の時期|
|---|---|---|
|[WIN-026](rules/windows/WIN-026.md)|Office直下ではない、Pcalua経由のMSHTAを親子PIDで確認|Huntress観測2026年5月、個人研究公開8月1日|
|[WIN-027](rules/windows/WIN-027.md)|Denoの遠隔コード起動後、同じ実行パス・URLでタスク登録|Sophos観測6月3〜4日、変化6月23日|
|[WIN-028](rules/windows/WIN-028.md)|画像取得だけでなく、端末で画素読取とバイナリ保存が同居|Microsoft公開8月28日|

各ルール内で情報源の信頼性とDetection Ideaの価値を分けています。上記以外の既存ルールを「最新脅威への対応済み」と扱っていません。全体のTP/FP・稼働負荷は未確認です。

2026-09-11追加：[WIN-029](rules/windows/WIN-029.md) — ScreenConnectから複数の一時VBScriptを起動（P1）。Huntressの8月観測・9月更新を参照し、固定ファイル名を使わず親プロセス単位で集約。

2026-09-12追加：[WIN-030](rules/windows/WIN-030.md) — VBScript起動後、同じパスのRun登録を4688→4657で相関（P1）。4657のSet Value監査が必須です。

2026-09-13追加：[WIN-031](rules/windows/WIN-031.md) — Defender除外指定とWeb取得・動的実行の同居（P2）。WIN-018の詳細化として調査をまとめ、二重加点を避けます。

2026-09-14追加：[WIN-032](rules/windows/WIN-032.md) — ネットワークログオン→同一セッションのサービス登録（P2）。接続元と登録主体を関連付け、実行成功とは区別します。

## Windows Event

|ルール|重要度|ATT&CK|
|---|---|---|
|[WIN-001 EncodedCommandを使うPowerShell](rules/windows/WIN-001.md)|P2|T1059.001|
|[WIN-002 Security監査ログの消去](rules/windows/WIN-002.md)|P2|T1685.005|
|[WIN-003 同一送信元・利用者への認証失敗集中](rules/windows/WIN-003.md)|P2|T1110.001|
|[WIN-004 ローカルAdministratorsへのメンバー追加](rules/windows/WIN-004.md)|P2|T1098.007|
|[WIN-005 新規スケジュールタスクの作成](rules/windows/WIN-005.md)|P3|T1053.005|
|[WIN-006 複数ユーザーへの低回数パスワード試行](rules/windows/WIN-006.md)|P2|T1110.003|
|[WIN-007 認証失敗の集中後に同じ主体がログオン成功](rules/windows/WIN-007.md)|P2|T1110.001|
|[WIN-008 新規アカウントの管理者追加後のログオン](rules/windows/WIN-008.md)|P1|T1098.007|
|[WIN-009 ドメイン特権グループへのメンバー追加](rules/windows/WIN-009.md)|P1|T1098.007|
|[WIN-010 書込可能パスやシェルを使うサービス登録](rules/windows/WIN-010.md)|P2|T1543.003|
|[WIN-011 高権限タスクに書込可能パスの実行を設定](rules/windows/WIN-011.md)|P2|T1053.005|
|[WIN-012 作成から5分以内に削除されたタスク](rules/windows/WIN-012.md)|P2|T1053.005|
|[WIN-013 comsvcsを使ったプロセスメモリのダンプ](rules/windows/WIN-013.md)|P1|T1003.001|
|[WIN-014 CertUtilでHTTPファイル取得を指定](rules/windows/WIN-014.md)|P2|T1105|
|[WIN-015 Regsvr32でリモートScriptletを指定](rules/windows/WIN-015.md)|P2|T1218.010|
|[WIN-016 Officeから起動したMSHTAがURLを指定](rules/windows/WIN-016.md)|P2|T1218.005|
|[WIN-017 BITSAdminジョブにHTTP転送元を指定](rules/windows/WIN-017.md)|P2|T1197|
|[WIN-018 PowerShellスクリプト内の取得と動的実行](rules/windows/WIN-018.md)|P2|T1059.001|
|[WIN-019 復元用シャドウコピーの一括削除指定](rules/windows/WIN-019.md)|P1|T1490|
|[WIN-020 NetshでWindowsファイアウォールを無効化](rules/windows/WIN-020.md)|P2|T1686|
|[WIN-021 Defenderリアルタイム保護の無効化](rules/windows/WIN-021.md)|P2|T1685|
|[WIN-022 非コンピュータアカウントによるディレクトリ複製権限利用](rules/windows/WIN-022.md)|P1|T1003.006|
|[WIN-023 短時間に多数のRC4サービスチケットを要求](rules/windows/WIN-023.md)|P2|T1558.003|
|[WIN-024 管理共有への実行形式の書込み権限チェック](rules/windows/WIN-024.md)|P2|T1570|
|[WIN-025 WinRM配下で転送ツールを起動](rules/windows/WIN-025.md)|P2|T1021.006|
|[WIN-026 Pcaluaから起動したMSHTAがWebを参照](rules/windows/WIN-026.md)|P1|T1218.005|
|[WIN-027 Denoの遠隔コード起動後に同じURLのタスクを登録](rules/windows/WIN-027.md)|P1|T1053.005|
|[WIN-028 PowerShell内でWeb取得・画像の画素読取・バイナリ保存が同居](rules/windows/WIN-028.md)|P1|T1027.003|
|[WIN-029 ScreenConnectから複数の一時VBScriptを起動](rules/windows/WIN-029.md)|P1|T1059.005|
|[WIN-030 起動した一時VBScriptをRunキーへ登録](rules/windows/WIN-030.md)|P1|T1547.001|
|[WIN-031 Defender除外指定とWeb取得・動的実行が同じPowerShellに同居](rules/windows/WIN-031.md)|P2|T1685|
|[WIN-032 ネットワークログオン直後の同一セッションによるサービス登録](rules/windows/WIN-032.md)|P2|T1543.003|

## FW

|ルール|重要度|ATT&CK|
|---|---|---|
|[FW-001 単一宛先への多数ポート接続試行](rules/fw/FW-001.md)|P3|T1046|
|[FW-002 内部複数ホストへのRDPポート接続許可](rules/fw/FW-002.md)|P3|T1021.001|
|[FW-003 同一ポートへの内部横断スキャン](rules/fw/FW-003.md)|P2|T1046|
|[FW-004 時間分散した内部ポート探索](rules/fw/FW-004.md)|P2|T1046|
|[FW-005 外部へのSMB接続で双方向通信を観測](rules/fw/FW-005.md)|P3|T1187|
|[FW-006 外部LDAPへの繰り返し接続](rules/fw/FW-006.md)|P3|T1190|
|[FW-007 同じ通信先への複数拒否後に許可](rules/fw/FW-007.md)|P3|T1686|
|[FW-008 HTTPSポート上で識別されたSSH通信](rules/fw/FW-008.md)|P3|T1571|
|[FW-009 外部非Web宛先への持続的な送信集中](rules/fw/FW-009.md)|P2|T1048|
|[FW-010 内部SMB経由の複数端末へのデータ配布](rules/fw/FW-010.md)|P2|T1570|

## Proxy

|ルール|重要度|ATT&CK|
|---|---|---|
|[PROXY-001 実行形式を示すURLからの取得成功](rules/proxy/PROXY-001.md)|P3|T1105|
|[PROXY-002 PowerShell User-AgentからのHTTP取得](rules/proxy/PROXY-002.md)|P3|T1105|
|[PROXY-003 BITSによる外部IP直指定ダウンロード](rules/proxy/PROXY-003.md)|P3|T1105|
|[PROXY-004 クラウド保存先への継続的・集中的アップロード](rules/proxy/PROXY-004.md)|P2|T1567.002|
|[PROXY-005 外部WebDAV探索後のスクリプト取得](rules/proxy/PROXY-005.md)|P2|T1105|
|[PROXY-006 Curl／Wgetによる実行形式の取得](rules/proxy/PROXY-006.md)|P3|T1105|
|[PROXY-007 Webhookへの反復・大容量POST](rules/proxy/PROXY-007.md)|P3|T1567.004|
|[PROXY-008 同じURLへのほぼ一定間隔の通信](rules/proxy/PROXY-008.md)|P3|T1071.001|
|[PROXY-009 非標準ポートへのCONNECTトンネルの繰り返し](rules/proxy/PROXY-009.md)|P3|T1572|
|[PROXY-010 HTTPSでのDNS問い合わせを繰り返す端末](rules/proxy/PROXY-010.md)|P3|T1071.004|
|[PROXY-011 外部WebSocketへの繰り返し切替](rules/proxy/PROXY-011.md)|P3|T1071.001|
|[PROXY-012 長いパラメータを変えながら同じURLパスへ送信](rules/proxy/PROXY-012.md)|P3|T1041|
|[PROXY-013 IPアドレス直指定先への大量アップロード](rules/proxy/PROXY-013.md)|P3|T1041|
|[PROXY-014 コマンドライン取得ツールによる複数アーカイブ取得](rules/proxy/PROXY-014.md)|P3|T1105|
|[PROXY-015 文書や画像らしいURLから実行形式の応答](rules/proxy/PROXY-015.md)|P2|T1105|
|[PROXY-016 多数の存在しないWebパスを試す端末](rules/proxy/PROXY-016.md)|P3|T1595.003|
|[PROXY-017 親ディレクトリをたどるURL要求の繰り返し](rules/proxy/PROXY-017.md)|P2|T1190|
|[PROXY-018 SQLの構文をURLへ埋め込む要求の繰り返し](rules/proxy/PROXY-018.md)|P2|T1190|
|[PROXY-019 URLにシェルの連結記号とコマンドを含む要求](rules/proxy/PROXY-019.md)|P2|T1190|
|[PROXY-020 環境設定・Git・バックアップファイルを探す要求](rules/proxy/PROXY-020.md)|P2|T1595.003|

## DNS

|ルール|重要度|ATT&CK|
|---|---|---|
|[DNS-001 長いDNSラベルを持つ多数の異なる問い合わせ](rules/dns/DNS-001.md)|P3|T1071.004|
|[DNS-002 多様な名前への継続的なNXDOMAIN探索](rules/dns/DNS-002.md)|P2|T1568.002|
|[DNS-003 TXT応答にダウンロード・実行の文字列](rules/dns/DNS-003.md)|P2|T1071.004|
|[DNS-004 DNS ANY問い合わせの宛先集中](rules/dns/DNS-004.md)|P3|T1498.002|
|[DNS-005 複数ゾーンへの転送要求](rules/dns/DNS-005.md)|P3|T1590.002|
|[DNS-006 逆引きDNSによる多数ホスト探索](rules/dns/DNS-006.md)|P3|T1018|
|[DNS-007 同じDNS名への低揺らぎ周期照会](rules/dns/DNS-007.md)|P3|T1071.004|

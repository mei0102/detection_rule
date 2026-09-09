# 対象ログと必要フィールド

以下はこのリポジトリ独自の正規化名です。Splunk CIMのフィールド名と同一とは限りません。
ルールごとの必須項目は `required_fields` と各ルールカードに記載します。欠損は非検知になるため、別途欠損率を監視してください。

|ログ|必須候補・型|元フィールド例／前提|調査用の推奨項目|
|---|---|---|---|
|共通|_time: Unix秒（数値）、log_type: windows/fw/proxy/ndr|UTCに正規化。重複排除後のイベントを入力|event_uid、収集時刻、sensor、製品名|
|FW|src_ip/dest_ip:文字列、dest_port:整数、transport:小文字文字列、action:allow/deny、src_zone/dest_zone:文字列|製品のsrc/dst/dport/proto/action。permit/acceptをallowに変換。internalは実際の組織ネットワークから分類|src_port、NAT前後IP、bytes_in/out、packets、session_id、rule_name|
|Proxy|src_ip、url、http_method:大文字、http_status:整数、user_agent:文字列|HTTP request URL/method/status/User-Agent。CONNECTログだけではURLパスやUAを取得できない|user、dest_host、dest_ip、content_type、bytes_in/out、action|
|NDR|src_ip、protocol:dns、dns_query:文字列|例：Zeek dns.logのid.orig_h→src_ip、query→dns_query。小文字化・末尾ドット除去。DNS問い合わせイベント単位|uid、dest_ip、query_type、rcode、answers、センサー位置|
|Windows Event|host、channel、event_id:整数、process_path、command_line、src_ip、user、target_sid|Computer→host、Channel→channel、EventID→event_id、NewProcessName→process_path、CommandLine→command_line、IpAddress→src_ip、TargetUserName→user、TargetSid→target_sid|SubjectUserName、SubjectLogonId、MemberSid、TaskName、TaskContent、LogonType、Status/SubStatus|

全項目を全ルールで要求するわけではありません。WIN-001は4688、WIN-002は1102、WIN-003は4625、WIN-004は4732、WIN-005は4698を使用します。
同じEvent IDでもチャネルを必ず限定します。4688のCommandLineは標準設定で空の場合があり、プロセス作成監査とコマンドライン収集の両設定が必要です。

正規化では複数テナントのhost/IP衝突を避けるため検索範囲をテナント単位に分けます。
FWのallowは接続成功・認証成功の証拠ではありません。ProxyのHTTP 200もファイル実行の証拠ではありません。
TLS復号のないProxy、DNSを復号できないNDR、FWを通らない内部通信はそれぞれ可視性の制限として記録します。

一次資料：[Microsoft 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)、[Microsoft 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)。

# PROXY-013 IPアドレス直指定先への大量アップロード

**検知概要：** ドメイン名を使わずIPv4アドレスを指定したWeb宛先へ、大量のデータを繰り返し送る端末を探す。

**検知意図：** 外部の直接指定先へデータを持ち出していないか調べる。

**過検知予想：** IP指定の業務API、装置へのアップロード、転送試験。利用目的の裏付けが必要で、単独で悪性とは判断しない。

|判断の目安|内容|
|---|---|
|**重要度**|**P3：調査・相関の材料**（感染確定度ではない）|
|重要度の理由|正規利用と重なる観測が中心。単独発報だけでインシデント扱いする根拠が弱い。|
|ルールの役割|単独イベント・集約／補助シグナル|
|発報したら|原則として単独Notableにせず、下記の追加証拠との相関やハンティングに使う。|
|疑いを強める追加証拠|IP所有者、業務API仕様、送信ファイル、端末の操作主体。 正常な説明がつかず、同一主体の不正操作が裏付けられること。|
|検知価値の評価|単独では低・相関用（設計上の判断。TP/FP・処理負荷は未検証）|

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `dest_zone`, `url`, `http_method`, `http_status`, `bytes_out`, `bytes_in`|
|ATT&CK 戦術|[TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010)|
|技法 → サブ技法|[T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)|
|検索|15分窓／5分間隔／5分遅延|

外向きForward Proxy用。src_ipは社内の要求元、dest_zoneは組織定義の外部区分。HTTPSのURL・ヘッダーを使う条件は復号・記録が必要。取得可否は未確認。探索・攻撃要求のルールも、社内端末から外部へ送った要求を扱う。

## 汎化

- 脅威固有の指標：攻撃者IP・ハッシュには依存せず、提案SPLのプロトコル・文字列・量を使用。
- 共通する実装パターン：ドメイン名を使わずIPv4アドレスを指定したWeb宛先へ、大量のデータを繰り返し送る端末を探す。
- 長期利用できる攻撃行動：外部の直接指定先へデータを持ち出していないか調べる。
- 今回採用する条件と理由：15分に5要求・50MiB以上、送信量が受信量の10倍以上。 単発の一致や通常通信と区別するための設計値。
- 採用しない条件と理由：未取得の本文・端末情報や許可台帳を必須にすると、このProxyだけで成立しないため。別の調査で補う。

## 検知意図と限界

- 検知できること：ドメイン名を使わずIPv4アドレスを指定したWeb宛先へ、大量のデータを繰り返し送る端末を探す。
- 検知できないこと：URLホストのIPv4形式を確認するだけで、実アドレス有効性はURLパーサーに依存。DNS名・IPv6・単発送信は対象外。C2経路は別途確認。
- 意図的に検知しないこと：閾値未満・掲載していない表現の通信、Proxyを通らない通信。
- 想定される回避方法：要求を時間・宛先へ分散する、文字列を変更する、観測対象外の本文やプロトコルへ移す。

## 誤検知

- 主な正常動作：IP指定の業務API、装置へのアップロード、転送試験。
- 誤検知を識別する追加情報：IP所有者、業務API仕様、送信ファイル、端末の操作主体。
- 改善方法：上記情報で承認済み業務と照合し、送信元・対象・時間帯の組を評価。
- 除外が必要な場合の対象と根拠：承認記録で裏付けられた業務の組だけ。今回のSPLには除外なし。
- 改善により新たに生じる検知漏れ：承認端末の侵害や業務に似せた通信、追加証拠が欠落した攻撃。

## SPL

- 現行SPL：該当なし（今回の新規ルール）。
- 提案SPL：

```spl
index=detection_lab log_type="proxy" dest_zone="external" earliest=-20m@m latest=-5m@m
| rex field=url "(?i)^https?://(?<url_host>[^/:]+)(?<url_path>/[^?#]*)?"
| eval url_host=lower(url_host), url_path=coalesce(url_path,"/")
| where http_method IN ("POST","PUT") AND http_status >= 200 AND http_status < 300
    AND match(url_host,"^[0-9]{1,3}([.][0-9]{1,3}){3}$")
| stats count as requests
        sum(bytes_out) as sent_bytes
        sum(bytes_in) as received_bytes
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip url_host
| where requests >= 5 AND sent_bytes >= 52428800
    AND sent_bytes >= 10*max(received_bytes,1)
| eval rule_id="PROXY-013", attack_id="T1041",
       risk_object=src_ip, risk_object_type="system", risk_score=10, severity="low"
```

- 差分：新規。IPアドレス直指定先への大量アップロードを調査対象として追加。
- index、sourcetype、製品固有フィールドの置換箇所：index=detection_labは実indexへ置換し、確認済みsourcetypeで限定。log_typeは分類用の仮列。必要フィールド表は実装要件であり取得済み台帳ではない。HTTP statusは数値、methodは大文字、bytesは要求/トンネル単位。ヘッダー列は製品ごとに対応確認。
- 想定負荷：中（15分のURL抽出・集約を行う設計上の概算、未測定）。
- 負荷を抑える工夫：外向きログと時間窓を先に限定。join/transaction/全件ソートなし。加速済みCIMが確認できる場合のみtstats化を別途検討。

## Splunk ES設定案

- 実行間隔：5分。
- earliest/latest：`-20m@m` / `-5m@m`。
- trigger：結果行数 > 0で調査対象。単独Notableは非推奨。別の侵害兆候との相関後に通知を検討。
- suppression/throttling：初期は無効。反復状況を確認後にrule_id・src_ip・宛先の組で15分抑制する案。別の攻撃を抑える可能性を評価。
- severity：`low`（P3の調査優先度に対応。悪性確定ではない）。
- risk score：`10`（未検証の相対値）。Risk Analysisアクションは別途設定。スコアだけで重要度を判断しない。
- risk object／type：src_ip / system。共有Proxy・NATのIPを端末と誤認しないこと。
- security domain：network。
- notable title：PROXY-013 IPアドレス直指定先への大量アップロード（採用時の案）。
- drilldown：src_ipと結果の宛先で同じ15分窓の元ログを再検索。IP所有者、業務API仕様、送信ファイル、端末の操作主体を確認。

## 閾値

- 初期値：15分に5要求・50MiB以上、送信量が受信量の10倍以上。
- 根拠：動作の比較に使う仮の設計値。参考資料の推奨値や実環境の正常分布ではない。
- 高感度設定：3要求・25MiB・比5。その他の条件は標準を維持する案。
- 標準設定：提案SPLの条件。
- 低誤検知設定：10要求・100MiB・比20。追加情報が必要なら収集を確認。効果は未検証。
- ベースライン取得方法：30日を同じ15分窓と集約軸で集計し、IP指定の業務API、装置へのアップロード、転送試験の確認済み結果と比較する。

## 人が評価すべき点

- 採用判断に必要な確認事項：必要列・HTTPS可視性・社内要求元の識別、正常業務との衝突。
- 不足データ：実ログ、必要列の充足率、正常業務台帳、TP/FP判定、実行時間、ESバージョン。
- 最大のリスク：IP指定の業務API、装置へのアップロード、転送試験を攻撃と誤認すること。
- 推奨判断：調査サーチ（補助シグナル）。
- 推奨理由：単独では正常利用との識別が弱いため。追加証拠を得てから相関用に採用する。

## 参考文献

- [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)：対応する攻撃行動を参照。下記の条件・閾値は独自の調査案。

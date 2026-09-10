# PROXY-009 非標準ポートへのCONNECTトンネルの繰り返し

**検知概要：** 同じ端末が外部の443番以外へ、Proxy経由のトンネル接続を繰り返す動きを探す。

**検知意図：** HTTPS用の中継機能を別プロトコルの通信路に使っていないか調べる。

**過検知予想：** 開発用の非標準HTTPS、承認済みリモート接続。利用目的の裏付けが必要で、単独で悪性とは判断しない。

|判断の目安|内容|
|---|---|
|**重要度**|**P3：調査・相関の材料**（感染確定度ではない）|
|重要度の理由|正規利用と重なる観測が中心。単独発報だけでインシデント扱いする根拠が弱い。|
|ルールの役割|単独イベント・集約／補助シグナル|
|発報したら|原則として単独Notableにせず、下記の追加証拠との相関やハンティングに使う。|
|疑いを強める追加証拠|接続先の用途・所有者、CONNECT許可設定、端末の実行プロセス。 正常な説明がつかず、同一主体の不正操作が裏付けられること。|
|検知価値の評価|単独では低・相関用（設計上の判断。TP/FP・処理負荷は未検証）|

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `dest_zone`, `dest_ip`, `dest_port`, `http_method`, `http_status`, `bytes_out`, `bytes_in`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572)|
|検索|15分窓／5分間隔／5分遅延|

外向きForward Proxy用。src_ipは社内の要求元、dest_zoneは組織定義の外部区分。HTTPSのURL・ヘッダーを使う条件は復号・記録が必要。取得可否は未確認。探索・攻撃要求のルールも、社内端末から外部へ送った要求を扱う。

## 汎化

- 脅威固有の指標：攻撃者IP・ハッシュには依存せず、提案SPLのプロトコル・文字列・量を使用。
- 共通する実装パターン：同じ端末が外部の443番以外へ、Proxy経由のトンネル接続を繰り返す動きを探す。
- 長期利用できる攻撃行動：HTTPS用の中継機能を別プロトコルの通信路に使っていないか調べる。
- 今回採用する条件と理由：15分に5接続以上、合計1MiB以上、双方向バイトあり。 単発の一致や通常通信と区別するための設計値。
- 採用しない条件と理由：未取得の本文・端末情報や許可台帳を必須にすると、このProxyだけで成立しないため。別の調査で補う。

## 検知意図と限界

- 検知できること：同じ端末が外部の443番以外へ、Proxy経由のトンネル接続を繰り返す動きを探す。
- 検知できないこと：CONNECTログで最終トンネルバイトを記録できる場合のみ。443上のトンネルは対象外で、内部プロトコルは不明。
- 意図的に検知しないこと：閾値未満・掲載していない表現の通信、Proxyを通らない通信。
- 想定される回避方法：要求を時間・宛先へ分散する、文字列を変更する、観測対象外の本文やプロトコルへ移す。

## 誤検知

- 主な正常動作：開発用の非標準HTTPS、承認済みリモート接続。
- 誤検知を識別する追加情報：接続先の用途・所有者、CONNECT許可設定、端末の実行プロセス。
- 改善方法：上記情報で承認済み業務と照合し、送信元・対象・時間帯の組を評価。
- 除外が必要な場合の対象と根拠：承認記録で裏付けられた業務の組だけ。今回のSPLには除外なし。
- 改善により新たに生じる検知漏れ：承認端末の侵害や業務に似せた通信、追加証拠が欠落した攻撃。

## SPL

- 現行SPL：該当なし（今回の新規ルール）。
- 提案SPL：

```spl
index=detection_lab log_type="proxy" dest_zone="external" earliest=-20m@m latest=-5m@m
| where http_method="CONNECT" AND http_status >= 200 AND http_status < 300
    AND dest_port != 443 AND bytes_out > 0 AND bytes_in > 0
| stats count as tunnels
        sum(bytes_out) as sent_bytes
        sum(bytes_in) as received_bytes
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip dest_ip dest_port
| where tunnels >= 5 AND sent_bytes+received_bytes >= 1048576
| eval rule_id="PROXY-009", attack_id="T1572",
       risk_object=src_ip, risk_object_type="system", risk_score=10, severity="low"
```

- 差分：新規。非標準ポートへのCONNECTトンネルの繰り返しを調査対象として追加。
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
- notable title：PROXY-009 非標準ポートへのCONNECTトンネルの繰り返し（採用時の案）。
- drilldown：src_ipと結果の宛先で同じ15分窓の元ログを再検索。接続先の用途・所有者、CONNECT許可設定、端末の実行プロセスを確認。

## 閾値

- 初期値：15分に5接続以上、合計1MiB以上、双方向バイトあり。
- 根拠：動作の比較に使う仮の設計値。参考資料の推奨値や実環境の正常分布ではない。
- 高感度設定：3接続・256KiB。その他の条件は標準を維持する案。
- 標準設定：提案SPLの条件。
- 低誤検知設定：10接続・5MiB。追加情報が必要なら収集を確認。効果は未検証。
- ベースライン取得方法：30日を同じ15分窓と集約軸で集計し、開発用の非標準HTTPS、承認済みリモート接続の確認済み結果と比較する。

## 人が評価すべき点

- 採用判断に必要な確認事項：必要列・HTTPS可視性・社内要求元の識別、正常業務との衝突。
- 不足データ：実ログ、必要列の充足率、正常業務台帳、TP/FP判定、実行時間、ESバージョン。
- 最大のリスク：開発用の非標準HTTPS、承認済みリモート接続を攻撃と誤認すること。
- 推奨判断：調査サーチ（補助シグナル）。
- 推奨理由：単独では正常利用との識別が弱いため。追加証拠を得てから相関用に採用する。

## 参考文献

- [T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572)：対応する攻撃行動を参照。下記の条件・閾値は独自の調査案。

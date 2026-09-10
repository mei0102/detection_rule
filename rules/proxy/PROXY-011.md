# PROXY-011 外部WebSocketへの繰り返し切替

**検知概要：** 同じ外部Webホストで、HTTPからWebSocketへの接続切替が何度も成功する端末を探す。

**検知意図：** 双方向のWeb通信を、指示受信やリモート操作の経路に使っていないか調べる。

**過検知予想：** チャット、共同編集、相場配信、ネットワーク不安定時の再接続。利用目的の裏付けが必要で、単独で悪性とは判断しない。

|判断の目安|内容|
|---|---|
|**重要度**|**P3：調査・相関の材料**（感染確定度ではない）|
|重要度の理由|正規利用と重なる観測が中心。単独発報だけでインシデント扱いする根拠が弱い。|
|ルールの役割|単独イベント・集約／補助シグナル|
|発報したら|原則として単独Notableにせず、下記の追加証拠との相関やハンティングに使う。|
|疑いを強める追加証拠|Webアプリ用途、切断理由、端末の接続プロセス。 正常な説明がつかず、同一主体の不正操作が裏付けられること。|
|検知価値の評価|単独では低・相関用（設計上の判断。TP/FP・処理負荷は未検証）|

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `dest_zone`, `url`, `http_method`, `http_status`, `response_upgrade`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071) → [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)|
|検索|15分窓／5分間隔／5分遅延|

外向きForward Proxy用。src_ipは社内の要求元、dest_zoneは組織定義の外部区分。HTTPSのURL・ヘッダーを使う条件は復号・記録が必要。取得可否は未確認。探索・攻撃要求のルールも、社内端末から外部へ送った要求を扱う。

## 汎化

- 脅威固有の指標：攻撃者IP・ハッシュには依存せず、提案SPLのプロトコル・文字列・量を使用。
- 共通する実装パターン：同じ外部Webホストで、HTTPからWebSocketへの接続切替が何度も成功する端末を探す。
- 長期利用できる攻撃行動：双方向のWeb通信を、指示受信やリモート操作の経路に使っていないか調べる。
- 今回採用する条件と理由：15分に10回以上の切替成功、3つ以上の1分区間。 単発の一致や通常通信と区別するための設計値。
- 採用しない条件と理由：未取得の本文・端末情報や許可台帳を必須にすると、このProxyだけで成立しないため。別の調査で補う。

## 検知意図と限界

- 検知できること：同じ外部Webホストで、HTTPからWebSocketへの接続切替が何度も成功する端末を探す。
- 検知できないこと：response_upgradeは応答Upgradeヘッダーの抽出列として要確認。フレーム内容・接続継続時間は評価しない。HTTP/2拡張CONNECTは対象外。
- 意図的に検知しないこと：閾値未満・掲載していない表現の通信、Proxyを通らない通信。
- 想定される回避方法：要求を時間・宛先へ分散する、文字列を変更する、観測対象外の本文やプロトコルへ移す。

## 誤検知

- 主な正常動作：チャット、共同編集、相場配信、ネットワーク不安定時の再接続。
- 誤検知を識別する追加情報：Webアプリ用途、切断理由、端末の接続プロセス。
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
| where http_method="GET" AND http_status=101 AND lower(response_upgrade)="websocket"
| eval minute=floor(_time/60)
| stats count as upgrades
        dc(minute) as active_minutes
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip url_host
| where upgrades >= 10 AND active_minutes >= 3
| eval rule_id="PROXY-011", attack_id="T1071.001",
       risk_object=src_ip, risk_object_type="system", risk_score=10, severity="low"
```

- 差分：新規。外部WebSocketへの繰り返し切替を調査対象として追加。
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
- notable title：PROXY-011 外部WebSocketへの繰り返し切替（採用時の案）。
- drilldown：src_ipと結果の宛先で同じ15分窓の元ログを再検索。Webアプリ用途、切断理由、端末の接続プロセスを確認。

## 閾値

- 初期値：15分に10回以上の切替成功、3つ以上の1分区間。
- 根拠：動作の比較に使う仮の設計値。参考資料の推奨値や実環境の正常分布ではない。
- 高感度設定：5回・2区間。その他の条件は標準を維持する案。
- 標準設定：提案SPLの条件。
- 低誤検知設定：20回・5区間。追加情報が必要なら収集を確認。効果は未検証。
- ベースライン取得方法：30日を同じ15分窓と集約軸で集計し、チャット、共同編集、相場配信、ネットワーク不安定時の再接続の確認済み結果と比較する。

## 人が評価すべき点

- 採用判断に必要な確認事項：必要列・HTTPS可視性・社内要求元の識別、正常業務との衝突。
- 不足データ：実ログ、必要列の充足率、正常業務台帳、TP/FP判定、実行時間、ESバージョン。
- 最大のリスク：チャット、共同編集、相場配信、ネットワーク不安定時の再接続を攻撃と誤認すること。
- 推奨判断：調査サーチ（補助シグナル）。
- 推奨理由：単独では正常利用との識別が弱いため。追加証拠を得てから相関用に採用する。

## 参考文献

- [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)：対応する攻撃行動を参照。下記の条件・閾値は独自の調査案。
- [RFC 6455 — The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455)：HTTPハンドシェイクと101応答による接続切替を参照。

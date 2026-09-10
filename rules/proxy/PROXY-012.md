# PROXY-012 長いパラメータを変えながら同じURLパスへ送信

**検知概要：** 同じWebページのパスへ、長い英数字のパラメータを変えて何度もGETする端末を探す。

**検知意図：** URLにデータを埋め込んで外へ送る可能性を調べる。暗号化や情報流出は文字列だけでは確定しない。

**過検知予想：** SSOトークン、アクセス解析、検索条件をURLに持つアプリ。利用目的の裏付けが必要で、単独で悪性とは判断しない。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `dest_zone`, `url`, `http_method`, `http_status`|
|ATT&CK 戦術|[TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010)|
|技法 → サブ技法|[T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)|
|検索|15分窓／5分間隔／5分遅延|

外向きForward Proxy用。src_ipは社内の要求元、dest_zoneは組織定義の外部区分。HTTPSのURL・ヘッダーを使う条件は復号・記録が必要。取得可否は未確認。探索・攻撃要求のルールも、社内端末から外部へ送った要求を扱う。

## 汎化

- 脅威固有の指標：攻撃者IP・ハッシュには依存せず、提案SPLのプロトコル・文字列・量を使用。
- 共通する実装パターン：同じWebページのパスへ、長い英数字のパラメータを変えて何度もGETする端末を探す。
- 長期利用できる攻撃行動：URLにデータを埋め込んで外へ送る可能性を調べる。暗号化や情報流出は文字列だけでは確定しない。
- 今回採用する条件と理由：15分に20要求・15種類以上、クエリ文字数合計10000以上、200文字以上の値を含む。 単発の一致や通常通信と区別するための設計値。
- 採用しない条件と理由：未取得の本文・端末情報や許可台帳を必須にすると、このProxyだけで成立しないため。別の調査で補う。

## 検知意図と限界

- 検知できること：同じWebページのパスへ、長い英数字のパラメータを変えて何度もGETする端末を探す。
- 検知できないこと：POST本文やCookieは対象外。文字数は転送バイトではない。T1041はC2経路の裏付けが必要な調査仮説。
- 意図的に検知しないこと：閾値未満・掲載していない表現の通信、Proxyを通らない通信。
- 想定される回避方法：要求を時間・宛先へ分散する、文字列を変更する、観測対象外の本文やプロトコルへ移す。

## 誤検知

- 主な正常動作：SSOトークン、アクセス解析、検索条件をURLに持つアプリ。
- 誤検知を識別する追加情報：パラメータ用途、アプリ所有者、端末処理、宛先の役割。トークンを不用意に共有しない。
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
| where http_method="GET" AND http_status >= 200 AND http_status < 300
| rex field=url "[?](?<query_string>[^#]+)"
| where match(query_string, "(^|&)[^=&]+=[A-Za-z0-9_%-]{200,}")
| stats count as requests
        dc(query_string) as payload_variants
        sum(eval(len(query_string))) as query_chars
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip url_host url_path
| where requests >= 20 AND payload_variants >= 15 AND query_chars >= 10000
| eval rule_id="PROXY-012", attack_id="T1041",
       risk_object=src_ip, risk_object_type="system", risk_score=20, severity="low"
```

- 差分：新規。長いパラメータを変えながら同じURLパスへ送信を調査対象として追加。
- index、sourcetype、製品固有フィールドの置換箇所：index=detection_labは実indexへ置換し、確認済みsourcetypeで限定。log_typeは分類用の仮列。必要フィールド表は実装要件であり取得済み台帳ではない。HTTP statusは数値、methodは大文字、bytesは要求/トンネル単位。ヘッダー列は製品ごとに対応確認。
- 想定負荷：中（15分のURL抽出・集約を行う設計上の概算、未測定）。
- 負荷を抑える工夫：外向きログと時間窓を先に限定。join/transaction/全件ソートなし。加速済みCIMが確認できる場合のみtstats化を別途検討。

## Splunk ES設定案

- 実行間隔：5分。
- earliest/latest：`-20m@m` / `-5m@m`。
- trigger：結果行数 > 0。まず調査結果として評価し、自動Notableは未設定。
- suppression/throttling：初期は無効。反復状況を確認後にrule_id・src_ip・宛先の組で15分抑制する案。別の攻撃を抑える可能性を評価。
- severity：low（調査用の仮案）。
- risk score：20（未検証）。Risk Analysisアクションの設定は別途必要で、SPL列だけでは加算されない。
- risk object／type：src_ip / system。共有Proxy・NATのIPを端末と誤認しないこと。
- security domain：network。
- notable title：PROXY-012 長いパラメータを変えながら同じURLパスへ送信（採用時の案）。
- drilldown：src_ipと結果の宛先で同じ15分窓の元ログを再検索。パラメータ用途、アプリ所有者、端末処理、宛先の役割。トークンを不用意に共有しないを確認。

## 閾値

- 初期値：15分に20要求・15種類以上、クエリ文字数合計10000以上、200文字以上の値を含む。
- 根拠：動作の比較に使う仮の設計値。参考資料の推奨値や実環境の正常分布ではない。
- 高感度設定：10要求・8種類・5000文字。その他の条件は標準を維持する案。
- 標準設定：提案SPLの条件。
- 低誤検知設定：40要求・30種類・20000文字。追加情報が必要なら収集を確認。効果は未検証。
- ベースライン取得方法：30日を同じ15分窓と集約軸で集計し、SSOトークン、アクセス解析、検索条件をURLに持つアプリの確認済み結果と比較する。

## 人が評価すべき点

- 採用判断に必要な確認事項：必要列・HTTPS可視性・社内要求元の識別、正常業務との衝突。
- 不足データ：実ログ、必要列の充足率、正常業務台帳、TP/FP判定、実行時間、ESバージョン。
- 最大のリスク：SSOトークン、アクセス解析、検索条件をURLに持つアプリを攻撃と誤認すること。
- 推奨判断：調査サーチ。
- 推奨理由：URLにデータを埋め込んで外へ送る可能性を調べる。暗号化や情報流出は文字列だけでは確定しない。 追加証拠を確認してからNotable/RBA化を判断する。

## 参考文献

- [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)：対応する攻撃行動を参照。下記の条件・閾値は独自の調査案。

# PROXY-001 実行形式を示すURLからの取得成功

- 状態：experimental / 重要度：low
- SIEM：Splunk Enterprise / Splunk Cloud Platform (SPL)
- 対象ログ：proxy

## MITRE ATT&CK Matrix上の位置

|戦術（Matrixの列）|親技法|サブ技法|本ルールとの関係|
|---|---|---|---|
|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|なし（親技法に対応）|主な検知仮説|

実行形式らしいURLへのGET/200をIngress Tool Transferの候補として扱う。内容の実体・ファイル保存・実行を評価していないため、関連づけは取得の代理指標である。

[リポジトリ全体のマトリクス](../matrix.md)。これは技法の一部に対する検知仮説で、技法全体のカバレッジではありません。

## 対象ログ・必要フィールド

- 検知に必須：`_time`, `http_method`, `http_status`, `log_type`, `src_ip`, `url`
- 調査に推奨：`src_ip`, `user`, `url`, `http_method`, `http_status`, `content_type`, `bytes_in`, `action`, `user_agent`

完全URLとHTTPレスポンスステータスを収集。TLS復号・端末側可視性が必要な場合がある。

型・元項目・欠損監視は[フィールド定義](../log-sources.md)を参照。推奨項目が未採取の場合は調査結果に制約を記録します。

## 検知条件

`=` は一致、`~=` は正規表現一致、`>=` は以上、`AND` はすべて満たす意味です。`dc()` は異なる値の数です。`~=` は説明・JSON定義の記号で、SPL本文では `match()` に変換します。必須フィールドがNULLなら対象外です。

```text
log_type = "proxy"
AND http_method = "GET"
AND http_status = 200
AND url ~= /(?i)\.(exe|dll|ps1|msi)(\?|$)/

GROUP BY src_ip
WINDOW = 300 seconds
count(*) >= 1
```

## 検知SPL（Splunk）

`index=detection_lab` を正規化済みログのindexに変更してください。5分間隔、5分遅延の検索を想定しています。生ログにそのまま適用せず[Splunk導入手順](../deployment.md)でフィールドを確認してください。

```spl
index=detection_lab log_type="proxy" earliest=-10m@m latest=-5m@m
| where isnotnull(_time)
    AND isnotnull(http_method)
    AND isnotnull(http_status)
    AND isnotnull(log_type)
    AND isnotnull(src_ip)
    AND isnotnull(url)
    AND http_method="GET"
    AND http_status=200
    AND match(url, "(?i)\\.(exe|dll|ps1|msi)(\\?|$)")
| stats count as observed min(_time) as first_seen max(_time) as last_seen by src_ip
| where observed >= 1
| eval rule_id="PROXY-001", attack_id="T1105"
```

## 誤検知とチューニング

正規ソフトウェア、配布サーバ、開発ツール。

## 調査手順・判断基準

1. URL、ホスト名、src_ip、HTTPステータス、Content-Type、応答サイズ、ユーザー、Proxy actionを確認する。URLの拡張子と実体が一致するか、200がブロックページ等の合成応答でないかを調べる。

2. 301/302等のリダイレクトが前後にあるかを確認し、最終取得先と初期URLを関連づける。認証済みユーザーと端末IPの対応を当該時刻で確認する。

3. 配布元が承認されたベンダー・社内配布先か、初観測ドメインかを既存の脅威情報・過去ログで確認する。分析のためにURL先のファイルを直接取得・実行しない。

4. EDR等で既に得られているファイルハッシュ、署名、保存先と、当該端末の後続4688を確認する。ブラウザ更新か、スクリプトやOffice経由の取得かを親プロセスから調べる。

5. 未承認の取得先に加え、不審ファイル実行・持続的外部通信が確認できた場合はタイムラインを添えて引き継ぐ。正規更新なら製品・配布元・署名・時間帯を記録して調整する。

### 調査SPL：元イベントの時系列

`REPLACE_...` を検知結果の集約キーに置換します。過去アラートでは `earliest` / `latest` を発生時刻の前後15分の絶対時刻（Unix秒）に変更してください。下記の直近30分は調査開始例です。別ログ種別との照合は対象indexとlog_typeを切り替え、端末IP・host・ユーザーの対応を確認して行います。

```spl
index=detection_lab log_type="proxy" src_ip="REPLACE_SRC_IP" earliest=-30m@m latest=now
| sort 0 _time
| table _time host log_type channel event_id src_ip user url http_method http_status content_type bytes_in action user_agent _raw
```

推奨フィールドが未抽出なら `_raw` を参照します。調査SPLは検知条件を再適用せず、同じキーの正常・異常両方を表示します。キー以外の宛先・利用者へ展開する場合は該当セレクタを外して範囲を広げます。

## 限界・見逃す条件

- URL依存：exe/dll/ps1/msiという末尾またはクエリ直前の拡張子のみ。拡張子なし、URLエンコード、別拡張子、パスパラメータやアーカイブは対象外。

- HTTP条件：GETかつ200のみ。POST、206部分取得、キャッシュ、別のステータスでの取得を網羅しない。200でもファイル内容とは限らない。

- 暗号化：CONNECTのみのProxyログではURLパスが分からない。TLS可視性・端末側URLログがない環境には適用できない。

- 特異度：一般的なソフト更新でも一致する。単独では悪性判定や自動隔離に使わず、配布元・ファイル署名・後続実行を確認する。

共通制約：固定5分窓をまたぐ閾値未満の分散、5分を超える収集遅延、必須フィールド欠損、重複転送の影響を評価してください。Splunk上の実ログ検証・PCRE評価は未実施で、合成テストの成功は本番検知率を示しません。

## 参考文献

- [MITRE ATT&CK — T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
  - 概要・利用箇所：外部から侵害環境へツールやファイルを転送する挙動を説明する技法ページ。HTTP取得の調査目的を整理する参考で、拡張子やUser-Agentの一致自体を悪性の証拠とはしていない。
  - 確認日：2026-09-09

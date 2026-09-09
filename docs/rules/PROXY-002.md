# PROXY-002 PowerShell User-AgentからのHTTP取得

- 状態：experimental / 重要度：low
- SIEM：Splunk Enterprise / Splunk Cloud Platform (SPL)
- 対象ログ：proxy

## MITRE ATT&CK Matrix上の位置

|戦術（Matrixの列）|親技法|サブ技法|本ルールとの関係|
|---|---|---|---|
|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|なし（親技法に対応）|主な検知仮説|

PowerShellを名乗るUser-Agentの取得を自動化されたツール転送の探索に使う。UAは自己申告で、PowerShellプロセスやファイル転送の証明ではない。

[リポジトリ全体のマトリクス](../matrix.md)。これは技法の一部に対する検知仮説で、技法全体のカバレッジではありません。

## 対象ログ・必要フィールド

- 検知に必須：`_time`, `http_method`, `http_status`, `log_type`, `src_ip`, `user_agent`
- 調査に推奨：`src_ip`, `user`, `url`, `http_method`, `http_status`, `user_agent`, `content_type`, `bytes_in`

HTTP User-Agentを保存。HTTPS CONNECTだけでは判定不能。

型・元項目・欠損監視は[フィールド定義](../log-sources.md)を参照。推奨項目が未採取の場合は調査結果に制約を記録します。

## 検知条件

`=` は一致、`~=` は正規表現一致、`>=` は以上、`AND` はすべて満たす意味です。`dc()` は異なる値の数です。`~=` は説明・JSON定義の記号で、SPL本文では `match()` に変換します。必須フィールドがNULLなら対象外です。

```text
log_type = "proxy"
AND http_method = "GET"
AND http_status = 200
AND user_agent ~= /(?i)WindowsPowerShell|PowerShell//

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
    AND isnotnull(user_agent)
    AND http_method="GET"
    AND http_status=200
    AND match(user_agent, "(?i)WindowsPowerShell|PowerShell/")
| stats count as observed min(_time) as first_seen max(_time) as last_seen by src_ip
| where observed >= 1
| eval rule_id="PROXY-002", attack_id="T1105"
```

## 誤検知とチューニング

運用スクリプトやAPI取得。

## 調査手順・判断基準

1. src_ip、認証ユーザー、User-Agent全文、URL、応答サイズ、Content-Typeを確認し、ダウンロード・API呼出し・ヘルスチェックのどれに見えるか分類する。

2. 送信元の前後15分の4688と、収集済みなら4104を調べ、PowerShellプロセス・引数・親プロセス・実行者と通信を関連づける。共有Proxy出口を端末IPと取り違えない。

3. 同じユーザー・端末の過去7〜14日を調べ、定期ジョブの周期、既知の取得先、普段と異なるURLパスやデータ量を確認する。

4. 既存のEDRテレメトリからファイル作成や後続実行を確認する。WIN-001との同時発生があれば復号内容のURLと比較するが、時間が近いだけで同一プロセスと断定しない。

5. 所有者が確認できる運用ジョブは宛先・ユーザー・実行時間を含めて例外化する。ユーザー不認知の実行や未知宛先からの取得後に不審操作があれば証跡を引き継ぐ。

### 調査SPL：元イベントの時系列

`REPLACE_...` を検知結果の集約キーに置換します。過去アラートでは `earliest` / `latest` を発生時刻の前後15分の絶対時刻（Unix秒）に変更してください。下記の直近30分は調査開始例です。別ログ種別との照合は対象indexとlog_typeを切り替え、端末IP・host・ユーザーの対応を確認して行います。

```spl
index=detection_lab log_type="proxy" src_ip="REPLACE_SRC_IP" earliest=-30m@m latest=now
| sort 0 _time
| table _time host log_type channel event_id src_ip user url http_method http_status user_agent content_type bytes_in _raw
```

推奨フィールドが未抽出なら `_raw` を参照します。調査SPLは検知条件を再適用せず、同じキーの正常・異常両方を表示します。キー以外の宛先・利用者へ展開する場合は該当セレクタを外して範囲を広げます。

## 限界・見逃す条件

- 自己申告：User-Agentは変更・省略・偽装できる。UAが一致してもPowerShellの実行証拠ではなく、不一致でもPowerShell通信を否定できない。

- 用途：文字列だけではツール転送とAPI取得を区別できない。ファイル内容や応答サイズを検知条件に含まないためハンティング用途から開始する。

- 対象条件：GET/200と二つのUAパターンだけ。別実装の既定UA、POST、部分応答、独自ヘッダ利用を網羅しない。

- 採取：HTTPS復号がないProxyやUAを保存しない設定では動かない。UAが空のイベントを正常扱いせず、ログ品質として監視する。

共通制約：固定5分窓をまたぐ閾値未満の分散、5分を超える収集遅延、必須フィールド欠損、重複転送の影響を評価してください。Splunk上の実ログ検証・PCRE評価は未実施で、合成テストの成功は本番検知率を示しません。

## 参考文献

- [MITRE ATT&CK — T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)
  - 概要・利用箇所：外部から侵害環境へツールやファイルを転送する挙動を説明する技法ページ。HTTP取得の調査目的を整理する参考で、拡張子やUser-Agentの一致自体を悪性の証拠とはしていない。
  - 確認日：2026-09-09

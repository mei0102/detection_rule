# PROXY-005 外部WebDAV探索後のスクリプト取得

WebDAVのPROPFIND成功後5分以内に、同じ外部ホストから実行形式をGET。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `url`, `user_agent`, `http_method`, `http_status`, `dest_zone`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|
|検索|10分窓／5分間隔／5分遅延|
|工夫|WebDAVのUAと拡張子だけでなく、探索→取得の順序を加える。|

## 汎化

- 脅威固有の指標：WebDAV UA、PROPFIND→GET、拡張子。
- 共通する実装パターン：遠隔リソース探索後に実行形式を取得。
- 長期利用できる攻撃行動：外部WebDAV探索後のスクリプト取得。特定攻撃者への帰属は行わない。
- 今回採用する条件と理由：WebDAVのPROPFIND成功後5分以内に、同じ外部ホストから実行形式をGET。 この観測範囲で遠隔リソース探索後に実行形式を取得の候補を抽出するため。
- 採用しない条件と理由：先行探索なし、窓外探索、別UAは今回の条件外。別の観測・検知条件が必要なため、この検索に混在させない。未提供の資産台帳による除外も行わない。

## 検知意図と限界

- 検知できること：WebDAVのPROPFIND成功後5分以内に、同じ外部ホストから実行形式をGET。
- 検知できないこと：PROPFINDが窓外なら対象外。GETは実行成功を証明しない。
- 意図的に検知しないこと：先行探索なし、窓外探索、別UA。
- 想定される回避方法：上記の条件外の経路・表記・タイミングへ変更する、または必要ログの記録を妨げる。

## 誤検知

- 主な正常動作：業務WebDAV、文書管理。
- 誤検知を識別する追加情報：元文書、マウント先、取得物、端末実行履歴。
- 改善方法：取得物の起動や文書起点と相関。追加情報が取得できる場合の案で、今回のSPLには未適用。
- 除外が必要な場合の対象と根拠：業務WebDAV、文書管理のうち、上記情報と承認記録で一致を確認した主体・対象・時間帯だけ。現時点の除外はなし。
- 改善により新たに生じる検知漏れ：承認済み主体の侵害を除外する恐れ。追加条件を必須にすると、正常判別用の証拠が欠落した攻撃も見逃す。

## SPL

- 現行SPL：変更前のリポジトリ版（`5d42ac6`）。顧客環境の稼働版ではない。

<details>
<summary>現行SPLを表示</summary>

```spl
index=detection_lab log_type="proxy" earliest=-15m@m latest=-5m@m
| rex field=url "(?i)^https?://(?<url_host>[^/:]+)"
| where dest_zone="external" AND match(user_agent, "(?i)^Microsoft-WebDAV-MiniRedir/")
    AND http_method IN ("PROPFIND","GET")
    AND http_status >= 200 AND http_status < 300
| sort 0 _time
| streamstats time_window=5m current=f
        max(eval(if(http_method="PROPFIND",_time,null()))) as discovered_at
    by src_ip url_host
| where http_method="GET" AND _time > discovered_at
    AND _time-discovered_at <= 300
    AND _time >= relative_time(now(),"-10m@m")
    AND match(url, "(?i)\\.(exe|dll|ps1|js|vbs|lnk)(\\?|$)")
| table _time src_ip url_host url discovered_at
| eval rule_id="PROXY-005", attack_id="T1105"
```

</details>

- 提案SPL：検知条件を維持し、ES設定用の出力列を追加。

```spl
index=detection_lab log_type="proxy" earliest=-15m@m latest=-5m@m
| rex field=url "(?i)^https?://(?<url_host>[^/:]+)"
| where dest_zone="external" AND match(user_agent, "(?i)^Microsoft-WebDAV-MiniRedir/")
    AND http_method IN ("PROPFIND","GET")
    AND http_status >= 200 AND http_status < 300
| sort 0 _time
| streamstats time_window=5m current=f
        max(eval(if(http_method="PROPFIND",_time,null()))) as discovered_at
    by src_ip url_host
| where http_method="GET" AND _time > discovered_at
    AND _time-discovered_at <= 300
    AND _time >= relative_time(now(),"-10m@m")
    AND match(url, "(?i)\\.(exe|dll|ps1|js|vbs|lnk)(\\?|$)")
| table _time src_ip url_host url discovered_at
| eval rule_id="PROXY-005", attack_id="T1105"
| eval risk_object=src_ip, risk_object_type="system",
       risk_score=40, severity="medium"
```

- 差分：末尾に`risk_object`、`risk_object_type`、`risk_score`、`severity`を追加。検知件数を変える条件変更はなし。列の追加だけではRiskイベント・Notableは生成されない。
- index、sourcetype、製品固有フィールドの置換箇所：`index=detection_lab`は仮置き。実indexと確認済みsourcetypeへ置換し、`log_type`は共通分類を用意するか実ログ条件へ置換。src_ip←元クライアント、url←HTTP URL、http_method/status←要求/応答、bytes_out/in←要求単位の送受信量。必要列：`_time`, `log_type`, `src_ip`, `url`, `user_agent`, `http_method`, `http_status`, `dest_zone`。
- 想定負荷：高（全件ソートと時系列状態を保持するため。データ量・同時実行数による概算で未測定）。
- 負荷を抑える工夫：必要イベントをソート前に絞る。検索窓と並列実行数を制限し、streamstatsの上限を確認。CIM対応と加速済みData Modelが確認できる場合のみtstats化を検討。未提供のData Modelは前提にしない。

## Splunk ES設定案

- 実行間隔：5分（設定案）。
- earliest/latest：`-15m@m` / `-5m@m`。取り込み遅延5分を仮定。
- trigger：結果行数 > 0、各結果行を対象。評価後にRisk Analysis等の応答アクションを別途設定。自動のNotable生成は未設定。
- suppression/throttling：初期は無効。重複実績を確認後、同じrule_id・risk_objectの反復を検索窓相当で抑制する案。別対象・別段階まで抑える可能性があるため宛先等の追加キーを評価。
- severity：`medium`（調査優先度の仮案、確信度ではない）。
- risk score：`40`（未検証の相対値）。繰り返し発報と他ルールとの重複加算を評価してから使用。
- risk object／type：`src_ip` → `risk_object` / `system`。出力に残る主体を使用し、資産・ID正規化と共有IPを確認。
- security domain：`network`。
- notable title：`PROXY-005 外部WebDAV探索後のスクリプト取得`。Notable化を採用する場合の案。
- drilldown：結果の`src_ip`を元ログの同じ列へ渡し、検知対象窓の前後5分を再検索。元文書、マウント先、取得物、端末実行履歴を表示・照合。未取得の列は追加収集が必要。

## 閾値

- 初期値：WebDAVのPROPFIND成功後5分以内に、同じ外部ホストから実行形式をGET。 数値のないイベント・文字列条件は1件一致で結果候補。
- 根拠：上記行動の候補を切り出す設計値。参照ルールの推奨値や実環境の正常分布を証明する値ではない。
- 高感度設定：相関10分。記載以外の条件は標準と同じ。SPLには未適用。
- 標準設定：提案SPLの条件。初期値と同一。
- 低誤検知設定：相関2分（検索窓も整合させる）。追加情報が必要な案は取得確認が前提で、効果は未確認。
- ベースライン取得方法：30日を同じ検索窓・集約主体`src_ip`で区切り、正常と確認した業務WebDAV、文書管理とそれ以外を分け、件数・対象数・数値条件の分布を比較。存在しない統計は補完しない。

## 人が評価すべき点

- 採用判断に必要な確認事項：HTTPSのURL可視性・HTTP項目とリクエスト単位バイトの取得状況。元文書、マウント先、取得物、端末実行履歴で正常業務と識別できるか。
- 不足データ：実index/sourcetype、必要列の充足率、ESバージョン、発報数・TP/FP判定、資産・業務台帳、実行時間。
- 最大のリスク：業務WebDAV、文書管理との衝突と、先行探索なし、窓外探索、別UAの取りこぼし。
- 推奨判断：実装候補（本番採用の確定ではない）。
- 推奨理由：観測条件を具体化できるため。必須フィールドと正常業務の識別を確認してから採用を判断する。

## 参考文献

- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)：対象行動と戦術の対応を参照。
- [Suspicious External WebDAV Execution](https://github.com/SigmaHQ/sigma/blob/5c9b21756f4e3ba137c1773ac9ba5a8332188961/rules/web/proxy_generic/proxy_webdav_external_execution.yml)：外部WebDAVからの実行形式の取得を扱う。

- [Splunk ES — Assign risk using risk modifiers](https://docs.splunk.com/Documentation/ES/8.1.0/Admin/AssignRisk)：Risk Analysisアクションでリスクを割り当てる仕組み。本文のスコアは本リポジトリ独自の仮案。

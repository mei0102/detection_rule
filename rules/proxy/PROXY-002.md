# PROXY-002 PowerShell User-AgentからのHTTP取得

PowerShellを名乗るUser-AgentからのGET／HTTP 200を検知。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `http_method`, `http_status`, `log_type`, `src_ip`, `user_agent`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|

## 汎化

- 脅威固有の指標：PowerShellを名乗るUA。
- 共通する実装パターン：スクリプト実行環境からHTTP取得。
- 長期利用できる攻撃行動：PowerShell User-AgentからのHTTP取得。特定攻撃者への帰属は行わない。
- 今回採用する条件と理由：PowerShellを名乗るUser-AgentからのGET／HTTP 200を検知。 この観測範囲でスクリプト実行環境からHTTP取得の候補を抽出するため。
- 採用しない条件と理由：UA変更、GET以外は今回の条件外。別の観測・検知条件が必要なため、この検索に混在させない。未提供の資産台帳による除外も行わない。

## 検知意図と限界

- 検知できること：PowerShellを名乗るUser-AgentからのGET／HTTP 200を検知。
- 検知できないこと：User-Agentは偽装可能。PowerShellの実行自体は証明しない。
- 意図的に検知しないこと：UA変更、GET以外。
- 想定される回避方法：上記の条件外の経路・表記・タイミングへ変更する、または必要ログの記録を妨げる。

## 誤検知

- 主な正常動作：管理スクリプト、API取得。
- 誤検知を識別する追加情報：端末の4104/4688、URL、ジョブ所有者。
- 改善方法：PowerShell側の取得・評価動作を相関。追加情報が取得できる場合の案で、今回のSPLには未適用。
- 除外が必要な場合の対象と根拠：管理スクリプト、API取得のうち、上記情報と承認記録で一致を確認した主体・対象・時間帯だけ。現時点の除外はなし。
- 改善により新たに生じる検知漏れ：承認済み主体の侵害を除外する恐れ。追加条件を必須にすると、正常判別用の証拠が欠落した攻撃も見逃す。

## SPL

- 現行SPL：変更前のリポジトリ版（`5d42ac6`）。顧客環境の稼働版ではない。

<details>
<summary>現行SPLを表示</summary>

```spl
index=detection_lab log_type="proxy" earliest=-10m@m latest=-5m@m
| where http_method="GET"
    AND http_status=200
    AND match(user_agent, "(?i)WindowsPowerShell|PowerShell/")
| stats count as observed
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip
| where observed >= 1
| eval rule_id="PROXY-002", attack_id="T1105"
```

</details>

- 提案SPL：検知条件を維持し、ES設定用の出力列を追加。

```spl
index=detection_lab log_type="proxy" earliest=-10m@m latest=-5m@m
| where http_method="GET"
    AND http_status=200
    AND match(user_agent, "(?i)WindowsPowerShell|PowerShell/")
| stats count as observed
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip
| where observed >= 1
| eval rule_id="PROXY-002", attack_id="T1105"
| eval risk_object=src_ip, risk_object_type="system",
       risk_score=20, severity="low"
```

- 差分：末尾に`risk_object`、`risk_object_type`、`risk_score`、`severity`を追加。検知件数を変える条件変更はなし。列の追加だけではRiskイベント・Notableは生成されない。
- index、sourcetype、製品固有フィールドの置換箇所：`index=detection_lab`は仮置き。実indexと確認済みsourcetypeへ置換し、`log_type`は共通分類を用意するか実ログ条件へ置換。src_ip←元クライアント、url←HTTP URL、http_method/status←要求/応答、bytes_out/in←要求単位の送受信量。必要列：`_time`, `http_method`, `http_status`, `log_type`, `src_ip`, `user_agent`。
- 想定負荷：低（固定時間窓で条件抽出と単段集約を行うため。データ量・同時実行数による概算で未測定）。
- 負荷を抑える工夫：必要列・対象ログ・時間窓を先に限定し、集約後の少数行で追加計算。CIM対応と加速済みData Modelが確認できる場合のみtstats化を検討。未提供のData Modelは前提にしない。

## Splunk ES設定案

- 実行間隔：5分（設定案）。
- earliest/latest：`-10m@m` / `-5m@m`。取り込み遅延5分を仮定。
- trigger：結果行数 > 0、各結果行を対象。評価後にRisk Analysis等の応答アクションを別途設定。自動のNotable生成は未設定。
- suppression/throttling：初期は無効。重複実績を確認後、同じrule_id・risk_objectの反復を検索窓相当で抑制する案。別対象・別段階まで抑える可能性があるため宛先等の追加キーを評価。
- severity：`low`（調査優先度の仮案、確信度ではない）。
- risk score：`20`（未検証の相対値）。繰り返し発報と他ルールとの重複加算を評価してから使用。
- risk object／type：`src_ip` → `risk_object` / `system`。出力に残る主体を使用し、資産・ID正規化と共有IPを確認。
- security domain：`network`。
- notable title：`PROXY-002 PowerShell User-AgentからのHTTP取得`。Notable化を採用する場合の案。
- drilldown：結果の`src_ip`を元ログの同じ列へ渡し、検知対象窓の前後5分を再検索。端末の4104/4688、URL、ジョブ所有者を表示・照合。未取得の列は追加収集が必要。

## 閾値

- 初期値：PowerShellを名乗るUser-AgentからのGET／HTTP 200を検知。 数値のないイベント・文字列条件は1件一致で結果候補。
- 根拠：上記行動の候補を切り出す設計値。参照ルールの推奨値や実環境の正常分布を証明する値ではない。
- 高感度設定：GET以外も調査する案。記載以外の条件は標準と同じ。SPLには未適用。
- 標準設定：提案SPLの条件。初期値と同一。
- 低誤検知設定：端末側の動的実行も要求。追加情報が必要な案は取得確認が前提で、効果は未確認。
- ベースライン取得方法：30日を同じ検索窓・集約主体`src_ip`で区切り、正常と確認した管理スクリプト、API取得とそれ以外を分け、件数・対象数・数値条件の分布を比較。存在しない統計は補完しない。

## 人が評価すべき点

- 採用判断に必要な確認事項：HTTPSのURL可視性・HTTP項目とリクエスト単位バイトの取得状況。端末の4104/4688、URL、ジョブ所有者で正常業務と識別できるか。
- 不足データ：実index/sourcetype、必要列の充足率、ESバージョン、発報数・TP/FP判定、資産・業務台帳、実行時間。
- 最大のリスク：管理スクリプト、API取得との衝突と、UA変更、GET以外の取りこぼし。
- 推奨判断：調査サーチ（本番採用の確定ではない）。
- 推奨理由：単独では行動の代理指標であり、追加証拠を得てから相関・Notable化を判断する。

## 参考文献

- [MITRE ATT&CK — T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)：外部から侵害環境へツールやファイルを転送する挙動を説明する技法ページ。

- [Splunk ES — Assign risk using risk modifiers](https://docs.splunk.com/Documentation/ES/8.1.0/Admin/AssignRisk)：Risk Analysisアクションでリスクを割り当てる仕組み。本文のスコアは本リポジトリ独自の仮案。

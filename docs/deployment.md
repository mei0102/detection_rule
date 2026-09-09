# Splunkへの導入と検証

1. 対象ルールの必要フィールドを実ログにマッピングし、型、時刻、重複、欠損を確認します。
2. `docs/rules/*.md` 内の「検知SPL」の `index=detection_lab` を対象の正規化済みログのindexへ変更します。log_typeも必須です。独自フィールド抽出が必要で、そのまま生ログには適用できません。
3. 初期運用は5分間隔、`earliest=-10m@m latest=-5m@m`。遅延到着を5分待ち、5分間の完了窓を検索します。schedulerの遅延と欠損を監視してください。
4. statsは検索範囲全体を1窓として集計します。手動で1日分を検索すると1日合計になり、5分ルールではなくなるため、必ず5分窓で実行します。
5. 単イベントルールもhost等で窓内集約します。元イベントはdrill-downで調査します。グループキー＋窓終了時刻をアラートIDとして重複通知を抑制します。
6. 7〜14日の実ログで遡及評価し、承認済み管理通信の除外と閾値を調整します。除外には所有者・理由・期限を付けます。
7. 現場の正常ログ・承認済み検証データを追加し、レビュー後にvalidatedへ昇格します。

## フィールド抽出とCIMの扱い

このSPLは通常のイベント検索と `stats` を使います。`tstats` やESCUマクロ、加速済みデータモデルには依存しません。
Splunk Add-on等で抽出した項目を、Field aliases / Calculated fieldsまたは検知SPLの `where` より前の `eval` で正規化してください。
log_typeはsourcetypeごとに固定付与し、同じ入力をFWとNDRに重複分類しないでください。
`eval`でlog_typeを作る場合、検知SPLの先頭にある `log_type="..."` はまだ存在しない項目を検索してしまいます。その先頭条件を削除し、対象sourcetypeで入力を限定したうえで、evalの後のwhereへlog_type条件を移してください。検索時点でField alias/Calculated fieldとして利用できる場合は、元の検知SPLのままで構いません。

Windowsの例です。フィールドが実際に抽出されていることを先に確認し、元のindex/sourcetypeを環境に合わせます。
これは正規化の確認用で、検知SPLに挿入する場合は検知側の時間窓を維持します。

```spl
index=REPLACE_WINDOWS_INDEX sourcetype="REPLACE_WINDOWS_SOURCETYPE" earliest=-30m latest=now
| eval log_type="windows",
       event_id=tonumber(coalesce(event_id, EventCode, EventID)),
       host=coalesce(Computer, ComputerName, host),
       channel=coalesce(channel, Channel),
       process_path=coalesce(process_path, NewProcessName),
       command_line=coalesce(command_line, CommandLine),
       src_ip=coalesce(src_ip, IpAddress),
       user=coalesce(user, TargetUserName),
       target_sid=coalesce(target_sid, TargetSid)
| table _time host channel event_id process_path command_line src_ip user target_sid _raw
```

XMLの名前付きEventDataを抽出していない環境では、先に対応するAdd-on/フィールド抽出を設定します。
channelが未抽出の入力を一律Securityにするのは避け、Security専用入力であることを確認した場合にだけ固定値を設定します。
Splunkのhostが収集サーバを指す場合は、WindowsのComputerに直してから集約します。
`user`にSubjectUserNameが入るAdd-onでは、WIN-003用にTargetUserNameを使うよう調整してください。操作主体と対象ユーザーは別の意味です。

FWでは `dest_port` を `tonumber()`、`transport` を `lower()`、permit/accept等を `allow` に正規化します。
Proxyではステータスを数値、methodを大文字にします。NDRではdns_queryを小文字化し末尾のドットを除去します。
値の対応は製品固有です。一般的な名称だけから未知のactionをallowに変換しないでください。

## 保存検索・アラート設定

|設定|初期値／確認事項|
|---|---|
|実行方式|Scheduled。cronは `*/5 * * * *`|
|検索窓|SPL本文の `earliest=-10m@m latest=-5m@m`。同時刻の5分窓を検索|
|トリガー|検索結果件数が0より大きい。すでにSPL内で閾値を評価済み|
|結果|1行＝集約キーごとの一致。observedはイベント数またはdc値|
|権限|保存検索所有者に対象indexとフィールド抽出の読取権限を設定|
|重複通知|rule_id＋集約キー＋検索窓終了時刻で設計。first_seenを窓境界と混同しない|
|抑制|初期は抑制なしで通知量を測定。長いhost単位の抑制は別ユーザーの活動も隠す|
|ES利用時|必要なら相関検索に登録。notable/RBA設定は別途行い、このSPLだけで作成済みとは扱わない|

最初は通知先を検証用にし、資産重要度・所有者・例外情報を追加してから運用へ移します。
調査SPLのREPLACE値は実際のキーへ置換し、過去アラートでは検索時刻も絶対時刻に直してください。

## 欠損・転送遅延の確認例

```spl
index=detection_lab log_type="windows" earliest=-24h latest=now
| eval lag_seconds=_indextime-_time,
       missing_cli=if(event_id=4688 AND (isnull(command_line) OR len(command_line)=0),1,0),
       process_event=if(event_id=4688,1,0)
| stats sum(missing_cli) as missing_cli sum(process_event) as process_events
        perc95(lag_seconds) as ingest_delay_p95 max(_time) as last_event by host
| eval missing_cli_pct=if(process_events>0,round(100*missing_cli/process_events,1),null())
```

検索されたイベントだけの集計なので、24時間まったくログを送っていない端末は表示されません。
無通信端末の検出には資産台帳との照合が必要です。`_indextime-_time` は時計ずれも含むため、転送遅延と即断しないでください。

固定窓の境界をまたぐイベントは閾値に達しないことがあります。初期版はローリング窓ではありません。
必要なら重複検索＋アラート重複排除を設計し、対応する境界テストを追加してください。収集遅延が5分を超える環境は検索遅延も変更します。

## 検証の範囲

`python tools/build.py` でSPL・カード・マトリクスを再生成し、`python -m unittest discover -s tests -v` を実行。
テストはJSON定義の参照評価器で正例・負例、必須項目欠損、異なるログ種別、窓外、閾値直下、重複値、グループ分離を確認します。
SPLは同一仕様から生成しますが、Python regexとSplunk PCREの完全互換性やSplunk実行を保証するテストではありません。
Splunk環境でフィールド抽出・検索の実行・合成fixtureとの照合を完了するまでは全件experimentalです。

## 参考文献

- [Splunk — Comparison and Conditional functions](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/evaluation-functions/comparison-and-conditional-functions)：`match()`等の条件評価関数。記号~=の定義をSPLへ変換する際の参照。
- [Splunk — stats](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/stats)：イベント集計の構文とグループ化。5分の検索範囲を集約するSPLの参照。

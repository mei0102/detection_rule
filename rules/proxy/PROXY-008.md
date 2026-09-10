# PROXY-008 同一URLへの低揺らぎ周期通信

同じ送信元・URLへのGET間隔が30〜300秒で、揺らぎが平均の10%以下。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `url`, `http_method`, `http_status`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071) → [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)|
|検索|30分窓／5分間隔／5分遅延|
|工夫|件数だけでなく、時刻差・揺らぎ・継続時間を組み合わせた独自相関。|

## SPL

```spl
index=detection_lab log_type="proxy" earliest=-35m@m latest=-5m@m
| where http_method="GET" AND http_status >= 200 AND http_status < 300
| dedup src_ip url _time
| sort 0 _time
| streamstats current=f last(_time) as previous_time by src_ip url
| eval interval=_time-previous_time
| where interval > 0
| stats count as intervals
        avg(interval) as mean_seconds
        stdev(interval) as jitter_seconds
        min(previous_time) as first_seen
        max(_time) as last_seen
    by src_ip url
| where intervals >= 12 AND mean_seconds >= 30 AND mean_seconds <= 300
    AND jitter_seconds/mean_seconds <= 0.1
    AND last_seen-first_seen >= 600
    AND last_seen >= relative_time(now(),"-10m@m")
| eval rule_id="PROXY-008", attack_id="T1071.001"
```

**範囲：** ヘルスチェックでも一致。URLを毎回変更する通信や大きなジッターは対象外。

## 参考文献

- [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)：対象行動と戦術の対応を参照。

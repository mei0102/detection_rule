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

## SPL

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

**範囲：** PROPFINDが窓外なら対象外。GETは実行成功を証明しない。

## 参考文献

- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)：対象行動と戦術の対応を参照。
- [Suspicious External WebDAV Execution](https://github.com/SigmaHQ/sigma/blob/5c9b21756f4e3ba137c1773ac9ba5a8332188961/rules/web/proxy_generic/proxy_webdav_external_execution.yml)：外部WebDAVからの実行形式の取得を扱う。

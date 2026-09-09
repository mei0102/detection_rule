# PROXY-001 実行形式を示すURLからの取得成功

exe・dll・ps1・msiのURLへのGETがHTTP 200で応答。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `http_method`, `http_status`, `log_type`, `src_ip`, `url`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|

## SPL

```spl
index=detection_lab log_type="proxy" earliest=-10m@m latest=-5m@m
| where http_method="GET"
    AND http_status=200
    AND match(url, "(?i)\\.(exe|dll|ps1|msi)(\\?|$)")
| stats count as observed
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip
| where observed >= 1
| eval rule_id="PROXY-001", attack_id="T1105"
```

**範囲：** URLパスの取得が必要。取得内容や実行の悪性は判定しない。

## 参考文献

- [MITRE ATT&CK — T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)：外部から侵害環境へツールやファイルを転送する挙動を説明する技法ページ。

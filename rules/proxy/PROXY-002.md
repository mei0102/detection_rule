# PROXY-002 PowerShell User-AgentからのHTTP取得

PowerShellを名乗るUser-AgentからのGET／HTTP 200を検知。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `http_method`, `http_status`, `log_type`, `src_ip`, `user_agent`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|

## SPL

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

**範囲：** User-Agentは偽装可能。PowerShellの実行自体は証明しない。

## 参考文献

- [MITRE ATT&CK — T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)：外部から侵害環境へツールやファイルを転送する挙動を説明する技法ページ。

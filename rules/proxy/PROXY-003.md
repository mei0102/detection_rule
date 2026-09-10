# PROXY-003 BITSによる外部IP直指定ダウンロード

BITSのUser-Agentで外部IPv4直指定URLを取得し、1KiB以上を受信。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `url`, `user_agent`, `http_method`, `http_status`, `bytes_in`, `dest_zone`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|
|検索|5分窓／5分間隔／5分遅延|
|工夫|UAとIPの末尾文字だけでなく、URLホスト全体・応答・受信量を組み合わせる。|

dest_zoneは実際の宛先IPに基づく内部・外部分類。

## SPL

```spl
index=detection_lab log_type="proxy" earliest=-10m@m latest=-5m@m
| rex field=url "(?i)^https?://(?<url_host>[^/:]+)"
| where dest_zone="external" AND http_method="GET"
    AND http_status IN (200,206) AND bytes_in >= 1024
    AND match(user_agent, "(?i)^Microsoft BITS/")
    AND match(url_host, "^(\\d{1,3}\\.){3}\\d{1,3}$")
| stats count as observed
        min(_time) as first_seen
        max(_time) as last_seen
        values(url) as urls sum(bytes_in) as received_bytes
    by src_ip url_host
| eval rule_id="PROXY-003", attack_id="T1105"
```

**範囲：** IPv4直指定だけが対象。正規配布も一致し、取得物の実行は不明。

## 参考文献

- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)：対象行動と戦術の対応を参照。
- [Bitsadmin to Uncommon IP Server Address](https://github.com/SigmaHQ/sigma/blob/5c9b21756f4e3ba137c1773ac9ba5a8332188961/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_ip.yml)：BITSのUser-AgentとIP直指定先に着目する。
- [Cisco Secure Firewall - Bits Network Activity](https://github.com/splunk/security_content/blob/4cd62e811c5eddf1245c780d48823d7b38998566/detections/network/cisco_secure_firewall___bits_network_activity.yml)：アプリ識別を使ってBITS通信を扱う。

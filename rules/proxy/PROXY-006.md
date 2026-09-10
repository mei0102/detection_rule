# PROXY-006 Curl／Wgetによる実行形式の取得

Curl／Wgetを名乗るGETで実行形式URLを取得し、1KiB以上受信。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `url`, `user_agent`, `http_method`, `http_status`, `bytes_in`, `content_type`|
|ATT&CK 戦術|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|
|技法 → サブ技法|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|
|検索|5分窓／5分間隔／5分遅延|
|工夫|CLI通信全般から、実行形式URL・非HTML応答・受信量の組み合わせへ限定。|

## SPL

```spl
index=detection_lab log_type="proxy" earliest=-10m@m latest=-5m@m
| where http_method="GET" AND http_status IN (200,206) AND bytes_in >= 1024
    AND match(user_agent, "(?i)^(curl|wget)/")
    AND match(url, "(?i)\\.(exe|dll|ps1|sh|py)(\\?|$)")
    AND NOT match(content_type, "(?i)^text/html\\b")
| stats count as observed
        min(_time) as first_seen
        max(_time) as last_seen
        values(url) as urls sum(bytes_in) as received_bytes
    by src_ip
| eval rule_id="PROXY-006", attack_id="T1105"
```

**範囲：** content_typeを保存するProxyが必要。正常インストーラも一致。

## 参考文献

- [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)：対象行動と戦術の対応を参照。
- [Cisco Secure Firewall - Wget or Curl Download](https://github.com/splunk/security_content/blob/4cd62e811c5eddf1245c780d48823d7b38998566/detections/network/cisco_secure_firewall___wget_or_curl_download.yml)：CurlやWgetを使うダウンロード通信を扱う。

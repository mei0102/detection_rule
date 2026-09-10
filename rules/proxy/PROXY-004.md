# PROXY-004 Rcloneからクラウド保存先への大容量アップロード

Rcloneを名乗るPOST／PUTがクラウドストレージ宛に成功し、15分で10MiB以上送信。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `url`, `user_agent`, `http_method`, `http_status`, `bytes_out`|
|ATT&CK 戦術|[TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010)|
|技法 → サブ技法|[T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567) → [T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)|
|検索|15分窓／5分間隔／5分遅延|
|工夫|Rclone UA単独から、クラウド宛先・アップロード操作・応答・量の組み合わせ。|

bytes_outはクライアントからWebサーバへ送信したリクエスト単位のバイト。

## SPL

```spl
index=detection_lab log_type="proxy" earliest=-20m@m latest=-5m@m
| rex field=url "(?i)^https?://(?<url_host>[^/:]+)"
| where http_method IN ("POST","PUT") AND http_status >= 200 AND http_status < 300
    AND match(user_agent, "(?i)^rclone/")
    AND match(url_host, "(?i)(^|\\.)(amazonaws\\.com|storage\\.googleapis\\.com|blob\\.core\\.windows\\.net)$")
| stats sum(bytes_out) as uploaded_bytes
        count as requests
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip url_host
| where uploaded_bytes >= 10485760
| eval rule_id="PROXY-004", attack_id="T1567.002"
```

**範囲：** UAは偽装可能。正規同期やバックアップも一致し、指定した保存先だけが対象。

## 参考文献

- [T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)：対象行動と戦術の対応を参照。
- [Rclone Activity via Proxy](https://github.com/SigmaHQ/sigma/blob/5c9b21756f4e3ba137c1773ac9ba5a8332188961/rules/web/proxy_generic/proxy_ua_rclone.yml)：ProxyのUser-AgentからRclone通信を探す。

# PROXY-007 Webhookへの反復・大容量POST

Discord／SlackのWebhookパスへ15分で5回以上POSTし、合計100KiB以上送信。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `url`, `http_method`, `http_status`, `bytes_out`|
|ATT&CK 戦術|[TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010)|
|技法 → サブ技法|[T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567) → [T1567.004 Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004)|
|検索|15分窓／5分間隔／5分遅延|
|工夫|WebhookのURL一致から、成功応答・反復・送信量を組み合わせた独自相関。|

URLパスとクライアント送信バイトが必要。Webhookトークンは出力しない。

## SPL

```spl
index=detection_lab log_type="proxy" earliest=-20m@m latest=-5m@m
| where http_method="POST" AND http_status >= 200 AND http_status < 300
    AND match(url, "(?i)^https://((canary\\.|ptb\\.)?discord(app)?\\.com/api/webhooks/|hooks\\.slack\\.com/services/)")
| rex field=url "(?i)^https://(?<url_host>[^/]+)"
| stats count as posts
        sum(bytes_out) as uploaded_bytes
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip url_host
| where posts >= 5 AND uploaded_bytes >= 102400
| eval rule_id="PROXY-007", attack_id="T1567.004"
```

**範囲：** 正規通知も一致。リクエスト内容を評価せず、情報流出を確定しない。

## 参考文献

- [T1567.004 Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004)：対象行動と戦術の対応を参照。

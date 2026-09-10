# PROXY-004 クラウド保存先への継続的・集中的アップロード

同一端末から特定クラウド保存先への成功アップロードが、15分で50MiB・3分区間以上にわたり、全送信量の80%以上。

|項目|内容|
|---|---|
|対象ログ|Proxy|
|必要フィールド|`_time`, `log_type`, `src_ip`, `url`, `user_agent`, `http_method`, `http_status`, `bytes_out`, `bytes_in`|
|ATT&CK 戦術|[TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010)|
|技法 → サブ技法|[T1567 Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567) → [T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)|
|検索|15分窓／5分間隔／5分遅延|
|工夫|UAを必須条件から調査情報へ変更。成功操作・継続性・送受信比・端末内の送信集中を判定。|

bytes_out/inはリクエスト単位の送受信バイト。全HTTP操作を取得し、URLホストを抽出できることが前提。

## SPL

```spl
index=detection_lab log_type="proxy" earliest=-20m@m latest=-5m@m
| rex field=url "(?i)^https?://(?<url_host>[^/:]+)"
| eval url_host=lower(url_host), minute=floor(_time/60)
| eval upload=if(http_method IN ("POST","PUT")
                    AND http_status >= 200 AND http_status < 300,1,0)
| stats sum(bytes_out) as sent_bytes
        sum(bytes_in) as received_bytes
        sum(eval(if(upload=1,bytes_out,0))) as uploaded_bytes
        sum(upload) as upload_requests
        dc(eval(if(upload=1,minute,null()))) as upload_minutes
        values(user_agent) as user_agents
        min(_time) as first_seen
        max(_time) as last_seen
    by src_ip url_host
| eventstats sum(sent_bytes) as source_sent_bytes by src_ip
| eval upload_share=uploaded_bytes/max(source_sent_bytes,1),
       outbound_ratio=uploaded_bytes/max(received_bytes,1)
| where match(url_host,"(?i)(^|[.])(amazonaws[.]com|storage[.]googleapis[.]com|blob[.]core[.]windows[.]net)$")
    AND uploaded_bytes >= 52428800 AND upload_requests >= 5
    AND upload_minutes >= 3 AND upload_share >= 0.8 AND outbound_ratio >= 10
| eval rule_id="PROXY-004", attack_id="T1567.002"
```

**範囲：** 正規バックアップも一致。未掲載サービス、単発・短時間転送、他通信に埋もれる転送は対象外。Proxyを通らない通信は分母に含まない。

**調査：** user_agents、保存先テナント、送信元の所有者を確認。正規同期の実行履歴と照合し、同時刻のファイル収集・圧縮操作を調べる。

## 参考文献

- [T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)：対象行動と戦術の対応を参照。
- [Rclone Activity via Proxy](https://github.com/SigmaHQ/sigma/blob/5c9b21756f4e3ba137c1773ac9ba5a8332188961/rules/web/proxy_generic/proxy_ua_rclone.yml)：ProxyのUser-AgentからRclone通信を探す。

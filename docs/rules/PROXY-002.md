# PROXY-002 PowerShell User-AgentからのHTTP取得

- 状態：experimental / 重要度：low
- ATT&CK：T1105 / command-and-control
- 対象ログ：proxy
- 必須フィールド：_time, http_method, http_status, log_type, src_ip, user_agent
- 窓：300秒（検索範囲全体） / 集約：src_ip
- 指標：count（count以外は異なる値の数） / 閾値：1以上

## 採取の前提

HTTP User-Agentを保存。HTTPS CONNECTだけでは判定不能。

## 誤検知と調整

運用スクリプトやAPI取得。

## 調査

URL、宛先、ユーザーと同時刻4688/4104を確認。承認済み自動化と照合。

## 限界

User-Agentは偽装・省略可能。PowerShell通信だけでツール転送や悪性とは断定しない。

## 条件（すべてAND）

```json
[
  [
    "http_method",
    "eq",
    "GET"
  ],
  [
    "http_status",
    "eq",
    200
  ],
  [
    "user_agent",
    "regex",
    "(?i)WindowsPowerShell|PowerShell/"
  ]
]
```

## SPL

[検索ファイル](../../queries/PROXY-002.spl)。正規化と導入手順は[こちら](../deployment.md)。

## 参考

- [参考資料 1](https://attack.mitre.org/techniques/T1105/)

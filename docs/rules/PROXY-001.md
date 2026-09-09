# PROXY-001 実行形式を示すURLからの取得成功

- 状態：experimental / 重要度：low
- ATT&CK：T1105 / command-and-control
- 対象ログ：proxy
- 必須フィールド：_time, http_method, http_status, log_type, src_ip, url
- 窓：300秒（検索範囲全体） / 集約：src_ip
- 指標：count（count以外は異なる値の数） / 閾値：1以上

## 採取の前提

完全URLとHTTPレスポンスステータスを収集。TLS復号・端末側可視性が必要な場合がある。

## 誤検知と調整

正規ソフトウェア、配布サーバ、開発ツール。

## 調査

ドメイン評判、Content-Type、ハッシュ、署名、後続実行を確認。

## 限界

低特異度のハンティング。拡張子偽装、拡張子なし、206応答は対象外。取得と実行は別。

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
    "url",
    "regex",
    "(?i)\\.(exe|dll|ps1|msi)(\\?|$)"
  ]
]
```

## SPL

[検索ファイル](../../queries/PROXY-001.spl)。正規化と導入手順は[こちら](../deployment.md)。

## 参考

- [参考資料 1](https://attack.mitre.org/techniques/T1105/)

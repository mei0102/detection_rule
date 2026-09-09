# ATT&CK × ログ（候補カバレッジ）

各セルは技法の一部を観測するルールへのリンクです。状態は各カードを参照。未記載技法は未評価です。

|Tactic|Technique|Windows Event|FW|Proxy|NDR|
|---|---|---|---|---|---|
|command-and-control|T1071.004|—|—|—|[NDR-001](rules/NDR-001.md)|
|command-and-control|T1105|—|—|[PROXY-001](rules/PROXY-001.md) / [PROXY-002](rules/PROXY-002.md)|—|
|credential-access|T1110.001|[WIN-003](rules/WIN-003.md)|—|—|—|
|defense-evasion|T1070.001|[WIN-002](rules/WIN-002.md)|—|—|—|
|discovery|T1046|—|[FW-001](rules/FW-001.md)|—|—|
|execution|T1059.001|[WIN-001](rules/WIN-001.md)|—|—|—|
|lateral-movement|T1021.001|—|[FW-002](rules/FW-002.md)|—|—|
|persistence|T1053.005|[WIN-005](rules/WIN-005.md)|—|—|—|
|persistence|T1098|[WIN-004](rules/WIN-004.md)|—|—|—|

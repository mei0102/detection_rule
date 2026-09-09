# MITRE ATT&CK Enterprise Matrixとルールの位置

公式の戦術列順で掲載し、横幅を抑えるため前半・後半に分けています。各セルの親技法→サブ技法がルールの位置です。未実装の技法一覧そのものは[公式Matrix](https://attack.mitre.org/matrices/enterprise/)を参照してください。

**主**＝本ルールの主な検知仮説、**関連**＝公式の所属戦術だが本ルールでは実行・権限昇格等の成立まで判定しない位置。未実装＝このリポジトリに対応ルールなし。全て候補カバレッジです。

基準：2026-09-09に取得した[MITRE公式STIX](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack.json)、commit `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`。旧Defense Evasionの分類を固定利用せず、このスナップショットのStealth / Defense Impairmentを用います。

## 戦術列 1〜8

|[TA0043 Reconnaissance](https://attack.mitre.org/tactics/TA0043)|[TA0042 Resource Development](https://attack.mitre.org/tactics/TA0042)|[TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001)|[TA0002 Execution](https://attack.mitre.org/tactics/TA0002)|[TA0003 Persistence](https://attack.mitre.org/tactics/TA0003)|[TA0004 Privilege Escalation](https://attack.mitre.org/tactics/TA0004)|[TA0005 Stealth](https://attack.mitre.org/tactics/TA0005)|[TA0112 Defense Impairment](https://attack.mitre.org/tactics/TA0112)|
|---|---|---|---|---|---|---|---|
|未実装|未実装|未実装|[T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) → [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)<br>[WIN-001](rules/WIN-001.md) / 主|[T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098) → [T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)<br>[WIN-004](rules/WIN-004.md) / 主|[T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098) → [T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)<br>[WIN-004](rules/WIN-004.md) / 関連|未実装|[T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685) → [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)<br>[WIN-002](rules/WIN-002.md) / 主|
| | | |[T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) → [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/WIN-005.md) / 関連|[T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) → [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/WIN-005.md) / 主|[T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) → [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/WIN-005.md) / 関連| | |

## 戦術列 9〜15

|[TA0006 Credential Access](https://attack.mitre.org/tactics/TA0006)|[TA0007 Discovery](https://attack.mitre.org/tactics/TA0007)|[TA0008 Lateral Movement](https://attack.mitre.org/tactics/TA0008)|[TA0009 Collection](https://attack.mitre.org/tactics/TA0009)|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|[TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010)|[TA0040 Impact](https://attack.mitre.org/tactics/TA0040)|
|---|---|---|---|---|---|---|
|[T1110 Brute Force](https://attack.mitre.org/techniques/T1110) → [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001)<br>[WIN-003](rules/WIN-003.md) / 主|[T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046)<br>[FW-001](rules/FW-001.md) / 主|[T1021 Remote Services](https://attack.mitre.org/techniques/T1021) → [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)<br>[FW-002](rules/FW-002.md) / 主|未実装|[T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071) → [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004)<br>[NDR-001](rules/NDR-001.md) / 主|未実装|未実装|
| | | | |[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)<br>[PROXY-001](rules/PROXY-001.md) / 主| | |
| | | | |[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)<br>[PROXY-002](rules/PROXY-002.md) / 主| | |

## 技法 × 対象ログ

|親技法 → サブ技法|Windows Event|FW|Proxy|NDR|
|---|---|---|---|---|
|[T1021 Remote Services](https://attack.mitre.org/techniques/T1021) → [T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)|—|[FW-002](rules/FW-002.md)|—|—|
|[T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046)|—|[FW-001](rules/FW-001.md)|—|—|
|[T1053 Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) → [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)|[WIN-005](rules/WIN-005.md)|—|—|—|
|[T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) → [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)|[WIN-001](rules/WIN-001.md)|—|—|—|
|[T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071) → [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004)|—|—|—|[NDR-001](rules/NDR-001.md)|
|[T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098) → [T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)|[WIN-004](rules/WIN-004.md)|—|—|—|
|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|—|—|[PROXY-001](rules/PROXY-001.md) / [PROXY-002](rules/PROXY-002.md)|—|
|[T1110 Brute Force](https://attack.mitre.org/techniques/T1110) → [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001)|[WIN-003](rules/WIN-003.md)|—|—|—|
|[T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685) → [T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)|[WIN-002](rules/WIN-002.md)|—|—|—|

WIN-002は旧T1070.001からT1685.005へ更新。WIN-004は親T1098からT1098.007へ詳細化。IDの更新で検知件数を増やした扱いにはしません。
